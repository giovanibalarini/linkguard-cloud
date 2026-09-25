// Package hosts é o inventário das máquinas que passam por esta caixa.
//
// ─── QUEM É UMA MÁQUINA ──────────────────────────────────────────────────────
//
// Um IP privado. A versão on-prem identificava pelo MAC da tabela de
// vizinhança, e na VCN isso não enxerga quase nada: a máquina de outra
// sub-rede chega pelo roteador virtual da Oracle e nunca aparece na
// vizinhança desta caixa. O IP de uma VNIC não muda enquanto ela existe.
//
// ─── DE ONDE ELAS VÊM ────────────────────────────────────────────────────────
//
// Dos contadores de tráfego do nftables (internal/nftables/accounting.go), que
// já são por endereço: toda máquina local que encaminhou um pacote por aqui
// está lá. Mais o que o banco já conhece, para quem sumiu aparecer como
// offline em vez de desaparecer.
//
// ─── E OS NOMES ──────────────────────────────────────────────────────────────
//
// Das máquinas da VCN, pelo DNS reverso do resolvedor da própria VCN (ver
// Nomes). Das pessoas da VPN, pelo usuário dono do peer.
package hosts

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/giovanibalarini/linkguard-cloud/internal/nftables"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
	"github.com/giovanibalarini/linkguard-cloud/internal/validate"
)

// Tipos de máquina.
const (
	KindVCN = "vcn"
	KindVPN = "vpn"
)

// onlineJanela é quanto tempo depois do último tráfego visto a máquina ainda
// conta como online.
const onlineJanela = 10 * time.Minute

// Host é uma linha do inventário.
type Host struct {
	IP string `json:"ip"`
	// Kind é "vcn" (máquina da conta) ou "vpn" (pessoa conectada pelo túnel).
	Kind   string `json:"kind"`
	Online bool   `json:"online"`
	// Hostname é o nome da instância (DNS reverso da VCN) ou o usuário da VPN.
	Hostname  string     `json:"hostname,omitempty"`
	Alias     string     `json:"alias,omitempty"`
	Blocked   bool       `json:"blocked"`
	FirstSeen *time.Time `json:"first_seen,omitempty"`
	LastSeen  *time.Time `json:"last_seen,omitempty"`
}

// Service monta o inventário.
type Service struct {
	db    *storage.DB
	nft   *nftables.Service
	nomes *Nomes
	agora func() time.Time
}

// NewService cria o serviço. nomes pode ser nil (sem DNS reverso).
func NewService(db *storage.DB, nft *nftables.Service, nomes *Nomes) *Service {
	return &Service{db: db, nft: nft, nomes: nomes, agora: time.Now}
}

// Registrar grava que estes IPs tiveram tráfego agora. Quem chama é o
// amostrador de consumo (internal/hosttraffic), que já sabe quem trafegou a
// cada rodada: assim a última vez vista fica certa mesmo sem ninguém abrir a
// tela.
func (s *Service) Registrar(ips []string) {
	validos := make([]string, 0, len(ips))
	for _, ip := range ips {
		if ehIPv4(ip) {
			validos = append(validos, ip)
		}
	}
	if err := s.db.UpsertHostSightings(validos); err != nil {
		slog.Debug("inventário: não foi possível gravar os avistamentos", "err", err)
	}
	if s.nomes != nil {
		s.nomes.Pedir(validos)
	}
}

// List devolve o inventário: toda máquina que o contador de tráfego conhece,
// mais as que o banco lembra.
//
// Erro ao ler os contadores NÃO vira lista vazia: o banco ainda sabe quem
// passou por aqui, e a tela mostra isso.
func (s *Service) List(ctx context.Context) ([]Host, error) {
	infos, err := s.db.ListHostInfo()
	if err != nil {
		return nil, err
	}
	porIP := make(map[string]storage.HostInfo, len(infos))
	for _, i := range infos {
		porIP[i.IP] = i
	}

	var novos []string
	if s.nft != nil {
		if contadores, err := s.nft.HostCounters(ctx); err != nil {
			slog.Debug("inventário: contadores indisponíveis; só o que o banco conhece", "err", err)
		} else {
			for ip := range contadores {
				if _, ok := porIP[ip]; !ok && ehIPv4(ip) {
					novos = append(novos, ip)
				}
			}
		}
	}
	if len(novos) > 0 {
		s.Registrar(novos)
		if infos, err = s.db.ListHostInfo(); err != nil {
			return nil, err
		}
	}

	pessoas := s.pessoasDaVPN()
	agora := s.agora()
	hosts := make([]Host, 0, len(infos))
	var semNome []string
	for _, i := range infos {
		i := i
		h := Host{
			IP: i.IP, Kind: KindVCN, Hostname: i.Hostname, Alias: i.Alias, Blocked: i.Blocked,
			FirstSeen: &i.FirstSeen, LastSeen: &i.LastSeen,
			Online: agora.Sub(i.LastSeen) < onlineJanela,
		}
		if pessoa, ok := pessoas[i.IP]; ok {
			h.Kind, h.Hostname = KindVPN, pessoa
		} else if h.Hostname == "" {
			semNome = append(semNome, i.IP)
		}
		hosts = append(hosts, h)
	}
	if s.nomes != nil {
		s.nomes.Pedir(semNome)
	}

	sort.Slice(hosts, func(a, b int) bool {
		if hosts[a].Online != hosts[b].Online {
			return hosts[a].Online
		}
		return ipMenor(hosts[a].IP, hosts[b].IP)
	})
	return hosts, nil
}

// pessoasDaVPN mapeia o IP de cada peer ao nome do usuário dono dele.
func (s *Service) pessoasDaVPN() map[string]string {
	out := map[string]string{}
	peers, err := s.db.ListWireGuardPeers()
	if err != nil {
		return out
	}
	for _, p := range peers {
		ip := p.Address
		if i := strings.IndexByte(ip, '/'); i >= 0 {
			ip = ip[:i]
		}
		if ehIPv4(ip) {
			out[ip] = p.Username
		}
	}
	return out
}

// ErrIPInvalido é devolvido quando o endereço pedido não é um IPv4.
var ErrIPInvalido = errors.New("endereço IPv4 inválido")

// SetAlias dá um apelido à máquina.
func (s *Service) SetAlias(ip, alias string) error {
	if ip = validate.IPv4Canonico(ip); ip == "" {
		return ErrIPInvalido
	}
	return s.db.SetHostAlias(ip, alias)
}

// SetBlocked bloqueia ou desbloqueia a máquina: grava a flag E aplica no
// firewall vivo, pondo ou tirando o IP do set `blocked_hosts` (a chain forward
// descarta o que vai para ele ou vem dele).
//
// O ERRO DO NFT NÃO É ENGOLIDO: a tela diria "bloqueado" sobre um elemento que
// o kernel recusou. O ruído benigno é separado por operação — ver o fim deste
// arquivo.
func (s *Service) SetBlocked(ctx context.Context, ip string, blocked bool) error {
	if ip = validate.IPv4Canonico(ip); ip == "" {
		return ErrIPInvalido
	}
	if err := s.db.SetHostBlocked(ip, blocked); err != nil {
		return err
	}
	var errNft error
	benigno := func(error) bool { return false }
	if blocked {
		_, errNft = s.nft.BlockHost(ctx, ip)
		benigno = func(e error) bool { return strings.Contains(strings.ToLower(e.Error()), "file exists") }
	} else {
		_, errNft = s.nft.UnblockHost(ctx, ip)
		benigno = func(e error) bool { return strings.Contains(strings.ToLower(e.Error()), "no such file") }
	}
	if errNft != nil && !benigno(errNft) {
		slog.Error("não foi possível aplicar o bloqueio no firewall; a tela vai mostrar um bloqueio que não está valendo",
			"ip", ip, "bloqueado", blocked, "err", errNft)
	}
	// O snapshot do ruleset vivo leva o bloqueio junto, para uma reinstalação do
	// zero restaurá-lo (espelha o saveNftSnapshot dos handlers; duplicado aqui
	// para este pacote não depender de internal/api/handlers).
	if rs, err := s.nft.PersistentRuleset(ctx); err == nil {
		_ = s.db.SetSetting(nftables.LiveSnapshotSettingKey, rs)
	}
	return nil
}

// SincronizaBloqueios põe no set `blocked_hosts` todo IP marcado como
// bloqueado no banco. Roda a cada boot e é idempotente: é o que faz o bloqueio
// sobreviver a uma tabela recriada, e o que traz para o set os bloqueios que a
// migração 102 converteu de MAC para IP.
func (s *Service) SincronizaBloqueios(ctx context.Context) {
	infos, err := s.db.ListHostInfo()
	if err != nil {
		slog.Warn("não foi possível ler as máquinas para sincronizar os bloqueios", "err", err)
		return
	}
	var n int
	for _, i := range infos {
		if !i.Blocked || !ehIPv4(i.IP) {
			continue
		}
		if _, err := s.nft.BlockHost(ctx, i.IP); err == nil || strings.Contains(strings.ToLower(err.Error()), "file exists") {
			n++
		}
	}
	if n > 0 {
		slog.Info("bloqueios sincronizados a partir do banco", "maquinas", n)
	}
}

// ehIPv4 diz se o endereço é IPv4. Os sets de máquina do nftables são
// `ipv4_addr`: gravar outra coisa não é uma limitação, é um elemento recusado.
func ehIPv4(ip string) bool {
	addr, err := netip.ParseAddr(ip)
	return err == nil && addr.Is4()
}

// ipMenor ordena por endereço de verdade, e não como texto ("10.0.1.9" antes
// de "10.0.1.10").
func ipMenor(a, b string) bool {
	x, errA := netip.ParseAddr(a)
	y, errB := netip.ParseAddr(b)
	if errA != nil || errB != nil {
		return a < b
	}
	return x.Less(y)
}

// O RUÍDO BENIGNO É SEPARADO POR OPERAÇÃO, E NÃO PELA MENSAGEM.
//
// O nft responde "No such file or directory" tanto para "esse elemento não está
// no set" — no-op legítimo de um desbloqueio repetido — quanto para "esse SET
// não existe", que foi exatamente a falha que escapou para produção na v1.0.147.
// Tratar a mensagem como benigna nos dois casos silenciaria de novo o bug que
// este trecho existe para denunciar.
//
// Somar já-existente só acontece no bloqueio; tirar já-ausente só no
// desbloqueio. Cada caminho aceita a sua, e nada mais.
