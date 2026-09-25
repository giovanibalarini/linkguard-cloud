package hosts

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

// ResolvedorOCI é o DNS da própria VCN. É ele que sabe o nome das instâncias
// (o hostname que o console e o Terraform dão a cada VNIC): o resolv.conf desta
// máquina aponta para o unbound local, que resolve a Internet e não conhece os
// nomes privados da Oracle.
const ResolvedorOCI = "169.254.169.254:53"

const (
	validadeNome    = 6 * time.Hour    // quanto um nome encontrado vale antes de perguntar de novo
	validadeSemNome = 30 * time.Minute // quanto esperar para perguntar de novo por quem não tem nome
	prazoConsulta   = 3 * time.Second
	paralelas       = 4
)

// Nomes resolve IP → nome pelo DNS reverso, em segundo plano e com cache.
//
// A tela NUNCA espera por isto: Pedir só enfileira, e o nome aparece na
// abertura seguinte. Uma consulta de DNS por máquina a cada abertura da tela
// seria o inventário travando por causa de um resolvedor lento.
type Nomes struct {
	resolver *net.Resolver
	gravar   func(map[string]string) error
	// resolver é trocado nos testes.
	consultar func(ctx context.Context, ip string) (string, error)

	mu        sync.Mutex
	proxima   map[string]time.Time // quando se pode perguntar de novo por este IP
	pendentes map[string]bool
	fila      chan string
}

// NovosNomes cria o resolvedor de nomes. servidor vazio usa o resolvedor do
// sistema; "host:porta" consulta aquele servidor diretamente. gravar recebe os
// nomes encontrados (normalmente storage.DB.SetHostnames).
func NovosNomes(servidor string, gravar func(map[string]string) error) *Nomes {
	r := net.DefaultResolver
	if servidor != "" {
		r = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: prazoConsulta}
				return d.DialContext(ctx, network, servidor)
			},
		}
	}
	n := &Nomes{
		resolver:  r,
		gravar:    gravar,
		proxima:   map[string]time.Time{},
		pendentes: map[string]bool{},
		fila:      make(chan string, 1024),
	}
	n.consultar = n.consultarDNS
	return n
}

// Pedir enfileira os IPs que ainda não têm nome ou cujo nome venceu. Nunca
// bloqueia: fila cheia descarta, e a próxima abertura pede de novo.
func (n *Nomes) Pedir(ips []string) {
	agora := time.Now()
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, ip := range ips {
		if n.pendentes[ip] || agora.Before(n.proxima[ip]) {
			continue
		}
		select {
		case n.fila <- ip:
			n.pendentes[ip] = true
		default:
			return
		}
	}
}

// Run consome a fila até o contexto acabar.
func (n *Nomes) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for i := 0; i < paralelas; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case ip := <-n.fila:
					n.resolverUm(ctx, ip)
				}
			}
		}()
	}
	wg.Wait()
}

func (n *Nomes) resolverUm(ctx context.Context, ip string) {
	c, cancel := context.WithTimeout(ctx, prazoConsulta)
	nome, err := n.consultar(c, ip)
	cancel()

	n.mu.Lock()
	delete(n.pendentes, ip)
	if err != nil || nome == "" {
		n.proxima[ip] = time.Now().Add(validadeSemNome)
	} else {
		n.proxima[ip] = time.Now().Add(validadeNome)
	}
	n.mu.Unlock()

	if nome == "" {
		return
	}
	if err := n.gravar(map[string]string{ip: nome}); err != nil {
		slog.Debug("nomes: não foi possível gravar", "ip", ip, "err", err)
	}
}

func (n *Nomes) consultarDNS(ctx context.Context, ip string) (string, error) {
	nomes, err := n.resolver.LookupAddr(ctx, ip)
	if err != nil || len(nomes) == 0 {
		return "", err
	}
	return nomeCurto(nomes[0]), nil
}

// nomeCurto fica com o primeiro rótulo: "k3s-server-1.private.vcn.oraclevcn.com."
// vira "k3s-server-1". O resto é a sub-rede e a VCN, que numa conta só se
// repetem em toda linha.
func nomeCurto(fqdn string) string {
	fqdn = strings.TrimSuffix(fqdn, ".")
	if i := strings.IndexByte(fqdn, '.'); i > 0 {
		return fqdn[:i]
	}
	return fqdn
}
