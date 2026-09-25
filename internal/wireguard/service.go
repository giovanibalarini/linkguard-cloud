package wireguard

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/giovanibalarini/linkguard-cloud/internal/bootstrapdeps"
	"github.com/giovanibalarini/linkguard-cloud/internal/firewall"
	"github.com/giovanibalarini/linkguard-cloud/internal/nftables"
	"github.com/giovanibalarini/linkguard-cloud/internal/secrets"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

const (
	wireGuardPackage = "wireguard-tools"
	qrencodePackage  = "qrencode"
)

// EndpointResolver chooses the client-facing endpoint. Main wires this to the
// selected link's enabled DDNS hostname and falls back to the validated
// explicit host.
type EndpointResolver func(linkID, explicitHost string) (string, error)

type QREncoder interface {
	Encode(ctx context.Context, value string) (dataURL string, err error)
}

type commandQREncoder struct{}

func (commandQREncoder) Encode(ctx context.Context, value string) (string, error) {
	cmd := exec.CommandContext(ctx, "qrencode", "-t", "SVG", "-o", "-", "-m", "1")
	cmd.Stdin = strings.NewReader(value) // secret never enters argv or process logs
	var out bytes.Buffer
	cmd.Stdout = &out
	// Deliberately discard stderr: a helper error must never echo the client
	// config (and private key) into an HTTP response or journal entry.
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("não foi possível gerar o QR code")
	}
	return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString(out.Bytes()), nil
}

type Overview struct {
	Config         Config `json:"config"`
	PublicKey      string `json:"public_key,omitempty"`
	Peers          []Peer `json:"peers"`
	Running        bool   `json:"running"`
	LastApplyOK    bool   `json:"last_apply_ok"`
	LastApplyError string `json:"last_apply_error,omitempty"`
	LastAppliedAt  int64  `json:"last_applied_at,omitempty"`
}

type Enrollment struct {
	Peer         Peer   `json:"peer"`
	ClientConfig string `json:"client_config"`
	QRDataURL    string `json:"qr_data_url,omitempty"`
	ApplyError   string `json:"apply_error,omitempty"`
	Warning      string `json:"warning,omitempty"`
}

type Service struct {
	db          *storage.DB
	secrets     secrets.Secrets
	exec        firewall.Executor
	installExec firewall.Executor
	configPath  string
	resolve     EndpointResolver
	qr          QREncoder
	now         func() time.Time
	mu          sync.Mutex
}

func NewService(db *storage.DB, sec secrets.Secrets, executor firewall.Executor) *Service {
	return &Service{
		db: db, secrets: sec, exec: executor, installExec: executor,
		configPath: ConfigPath, qr: commandQREncoder{}, now: time.Now,
	}
}

func (s *Service) SetInstallExecutor(executor firewall.Executor) {
	if executor != nil {
		s.installExec = executor
	}
}

func (s *Service) SetEndpointResolver(resolve EndpointResolver) { s.resolve = resolve }

func (s *Service) Config() (Config, error) {
	row, err := s.db.GetWireGuardConfig()
	if err != nil {
		return Config{}, err
	}
	if row == nil {
		return DefaultConfig(), nil
	}
	return configFromStorage(row), nil
}

func configFromStorage(row *storage.WireGuardConfig) Config {
	return Config{Enabled: row.Enabled, ListenPort: row.ListenPort, Address: row.Address,
		EndpointHost: row.EndpointHost, EndpointLinkID: row.EndpointLinkID}
}

func (s *Service) UpdateConfig(ctx context.Context, c Config) error {
	if err := ValidateConfig(c); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prior, err := s.db.GetWireGuardConfig()
	if err != nil {
		return err
	}
	row := storage.WireGuardConfig{Enabled: c.Enabled, ListenPort: c.ListenPort,
		Address: c.Address, EndpointHost: c.EndpointHost, EndpointLinkID: c.EndpointLinkID}
	if prior != nil {
		row.LastApplyOK, row.LastApplyError, row.LastAppliedAt = prior.LastApplyOK, prior.LastApplyError, prior.LastAppliedAt
	}
	if err := s.db.SaveWireGuardConfig(&row); err != nil {
		return err
	}
	return s.reconcileLocked(ctx)
}

func (s *Service) Reconcile(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reconcileLocked(ctx)
}

// RecordIntegrationError marks the desired state as not fully applied when a
// caller fails to reconcile a dependent subsystem (firewall or DNS). The raw
// dependency error is intentionally not persisted: it may contain command
// stderr or paths and Overview is available to lower-privileged VPN readers.
func (s *Service) RecordIntegrationError(integrationErr error) {
	if integrationErr == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := s.Config()
	if err != nil {
		return
	}
	s.recordApply(c, fmt.Errorf("a integração da VPN com firewall/DNS não foi reconciliada"))
}

func (s *Service) reconcileLocked(ctx context.Context) error {
	c, err := s.Config()
	if err == nil {
		// Sink validation is intentionally repeated for DB rows restored or
		// written by an older build. It runs before package/secret/file changes.
		err = ValidateConfig(c)
	}
	if err == nil {
		if c.Enabled {
			err = s.applyEnabled(ctx, c)
		} else {
			err = s.applyDisabled(ctx)
		}
	}
	s.recordApply(c, err)
	return err
}

func (s *Service) recordApply(c Config, applyErr error) {
	row, err := s.db.GetWireGuardConfig()
	if err != nil || row == nil {
		row = &storage.WireGuardConfig{Enabled: c.Enabled, ListenPort: c.ListenPort,
			Address: c.Address, EndpointHost: c.EndpointHost, EndpointLinkID: c.EndpointLinkID}
	}
	row.LastApplyOK = applyErr == nil
	row.LastAppliedAt = s.now().Unix()
	row.LastApplyError = ""
	if applyErr != nil {
		row.LastApplyError = applyErr.Error()
	}
	_ = s.db.SaveWireGuardConfig(row)
}

func (s *Service) applyDisabled(ctx context.Context) error {
	if s.exec.IsDryRun() {
		return nil
	}
	if s.isActive(ctx) || s.isEnabled(ctx) {
		if _, err := s.exec.Execute(ctx, "systemctl", "disable", "--now", ServiceName); err != nil {
			return fmt.Errorf("não foi possível parar o serviço WireGuard")
		}
	}
	if _, err := os.Lstat(s.configPath); err == nil {
		if _, err := s.exec.Execute(ctx, "rm", "-f", "--", s.configPath); err != nil {
			return fmt.Errorf("não foi possível remover a configuração WireGuard desativada")
		}
	}
	return nil
}

func (s *Service) applyEnabled(ctx context.Context, c Config) error {
	if s.exec.IsDryRun() {
		return nil
	}
	if _, err := bootstrapdeps.EnsureInstalled(ctx, s.installExec, wireGuardPackage, qrencodePackage); err != nil {
		return err
	}
	private, _, err := s.ensureServerKey()
	if err != nil {
		return fmt.Errorf("não foi possível preparar a identidade do servidor: %w", err)
	}
	storedPeers, err := s.db.ListWireGuardPeers()
	if err != nil {
		return err
	}
	for _, p := range storedPeers {
		fallthroughMode := nftables.FallthroughContinue
		if p.AccessMode == "restricted" {
			fallthroughMode = nftables.FallthroughDrop
		}
		group := storage.FirewallGroup{ID: p.FirewallGroupID, Name: "VPN — " + p.Username,
			ChainName: nftables.GroupChainName(p.FirewallGroupID), Enabled: true,
			CondSaddr: p.Address, Fallthrough: fallthroughMode,
			Kind: nftables.GroupKindWireGuardPeer, Scope: nftables.ScopeForward,
			ConnState: nftables.ConnStateAny}
		if err := s.db.EnsureWireGuardPeerGroup(&group); err != nil {
			return fmt.Errorf("não foi possível reconciliar o grupo do peer %s: %w", p.UserID, err)
		}
		if err := s.reconcilePeerZTNARules(ctx, p); err != nil {
			return fmt.Errorf("não foi possível reconciliar regras ZTNA do peer %s: %w", p.UserID, err)
		}
	}
	peers := peersFromStorage(storedPeers)
	content, err := RenderServerConfig(c, private, peers)
	if err != nil {
		return err
	}

	dir := filepath.Dir(s.configPath)
	if _, err := s.exec.Execute(ctx, "install", "-d", "-m", "0700", "-o", "root", "-g", "root", dir); err != nil {
		return fmt.Errorf("não foi possível proteger o diretório do WireGuard")
	}
	old, _ := os.ReadFile(s.configPath)
	changed := string(old) != content
	if changed {
		// wg-quick exige estritamente por regex que o arquivo termine em .conf e
		// o nome base da interface tenha no máximo 15 caracteres (^[a-zA-Z0-9_=+.-]{1,15}\.conf$).
		tmp := filepath.Join(dir, fmt.Sprintf("lgchk%x.conf", time.Now().UnixNano()&0xffffff))
		cleanup := true
		defer func() {
			if cleanup {
				_, _ = s.exec.Execute(context.Background(), "rm", "-f", "--", tmp)
			}
		}()
		if err := s.exec.WriteFile(tmp, []byte(content), 0o600); err != nil {
			return fmt.Errorf("não foi possível gravar a configuração WireGuard")
		}
		if _, err := s.exec.Execute(ctx, "chmod", "0600", tmp); err != nil {
			return fmt.Errorf("não foi possível proteger a configuração WireGuard")
		}
		if _, err := s.exec.Execute(ctx, "chown", "root:root", tmp); err != nil {
			return fmt.Errorf("não foi possível definir o dono da configuração WireGuard")
		}
		if _, err := s.exec.ExecuteRead(ctx, "wg-quick", "strip", tmp); err != nil {
			return fmt.Errorf("a configuração WireGuard foi recusada pelo validador; nada foi aplicado")
		}
		if _, err := s.exec.Execute(ctx, "mv", "--", tmp, s.configPath); err != nil {
			return fmt.Errorf("não foi possível ativar a configuração WireGuard validada")
		}
		cleanup = false
	}
	// Reassert ownership even when bytes are unchanged: package upgrades or a
	// manual chmod must not make the private server key world-readable.
	if _, err := s.exec.Execute(ctx, "chmod", "0600", s.configPath); err != nil {
		return fmt.Errorf("não foi possível proteger a configuração WireGuard")
	}
	if _, err := s.exec.Execute(ctx, "chown", "root:root", s.configPath); err != nil {
		return fmt.Errorf("não foi possível definir o dono da configuração WireGuard")
	}
	if _, err := s.exec.Execute(ctx, "systemctl", "enable", ServiceName); err != nil {
		return fmt.Errorf("não foi possível habilitar o serviço WireGuard")
	}
	if changed {
		if _, err := s.exec.Execute(ctx, "systemctl", "restart", ServiceName); err != nil {
			return fmt.Errorf("não foi possível iniciar o serviço WireGuard")
		}
	} else if !s.isActive(ctx) {
		if _, err := s.exec.Execute(ctx, "systemctl", "start", ServiceName); err != nil {
			return fmt.Errorf("não foi possível iniciar o serviço WireGuard")
		}
	}
	return nil
}

func (s *Service) ensureServerKey() (private, public string, err error) {
	private, err = s.secrets.Get(ServerSecret)
	if err != nil {
		return "", "", err
	}
	if private == "" {
		private, public, err = GenerateKeypair()
		if err != nil {
			return "", "", err
		}
		if err := s.secrets.Set(ServerSecret, private); err != nil {
			return "", "", err
		}
		return private, public, nil
	}
	public, err = PublicKey(private)
	return private, public, err
}

func peersFromStorage(rows []storage.WireGuardPeer) []Peer {
	out := make([]Peer, 0, len(rows))
	for _, p := range rows {
		mode := p.AccessMode
		if mode == "" {
			mode = "full"
		}
		groups := p.AllowedHostGroups
		if groups == nil {
			groups = []string{}
		}
		tunnel := p.TunnelMode
		if tunnel == "" {
			tunnel = TunnelFull
		}
		routes := p.ExtraRoutes
		if routes == nil {
			routes = []string{}
		}
		out = append(out, Peer{
			UserID:            p.UserID,
			Username:          p.Username,
			PublicKey:         p.PublicKey,
			Address:           p.Address,
			FirewallGroupID:   p.FirewallGroupID,
			AccessMode:        mode,
			AllowedHostGroups: groups,
			AllowedPorts:      p.AllowedPorts,
			TunnelMode:        tunnel,
			ExtraRoutes:       routes,
			MTU:               p.MTU,
			ConfigStale:       p.ConfigStale,
			CreatedAt:         p.CreatedAt.Unix(),
			RotatedAt:         p.RotatedAt.Unix(),
		})
	}
	return out
}

func (s *Service) resolveEndpoint(c Config) (string, error) {
	host := c.EndpointHost
	if s.resolve != nil {
		var err error
		host, err = s.resolve(c.EndpointLinkID, c.EndpointHost)
		if err != nil {
			return "", err
		}
	}
	if !validEndpointHost(host) {
		return "", fmt.Errorf("configure o endereço público da VPN (hostname ou IP)")
	}
	return host, nil
}

func (s *Service) Enroll(ctx context.Context, userID string) (Enrollment, error) {
	return s.enroll(ctx, userID, nil)
}

// EnrollFor é o admin entregando o acesso de OUTRA pessoa, já com o perfil
// escolhido: o que ela alcança e por qual túnel.
//
// Até 24/09/2026 só existia o enrolamento do próprio usuário. Para dar a um
// colega acesso restrito ao k3s foi preciso logar como ele, enrolar, restringir
// e reemitir, nessa ordem, porque o perfil não podia ser definido antes de o
// peer existir. Aqui o perfil entra junto: a primeira configuração entregue já
// é a definitiva, e um peer novo nunca existe com acesso total.
func (s *Service) EnrollFor(ctx context.Context, userID string, access PeerAccess) (Enrollment, error) {
	normalized, err := normalizeAccess(access)
	if err != nil {
		return Enrollment{}, err
	}
	return s.enroll(ctx, userID, &normalized)
}

// enroll gera (ou rotaciona) a identidade do peer. Com access nil o perfil
// atual atravessa a rotação; com access, ele é o perfil que passa a valer.
func (s *Service) enroll(ctx context.Context, userID string, access *PeerAccess) (Enrollment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := s.Config()
	if err != nil {
		return Enrollment{}, err
	}
	if err := ValidateConfig(c); err != nil {
		return Enrollment{}, err
	}
	if !c.Enabled {
		return Enrollment{}, fmt.Errorf("ative o WireGuard antes de enrolar um usuário")
	}
	endpoint, err := s.resolveEndpoint(c)
	if err != nil {
		return Enrollment{}, err
	}
	user, err := s.db.GetUserByID(userID)
	if err != nil {
		return Enrollment{}, err
	}
	if user == nil {
		return Enrollment{}, fmt.Errorf("usuário local não encontrado")
	}
	stored, err := s.db.ListWireGuardPeers()
	if err != nil {
		return Enrollment{}, err
	}
	current, err := s.db.GetWireGuardPeer(userID)
	if err != nil {
		return Enrollment{}, err
	}
	address := ""
	groupID := ""
	accessMode, tunnelMode := "full", TunnelFull
	allowedGroups, extraRoutes := []string{}, []string{}
	mtu := 0
	if current != nil {
		address, groupID = current.Address, current.FirewallGroupID
		// Rotacionar a chave não é mudar a política: o perfil do peer
		// atravessa intacto, senão um "gerar de novo" silenciosamente
		// devolveria o usuário para full tunnel.
		accessMode, tunnelMode = current.AccessMode, current.TunnelMode
		allowedGroups, extraRoutes, mtu = current.AllowedHostGroups, current.ExtraRoutes, current.MTU
	} else {
		address, err = NextAddress(c, peersFromStorage(stored))
		if err != nil {
			return Enrollment{}, err
		}
		groupID = uuid.NewString()
	}
	allowedPorts := ""
	if current != nil {
		allowedPorts = current.AllowedPorts
	}
	if access != nil {
		accessMode, tunnelMode = access.AccessMode, access.TunnelMode
		allowedGroups, allowedPorts = access.AllowedHostGroups, access.AllowedPorts
		extraRoutes, mtu = access.ExtraRoutes, access.MTU
	}
	clientPrivate, clientPublic, err := GenerateKeypair()
	if err != nil {
		return Enrollment{}, err
	}
	serverPrivate, serverPublic, err := s.ensureServerKey()
	if err != nil {
		return Enrollment{}, err
	}
	_ = serverPrivate // never leaves this method; public is all clients need
	peer := Peer{UserID: userID, Username: user.Username, PublicKey: clientPublic,
		Address: address, FirewallGroupID: groupID, AccessMode: accessMode,
		AllowedHostGroups: allowedGroups, AllowedPorts: allowedPorts, TunnelMode: tunnelMode,
		ExtraRoutes: extraRoutes, MTU: mtu}
	routes, err := s.resolveRoutes(accessMode, allowedGroups, extraRoutes)
	if err != nil {
		return Enrollment{}, err
	}
	clientConfig, err := RenderClientConfig(c, serverPublic, peer, clientPrivate, endpoint, routes)
	if err != nil {
		return Enrollment{}, err
	}
	secretName := "wireguard_peer_private_" + uuid.NewString()
	if err := s.secrets.Set(secretName, clientPrivate); err != nil {
		return Enrollment{}, err
	}
	row := storage.WireGuardPeer{UserID: userID, PublicKey: clientPublic, Address: address,
		SecretName: secretName, FirewallGroupID: groupID, AccessMode: accessMode,
		AllowedHostGroups: allowedGroups, AllowedPorts: allowedPorts, TunnelMode: tunnelMode,
		ExtraRoutes: extraRoutes, MTU: mtu}
	group := storage.FirewallGroup{ID: groupID, Name: "VPN — " + user.Username,
		ChainName: nftables.GroupChainName(groupID), Enabled: true, CondSaddr: address,
		Fallthrough: peerFallthrough(accessMode), Kind: nftables.GroupKindWireGuardPeer,
		Scope: nftables.ScopeForward, ConnState: nftables.ConnStateAny}
	old, err := s.db.UpsertWireGuardPeer(&row, &group)
	if err != nil {
		_ = s.secrets.Delete(secretName)
		return Enrollment{}, err
	}
	if old != nil {
		_ = s.secrets.Delete(old.SecretName)
	}
	if access != nil && current != nil {
		// O upsert completa com o perfil anterior os campos que chegam vazios —
		// é o que faz a rotação preservar a política. Um perfil escolhido agora
		// vale por inteiro, inclusive o que ele esvazia.
		if err := s.db.UpdateWireGuardPeerAccess(userID, storage.WireGuardPeerAccess{
			AccessMode: accessMode, AllowedHostGroups: allowedGroups, AllowedPorts: allowedPorts,
			TunnelMode: tunnelMode, ExtraRoutes: extraRoutes, MTU: mtu,
		}); err != nil {
			return Enrollment{}, err
		}
	}
	// A config que sai daqui já tem o perfil vigente: ela não está desatualizada.
	if err := s.db.MarkWireGuardConfigIssued(userID); err != nil {
		return Enrollment{}, err
	}
	if stored, err := s.db.GetWireGuardPeer(userID); err == nil && stored != nil {
		if err := s.reconcilePeerZTNARules(ctx, *stored); err != nil {
			return Enrollment{}, err
		}
	}
	peer.CreatedAt, peer.RotatedAt = row.CreatedAt.Unix(), row.RotatedAt.Unix()
	result := Enrollment{Peer: peer, ClientConfig: clientConfig}
	if applyErr := s.reconcileLocked(ctx); applyErr != nil {
		// Persistence succeeded and this is the only delivery of the private
		// config. Return it with an honest runtime error instead of losing it.
		result.ApplyError = applyErr.Error()
	}
	if s.qr != nil {
		qr, qrErr := s.qr.Encode(ctx, clientConfig)
		if qrErr != nil {
			result.Warning = qrErr.Error()
		} else {
			result.QRDataURL = qr
		}
	}
	return result, nil
}

func (s *Service) Revoke(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed, err := s.db.DeleteWireGuardPeer(userID)
	if err != nil || removed == nil {
		return err
	}
	secretErr := s.secrets.Delete(removed.SecretName)
	if err := s.deletePeerInputGroup(removed.FirewallGroupID); err != nil {
		return err
	}
	applyErr := s.reconcileLocked(ctx)
	if secretErr != nil {
		return secretErr
	}
	return applyErr
}

// PeerAccess é o perfil que o painel edita de uma vez: o que o peer ALCANÇA
// (access, aplicado em nftables) e o que ele MANDA para o túnel (tunnel,
// aplicado na config do cliente).
type PeerAccess struct {
	AccessMode        string
	AllowedHostGroups []string
	AllowedPorts      string
	TunnelMode        string
	ExtraRoutes       []string
	MTU               int
}

// resolveRoutes traduz o perfil do peer nos destinos que entram no AllowedIPs
// do cliente: os hosts dos grupos liberados, mais as rotas extras digitadas.
//
// Só o serviço faz isto porque só ele alcança o banco; o render recebe a lista
// pronta e a revalida antes de escrever.
func (s *Service) resolveRoutes(accessMode string, allowedHostGroups, extraRoutes []string) ([]string, error) {
	routes := append([]string(nil), extraRoutes...)
	if accessMode == "restricted" {
		for _, id := range allowedHostGroups {
			group, err := s.db.GetHostGroup(id)
			if err != nil {
				return nil, err
			}
			if group == nil {
				continue
			}
			routes = append(routes, group.Hosts...)
		}
	}
	return NormalizeRoutes(routes)
}

// ClientConfig reemite a config do peer SEM rotacionar a chave.
//
// É o par necessário do modo de túnel por peer: o WireGuard não empurra rota
// nenhuma para um cliente já configurado, então mudar o perfil exige entregar o
// arquivo de novo. Sem este caminho, a única forma de reemitir seria enrolar
// outra vez — o que troca a chave e derruba o dispositivo que ainda estava
// funcionando.
func (s *Service) ClientConfig(ctx context.Context, userID string) (Enrollment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := s.Config()
	if err != nil {
		return Enrollment{}, err
	}
	if err := ValidateConfig(c); err != nil {
		return Enrollment{}, err
	}
	endpoint, err := s.resolveEndpoint(c)
	if err != nil {
		return Enrollment{}, err
	}
	stored, err := s.db.GetWireGuardPeer(userID)
	if err != nil {
		return Enrollment{}, err
	}
	if stored == nil {
		return Enrollment{}, fmt.Errorf("nenhuma identidade WireGuard para este usuário")
	}
	private, err := s.secrets.Get(stored.SecretName)
	if err != nil {
		return Enrollment{}, err
	}
	if private == "" {
		return Enrollment{}, fmt.Errorf("a chave deste peer não está mais no cofre; gere a configuração novamente")
	}
	// A privada guardada tem que corresponder à pública que o servidor conhece.
	// Sem esta conferência, um cofre restaurado de outro backup entregaria uma
	// config que o túnel não aceita, e o sintoma seria só um handshake mudo.
	public, err := PublicKey(private)
	if err != nil || public != stored.PublicKey {
		return Enrollment{}, fmt.Errorf("a chave guardada não corresponde ao peer registrado; gere a configuração novamente")
	}
	routes, err := s.resolveRoutes(stored.AccessMode, stored.AllowedHostGroups, stored.ExtraRoutes)
	if err != nil {
		return Enrollment{}, err
	}
	_, serverPublic, err := s.ensureServerKey()
	if err != nil {
		return Enrollment{}, err
	}
	peer := peersFromStorage([]storage.WireGuardPeer{*stored})[0]
	clientConfig, err := RenderClientConfig(c, serverPublic, peer, private, endpoint, routes)
	if err != nil {
		return Enrollment{}, err
	}
	if err := s.db.MarkWireGuardConfigIssued(userID); err != nil {
		return Enrollment{}, err
	}
	peer.ConfigStale = false
	result := Enrollment{Peer: peer, ClientConfig: clientConfig}
	if s.qr != nil {
		qr, qrErr := s.qr.Encode(ctx, clientConfig)
		if qrErr != nil {
			result.Warning = qrErr.Error()
		} else {
			result.QRDataURL = qr
		}
	}
	return result, nil
}

func (s *Service) SetPeerAccess(ctx context.Context, userID string, access PeerAccess) error {
	access, err := normalizeAccess(access)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	peer, err := s.db.GetWireGuardPeer(userID)
	if err != nil {
		return err
	}
	if peer == nil {
		return fmt.Errorf("peer não encontrado")
	}

	if err := s.db.UpdateWireGuardPeerAccess(userID, storage.WireGuardPeerAccess{
		AccessMode:        access.AccessMode,
		AllowedHostGroups: access.AllowedHostGroups,
		AllowedPorts:      access.AllowedPorts,
		TunnelMode:        access.TunnelMode,
		ExtraRoutes:       access.ExtraRoutes,
		MTU:               access.MTU,
	}); err != nil {
		return err
	}

	updated, err := s.db.GetWireGuardPeer(userID)
	if err != nil || updated == nil {
		return err
	}

	fallthroughMode := nftables.FallthroughContinue
	if updated.AccessMode == "restricted" {
		fallthroughMode = nftables.FallthroughDrop
	}
	group := storage.FirewallGroup{
		ID:          updated.FirewallGroupID,
		Name:        "VPN — " + updated.Username,
		ChainName:   nftables.GroupChainName(updated.FirewallGroupID),
		Enabled:     true,
		CondSaddr:   updated.Address,
		Fallthrough: fallthroughMode,
		Kind:        nftables.GroupKindWireGuardPeer,
		Scope:       nftables.ScopeForward,
		ConnState:   nftables.ConnStateAny,
	}
	if err := s.db.EnsureWireGuardPeerGroup(&group); err != nil {
		return err
	}

	if err := s.reconcilePeerZTNARules(ctx, *updated); err != nil {
		return err
	}

	return s.reconcileLocked(ctx)
}

func (s *Service) reconcilePeerZTNARules(_ context.Context, p storage.WireGuardPeer) error {
	if err := s.reconcilePeerInputGroup(p); err != nil {
		return err
	}
	rules, err := s.db.ListFirewallRules()
	if err != nil {
		return err
	}
	for _, r := range rules {
		if r.GroupID == p.FirewallGroupID && strings.HasPrefix(r.Description, "ZTNA:") {
			_ = s.db.DeleteFirewallRule(r.ID)
		}
	}

	if p.AccessMode != "restricted" || len(p.AllowedHostGroups) == 0 {
		return nil
	}

	for _, hgID := range p.AllowedHostGroups {
		hg, err := s.db.GetHostGroup(hgID)
		if err != nil || hg == nil {
			continue
		}
		for _, host := range hg.Hosts {
			host = strings.TrimSpace(host)
			if host == "" {
				continue
			}
			if p.AllowedPorts != "" {
				ports := strings.Split(p.AllowedPorts, ",")
				for _, port := range ports {
					port = strings.TrimSpace(port)
					if port == "" {
						continue
					}
					rule := storage.FirewallRule{
						GroupID:     p.FirewallGroupID,
						Action:      "accept",
						Daddr:       host,
						Proto:       "tcp",
						Dport:       port,
						Description: "ZTNA: " + hg.Name + " (TCP:" + port + ")",
					}
					_ = s.db.CreateFirewallRule(&rule)
				}
				icmpRule := storage.FirewallRule{
					GroupID:     p.FirewallGroupID,
					Action:      "accept",
					Daddr:       host,
					Proto:       "icmp",
					Description: "ZTNA: " + hg.Name + " (ICMP)",
				}
				_ = s.db.CreateFirewallRule(&icmpRule)
			} else {
				rule := storage.FirewallRule{
					GroupID:     p.FirewallGroupID,
					Action:      "accept",
					Daddr:       host,
					Description: "ZTNA: " + hg.Name,
				}
				_ = s.db.CreateFirewallRule(&rule)
			}
		}
	}
	return nil
}

func (s *Service) Overview(ctx context.Context) (Overview, error) {
	c, err := s.Config()
	if err != nil {
		return Overview{}, err
	}
	rows, err := s.db.ListWireGuardPeers()
	if err != nil {
		return Overview{}, err
	}
	row, err := s.db.GetWireGuardConfig()
	if err != nil {
		return Overview{}, err
	}
	public := ""
	if private, err := s.secrets.Get(ServerSecret); err == nil && private != "" {
		public, _ = PublicKey(private)
	}
	peers := peersFromStorage(rows)
	running := s.isActive(ctx)
	if running {
		s.enrichPeersTelemetry(ctx, peers)
	}
	out := Overview{Config: c, PublicKey: public, Peers: peers, Running: running}
	if row != nil {
		out.LastApplyOK, out.LastApplyError, out.LastAppliedAt = row.LastApplyOK, row.LastApplyError, row.LastAppliedAt
	}
	return out, nil
}

type peerDump struct {
	endpoint        string
	latestHandshake int64
	transferRx      int64
	transferTx      int64
}

func parseWgDump(raw string) map[string]peerDump {
	out := make(map[string]peerDump)
	lines := strings.Split(raw, "\n")
	if len(lines) <= 1 {
		return out
	}
	// Line 0 is interface info; lines 1+ are peer info.
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 8 {
			continue
		}
		pubKey := strings.TrimSpace(fields[0])
		endpoint := strings.TrimSpace(fields[2])
		if endpoint == "(none)" {
			endpoint = ""
		}
		handshake, _ := strconv.ParseInt(strings.TrimSpace(fields[4]), 10, 64)
		rx, _ := strconv.ParseInt(strings.TrimSpace(fields[5]), 10, 64)
		tx, _ := strconv.ParseInt(strings.TrimSpace(fields[6]), 10, 64)
		out[pubKey] = peerDump{
			endpoint:        endpoint,
			latestHandshake: handshake,
			transferRx:      rx,
			transferTx:      tx,
		}
	}
	return out
}

var (
	pingTimeRE = regexp.MustCompile(`time=([0-9.]+)\s*ms`)
	pingRttRE  = regexp.MustCompile(`rtt [^=]+=\s*[^/]+/([0-9.]+)`)
)

func parsePingOutput(output string) float64 {
	if m := pingTimeRE.FindStringSubmatch(output); len(m) > 1 {
		if val, err := strconv.ParseFloat(m[1], 64); err == nil {
			return val
		}
	}
	if m := pingRttRE.FindStringSubmatch(output); len(m) > 1 {
		if val, err := strconv.ParseFloat(m[1], 64); err == nil {
			return val
		}
	}
	return 0
}

func (s *Service) measureLatency(ctx context.Context, ip string) float64 {
	out, err := s.exec.ExecuteRead(ctx, "ping", "-c", "1", "-W", "1", "-w", "1", ip)
	if err != nil {
		return 0
	}
	return parsePingOutput(out)
}

func (s *Service) enrichPeersTelemetry(ctx context.Context, peers []Peer) {
	if len(peers) == 0 {
		return
	}
	raw, err := s.exec.ExecuteRead(ctx, "wg", "show", InterfaceName, "dump")
	if err != nil || strings.TrimSpace(raw) == "" {
		return
	}
	dumpMap := parseWgDump(raw)
	var onlineIndices []int
	for i := range peers {
		if data, ok := dumpMap[peers[i].PublicKey]; ok {
			peers[i].Endpoint = data.endpoint
			peers[i].LatestHandshake = data.latestHandshake
			peers[i].TransferRx = data.transferRx
			peers[i].TransferTx = data.transferTx
			if data.latestHandshake > 0 && s.now().Sub(time.Unix(data.latestHandshake, 0)) <= 3*time.Minute {
				peers[i].Online = true
				onlineIndices = append(onlineIndices, i)
			}
		}
	}
	if len(onlineIndices) == 0 {
		return
	}
	ctxPing, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
	defer cancel()
	var wg sync.WaitGroup
	for _, idx := range onlineIndices {
		ip := strings.Split(peers[idx].Address, "/")[0]
		if ip == "" {
			continue
		}
		wg.Add(1)
		go func(pIdx int, targetIP string) {
			defer wg.Done()
			peers[pIdx].LatencyMs = s.measureLatency(ctxPing, targetIP)
		}(idx, ip)
	}
	wg.Wait()
}

func (s *Service) isActive(ctx context.Context) bool {
	out, err := s.exec.ExecuteRead(ctx, "systemctl", "is-active", ServiceName)
	return err == nil && strings.TrimSpace(out) == "active"
}

func (s *Service) isEnabled(ctx context.Context) bool {
	out, err := s.exec.ExecuteRead(ctx, "systemctl", "is-enabled", ServiceName)
	return err == nil && strings.TrimSpace(out) == "enabled"
}

func (s *Service) InputPort() (bool, int, error) {
	c, err := s.Config()
	if err != nil {
		return false, 0, err
	}
	if err := ValidateConfig(c); err != nil {
		return false, 0, err
	}
	return c.Enabled, c.ListenPort, nil
}

// DNSBinding returns the tunnel address/network unbound must listen on and
// authorize. Both are derived from one validated prefix, so they cannot drift.
func (s *Service) DNSBinding() (address, network string, enabled bool, err error) {
	c, err := s.Config()
	if err != nil {
		return "", "", false, err
	}
	if err := ValidateConfig(c); err != nil {
		return "", "", false, err
	}
	if !c.Enabled {
		return "", "", false, nil
	}
	prefix, _ := netip.ParsePrefix(c.Address)
	return prefix.Addr().String(), prefix.Masked().String(), true, nil
}

// peerFallthrough é o fim da chain de encaminhamento de um peer: restrito
// termina em drop; o resto devolve a decisão às regras seguintes.
func peerFallthrough(accessMode string) string {
	if accessMode == "restricted" {
		return nftables.FallthroughDrop
	}
	return nftables.FallthroughContinue
}

// normalizeAccess valida e completa um perfil de acesso antes de ele tocar o
// banco. É a mesma porta para quem edita o perfil de um peer que já existe e
// para quem entrega o acesso de alguém já com o perfil.
func normalizeAccess(access PeerAccess) (PeerAccess, error) {
	access.AccessMode = strings.TrimSpace(access.AccessMode)
	if access.AccessMode == "" {
		access.AccessMode = "full"
	}
	if access.AccessMode != "full" && access.AccessMode != "restricted" {
		return PeerAccess{}, fmt.Errorf("modo de acesso inválido: use 'full' ou 'restricted'")
	}
	access.TunnelMode = strings.TrimSpace(access.TunnelMode)
	if access.TunnelMode == "" {
		access.TunnelMode = TunnelFull
	}
	if access.TunnelMode != TunnelFull && access.TunnelMode != TunnelSplit {
		return PeerAccess{}, fmt.Errorf("modo de túnel inválido: use %q ou %q", TunnelFull, TunnelSplit)
	}
	if err := ValidateMTU(access.MTU); err != nil {
		return PeerAccess{}, err
	}
	normalized, err := NormalizeRoutes(access.ExtraRoutes)
	if err != nil {
		return PeerAccess{}, err
	}
	access.ExtraRoutes = normalized
	if access.AllowedHostGroups == nil {
		access.AllowedHostGroups = []string{}
	}
	var ports []string
	for _, port := range strings.Split(access.AllowedPorts, ",") {
		port = strings.TrimSpace(port)
		if port == "" {
			continue
		}
		if !nftables.ValidPort(port) {
			return PeerAccess{}, fmt.Errorf("porta inválida %q: use números de 1 a 65535 ou faixas como 8000-8100", port)
		}
		ports = append(ports, port)
	}
	access.AllowedPorts = strings.Join(ports, ",")
	return access, nil
}

// inputGroupID identifica o grupo de ENTRADA de um peer. É derivado do grupo
// de encaminhamento, e não guardado, para dispensar coluna nova e sobreviver a
// um backup restaurado.
func inputGroupID(forwardGroupID string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("linkguard-cloud/wireguard/entrada/"+forwardGroupID)).String()
}

// reconcilePeerInputGroup fecha a própria caixa para um peer restrito.
//
// O perfil restrito vive na chain forward: decide o que o peer alcança ATRAVÉS
// do gateway. A caixa em si fica na chain input, que aceita o que vem de rede
// privada — e a rede da VPN é privada. Um peer liberado só para o k3s alcançava,
// pelo 10.7.0.1, o SSH, o painel e qualquer outra porta do gateway (achado de
// 24/09/2026). Este grupo, de escopo input, deixa passar só o que o túnel
// precisa para funcionar — o DNS para onde a config do cliente aponta e o ping
// — e descarta conexão nova para o resto. O filtro vale só para estado new:
// o que a caixa abre na direção do peer (a sonda de latência) continua voltando.
func (s *Service) reconcilePeerInputGroup(p storage.WireGuardPeer) error {
	if p.AccessMode != "restricted" {
		return s.deletePeerInputGroup(p.FirewallGroupID)
	}
	id := inputGroupID(p.FirewallGroupID)
	group := storage.FirewallGroup{
		ID:          id,
		Name:        "VPN — " + p.Username + " (entrada na caixa)",
		ChainName:   nftables.GroupChainName(id),
		Enabled:     true,
		CondSaddr:   p.Address,
		Fallthrough: nftables.FallthroughDrop,
		Kind:        nftables.GroupKindWireGuardPeer,
		Scope:       nftables.ScopeInput,
		ConnState:   nftables.ConnStateNew,
	}
	if err := s.db.EnsureWireGuardPeerGroup(&group); err != nil {
		return err
	}
	rules, err := s.db.ListFirewallRules()
	if err != nil {
		return err
	}
	for _, r := range rules {
		if r.GroupID == id {
			if err := s.db.DeleteFirewallRule(r.ID); err != nil {
				return err
			}
		}
	}
	for _, r := range []storage.FirewallRule{
		{Proto: "udp", Dport: "53", Description: "ZTNA: DNS do túnel (UDP)"},
		{Proto: "tcp", Dport: "53", Description: "ZTNA: DNS do túnel (TCP)"},
		{Proto: "icmp", Description: "ZTNA: ping da caixa"},
	} {
		r.GroupID, r.Action = id, "accept"
		if err := s.db.CreateFirewallRule(&r); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) deletePeerInputGroup(forwardGroupID string) error {
	id := inputGroupID(forwardGroupID)
	groups, err := s.db.ListFirewallGroups()
	if err != nil {
		return err
	}
	for _, g := range groups {
		if g.ID == id {
			return s.db.DeleteFirewallGroup(id)
		}
	}
	return nil
}

// MyVPN é o que um usuário vê da PRÓPRIA VPN, sem enxergar a de ninguém.
//
// Existe porque a única leitura da VPN era o Overview, que mostra todos os
// peers e por isso exige vpn.read. Quem só podia usar a própria VPN
// (vpn.enroll) abria a tela sem saber se já tinha identidade, e o único botão
// disponível — "Gerar configuração" — trocava a chave sem avisar.
type MyVPN struct {
	Enabled  bool    `json:"enabled"`
	Running  bool    `json:"running"`
	Endpoint string  `json:"endpoint,omitempty"`
	Peer     *Peer   `json:"peer,omitempty"`
	Reach    []Reach `json:"reach"`
}

// Reach é um destino liberado para um peer restrito, dito como quem usa entende:
// o nome do grupo, os endereços e as portas.
type Reach struct {
	Name  string   `json:"name"`
	Hosts []string `json:"hosts"`
	Ports string   `json:"ports,omitempty"`
}

func (s *Service) Mine(ctx context.Context, userID string) (MyVPN, error) {
	c, err := s.Config()
	if err != nil {
		return MyVPN{}, err
	}
	out := MyVPN{Enabled: c.Enabled, Reach: []Reach{}}
	if c.Enabled {
		if host, err := s.resolveEndpoint(c); err == nil {
			out.Endpoint = net.JoinHostPort(host, strconv.Itoa(c.ListenPort))
		}
	}
	stored, err := s.db.GetWireGuardPeer(userID)
	if err != nil {
		return MyVPN{}, err
	}
	out.Running = s.isActive(ctx)
	if stored == nil {
		return out, nil
	}
	peers := peersFromStorage([]storage.WireGuardPeer{*stored})
	if out.Running {
		s.enrichPeersTelemetry(ctx, peers)
	}
	out.Peer = &peers[0]
	if stored.AccessMode == "restricted" {
		for _, id := range stored.AllowedHostGroups {
			g, err := s.db.GetHostGroup(id)
			if err != nil {
				return MyVPN{}, err
			}
			if g == nil {
				continue
			}
			// O grupo guarda o host como /32; para quem usa, é só o endereço.
			hosts := make([]string, 0, len(g.Hosts))
			for _, h := range g.Hosts {
				hosts = append(hosts, strings.TrimSuffix(h, "/32"))
			}
			out.Reach = append(out.Reach, Reach{Name: g.Name, Hosts: hosts, Ports: stored.AllowedPorts})
		}
	}
	return out, nil
}

// NormalizeAccess expõe a validação do perfil para a borda HTTP recusar um
// perfil inválido com 400 antes de chamar o serviço.
func NormalizeAccess(access PeerAccess) (PeerAccess, error) { return normalizeAccess(access) }
