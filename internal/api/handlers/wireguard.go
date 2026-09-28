package handlers

import (
	"context"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/giovanibalarini/linkguard-cloud/internal/auth"
	"github.com/giovanibalarini/linkguard-cloud/internal/firewallrules"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
	"github.com/giovanibalarini/linkguard-cloud/internal/wireguard"
)

const wireGuardApplyFailure = "a configuração foi salva, mas a reconciliação da VPN não terminou; tente aplicar novamente"

type wireGuardService interface {
	Config() (wireguard.Config, error)
	Overview(context.Context) (wireguard.Overview, error)
	UpdateConfig(context.Context, wireguard.Config) error
	Enroll(context.Context, string) (wireguard.Enrollment, error)
	EnrollFor(context.Context, string, wireguard.PeerAccess) (wireguard.Enrollment, error)
	Mine(context.Context, string) (wireguard.MyVPN, error)
	ClientConfig(context.Context, string) (wireguard.Enrollment, error)
	Revoke(context.Context, string) error
	SetPeerAccess(context.Context, string, wireguard.PeerAccess) error
	RecordIntegrationError(error)
}

type vpnApplier interface {
	AplicarMudancaVPN(ctx context.Context, por, resumo string, escrever func() error, desfazer func() error) (*firewallrules.Applied, error)
}

// WireGuardHandler keeps HTTP concerns at the boundary. Key generation,
// persistence, vault access and process execution remain in internal/wireguard.
type WireGuardHandler struct {
	db        *storage.DB
	svc       wireGuardService
	fr        vpnApplier
	reloadDNS func(context.Context) error
}

func NewWireGuardHandler(db *storage.DB, svc wireGuardService, fr vpnApplier) *WireGuardHandler {
	return &WireGuardHandler{db: db, svc: svc, fr: fr}
}

// SetVPNApplier liga o firewall às mudanças da VPN. É um setter, e não só o
// argumento do construtor, para que um *Service nulo nunca vire uma interface
// não nula: o servidor só chama quando o firewall existe.
func (h *WireGuardHandler) SetVPNApplier(fr vpnApplier) { h.fr = fr }

func (h *WireGuardHandler) SetDNSReload(reload func(context.Context) error) {
	h.reloadDNS = reload
}

func (h *WireGuardHandler) Get(w http.ResponseWriter, r *http.Request) {
	overview, err := h.svc.Overview(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, overview)
}

func (h *WireGuardHandler) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	var config wireguard.Config
	if err := decodeJSON(r, &config); err != nil {
		writeError(w, http.StatusBadRequest, "corpo inválido")
		return
	}
	config.Address = strings.TrimSpace(config.Address)
	config.EndpointHost = strings.TrimSpace(config.EndpointHost)
	if err := wireguard.ValidateConfig(config); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	actor := actorName(r)
	oldConfig, err := h.svc.Config()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	escrever := func() error {
		return h.svc.UpdateConfig(r.Context(), config)
	}
	desfazer := func() error {
		return h.svc.UpdateConfig(r.Context(), oldConfig)
	}
	falhaWG, err := aplicarMudancaVPN(r.Context(), h.fr, actor, "atualizar configuração da VPN", escrever, desfazer)
	if err != nil {
		auditAction(h.db, r, "vpn.config", "vpn", "erro: "+resumoDoErro(err))
		h.writeVPNError(w, err)
		return
	}
	if falhaWG != nil {
		auditAction(h.db, r, "vpn.config", "vpn", "reconciliação pendente")
		writeError(w, http.StatusServiceUnavailable, wireGuardApplyFailure)
		return
	}
	if h.reloadDNS != nil {
		_ = h.reloadDNS(r.Context())
	}
	auditAction(h.db, r, "vpn.config", "vpn", "")
	writeJSON(w, http.StatusOK, map[string]bool{"saved": true})
}

func (h *WireGuardHandler) EnrollSelf(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil || strings.TrimSpace(claims.UserID) == "" {
		writeError(w, http.StatusUnauthorized, "autenticação necessária")
		return
	}
	h.entregar(w, r, claims.UserID, "gerar VPN para "+actorName(r), "vpn.enroll", "",
		func() (wireguard.Enrollment, error) { return h.svc.Enroll(r.Context(), claims.UserID) })
}

// entregar cria (ou gira) a identidade de userID e passa a mudança pelo
// firewall. A resposta é a única entrega da chave privada do cliente, e por
// isso as duas coisas que ela nunca faz: devolver a config de um peer que a
// volta da mudança apagou, e perder a de um peer que ficou.
func (h *WireGuardHandler) entregar(w http.ResponseWriter, r *http.Request, userID, resumo, acao, detalhe string,
	gerar func() (wireguard.Enrollment, error)) {
	prior, err := h.db.GetWireGuardPeer(userID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	var result wireguard.Enrollment
	escrever := func() error {
		var err error
		result, err = gerar()
		return err
	}
	// Um peer novo se desfaz revogando; girar a chave de quem já tinha VPN não
	// tem volta — a chave antiga já foi substituída, e ressuscitá-la reabriria
	// o acesso de um dispositivo que o operador acabou de trocar.
	var desfazer func() error
	if prior == nil {
		desfazer = func() error { return h.svc.Revoke(r.Context(), userID) }
	}
	falhaWG, err := aplicarMudancaVPN(r.Context(), h.fr, actorName(r), resumo, escrever, desfazer)
	if err != nil {
		ficou := false
		if result.ClientConfig != "" {
			p, perr := h.db.GetWireGuardPeer(userID)
			ficou = perr != nil || p != nil
		}
		if !ficou {
			auditAction(h.db, r, acao, "vpn-user:"+userID, "erro: "+resumoDoErro(err))
			h.writeVPNError(w, err)
			return
		}
		h.svc.RecordIntegrationError(err)
		result.ApplyError = wireGuardApplyFailure
	}
	if falhaWG != nil || result.ApplyError != "" {
		// O erro do domínio pode trazer caminho e saída de comando, e esta
		// resposta também carrega material privado: o resto fica genérico.
		result.ApplyError = wireGuardApplyFailure
	}
	if err == nil && falhaWG == nil && h.reloadDNS != nil {
		_ = h.reloadDNS(r.Context())
	}
	auditAction(h.db, r, acao, "vpn-user:"+userID, detalhe)
	// Única resposta que pode conter a chave privada do cliente e o QR.
	// Nenhum GET a recupera depois.
	writeJSON(w, http.StatusCreated, result)
}

func (h *WireGuardHandler) RevokeSelf(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil || strings.TrimSpace(claims.UserID) == "" {
		writeError(w, http.StatusUnauthorized, "autenticação necessária")
		return
	}
	h.revoke(w, r, claims.UserID)
}

func (h *WireGuardHandler) RevokePeer(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(chi.URLParam(r, "userID"))
	if userID == "" {
		writeError(w, http.StatusBadRequest, "userID é obrigatório")
		return
	}
	h.revoke(w, r, userID)
}

// revoke não tem volta (desfazer nil): voltar atrás ressuscitaria o acesso que
// o operador acabou de tirar.
func (h *WireGuardHandler) revoke(w http.ResponseWriter, r *http.Request, userID string) {
	escrever := func() error { return h.svc.Revoke(r.Context(), userID) }
	falhaWG, err := aplicarMudancaVPN(r.Context(), h.fr, actorName(r), "revogar VPN do usuário "+userID, escrever, nil)
	if err != nil {
		auditAction(h.db, r, "vpn.revoke", "vpn-user:"+userID, "erro: "+resumoDoErro(err))
		h.writeVPNError(w, err)
		return
	}
	if falhaWG != nil {
		auditAction(h.db, r, "vpn.revoke", "vpn-user:"+userID, "reconciliação pendente")
		writeError(w, http.StatusServiceUnavailable, wireGuardApplyFailure)
		return
	}
	if h.reloadDNS != nil {
		_ = h.reloadDNS(r.Context())
	}
	auditAction(h.db, r, "vpn.revoke", "vpn-user:"+userID, "")
	writeJSON(w, http.StatusOK, map[string]bool{"revoked": true})
}

type peerAccessBody struct {
	AccessMode        string   `json:"access_mode"`
	AllowedHostGroups []string `json:"allowed_host_groups"`
	AllowedPorts      string   `json:"allowed_ports"`
	TunnelMode        string   `json:"tunnel_mode"`
	ExtraRoutes       []string `json:"extra_routes"`
	MTU               int      `json:"mtu"`
}

func (h *WireGuardHandler) SetPeerAccess(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(chi.URLParam(r, "userID"))
	if userID == "" {
		writeError(w, http.StatusBadRequest, "userID é obrigatório")
		return
	}
	var req peerAccessBody
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "corpo inválido")
		return
	}
	access, verr := wireguard.NormalizeAccess(h.db, req.access())
	if verr != nil {
		writeError(w, http.StatusBadRequest, verr.Error())
		return
	}
	prior, err := h.db.GetWireGuardPeer(userID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if prior == nil {
		writeError(w, http.StatusNotFound, "peer não encontrado")
		return
	}
	escrever := func() error {
		return h.svc.SetPeerAccess(r.Context(), userID, access)
	}
	desfazer := func() error {
		return h.db.UpdateWireGuardPeerAccess(userID, storage.WireGuardPeerAccess{
			AccessMode:        prior.AccessMode,
			AllowedHostGroups: prior.AllowedHostGroups,
			AllowedPorts:      prior.AllowedPorts,
			TunnelMode:        prior.TunnelMode,
			ExtraRoutes:       prior.ExtraRoutes,
			MTU:               prior.MTU,
		})
	}
	falhaWG, err := aplicarMudancaVPN(r.Context(), h.fr, actorName(r), "alterar perfil VPN de "+prior.Username, escrever, desfazer)
	if err != nil {
		auditAction(h.db, r, "vpn.peer_access", "vpn-user:"+userID, "erro: "+resumoDoErro(err))
		h.writeVPNError(w, err)
		return
	}
	if falhaWG != nil {
		auditAction(h.db, r, "vpn.peer_access", "vpn-user:"+userID, "reconciliação pendente")
		writeError(w, http.StatusServiceUnavailable, wireGuardApplyFailure)
		return
	}
	if h.reloadDNS != nil {
		_ = h.reloadDNS(r.Context())
	}
	auditAction(h.db, r, "vpn.peer_access", "vpn-user:"+userID,
		"modo: "+access.AccessMode+", túnel: "+access.TunnelMode)
	writeJSON(w, http.StatusOK, map[string]bool{"saved": true})
}

// ReissueSelf devolve a configuração do próprio usuário com o perfil atual, sem
// gerar chave nova.
func (h *WireGuardHandler) ReissueSelf(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil || strings.TrimSpace(claims.UserID) == "" {
		writeError(w, http.StatusUnauthorized, "autenticação necessária")
		return
	}
	result, err := h.svc.ClientConfig(r.Context(), claims.UserID)
	if err != nil {
		h.writeVPNError(w, err)
		return
	}
	auditAction(h.db, r, "vpn.reissue", "vpn-user:"+claims.UserID, "")
	// Mesma natureza do enroll: a resposta carrega a chave privada do cliente.
	writeJSON(w, http.StatusOK, result)
}

// Me devolve a VPN do próprio usuário — e só a dele. É a leitura de quem tem
// vpn.enroll e não pode ver os outros peers (vpn.read).
func (h *WireGuardHandler) Me(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil || strings.TrimSpace(claims.UserID) == "" {
		writeError(w, http.StatusUnauthorized, "autenticação necessária")
		return
	}
	mine, err := h.svc.Mine(r.Context(), claims.UserID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, mine)
}

// EnrollPeer é o admin entregando a VPN de outra pessoa.
func (h *WireGuardHandler) EnrollPeer(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(chi.URLParam(r, "userID"))
	if userID == "" {
		writeError(w, http.StatusBadRequest, "userID é obrigatório")
		return
	}
	gerar := func() (wireguard.Enrollment, error) { return h.svc.Enroll(r.Context(), userID) }
	detalhe := ""
	if r.ContentLength != 0 {
		var req peerAccessBody
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "corpo inválido")
			return
		}
		access, verr := wireguard.NormalizeAccess(h.db, req.access())
		if verr != nil {
			writeError(w, http.StatusBadRequest, verr.Error())
			return
		}
		detalhe = "modo: " + access.AccessMode + ", túnel: " + access.TunnelMode
		gerar = func() (wireguard.Enrollment, error) { return h.svc.EnrollFor(r.Context(), userID, access) }
	}
	h.entregar(w, r, userID, "entregar VPN para "+userID, "vpn.enroll_for", detalhe, gerar)
}

// ReissuePeer devolve ao admin a config atual de outra pessoa, sem trocar a
// chave: é o caminho para entregar de novo depois de mudar o perfil dela.
func (h *WireGuardHandler) ReissuePeer(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(chi.URLParam(r, "userID"))
	if userID == "" {
		writeError(w, http.StatusBadRequest, "userID é obrigatório")
		return
	}
	result, err := h.svc.ClientConfig(r.Context(), userID)
	if err != nil {
		h.writeVPNError(w, err)
		return
	}
	auditAction(h.db, r, "vpn.reissue_for", "vpn-user:"+userID, "")
	writeJSON(w, http.StatusOK, result)
}

type vpnCandidate struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

// Candidates lista quem ainda não tem VPN, para o admin escolher a quem
// entregar sem precisar da permissão de gerenciar usuários.
func (h *WireGuardHandler) Candidates(w http.ResponseWriter, r *http.Request) {
	users, err := h.db.ListUsers()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	peers, err := h.db.ListWireGuardPeers()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	has := make(map[string]bool, len(peers))
	for _, p := range peers {
		has[p.UserID] = true
	}
	out := []vpnCandidate{}
	for _, u := range users {
		if !has[u.ID] {
			out = append(out, vpnCandidate{ID: u.ID, Username: u.Username})
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (b peerAccessBody) access() wireguard.PeerAccess {
	return wireguard.PeerAccess{
		AccessMode:        strings.TrimSpace(b.AccessMode),
		AllowedHostGroups: b.AllowedHostGroups,
		AllowedPorts:      b.AllowedPorts,
		TunnelMode:        strings.TrimSpace(b.TunnelMode),
		ExtraRoutes:       b.ExtraRoutes,
		MTU:               b.MTU,
	}
}
