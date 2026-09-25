package handlers

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/giovanibalarini/linkguard-cloud/internal/auth"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
	"github.com/giovanibalarini/linkguard-cloud/internal/wireguard"
)

const wireGuardApplyFailure = "a configuração foi salva, mas a reconciliação da VPN não terminou; tente aplicar novamente"

type wireGuardService interface {
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

type wireGuardReconciler interface {
	Reconcile(context.Context) error
}

type wireGuardInputReconciler interface {
	ReconcileInputProtection(context.Context) error
}

// WireGuardHandler keeps HTTP concerns at the boundary. Key generation,
// persistence, vault access and process execution remain in internal/wireguard.
type WireGuardHandler struct {
	db        *storage.DB
	svc       wireGuardService
	groups    wireGuardReconciler
	input     wireGuardInputReconciler
	reloadDNS func(context.Context) error
}

func NewWireGuardHandler(db *storage.DB, svc wireGuardService, groups wireGuardReconciler, input wireGuardInputReconciler) *WireGuardHandler {
	return &WireGuardHandler{db: db, svc: svc, groups: groups, input: input}
}

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
	if err := h.svc.UpdateConfig(r.Context(), config); err != nil {
		auditAction(h.db, r, "vpn.config", "vpn", "reconciliação pendente")
		writeError(w, http.StatusServiceUnavailable, wireGuardApplyFailure)
		return
	}
	if err := h.reconcileIntegrations(r.Context()); err != nil {
		h.svc.RecordIntegrationError(err)
		auditAction(h.db, r, "vpn.config", "vpn", "reconciliação pendente")
		writeError(w, http.StatusServiceUnavailable, wireGuardApplyFailure)
		return
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
	result, err := h.svc.Enroll(r.Context(), claims.UserID)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "não foi possível criar a identidade WireGuard")
		return
	}
	if result.ApplyError != "" {
		// The domain error can contain package/process details. This response
		// also carries private material, so keep every other field generic.
		result.ApplyError = wireGuardApplyFailure
	}
	if err := h.reconcileIntegrations(r.Context()); err != nil {
		h.svc.RecordIntegrationError(err)
		result.ApplyError = wireGuardApplyFailure
	}
	auditAction(h.db, r, "vpn.enroll", "vpn-user:"+claims.UserID, "")
	// This is the sole response that may contain the client private key and
	// QR data. No GET endpoint exists for recovering it later.
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

func (h *WireGuardHandler) revoke(w http.ResponseWriter, r *http.Request, userID string) {
	serviceErr := h.svc.Revoke(r.Context(), userID)
	integrationErr := h.reconcileIntegrations(r.Context())
	if integrationErr != nil {
		h.svc.RecordIntegrationError(integrationErr)
	}
	auditAction(h.db, r, "vpn.revoke", "vpn-user:"+userID, "")
	if serviceErr != nil || integrationErr != nil {
		writeError(w, http.StatusServiceUnavailable, wireGuardApplyFailure)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"revoked": true})
}

func (h *WireGuardHandler) reconcileIntegrations(ctx context.Context) error {
	var failures []error
	if h.input != nil {
		failures = appendIfError(failures, h.input.ReconcileInputProtection(ctx))
	}
	if h.groups != nil {
		failures = appendIfError(failures, h.groups.Reconcile(ctx))
	}
	if h.reloadDNS != nil {
		failures = appendIfError(failures, h.reloadDNS(ctx))
	}
	return errors.Join(failures...)
}

func appendIfError(errs []error, err error) []error {
	if err != nil {
		return append(errs, err)
	}
	return errs
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
	req.AccessMode = strings.TrimSpace(req.AccessMode)
	if req.AccessMode == "" {
		req.AccessMode = "full"
	}
	if req.AccessMode != "full" && req.AccessMode != "restricted" {
		writeError(w, http.StatusBadRequest, "modo de acesso inválido: use 'full' ou 'restricted'")
		return
	}
	req.TunnelMode = strings.TrimSpace(req.TunnelMode)
	if req.TunnelMode == "" {
		req.TunnelMode = wireguard.TunnelFull
	}
	if req.TunnelMode != wireguard.TunnelFull && req.TunnelMode != wireguard.TunnelSplit {
		writeError(w, http.StatusBadRequest, "modo de túnel inválido: use 'full' ou 'split'")
		return
	}
	// Rotas e MTU são validados aqui para que um valor digitado errado volte
	// como 400 com o motivo, e não como falha interna. O serviço revalida.
	if err := wireguard.ValidateMTU(req.MTU); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := wireguard.NormalizeRoutes(req.ExtraRoutes); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	access := wireguard.PeerAccess{
		AccessMode:        req.AccessMode,
		AllowedHostGroups: req.AllowedHostGroups,
		AllowedPorts:      strings.TrimSpace(req.AllowedPorts),
		TunnelMode:        req.TunnelMode,
		ExtraRoutes:       req.ExtraRoutes,
		MTU:               req.MTU,
	}
	if err := h.svc.SetPeerAccess(r.Context(), userID, access); err != nil {
		auditAction(h.db, r, "vpn.peer_access", "vpn-user:"+userID, "erro: "+err.Error())
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := h.reconcileIntegrations(r.Context()); err != nil {
		h.svc.RecordIntegrationError(err)
	}
	auditAction(h.db, r, "vpn.peer_access", "vpn-user:"+userID,
		"modo: "+req.AccessMode+", túnel: "+req.TunnelMode)
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
		writeError(w, http.StatusConflict, err.Error())
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
//
// Até 24/09/2026 o desenho era que só o dono da identidade visse a própria
// chave privada: nenhum admin gerava nem reemitia a config de outro. Na prática
// isso obrigava o admin a logar COMO a pessoa para entregar o acesso — ele via a
// chave do mesmo jeito, só que por um caminho pior e fora da auditoria. Agora a
// entrega é uma ação de admin, com vpn.write, registrada como "vpn.enroll_for".
// Quem recebe pode trocar a chave depois pela própria tela e ficar com uma que
// o admin nunca viu.
//
// Corpo opcional: sem ele, gera ou rotaciona mantendo o perfil atual; com ele,
// o perfil informado já vale para a primeira configuração.
func (h *WireGuardHandler) EnrollPeer(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(chi.URLParam(r, "userID"))
	if userID == "" {
		writeError(w, http.StatusBadRequest, "userID é obrigatório")
		return
	}
	var (
		result wireguard.Enrollment
		err    error
		detail string
	)
	if r.ContentLength != 0 {
		var req peerAccessBody
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "corpo inválido")
			return
		}
		access, verr := wireguard.NormalizeAccess(req.access())
		if verr != nil {
			writeError(w, http.StatusBadRequest, verr.Error())
			return
		}
		detail = "modo: " + access.AccessMode + ", túnel: " + access.TunnelMode
		result, err = h.svc.EnrollFor(r.Context(), userID, access)
	} else {
		result, err = h.svc.Enroll(r.Context(), userID)
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	if result.ApplyError != "" {
		result.ApplyError = wireGuardApplyFailure
	}
	if err := h.reconcileIntegrations(r.Context()); err != nil {
		h.svc.RecordIntegrationError(err)
		result.ApplyError = wireGuardApplyFailure
	}
	auditAction(h.db, r, "vpn.enroll_for", "vpn-user:"+userID, detail)
	writeJSON(w, http.StatusCreated, result)
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
		writeError(w, http.StatusConflict, err.Error())
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
