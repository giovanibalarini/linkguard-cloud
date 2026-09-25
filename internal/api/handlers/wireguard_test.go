package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/giovanibalarini/linkguard-cloud/internal/auth"
	"github.com/giovanibalarini/linkguard-cloud/internal/firewallrules"
	"github.com/giovanibalarini/linkguard-cloud/internal/fwmodel"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
	"github.com/giovanibalarini/linkguard-cloud/internal/wireguard"
)

type wireGuardServiceStub struct {
	overview       wireguard.Overview
	enrollment     wireguard.Enrollment
	updateCalled   bool
	enrolledUserID string
	revokedUserID  string
	reissuedUserID string
	reissueErr     error
	accessUserID   string
	access         wireguard.PeerAccess
	recorded       error
	enrolledFor    bool
	mine           wireguard.MyVPN
	mineUserID     string
}

func (s *wireGuardServiceStub) Overview(context.Context) (wireguard.Overview, error) {
	return s.overview, nil
}
func (s *wireGuardServiceStub) UpdateConfig(_ context.Context, _ wireguard.Config) error {
	s.updateCalled = true
	return nil
}
func (s *wireGuardServiceStub) Enroll(_ context.Context, userID string) (wireguard.Enrollment, error) {
	s.enrolledUserID = userID
	return s.enrollment, nil
}
func (s *wireGuardServiceStub) Revoke(_ context.Context, userID string) error {
	s.revokedUserID = userID
	return nil
}
func (s *wireGuardServiceStub) SetPeerAccess(_ context.Context, userID string, access wireguard.PeerAccess) error {
	s.accessUserID = userID
	s.access = access
	return nil
}
func (s *wireGuardServiceStub) ClientConfig(_ context.Context, userID string) (wireguard.Enrollment, error) {
	s.reissuedUserID = userID
	return s.enrollment, s.reissueErr
}
func (s *wireGuardServiceStub) RecordIntegrationError(err error) { s.recorded = err }
func (s *wireGuardServiceStub) EnrollFor(_ context.Context, userID string, access wireguard.PeerAccess) (wireguard.Enrollment, error) {
	s.enrolledUserID = userID
	s.access = access
	s.enrolledFor = true
	return s.enrollment, nil
}
func (s *wireGuardServiceStub) Mine(_ context.Context, userID string) (wireguard.MyVPN, error) {
	s.mineUserID = userID
	return s.mine, nil
}
func (s *wireGuardServiceStub) Config() (wireguard.Config, error) {
	return wireguard.Config{
		Enabled:    true,
		Address:    "10.7.0.1/24",
		ListenPort: 51820,
	}, nil
}

type wireGuardReconcilerStub struct{ err error }

func (s wireGuardReconcilerStub) Reconcile(context.Context) error { return s.err }

func (s wireGuardReconcilerStub) AplicarMudancaVPN(ctx context.Context, por, resumo string, escrever func() error, desfazer func() error) (*firewallrules.Applied, error) {
	if escrever != nil {
		if err := escrever(); err != nil {
			return nil, err
		}
	}
	if s.err != nil {
		if desfazer != nil {
			_ = desfazer()
		}
		return nil, s.err
	}
	return &firewallrules.Applied{}, nil
}

type wireGuardInputStub struct{ err error }

func (s wireGuardInputStub) ReconcileInputProtection(context.Context) error { return s.err }

func newWireGuardHandlerTestDB(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cfg := fwmodel.Config{
		Formato: 1,
		Aliases: []fwmodel.Alias{
			{
				ID:    "hg-1",
				Nome:  "hg-1",
				Tipo:  fwmodel.AliasTipoEnderecos,
				Itens: []string{"10.0.1.0/24"},
			},
			{
				ID:    "hg-k3s",
				Nome:  "hg-k3s",
				Tipo:  fwmodel.AliasTipoEnderecos,
				Itens: []string{"10.0.2.0/24"},
			},
		},
		Ajustes: fwmodel.AjustesPadrao(),
	}
	if err := db.SalvarAplicadaERevisao(cfg, "teste", "seed", "aplicar", time.Now()); err != nil {
		t.Fatalf("SalvarAplicadaERevisao: %v", err)
	}
	_ = db.CreateUser(&storage.User{ID: "u-123", Username: "user123"}, "hash", nil)
	return db
}

func TestWireGuardEnrollUsesAuthenticatedUserAndNeverAuditsPrivateConfig(t *testing.T) {
	db := newWireGuardHandlerTestDB(t)
	const private = "PRIVATE-SECRET-MUST-NOT-LEAK"
	svc := &wireGuardServiceStub{enrollment: wireguard.Enrollment{
		Peer:         wireguard.Peer{UserID: "local-user", Username: "luan", Address: "10.7.0.2/32"},
		ClientConfig: "[Interface]\nPrivateKey = " + private,
		QRDataURL:    "data:image/svg+xml;base64,PHN2Zz4=",
	}}
	h := NewWireGuardHandler(db, svc, wireGuardReconcilerStub{}, wireGuardInputStub{})
	req := httptest.NewRequest(http.MethodPost, "/api/vpn/enrollment", nil)
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{
		UserID: "local-user", Username: "luan",
	}))
	w := httptest.NewRecorder()

	h.EnrollSelf(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if svc.enrolledUserID != "local-user" {
		t.Fatalf("enrolled user = %q, want authenticated user", svc.enrolledUserID)
	}
	if !strings.Contains(w.Body.String(), private) {
		t.Fatal("one-time response must contain the client private config")
	}
	logs, err := db.GetAuditLogs(10)
	if err != nil {
		t.Fatalf("GetAuditLogs: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("audit log count = %d, want 1", len(logs))
	}
	if strings.Contains(logs[0].Details, private) || strings.Contains(logs[0].Resource, private) {
		t.Fatal("private client config leaked into audit log")
	}
}

func TestWireGuardUpdateRejectsInjectionBeforeCallingService(t *testing.T) {
	db := newWireGuardHandlerTestDB(t)
	svc := &wireGuardServiceStub{}
	h := NewWireGuardHandler(db, svc, wireGuardReconcilerStub{}, wireGuardInputStub{})
	body := `{"enabled":true,"listen_port":51820,"address":"10.7.0.1/24\nPostUp = touch /tmp/pwn","endpoint_host":"vpn.example.test"}`
	w := httptest.NewRecorder()

	h.UpdateConfig(w, httptest.NewRequest(http.MethodPut, "/api/vpn", strings.NewReader(body)))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if svc.updateCalled {
		t.Fatal("invalid input reached the service")
	}
}

func TestWireGuardEnrollmentSurvivesIntegrationFailure(t *testing.T) {
	db := newWireGuardHandlerTestDB(t)
	svc := &wireGuardServiceStub{enrollment: wireguard.Enrollment{ClientConfig: "one-time-private"}}
	h := NewWireGuardHandler(db, svc, wireGuardReconcilerStub{err: errors.New("nft unavailable")}, wireGuardInputStub{})
	req := httptest.NewRequest(http.MethodPost, "/api/vpn/enrollment", nil)
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "local-user"}))
	w := httptest.NewRecorder()

	h.EnrollSelf(w, req)

	if w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), "one-time-private") {
		t.Fatalf("one-time material was lost: status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "apply_error") || svc.recorded == nil {
		t.Fatalf("integration failure not reported/recorded: body=%s recorded=%v", w.Body.String(), svc.recorded)
	}
}

func TestWireGuardSetPeerAccess(t *testing.T) {
	db := newWireGuardHandlerTestDB(t)
	if _, err := db.UpsertWireGuardPeer(&storage.WireGuardPeer{UserID: "u-123", Username: "user123", Address: "10.7.0.5/32"}); err != nil {
		t.Fatalf("UpsertWireGuardPeer: %v", err)
	}
	svc := &wireGuardServiceStub{}
	h := NewWireGuardHandler(db, svc, wireGuardReconcilerStub{}, wireGuardInputStub{})

	r := chi.NewRouter()
	r.Put("/api/vpn/peers/{userID}/access", h.SetPeerAccess)

	body := `{"access_mode":"restricted","allowed_host_groups":["hg-1"],"allowed_ports":"22,80"}`
	req := httptest.NewRequest(http.MethodPut, "/api/vpn/peers/u-123/access", strings.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	logs, err := db.GetAuditLogs(10)
	if err != nil || len(logs) == 0 {
		t.Fatalf("audit logs missing: %v", err)
	}
	if logs[0].Action != "vpn.peer_access" {
		t.Fatalf("audit action = %q, want vpn.peer_access", logs[0].Action)
	}
}

func TestWireGuardSetPeerAccessGuardaOPerfilDeTunel(t *testing.T) {
	db := newWireGuardHandlerTestDB(t)
	if _, err := db.UpsertWireGuardPeer(&storage.WireGuardPeer{UserID: "u-123", Username: "user123", Address: "10.7.0.5/32"}); err != nil {
		t.Fatalf("UpsertWireGuardPeer: %v", err)
	}
	svc := &wireGuardServiceStub{}
	h := NewWireGuardHandler(db, svc, wireGuardReconcilerStub{}, wireGuardInputStub{})

	r := chi.NewRouter()
	r.Put("/api/vpn/peers/{userID}/access", h.SetPeerAccess)

	body := `{"access_mode":"restricted","allowed_host_groups":["hg-1"],"allowed_ports":"22",
	          "tunnel_mode":"split","extra_routes":["10.0.1.0/24"],"mtu":1440}`
	req := httptest.NewRequest(http.MethodPut, "/api/vpn/peers/u-123/access", strings.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if svc.access.TunnelMode != "split" || svc.access.MTU != 1440 {
		t.Fatalf("perfil de túnel não chegou ao serviço: %+v", svc.access)
	}
	if len(svc.access.ExtraRoutes) != 1 || svc.access.ExtraRoutes[0] != "10.0.1.0/24" {
		t.Fatalf("rotas extras não chegaram: %+v", svc.access.ExtraRoutes)
	}
}

func TestWireGuardSetPeerAccessRecusaAliasInexistente(t *testing.T) {
	db := newWireGuardHandlerTestDB(t)
	if _, err := db.UpsertWireGuardPeer(&storage.WireGuardPeer{UserID: "u-123", Username: "user123", Address: "10.7.0.5/32"}); err != nil {
		t.Fatalf("UpsertWireGuardPeer: %v", err)
	}
	svc := &wireGuardServiceStub{}
	h := NewWireGuardHandler(db, svc, wireGuardReconcilerStub{}, wireGuardInputStub{})
	r := chi.NewRouter()
	r.Put("/api/vpn/peers/{userID}/access", h.SetPeerAccess)

	body := `{"access_mode":"restricted","allowed_host_groups":["alias-inexistente"]}`
	req := httptest.NewRequest(http.MethodPut, "/api/vpn/peers/u-123/access", strings.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "alias de endereços inexistente ou ainda não aplicado") {
		t.Fatalf("mensagem inesperada: %s", w.Body.String())
	}
}

type wireGuardServiceRealUpdateStub struct {
	wireGuardServiceStub
	db *storage.DB
}

func (s *wireGuardServiceRealUpdateStub) SetPeerAccess(_ context.Context, userID string, access wireguard.PeerAccess) error {
	return s.db.UpdateWireGuardPeerAccess(userID, storage.WireGuardPeerAccess{
		AccessMode:        access.AccessMode,
		AllowedHostGroups: access.AllowedHostGroups,
		AllowedPorts:      access.AllowedPorts,
		TunnelMode:        access.TunnelMode,
		ExtraRoutes:       access.ExtraRoutes,
		MTU:               access.MTU,
	})
}

func TestWireGuardSetPeerAccessReverteEmFalhaDoFirewall(t *testing.T) {
	db := newWireGuardHandlerTestDB(t)
	if _, err := db.UpsertWireGuardPeer(&storage.WireGuardPeer{
		UserID:     "u-123",
		Username:   "user123",
		Address:    "10.7.0.5/32",
		AccessMode: "full",
	}); err != nil {
		t.Fatalf("UpsertWireGuardPeer: %v", err)
	}
	svc := &wireGuardServiceRealUpdateStub{db: db}
	applierFalha := wireGuardReconcilerStub{err: errors.New("falha nftables")}
	h := NewWireGuardHandler(db, svc, applierFalha, wireGuardInputStub{})
	r := chi.NewRouter()
	r.Put("/api/vpn/peers/{userID}/access", h.SetPeerAccess)

	body := `{"access_mode":"restricted","allowed_host_groups":["hg-1"]}`
	req := httptest.NewRequest(http.MethodPut, "/api/vpn/peers/u-123/access", strings.NewReader(body))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body = %s", w.Code, w.Body.String())
	}
	peer, err := db.GetWireGuardPeer("u-123")
	if err != nil {
		t.Fatalf("GetWireGuardPeer: %v", err)
	}
	if peer.AccessMode != "full" {
		t.Fatalf("perfil no banco não reverteu: modo=%s", peer.AccessMode)
	}
}

func TestWireGuardSetPeerAccessRecusaTunelERotaInvalidosAntesDoServico(t *testing.T) {
	casos := map[string]string{
		"modo inexistente": `{"access_mode":"full","tunnel_mode":"halfsies"}`,
		"rota injetada":    `{"access_mode":"full","tunnel_mode":"split","extra_routes":["10.0.0.0/8\nPostUp = touch /tmp/pwn"]}`,
		"mtu impraticável": `{"access_mode":"full","tunnel_mode":"split","mtu":42}`,
	}
	for nome, body := range casos {
		t.Run(nome, func(t *testing.T) {
			db := newWireGuardHandlerTestDB(t)
			svc := &wireGuardServiceStub{}
			h := NewWireGuardHandler(db, svc, wireGuardReconcilerStub{}, wireGuardInputStub{})
			r := chi.NewRouter()
			r.Put("/api/vpn/peers/{userID}/access", h.SetPeerAccess)

			req := httptest.NewRequest(http.MethodPut, "/api/vpn/peers/u-123/access", strings.NewReader(body))
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
			}
			if svc.accessUserID != "" {
				t.Fatal("entrada inválida chegou ao serviço")
			}
		})
	}
}

func TestWireGuardReemiteConfigDoProprioUsuario(t *testing.T) {
	db := newWireGuardHandlerTestDB(t)
	svc := &wireGuardServiceStub{enrollment: wireguard.Enrollment{ClientConfig: "config-reemitida"}}
	h := NewWireGuardHandler(db, svc, wireGuardReconcilerStub{}, wireGuardInputStub{})

	req := httptest.NewRequest(http.MethodPost, "/api/vpn/enrollment/config", nil)
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "local-user"}))
	w := httptest.NewRecorder()

	h.ReissueSelf(w, req)

	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "config-reemitida") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	// Reemitir serve apenas a si mesmo: o userID vem do token, nunca da URL.
	if svc.reissuedUserID != "local-user" {
		t.Fatalf("reemitiu para %q em vez do usuário autenticado", svc.reissuedUserID)
	}
	logs, err := db.GetAuditLogs(10)
	if err != nil {
		t.Fatalf("GetAuditLogs: %v", err)
	}
	if len(logs) != 1 || strings.Contains(logs[0].Details, "config-reemitida") {
		t.Fatalf("auditoria ausente ou vazou a config: %+v", logs)
	}
}

func TestWireGuardReemissaoExigeAutenticacao(t *testing.T) {
	db := newWireGuardHandlerTestDB(t)
	svc := &wireGuardServiceStub{}
	h := NewWireGuardHandler(db, svc, wireGuardReconcilerStub{}, wireGuardInputStub{})
	w := httptest.NewRecorder()

	h.ReissueSelf(w, httptest.NewRequest(http.MethodPost, "/api/vpn/enrollment/config", nil))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if svc.reissuedUserID != "" {
		t.Fatal("pedido sem identidade chegou ao serviço")
	}
}

func TestWireGuardAdminEntregaAVPNDeOutraPessoaComOPerfil(t *testing.T) {
	db := newWireGuardHandlerTestDB(t)
	svc := &wireGuardServiceStub{enrollment: wireguard.Enrollment{ClientConfig: "config-do-diego"}}
	h := NewWireGuardHandler(db, svc, wireGuardReconcilerStub{}, wireGuardInputStub{})
	r := chi.NewRouter()
	r.Post("/api/vpn/peers/{userID}/enrollment", h.EnrollPeer)

	body := `{"access_mode":"restricted","allowed_host_groups":["hg-k3s"],"allowed_ports":" 6443 ","tunnel_mode":"split"}`
	req := httptest.NewRequest(http.MethodPost, "/api/vpn/peers/u-diego/enrollment", strings.NewReader(body))
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "admin", Username: "admin"}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), "config-do-diego") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	// A identidade é de quem está na URL, não de quem está logado.
	if !svc.enrolledFor || svc.enrolledUserID != "u-diego" {
		t.Fatalf("EnrollFor para %q (chamado=%v), queria u-diego", svc.enrolledUserID, svc.enrolledFor)
	}
	if svc.access.AccessMode != "restricted" || svc.access.TunnelMode != "split" || svc.access.AllowedPorts != "6443" {
		t.Fatalf("perfil chegou ao serviço diferente do pedido: %+v", svc.access)
	}
	logs, err := db.GetAuditLogs(10)
	if err != nil || len(logs) != 1 || logs[0].Action != "vpn.enroll_for" || strings.Contains(logs[0].Details, "config-do-diego") {
		t.Fatalf("auditoria ausente, com ação errada ou vazando a config: %+v, %v", logs, err)
	}
}

func TestWireGuardAdminEntregaSemPerfilMantemOAtual(t *testing.T) {
	db := newWireGuardHandlerTestDB(t)
	svc := &wireGuardServiceStub{}
	h := NewWireGuardHandler(db, svc, wireGuardReconcilerStub{}, wireGuardInputStub{})
	r := chi.NewRouter()
	r.Post("/api/vpn/peers/{userID}/enrollment", h.EnrollPeer)

	req := httptest.NewRequest(http.MethodPost, "/api/vpn/peers/u-bia/enrollment", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated || svc.enrolledFor || svc.enrolledUserID != "u-bia" {
		t.Fatalf("status=%d enrolledFor=%v user=%q", w.Code, svc.enrolledFor, svc.enrolledUserID)
	}
}

func TestWireGuardAdminEntregaRecusaPerfilInvalidoAntesDoServico(t *testing.T) {
	for nome, body := range map[string]string{
		"porta fora da faixa": `{"access_mode":"restricted","allowed_ports":"70000"}`,
		"porta com injeção":   `{"access_mode":"restricted","allowed_ports":"22; flush ruleset"}`,
		"modo inexistente":    `{"access_mode":"quase"}`,
	} {
		t.Run(nome, func(t *testing.T) {
			db := newWireGuardHandlerTestDB(t)
			svc := &wireGuardServiceStub{}
			h := NewWireGuardHandler(db, svc, wireGuardReconcilerStub{}, wireGuardInputStub{})
			r := chi.NewRouter()
			r.Post("/api/vpn/peers/{userID}/enrollment", h.EnrollPeer)

			req := httptest.NewRequest(http.MethodPost, "/api/vpn/peers/u-1/enrollment", strings.NewReader(body))
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest || svc.enrolledUserID != "" {
				t.Fatalf("status=%d serviço chamado para %q", w.Code, svc.enrolledUserID)
			}
		})
	}
}

func TestWireGuardAdminReemiteAConfigDeOutraPessoa(t *testing.T) {
	db := newWireGuardHandlerTestDB(t)
	svc := &wireGuardServiceStub{enrollment: wireguard.Enrollment{ClientConfig: "config-atual"}}
	h := NewWireGuardHandler(db, svc, wireGuardReconcilerStub{}, wireGuardInputStub{})
	r := chi.NewRouter()
	r.Post("/api/vpn/peers/{userID}/config", h.ReissuePeer)

	req := httptest.NewRequest(http.MethodPost, "/api/vpn/peers/u-diego/config", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK || svc.reissuedUserID != "u-diego" {
		t.Fatalf("status=%d reemitido para %q", w.Code, svc.reissuedUserID)
	}
	logs, _ := db.GetAuditLogs(10)
	if len(logs) != 1 || logs[0].Action != "vpn.reissue_for" {
		t.Fatalf("auditoria = %+v", logs)
	}
}

func TestWireGuardMinhaVPNUsaSoOUsuarioDoToken(t *testing.T) {
	db := newWireGuardHandlerTestDB(t)
	svc := &wireGuardServiceStub{mine: wireguard.MyVPN{Enabled: true, Reach: []wireguard.Reach{}}}
	h := NewWireGuardHandler(db, svc, wireGuardReconcilerStub{}, wireGuardInputStub{})

	req := httptest.NewRequest(http.MethodGet, "/api/vpn/me?user=outra-pessoa", nil)
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: "u-diego"}))
	w := httptest.NewRecorder()
	h.Me(w, req)

	if w.Code != http.StatusOK || svc.mineUserID != "u-diego" {
		t.Fatalf("status=%d consultou %q", w.Code, svc.mineUserID)
	}

	sem := httptest.NewRecorder()
	h.Me(sem, httptest.NewRequest(http.MethodGet, "/api/vpn/me", nil))
	if sem.Code != http.StatusUnauthorized {
		t.Fatalf("sem token: status=%d", sem.Code)
	}
}

func TestWireGuardCandidatosSaoQuemAindaNaoTemVPN(t *testing.T) {
	db := newWireGuardHandlerTestDB(t)
	for _, nome := range []string{"diego", "bia"} {
		if err := db.CreateUser(&storage.User{ID: "u-" + nome, Username: nome}, "hash", nil); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
	}
	if _, err := db.UpsertWireGuardPeer(&storage.WireGuardPeer{UserID: "u-bia", PublicKey: "pk", Address: "10.7.0.2/32", SecretName: "s"}); err != nil {
		t.Fatalf("UpsertWireGuardPeer: %v", err)
	}
	h := NewWireGuardHandler(db, &wireGuardServiceStub{}, wireGuardReconcilerStub{}, wireGuardInputStub{})
	w := httptest.NewRecorder()
	h.Candidates(w, httptest.NewRequest(http.MethodGet, "/api/vpn/candidates", nil))

	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"username":"diego"`) || strings.Contains(w.Body.String(), `"username":"bia"`) {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}
