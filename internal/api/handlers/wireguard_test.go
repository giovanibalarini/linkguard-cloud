package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/giovanibalarini/linkguard-fw/internal/auth"
	"github.com/giovanibalarini/linkguard-fw/internal/storage"
	"github.com/giovanibalarini/linkguard-fw/internal/wireguard"
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

type wireGuardReconcilerStub struct{ err error }

func (s wireGuardReconcilerStub) Reconcile(context.Context) error { return s.err }

type wireGuardInputStub struct{ err error }

func (s wireGuardInputStub) ReconcileInputProtection(context.Context) error { return s.err }

func newWireGuardHandlerTestDB(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
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
