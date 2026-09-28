package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/giovanibalarini/linkguard-cloud/internal/auth"
	"github.com/giovanibalarini/linkguard-cloud/internal/firewallrules"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
	"github.com/giovanibalarini/linkguard-cloud/internal/wireguard"
)

// detalheInterno é o que um erro de sistema costuma carregar e que jamais pode
// chegar à tela ou à trilha de auditoria.
const detalheInterno = "exit status 1: /var/lib/linkguard/wg0.conf: permission denied"

// vpnApplierStub reproduz o contrato de AplicarMudancaVPN: a janela aberta
// recusa antes de escrever; um erro da escrita volta como veio; uma falha
// depois dela desfaz a mudança quando há como (senão diz que ficou gravada).
type vpnApplierStub struct {
	trancada    bool
	falhaDepois string

	chamadas   int
	reversivel bool
	escreveu   bool
	desfez     bool
	por        string
	resumo     string
}

func (a *vpnApplierStub) AplicarMudancaVPN(_ context.Context, por, resumo string, escrever func() error, desfazer func() error) (*firewallrules.Applied, error) {
	a.chamadas++
	a.por, a.resumo = por, resumo
	a.reversivel = desfazer != nil
	if a.trancada {
		return nil, &firewallrules.GuardError{Stage: firewallrules.StageLocked, Message: "há uma janela de confirmação aberta"}
	}
	if escrever != nil {
		if err := escrever(); err != nil {
			return nil, err
		}
		a.escreveu = true
	}
	if a.falhaDepois == "" {
		return &firewallrules.Applied{}, nil
	}
	causa := errors.New(detalheInterno)
	if desfazer == nil {
		return nil, &firewallrules.GuardError{
			Stage: firewallrules.StageReconcile, Gravada: true, Err: causa,
			Message: a.falhaDepois + "; a mudança ficou gravada, mas o firewall não foi reconciliado",
		}
	}
	if err := desfazer(); err != nil {
		return nil, &firewallrules.GuardError{
			Stage: firewallrules.StageStuck, Gravada: true, Err: causa,
			Message: a.falhaDepois + ", e a mudança da VPN não pôde ser desfeita: confira a VPN e o firewall",
		}
	}
	a.desfez = true
	return nil, &firewallrules.GuardError{
		Stage: firewallrules.StageReconcile, Err: causa,
		Message: a.falhaDepois + "; nada foi alterado",
	}
}

// wireGuardServiceRealUpdateStub grava o perfil no banco como o serviço real faria.
type wireGuardServiceRealUpdateStub struct {
	wireGuardServiceStub
}

func (s *wireGuardServiceRealUpdateStub) SetPeerAccess(_ context.Context, userID string, access wireguard.PeerAccess) error {
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
	return s.accessErr
}

func refazFalha() error {
	return &wireguard.FalhaDeReconciliacao{Err: errors.New(detalheInterno)}
}

func recusaDo(m wireguard.Motivo, msg string) error {
	return &wireguard.Recusa{Motivo: m, Msg: msg}
}

func comoUsuario(r *http.Request, id string) *http.Request {
	return r.WithContext(auth.ContextWithClaims(r.Context(), &auth.Claims{UserID: id, Username: "user123"}))
}

func roteadorVPN(h *WireGuardHandler) http.Handler {
	r := chi.NewRouter()
	r.Put("/api/vpn", h.UpdateConfig)
	r.Post("/api/vpn/enrollment", h.EnrollSelf)
	r.Post("/api/vpn/reissue", h.ReissueSelf)
	r.Delete("/api/vpn/peers/{userID}", h.RevokePeer)
	r.Put("/api/vpn/peers/{userID}/access", h.SetPeerAccess)
	r.Post("/api/vpn/peers/{userID}/enrollment", h.EnrollPeer)
	r.Post("/api/vpn/peers/{userID}/reissue", h.ReissuePeer)
	return r
}

func chamaVPN(h *WireGuardHandler, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	roteadorVPN(h).ServeHTTP(w, req)
	return w
}

func semDetalheInterno(t *testing.T, db *storage.DB, w *httptest.ResponseRecorder) {
	t.Helper()
	if strings.Contains(w.Body.String(), "wg0.conf") || strings.Contains(w.Body.String(), "permission denied") {
		t.Fatalf("detalhe interno vazou na resposta: %s", w.Body.String())
	}
	logs, err := db.GetAuditLogs(50)
	if err != nil {
		t.Fatalf("GetAuditLogs: %v", err)
	}
	for _, l := range logs {
		if strings.Contains(l.Details, "wg0.conf") || strings.Contains(l.Details, "permission denied") {
			t.Fatalf("detalhe interno vazou na auditoria: %q", l.Details)
		}
	}
}

func peerNoBanco(t *testing.T, db *storage.DB, id string) *storage.WireGuardPeer {
	t.Helper()
	p, err := db.GetWireGuardPeer(id)
	if err != nil {
		t.Fatalf("GetWireGuardPeer: %v", err)
	}
	return p
}

func semeiaPeer(t *testing.T, db *storage.DB, id, modo string) {
	t.Helper()
	if _, err := db.UpsertWireGuardPeer(&storage.WireGuardPeer{
		UserID: id, Username: "user123", Address: "10.7.0.5/32", AccessMode: modo,
	}); err != nil {
		t.Fatalf("UpsertWireGuardPeer: %v", err)
	}
}

const corpoConfigVPN = `{"enabled":true,"listen_port":51820,"address":"10.7.0.1/24","endpoint_host":"vpn.example.test"}`

func TestVPNUpdateConfigFalhaDoFirewallDesfazEDiz(t *testing.T) {
	db := newWireGuardHandlerTestDB(t)
	svc := &wireGuardServiceStub{}
	fw := &vpnApplierStub{falhaDepois: "o firewall recusou o ruleset"}
	h := NewWireGuardHandler(db, svc, fw)

	w := chamaVPN(h, httptest.NewRequest(http.MethodPut, "/api/vpn", strings.NewReader(corpoConfigVPN)))

	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "nada foi alterado") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if len(svc.updates) != 2 {
		t.Fatalf("a configuração nova devia ser gravada e desfeita: %d gravações", len(svc.updates))
	}
	if svc.recorded != nil {
		t.Fatalf("a mudança foi desfeita; não há erro de integração a registrar: %v", svc.recorded)
	}
	semDetalheInterno(t, db, w)
}

func TestVPNUpdateConfigFalhaDoWireGuardNaoImpedeOFirewall(t *testing.T) {
	db := newWireGuardHandlerTestDB(t)
	svc := &wireGuardServiceStub{updateErr: refazFalha()}
	fw := &vpnApplierStub{}
	h := NewWireGuardHandler(db, svc, fw)

	w := chamaVPN(h, httptest.NewRequest(http.MethodPut, "/api/vpn", strings.NewReader(corpoConfigVPN)))

	if !fw.escreveu || fw.desfez {
		t.Fatalf("a mudança está gravada: o firewall tem de seguir a decisão (escreveu=%v desfez=%v)", fw.escreveu, fw.desfez)
	}
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), wireGuardApplyFailure) {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if len(svc.updates) != 1 {
		t.Fatalf("gravada uma vez, sem desfazer: %d", len(svc.updates))
	}
	semDetalheInterno(t, db, w)
}

func TestVPNUpdateConfigRecusaEJanelaAberta(t *testing.T) {
	db := newWireGuardHandlerTestDB(t)

	svc := &wireGuardServiceStub{updateErr: recusaDo(wireguard.EstadoImpede, "configure o endereço público da VPN")}
	fw := &vpnApplierStub{}
	w := chamaVPN(NewWireGuardHandler(db, svc, fw), httptest.NewRequest(http.MethodPut, "/api/vpn", strings.NewReader(corpoConfigVPN)))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "endereço público") {
		t.Fatalf("recusa do serviço: status=%d body=%s", w.Code, w.Body.String())
	}
	if fw.desfez {
		t.Fatal("a escrita recusada não gravou nada: não há o que desfazer")
	}

	svc = &wireGuardServiceStub{}
	w = chamaVPN(NewWireGuardHandler(db, svc, &vpnApplierStub{trancada: true}), httptest.NewRequest(http.MethodPut, "/api/vpn", strings.NewReader(corpoConfigVPN)))
	if w.Code != http.StatusConflict || len(svc.updates) != 0 {
		t.Fatalf("janela aberta: status=%d gravações=%d", w.Code, len(svc.updates))
	}
}

func TestVPNEnrollSelfFalhaDoFirewallDesfazOPeerNovo(t *testing.T) {
	db := newWireGuardHandlerTestDB(t)
	svc := &wireGuardServiceStub{db: db, enrollment: wireguard.Enrollment{ClientConfig: "one-time-private"}}
	fw := &vpnApplierStub{falhaDepois: "o firewall recusou o ruleset"}
	h := NewWireGuardHandler(db, svc, fw)

	w := chamaVPN(h, comoUsuario(httptest.NewRequest(http.MethodPost, "/api/vpn/enrollment", nil), "u-123"))

	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "one-time-private") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if !fw.reversivel || !fw.desfez || len(svc.revokes) != 1 || peerNoBanco(t, db, "u-123") != nil {
		t.Fatalf("o peer novo devia ter sido desfeito (reversivel=%v desfez=%v revokes=%v)", fw.reversivel, fw.desfez, svc.revokes)
	}
	semDetalheInterno(t, db, w)
}

func TestVPNEnrollSelfSemVoltaEntregaAConfigQueFicou(t *testing.T) {
	db := newWireGuardHandlerTestDB(t)
	svc := &wireGuardServiceStub{
		db: db, enrollment: wireguard.Enrollment{ClientConfig: "one-time-private"},
		revokeErr: errors.New(detalheInterno),
	}
	fw := &vpnApplierStub{falhaDepois: "o firewall recusou o ruleset"}
	h := NewWireGuardHandler(db, svc, fw)

	w := chamaVPN(h, comoUsuario(httptest.NewRequest(http.MethodPost, "/api/vpn/enrollment", nil), "u-123"))

	if w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), "one-time-private") ||
		!strings.Contains(w.Body.String(), `"apply_error":"`+wireGuardApplyFailure+`"`) {
		t.Fatalf("o peer ficou; a config única não pode se perder: status=%d body=%s", w.Code, w.Body.String())
	}
	if svc.recorded == nil {
		t.Fatal("a falha que ficou devia ser registrada no painel da VPN")
	}
	semDetalheInterno(t, db, w)
}

func TestVPNEnrollSelfRotacaoNaoTemVolta(t *testing.T) {
	db := newWireGuardHandlerTestDB(t)
	semeiaPeer(t, db, "u-123", "full")
	svc := &wireGuardServiceStub{db: db, enrollment: wireguard.Enrollment{ClientConfig: "one-time-private"}}
	fw := &vpnApplierStub{falhaDepois: "o firewall recusou o ruleset"}
	h := NewWireGuardHandler(db, svc, fw)

	w := chamaVPN(h, comoUsuario(httptest.NewRequest(http.MethodPost, "/api/vpn/enrollment", nil), "u-123"))

	if fw.reversivel || len(svc.revokes) != 0 {
		t.Fatalf("girar a chave não tem volta: reversivel=%v revokes=%v", fw.reversivel, svc.revokes)
	}
	if w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), "one-time-private") || svc.recorded == nil {
		t.Fatalf("status=%d recorded=%v body=%s", w.Code, svc.recorded, w.Body.String())
	}
	semDetalheInterno(t, db, w)
}

func TestVPNEnrollSelfRecusaChegaComOMotivo(t *testing.T) {
	db := newWireGuardHandlerTestDB(t)
	svc := &wireGuardServiceStub{enrollErr: recusaDo(wireguard.EstadoImpede, "a VPN está desligada")}
	h := NewWireGuardHandler(db, svc, &vpnApplierStub{})

	w := chamaVPN(h, comoUsuario(httptest.NewRequest(http.MethodPost, "/api/vpn/enrollment", nil), "u-123"))

	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "a VPN está desligada") || svc.recorded != nil {
		t.Fatalf("status=%d recorded=%v body=%s", w.Code, svc.recorded, w.Body.String())
	}
}

func TestVPNEnrollSelfErroDeSistemaNaoVazaOTexto(t *testing.T) {
	db := newWireGuardHandlerTestDB(t)
	svc := &wireGuardServiceStub{enrollErr: errors.New(detalheInterno)}
	h := NewWireGuardHandler(db, svc, &vpnApplierStub{})

	w := chamaVPN(h, comoUsuario(httptest.NewRequest(http.MethodPost, "/api/vpn/enrollment", nil), "u-123"))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	semDetalheInterno(t, db, w)
}

func TestVPNEnrollSelfApplyErrorDoServicoVemGenerico(t *testing.T) {
	db := newWireGuardHandlerTestDB(t)
	svc := &wireGuardServiceStub{db: db, enrollment: wireguard.Enrollment{ClientConfig: "one-time-private", ApplyError: detalheInterno}}
	h := NewWireGuardHandler(db, svc, &vpnApplierStub{})

	w := chamaVPN(h, comoUsuario(httptest.NewRequest(http.MethodPost, "/api/vpn/enrollment", nil), "u-123"))

	if w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), wireGuardApplyFailure) {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	semDetalheInterno(t, db, w)
}

func TestVPNEnrollPeerFalhaDoFirewallDesfazOPeerNovo(t *testing.T) {
	db := newWireGuardHandlerTestDB(t)
	svc := &wireGuardServiceStub{db: db, enrollment: wireguard.Enrollment{ClientConfig: "one-time-private"}}
	fw := &vpnApplierStub{falhaDepois: "o firewall recusou o ruleset"}
	h := NewWireGuardHandler(db, svc, fw)

	req := httptest.NewRequest(http.MethodPost, "/api/vpn/peers/u-123/enrollment", strings.NewReader(`{"access_mode":"full"}`))
	w := chamaVPN(h, req)

	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "one-time-private") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if !svc.enrolledFor || !fw.desfez || peerNoBanco(t, db, "u-123") != nil {
		t.Fatalf("o peer novo devia ter sido desfeito (enrolledFor=%v desfez=%v)", svc.enrolledFor, fw.desfez)
	}
	semDetalheInterno(t, db, w)
}

func TestVPNEnrollPeerRecusaChegaComOMotivo(t *testing.T) {
	db := newWireGuardHandlerTestDB(t)
	svc := &wireGuardServiceStub{enrollErr: recusaDo(wireguard.NaoEncontrado, "usuário não encontrado")}
	h := NewWireGuardHandler(db, svc, &vpnApplierStub{})

	w := chamaVPN(h, httptest.NewRequest(http.MethodPost, "/api/vpn/peers/u-999/enrollment", nil))

	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "usuário não encontrado") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestVPNRevogarSegueOFirewallMesmoSeOWireGuardFalha(t *testing.T) {
	db := newWireGuardHandlerTestDB(t)
	svc := &wireGuardServiceStub{revokeErr: refazFalha()}
	fw := &vpnApplierStub{}
	h := NewWireGuardHandler(db, svc, fw)

	w := chamaVPN(h, httptest.NewRequest(http.MethodDelete, "/api/vpn/peers/u-123", nil))

	if !fw.escreveu || fw.reversivel {
		t.Fatalf("revogar não tem volta e o firewall tem de seguir: escreveu=%v reversivel=%v", fw.escreveu, fw.reversivel)
	}
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), wireGuardApplyFailure) {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	semDetalheInterno(t, db, w)
}

func TestVPNRevogarFalhaDoFirewallDizQueFicouGravado(t *testing.T) {
	db := newWireGuardHandlerTestDB(t)
	svc := &wireGuardServiceStub{}
	fw := &vpnApplierStub{falhaDepois: "o firewall recusou o ruleset"}
	h := NewWireGuardHandler(db, svc, fw)

	w := chamaVPN(h, httptest.NewRequest(http.MethodDelete, "/api/vpn/peers/u-123", nil))

	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "ficou gravada") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if fw.reversivel || fw.desfez || svc.recorded == nil {
		t.Fatalf("reversivel=%v desfez=%v recorded=%v", fw.reversivel, fw.desfez, svc.recorded)
	}
	semDetalheInterno(t, db, w)
}

func TestVPNRevogarSemAplicadorDeFirewall(t *testing.T) {
	db := newWireGuardHandlerTestDB(t)
	svc := &wireGuardServiceStub{}
	h := NewWireGuardHandler(db, svc, nil)

	w := chamaVPN(h, httptest.NewRequest(http.MethodDelete, "/api/vpn/peers/u-123", nil))

	if w.Code != http.StatusOK || svc.revokedUserID != "u-123" {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestVPNPerfilFalhaDoFirewallReverteODiz(t *testing.T) {
	db := newWireGuardHandlerTestDB(t)
	semeiaPeer(t, db, "u-123", "full")
	svc := &wireGuardServiceRealUpdateStub{wireGuardServiceStub{db: db}}
	fw := &vpnApplierStub{falhaDepois: "o firewall recusou o ruleset"}
	h := NewWireGuardHandler(db, svc, fw)

	body := `{"access_mode":"restricted","allowed_host_groups":["hg-1"]}`
	w := chamaVPN(h, httptest.NewRequest(http.MethodPut, "/api/vpn/peers/u-123/access", strings.NewReader(body)))

	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "nada foi alterado") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if p := peerNoBanco(t, db, "u-123"); p == nil || p.AccessMode != "full" {
		t.Fatalf("perfil no banco não reverteu: %+v", p)
	}
	semDetalheInterno(t, db, w)
}

func TestVPNPerfilFalhaDoWireGuardMantemOPerfilEDizPendente(t *testing.T) {
	db := newWireGuardHandlerTestDB(t)
	semeiaPeer(t, db, "u-123", "full")
	svc := &wireGuardServiceRealUpdateStub{wireGuardServiceStub{db: db, accessErr: refazFalha()}}
	fw := &vpnApplierStub{}
	h := NewWireGuardHandler(db, svc, fw)

	body := `{"access_mode":"restricted","allowed_host_groups":["hg-1"]}`
	w := chamaVPN(h, httptest.NewRequest(http.MethodPut, "/api/vpn/peers/u-123/access", strings.NewReader(body)))

	if !fw.escreveu || fw.desfez {
		t.Fatalf("o perfil mais restrito está gravado e o firewall tem de segui-lo: escreveu=%v desfez=%v", fw.escreveu, fw.desfez)
	}
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), wireGuardApplyFailure) {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if p := peerNoBanco(t, db, "u-123"); p == nil || p.AccessMode != "restricted" {
		t.Fatalf("o perfil devia ter ficado: %+v", p)
	}
	semDetalheInterno(t, db, w)
}

func TestVPNPerfilRecusaChegaComOMotivo(t *testing.T) {
	db := newWireGuardHandlerTestDB(t)
	semeiaPeer(t, db, "u-123", "full")
	svc := &wireGuardServiceStub{accessErr: recusaDo(wireguard.NaoEncontrado, "peer não encontrado")}
	h := NewWireGuardHandler(db, svc, &vpnApplierStub{})

	w := chamaVPN(h, httptest.NewRequest(http.MethodPut, "/api/vpn/peers/u-123/access", strings.NewReader(`{"access_mode":"full"}`)))

	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "peer não encontrado") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestVPNReemitirTraduzOMotivo(t *testing.T) {
	casos := []struct {
		nome string
		err  error
		want int
	}{
		{"estado impede", recusaDo(wireguard.EstadoImpede, "a chave não está no cofre"), http.StatusConflict},
		{"não encontrado", recusaDo(wireguard.NaoEncontrado, "essa pessoa não tem VPN"), http.StatusNotFound},
		{"pedido inválido", recusaDo(wireguard.PedidoInvalido, "pedido inválido"), http.StatusBadRequest},
		{"falha de sistema", errors.New(detalheInterno), http.StatusInternalServerError},
	}
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			db := newWireGuardHandlerTestDB(t)
			svc := &wireGuardServiceStub{reissueErr: c.err}
			h := NewWireGuardHandler(db, svc, &vpnApplierStub{})

			w := chamaVPN(h, comoUsuario(httptest.NewRequest(http.MethodPost, "/api/vpn/reissue", nil), "u-123"))
			if w.Code != c.want {
				t.Fatalf("ReissueSelf: status=%d want=%d body=%s", w.Code, c.want, w.Body.String())
			}
			semDetalheInterno(t, db, w)

			w = chamaVPN(h, httptest.NewRequest(http.MethodPost, "/api/vpn/peers/u-123/reissue", nil))
			if w.Code != c.want {
				t.Fatalf("ReissuePeer: status=%d want=%d body=%s", w.Code, c.want, w.Body.String())
			}
			semDetalheInterno(t, db, w)
		})
	}
}
