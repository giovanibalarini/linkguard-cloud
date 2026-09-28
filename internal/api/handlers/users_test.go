package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/giovanibalarini/linkguard-cloud/internal/api/handlers"
	"github.com/giovanibalarini/linkguard-cloud/internal/auth"
	"github.com/giovanibalarini/linkguard-cloud/internal/firewallrules"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
	"github.com/giovanibalarini/linkguard-cloud/internal/wireguard"
)

func withChiURLParam(r *http.Request, key, value string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, value)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

func newUsersTestHandler(t *testing.T) (*handlers.UsersHandler, *storage.DB) {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return handlers.NewUsersHandler(db), db
}

// helpdeskOnlyUser creates a role with ONLY users.manage (no roles.manage) and
// a user assigned to it — the exact "limited helpdesk account" scenario the
// vulnerability targets.
func helpdeskOnlyUser(t *testing.T, db *storage.DB) *storage.User {
	t.Helper()
	role := &storage.Role{Name: "Helpdesk", Permissions: []string{string(auth.PermUsersManage)}}
	if err := db.CreateRole(role); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	u := &storage.User{Username: "helpdesk"}
	if err := db.CreateUser(u, "$2a$10$fakehashfakehashfakehashfakehashfakehashfakehashfa", []string{role.ID}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return u
}

func adminRoleID(t *testing.T, db *storage.DB) string {
	t.Helper()
	role := &storage.Role{Name: "Admin de verdade", Permissions: []string{string(auth.PermRolesManage), string(auth.PermUsersManage)}}
	if err := db.CreateRole(role); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	return role.ID
}

func TestUpdateBlocksSelfPromotionWithoutRolesManage(t *testing.T) {
	h, db := newUsersTestHandler(t)
	attacker := helpdeskOnlyUser(t, db)
	adminRole := adminRoleID(t, db)

	body, _ := json.Marshal(map[string]interface{}{"role_ids": []string{adminRole}})
	req := httptest.NewRequest(http.MethodPut, "/api/users/"+attacker.ID, bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: attacker.ID, Username: attacker.Username}))
	req = withChiURLParam(req, "id", attacker.ID)
	w := httptest.NewRecorder()
	h.Update(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (roles.manage required), got %d: %s", w.Code, w.Body.String())
	}
	roleIDs, err := db.GetUserRoleIDs(attacker.ID)
	if err != nil {
		t.Fatalf("GetUserRoleIDs: %v", err)
	}
	for _, rid := range roleIDs {
		if rid == adminRole {
			t.Fatal("attacker's role_ids were changed despite the 403 — self-promotion succeeded")
		}
	}
}

func TestCreateBlocksRoleGrantWithoutRolesManage(t *testing.T) {
	h, db := newUsersTestHandler(t)
	attacker := helpdeskOnlyUser(t, db)
	adminRole := adminRoleID(t, db)

	body, _ := json.Marshal(map[string]interface{}{
		"username": "backdoor",
		"password": "senhaForte12345",
		"role_ids": []string{adminRole},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: attacker.ID, Username: attacker.Username}))
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (roles.manage required to grant a role at creation), got %d: %s", w.Code, w.Body.String())
	}
	// The attack must not have created the user in the DB.
	created, err := db.GetUserByUsername("backdoor")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if created != nil {
		t.Fatal("user was created despite the 403 — privilege escalation via Create succeeded")
	}
}

func TestCreateWithoutRolesDoesNotRequireRolesManage(t *testing.T) {
	h, db := newUsersTestHandler(t)
	actor := helpdeskOnlyUser(t, db)

	body, _ := json.Marshal(map[string]interface{}{
		"username": "conta-sem-papel",
		"password": "senhaForte12345",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: actor.ID, Username: actor.Username}))
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 for role-less creation (no grant), got %d: %s", w.Code, w.Body.String())
	}
	created, err := db.GetUserByUsername("conta-sem-papel")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if created == nil {
		t.Fatal("legitimate role-less user was not created")
	}
}

func TestCreateWithRolesManageCanGrantRoles(t *testing.T) {
	h, db := newUsersTestHandler(t)
	actorRole := adminRoleID(t, db)
	actor := &storage.User{Username: "real-admin"}
	if err := db.CreateUser(actor, "$2a$10$fakehashfakehashfakehashfakehashfakehashfakehashfa", []string{actorRole}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	body, _ := json.Marshal(map[string]interface{}{
		"username": "novo-admin",
		"password": "senhaForte12345",
		"role_ids": []string{actorRole},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/users", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: actor.ID, Username: actor.Username}))
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 — actor holds roles.manage, legitimate role grant, got %d: %s", w.Code, w.Body.String())
	}
	created, err := db.GetUserByUsername("novo-admin")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if created == nil {
		t.Fatal("user with granted role was not created")
	}
}

func TestUpdatePasswordOnlyDoesNotRequireRolesManage(t *testing.T) {
	h, db := newUsersTestHandler(t)
	attacker := helpdeskOnlyUser(t, db)

	body, _ := json.Marshal(map[string]interface{}{"password": "novaSenhaForte123"})
	req := httptest.NewRequest(http.MethodPut, "/api/users/"+attacker.ID, bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: attacker.ID, Username: attacker.Username}))
	req = withChiURLParam(req, "id", attacker.ID)
	w := httptest.NewRecorder()
	h.Update(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for password-only update (no role change), got %d: %s", w.Code, w.Body.String())
	}
}

func TestUpdateWithRolesManageCanChangeRoles(t *testing.T) {
	h, db := newUsersTestHandler(t)
	actorRole := adminRoleID(t, db)
	actor := &storage.User{Username: "real-admin"}
	if err := db.CreateUser(actor, "$2a$10$fakehashfakehashfakehashfakehashfakehashfakehashfa", []string{actorRole}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	target := helpdeskOnlyUser(t, db)

	body, _ := json.Marshal(map[string]interface{}{"role_ids": []string{actorRole}})
	req := httptest.NewRequest(http.MethodPut, "/api/users/"+target.ID, bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: actor.ID, Username: actor.Username}))
	req = withChiURLParam(req, "id", target.ID)
	w := httptest.NewRecorder()
	h.Update(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 — actor holds roles.manage, legitimate role change, got %d: %s", w.Code, w.Body.String())
	}
}

// ─── Reset de senha como caminho de escalação ────────────────────────────────
//
// Trocar a senha de uma conta É adquirir as permissões daquela conta. O gate de
// roles.manage cobria só a troca de papel; o bloco de senha não tinha checagem
// nenhuma, então users.manage sozinho bastava para tomar a conta de admin.

func adminTargetUser(t *testing.T, db *storage.DB) *storage.User {
	t.Helper()
	u := &storage.User{Username: "admin-alvo"}
	if err := db.CreateUser(u, "$2a$10$originaloriginaloriginaloriginaloriginaloriginalor", []string{adminRoleID(t, db)}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	return u
}

func TestUpdateRefusesPasswordResetOnMorePrivilegedTarget(t *testing.T) {
	h, db := newUsersTestHandler(t)
	attacker := helpdeskOnlyUser(t, db)
	target := adminTargetUser(t, db)

	before, err := db.GetUserByID(target.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}

	body, _ := json.Marshal(map[string]interface{}{"password": "novaSenhaForte123"})
	req := httptest.NewRequest(http.MethodPut, "/api/users/"+target.ID, bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: attacker.ID, Username: attacker.Username}))
	req = withChiURLParam(req, "id", target.ID)
	w := httptest.NewRecorder()
	h.Update(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 — helpdesk (users.manage only) must not reset an admin's password, got %d: %s", w.Code, w.Body.String())
	}
	after, err := db.GetUserByID(target.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if after.Password != before.Password {
		t.Fatal("a senha do alvo foi trocada apesar do 403 — a escalação funcionou")
	}
	if after.PasswordVersion != before.PasswordVersion {
		t.Fatal("password_version subiu apesar do 403 — a sessão do admin legítimo foi derrubada")
	}
}

func TestUpdateAllowsSelfPasswordResetRegardlessOfPrivilege(t *testing.T) {
	h, db := newUsersTestHandler(t)
	actor := adminTargetUser(t, db)

	body, _ := json.Marshal(map[string]interface{}{"password": "minhaNovaSenha123"})
	req := httptest.NewRequest(http.MethodPut, "/api/users/"+actor.ID, bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: actor.ID, Username: actor.Username}))
	req = withChiURLParam(req, "id", actor.ID)
	w := httptest.NewRecorder()
	h.Update(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 — trocar a própria senha nunca é escalação, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUpdateAllowsPasswordResetOnEquallyOrLessPrivilegedTarget(t *testing.T) {
	h, db := newUsersTestHandler(t)
	actorRole := adminRoleID(t, db)
	actor := &storage.User{Username: "real-admin"}
	if err := db.CreateUser(actor, "$2a$10$fakehashfakehashfakehashfakehashfakehashfakehashfa", []string{actorRole}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	target := helpdeskOnlyUser(t, db)

	body, _ := json.Marshal(map[string]interface{}{"password": "senhaResetada123"})
	req := httptest.NewRequest(http.MethodPut, "/api/users/"+target.ID, bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: actor.ID, Username: actor.Username}))
	req = withChiURLParam(req, "id", target.ID)
	w := httptest.NewRecorder()
	h.Update(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 — reset legítimo de conta menos privilegiada, got %d: %s", w.Code, w.Body.String())
	}
}

type testVPNApplier struct {
	called     bool
	por        string
	resumo     string
	reversivel bool
	trancada   bool  // recusa antes de escrever, como a janela aberta
	depois     error // falha do firewall depois de a escrita ter ficado
}

func (a *testVPNApplier) AplicarMudancaVPN(ctx context.Context, por, resumo string, escrever func() error, desfazer func() error) (*firewallrules.Applied, error) {
	a.called = true
	a.por = por
	a.resumo = resumo
	a.reversivel = desfazer != nil
	if a.trancada {
		return nil, &firewallrules.GuardError{Stage: firewallrules.StageLocked, Message: "há uma janela de confirmação aberta"}
	}
	if escrever != nil {
		if err := escrever(); err != nil {
			return nil, err
		}
	}
	if a.depois != nil {
		return nil, a.depois
	}
	return &firewallrules.Applied{}, nil
}

type testVPNReconciler struct {
	chamadas int
	err      error
}

func (r *testVPNReconciler) Reconcile(context.Context) error {
	r.chamadas++
	return r.err
}

const detalheInternoUsuarios = "exit status 1: /var/lib/linkguard/wg0.conf: permission denied"

// usuarioComVPN cria o admin que pede e o alvo com peer, e devolve a chamada
// já montada.
func usuarioComVPN(t *testing.T, h *handlers.UsersHandler, db *storage.DB) (alvo *storage.User, apaga func() *httptest.ResponseRecorder) {
	t.Helper()
	adminRole := adminRoleID(t, db)
	admin := &storage.User{Username: "superadmin"}
	if err := db.CreateUser(admin, "$2a$10$fakehashfakehashfakehashfakehashfakehashfakehashfa", []string{adminRole}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	alvo = &storage.User{Username: "alvo-vpn"}
	if err := db.CreateUser(alvo, "$2a$10$fakehashfakehashfakehashfakehashfakehashfakehashfa", []string{adminRole}); err != nil {
		t.Fatalf("CreateUser alvo: %v", err)
	}
	if _, err := db.UpsertWireGuardPeer(&storage.WireGuardPeer{UserID: alvo.ID, Username: alvo.Username, Address: "10.7.0.10/32"}); err != nil {
		t.Fatalf("UpsertWireGuardPeer: %v", err)
	}
	return alvo, func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodDelete, "/api/users/"+alvo.ID, nil)
		req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: admin.ID, Username: admin.Username}))
		req = withChiURLParam(req, "id", alvo.ID)
		w := httptest.NewRecorder()
		h.Delete(w, req)
		return w
	}
}

func usuarioExiste(t *testing.T, db *storage.DB, id string) bool {
	t.Helper()
	u, err := db.GetUserByID(id)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	return u != nil
}

func TestDeleteUserReconciliaAVPNESemVolta(t *testing.T) {
	h, db := newUsersTestHandler(t)
	alvo, apaga := usuarioComVPN(t, h, db)
	fw, wg := &testVPNApplier{}, &testVPNReconciler{}
	h.SetVPNApplier(fw)
	h.SetVPNReconciler(wg)

	w := apaga()

	if w.Code != http.StatusOK || usuarioExiste(t, db, alvo.ID) {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if wg.chamadas != 1 {
		t.Fatalf("apagar o usuário tem de tirar a chave do wg0.conf: %d reconciliações", wg.chamadas)
	}
	if fw.reversivel {
		t.Fatal("apagar um usuário não tem volta")
	}
	if bytes.Contains(w.Body.Bytes(), []byte("warning")) {
		t.Fatalf("nada pendente: %s", w.Body.String())
	}
}

func TestDeleteUserFalhaDoWireGuardApagaEAvisaSemVazar(t *testing.T) {
	h, db := newUsersTestHandler(t)
	alvo, apaga := usuarioComVPN(t, h, db)
	fw := &testVPNApplier{}
	h.SetVPNApplier(fw)
	h.SetVPNReconciler(&testVPNReconciler{err: &wireguard.FalhaDeReconciliacao{Err: errors.New(detalheInternoUsuarios)}})

	w := apaga()

	if w.Code != http.StatusOK || usuarioExiste(t, db, alvo.ID) {
		t.Fatalf("o usuário foi apagado no banco: status=%d body=%s", w.Code, w.Body.String())
	}
	if !fw.called || fw.reversivel {
		t.Fatalf("o firewall tem de seguir a decisão mesmo com o WireGuard falho (called=%v reversivel=%v)", fw.called, fw.reversivel)
	}
	var out map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("resposta: %v %s", err, w.Body.String())
	}
	if out["status"] != "deleted" || out["warning"] != "vpn_reconcile_pending" {
		t.Fatalf("resposta = %v", out)
	}
	if bytes.Contains(w.Body.Bytes(), []byte("wg0.conf")) {
		t.Fatalf("detalhe interno vazou: %s", w.Body.String())
	}
	auditouExclusao(t, db, alvo.Username)
}

func TestDeleteUserFalhaDoFirewallDepoisDeApagarAvisa(t *testing.T) {
	h, db := newUsersTestHandler(t)
	alvo, apaga := usuarioComVPN(t, h, db)
	h.SetVPNApplier(&testVPNApplier{depois: &firewallrules.GuardError{
		Stage: firewallrules.StageReconcile, Gravada: true, Err: errors.New(detalheInternoUsuarios),
		Message: "o firewall recusou o ruleset; a mudança ficou gravada, mas o firewall não foi reconciliado",
	}})
	h.SetVPNReconciler(&testVPNReconciler{})

	w := apaga()

	if w.Code != http.StatusOK || usuarioExiste(t, db, alvo.ID) {
		t.Fatalf("o usuário foi apagado no banco: status=%d body=%s", w.Code, w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("vpn_reconcile_pending")) || bytes.Contains(w.Body.Bytes(), []byte("wg0.conf")) {
		t.Fatalf("body=%s", w.Body.String())
	}
	auditouExclusao(t, db, alvo.Username)
}

func TestDeleteUserComJanelaAbertaNaoApagaNada(t *testing.T) {
	h, db := newUsersTestHandler(t)
	alvo, apaga := usuarioComVPN(t, h, db)
	wg := &testVPNReconciler{}
	h.SetVPNApplier(&testVPNApplier{trancada: true})
	h.SetVPNReconciler(wg)

	w := apaga()

	if w.Code != http.StatusConflict || !usuarioExiste(t, db, alvo.ID) || wg.chamadas != 0 {
		t.Fatalf("status=%d existe=%v reconciliações=%d body=%s", w.Code, usuarioExiste(t, db, alvo.ID), wg.chamadas, w.Body.String())
	}
}

func auditouExclusao(t *testing.T, db *storage.DB, username string) {
	t.Helper()
	logs, err := db.GetAuditLogs(50)
	if err != nil {
		t.Fatalf("GetAuditLogs: %v", err)
	}
	achou := false
	for _, l := range logs {
		if l.Action == "user.delete" && l.Resource == "user:"+username {
			achou = true
		}
		if bytes.Contains([]byte(l.Details), []byte("wg0.conf")) {
			t.Fatalf("detalhe interno vazou na auditoria: %q", l.Details)
		}
	}
	if !achou {
		t.Fatal("o usuário foi apagado e a exclusão tem de estar na auditoria")
	}
}

func TestDeleteUserWithWireGuardPeerTriggersVPNApplier(t *testing.T) {
	h, db := newUsersTestHandler(t)
	adminRole := adminRoleID(t, db)
	admin := &storage.User{Username: "superadmin"}
	if err := db.CreateUser(admin, "$2a$10$fakehashfakehashfakehashfakehashfakehashfakehashfa", []string{adminRole}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	target := &storage.User{Username: "alvo-vpn"}
	if err := db.CreateUser(target, "$2a$10$fakehashfakehashfakehashfakehashfakehashfakehashfa", []string{adminRole}); err != nil {
		t.Fatalf("CreateUser target: %v", err)
	}

	if _, err := db.UpsertWireGuardPeer(&storage.WireGuardPeer{UserID: target.ID, Username: target.Username, Address: "10.7.0.10/32"}); err != nil {
		t.Fatalf("UpsertWireGuardPeer: %v", err)
	}

	applier := &testVPNApplier{}
	h.SetVPNApplier(applier)

	req := httptest.NewRequest(http.MethodDelete, "/api/users/"+target.ID, nil)
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: admin.ID, Username: admin.Username}))
	req = withChiURLParam(req, "id", target.ID)
	w := httptest.NewRecorder()
	h.Delete(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Delete status = %d, body = %s", w.Code, w.Body.String())
	}
	if !applier.called {
		t.Fatal("AplicarMudancaVPN não foi chamado ao deletar usuário com peer WireGuard")
	}
	if applier.por != admin.Username {
		t.Fatalf("por = %q, want %q", applier.por, admin.Username)
	}
	deletedUser, err := db.GetUserByID(target.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if deletedUser != nil {
		t.Fatal("usuário ainda existe no banco após Delete")
	}
}
