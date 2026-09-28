package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/giovanibalarini/linkguard-cloud/internal/api/handlers"
	"github.com/giovanibalarini/linkguard-cloud/internal/auth"
	"github.com/giovanibalarini/linkguard-cloud/internal/domainrouting"
	"github.com/giovanibalarini/linkguard-cloud/internal/domtargets"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

type domainRBACRuntime struct{}

func (*domainRBACRuntime) DefinirAlvos([]domtargets.Alvo) {}
func (*domainRBACRuntime) Estado(context.Context) domtargets.Estado {
	return domtargets.Estado{Vivo: true, KernelLido: true}
}

func TestDomainTargetRoutesUseLinksReadAndWriteRBAC(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "rbac.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	readerRole := &storage.Role{Name: "Leitor do firewall", Permissions: []string{string(auth.PermFirewallRead)}}
	writerRole := &storage.Role{Name: "Editor do firewall", Permissions: []string{string(auth.PermFirewallWrite)}}
	for _, role := range []*storage.Role{readerRole, writerRole} {
		if err := db.CreateRole(role); err != nil {
			t.Fatal(err)
		}
	}
	reader := &storage.User{Username: "reader"}
	writer := &storage.User{Username: "writer"}
	if err := db.CreateUser(reader, "hash", []string{readerRole.ID}); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateUser(writer, "hash", []string{writerRole.ID}); err != nil {
		t.Fatal(err)
	}

	coordinator := domainrouting.New(db, &domainRBACRuntime{})
	if err := coordinator.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	handler := handlers.NewDomainTargetsHandler(coordinator, db)
	authSvc := auth.NewService(db, "test-secret", nil)
	router := chi.NewRouter()
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if userID := r.Header.Get("X-Test-User"); userID != "" {
				r = r.WithContext(auth.ContextWithClaims(r.Context(), &auth.Claims{UserID: userID}))
			}
			next.ServeHTTP(w, r)
		})
	})
	registerDomainTargetRoutes(router, authSvc.Require, handler)

	request := func(method, path, userID, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Test-User", userID)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		return response
	}

	if got := request(http.MethodGet, "/api/domain-targets", "", ""); got.Code != http.StatusUnauthorized {
		t.Fatalf("sem sessão = %d: %s", got.Code, got.Body.String())
	}
	if got := request(http.MethodGet, "/api/domain-targets", reader.ID, ""); got.Code != http.StatusOK {
		t.Fatalf("firewall.read GET = %d: %s", got.Code, got.Body.String())
	}
	if got := request(http.MethodPost, "/api/domain-targets", reader.ID,
		`{"domain":"ads.example.com","capability":"barrar"}`); got.Code != http.StatusForbidden {
		t.Fatalf("firewall.read POST = %d: %s", got.Code, got.Body.String())
	}
	if got := request(http.MethodPost, "/api/domain-targets", writer.ID,
		`{"domain":"ads.example.com","capability":"barrar"}`); got.Code != http.StatusCreated {
		t.Fatalf("firewall.write POST = %d: %s", got.Code, got.Body.String())
	}
	if got := request(http.MethodGet, "/api/domain-targets", writer.ID, ""); got.Code != http.StatusForbidden {
		t.Fatalf("firewall.write sem read GET = %d: %s", got.Code, got.Body.String())
	}
}
