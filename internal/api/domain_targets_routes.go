package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/giovanibalarini/linkguard-cloud/internal/api/handlers"
	"github.com/giovanibalarini/linkguard-cloud/internal/auth"
)

// registerDomainTargetRoutes concentra caminho e permissão no mesmo ponto para
// o teste de RBAC exercitar exatamente a montagem usada em produção.
func registerDomainTargetRoutes(
	r chi.Router,
	require func(auth.Permission) func(http.Handler) http.Handler,
	h *handlers.DomainTargetsHandler,
) {
	r.With(require(auth.PermFirewallRead)).Get("/api/domain-targets", h.List)
	r.With(require(auth.PermFirewallWrite)).Post("/api/domain-targets", h.Create)
	r.With(require(auth.PermFirewallWrite)).Put("/api/domain-targets/{id}", h.Update)
	r.With(require(auth.PermFirewallWrite)).Delete("/api/domain-targets/{id}", h.Delete)
	r.With(require(auth.PermFirewallWrite)).Post("/api/domain-targets/{id}/stage", h.SetStage)
}
