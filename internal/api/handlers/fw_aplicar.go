package handlers

import (
	"net/http"
)

// GetPendencias devolve a lista de mudanças pendentes entre a configuração em edição e a aplicada.
func (h *FirewallHandler) GetPendencias(w http.ResponseWriter, r *http.Request) {
	pend, err := h.fr.Pendencias(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, pend)
}

// Aplicar executa os 12 passos da aplicação segura do firewall por zonas (§2.8).
func (h *FirewallHandler) Aplicar(w http.ResponseWriter, r *http.Request) {
	applied, err := h.fr.Aplicar(r.Context(), actingUser(r))
	if err != nil {
		writeGuardError(w, err)
		return
	}

	res := map[string]any{"status": "ok"}
	if applied != nil && applied.Pending != nil {
		res["pending"] = h.pendingView(applied.Pending)
	}
	writeJSON(w, http.StatusOK, res)
}

// Descartar descarta as alterações em edição, revertendo-as para a última configuração aplicada.
func (h *FirewallHandler) Descartar(w http.ResponseWriter, r *http.Request) {
	err := h.fr.Descartar(r.Context(), actingUser(r))
	if err != nil {
		writeGuardError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
