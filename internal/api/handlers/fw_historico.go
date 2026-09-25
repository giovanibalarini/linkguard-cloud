package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

// GetHistorico devolve as últimas revisões gravadas da configuração aplicada do firewall.
func (h *FirewallHandler) GetHistorico(w http.ResponseWriter, r *http.Request) {
	revisoes, err := h.db.ListarRevisoes(30)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if revisoes == nil {
		revisoes = []storage.RevisaoFW{}
	}
	writeJSON(w, http.StatusOK, revisoes)
}

// RestaurarRevisao restaura uma revisão do histórico para a configuração em edição (ficando pendente).
func (h *FirewallHandler) RestaurarRevisao(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id da revisão é obrigatório")
		return
	}

	err := h.fr.RestaurarRevisao(r.Context(), id, actingUser(r))
	if err != nil {
		writeGuardError(w, err)
		return
	}

	auditAction(h.db, r, "fw.revisao.restaurar", "firewall", id)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
