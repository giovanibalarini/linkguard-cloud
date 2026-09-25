package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/giovanibalarini/linkguard-cloud/internal/fwmodel"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

// GetNAT lista todos os encaminhamentos de porta (DNAT) configurados em edição.
func (h *FirewallHandler) GetNAT(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.db.CarregarConfigEmEdicao()
	if err != nil {
		writeInternalError(w, err)
		return
	}

	encs := cfg.Encaminhamentos
	if encs == nil {
		encs = []fwmodel.Encaminhamento{}
	}
	writeJSON(w, http.StatusOK, encs)
}

// CriarNAT adiciona um novo encaminhamento de porta à configuração em edição.
func (h *FirewallHandler) CriarNAT(w http.ResponseWriter, r *http.Request) {
	var enc fwmodel.Encaminhamento
	if err := decodeJSON(r, &enc); err != nil {
		writeError(w, http.StatusBadRequest, "corpo da requisição inválido")
		return
	}

	if enc.ID == "" {
		enc.ID = uuid.NewString()
	}
	if enc.Proto == "" {
		enc.Proto = "tcp"
	}

	err := h.fr.EditarConfig(r.Context(), actingUser(r), func(db *storage.DB) error {
		return db.CriarEncaminhamentoFW(&enc)
	})
	if err != nil {
		writeGuardError(w, err)
		return
	}

	auditAction(h.db, r, "fw.nat.criar", "firewall", enc.ID)
	writeJSON(w, http.StatusCreated, enc)
}

// AtualizarNAT atualiza um encaminhamento de porta existente.
func (h *FirewallHandler) AtualizarNAT(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id do encaminhamento é obrigatório")
		return
	}

	var enc fwmodel.Encaminhamento
	if err := decodeJSON(r, &enc); err != nil {
		writeError(w, http.StatusBadRequest, "corpo da requisição inválido")
		return
	}
	enc.ID = id

	err := h.fr.EditarConfig(r.Context(), actingUser(r), func(db *storage.DB) error {
		return db.AtualizarEncaminhamentoFW(enc)
	})
	if err != nil {
		writeGuardError(w, err)
		return
	}

	auditAction(h.db, r, "fw.nat.alterar", "firewall", id)
	writeJSON(w, http.StatusOK, enc)
}

// ApagarNAT remove um encaminhamento de porta da configuração em edição.
func (h *FirewallHandler) ApagarNAT(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id do encaminhamento é obrigatório")
		return
	}

	err := h.fr.EditarConfig(r.Context(), actingUser(r), func(db *storage.DB) error {
		return db.ApagarEncaminhamentoFW(id)
	})
	if err != nil {
		writeGuardError(w, err)
		return
	}

	auditAction(h.db, r, "fw.nat.apagar", "firewall", id)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// AtivarNAT ativa ou desativa um encaminhamento de porta existente.
func (h *FirewallHandler) AtivarNAT(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id do encaminhamento é obrigatório")
		return
	}

	var body struct {
		Ativo bool `json:"ativo"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "corpo da requisição inválido")
		return
	}

	err := h.fr.EditarConfig(r.Context(), actingUser(r), func(db *storage.DB) error {
		return db.AtivarEncaminhamentoFW(id, body.Ativo)
	})
	if err != nil {
		writeGuardError(w, err)
		return
	}

	action := "fw.nat.desativar"
	if body.Ativo {
		action = "fw.nat.ativar"
	}
	auditAction(h.db, r, action, "firewall", id)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
