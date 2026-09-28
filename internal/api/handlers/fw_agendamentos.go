package handlers

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/giovanibalarini/linkguard-cloud/internal/fwmodel"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

// AgendamentoView descreve a representação de um agendamento na interface web.
type AgendamentoView struct {
	ID        string   `json:"id"`
	Nome      string   `json:"nome"`
	Descricao string   `json:"descricao"`
	Dias      string   `json:"dias"`
	Inicio    string   `json:"inicio"`
	Fim       string   `json:"fim"`
	Usos      int      `json:"usos"`
	UsosLista []string `json:"usos_lista,omitempty"`
}

// GetAgendamentos lista todos os agendamentos cadastrados na configuração em edição.
func (h *FirewallHandler) GetAgendamentos(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.db.CarregarConfigEmEdicao()
	if err != nil {
		writeInternalError(w, err)
		return
	}

	res := make([]AgendamentoView, 0, len(cfg.Agendamentos))
	for _, ag := range cfg.Agendamentos {
		usos, err := h.db.UsosDoAgendamento(ag.ID)
		if err != nil {
			writeInternalError(w, err)
			return
		}
		res = append(res, AgendamentoView{
			ID:        ag.ID,
			Nome:      ag.Nome,
			Descricao: ag.Descricao,
			Dias:      ag.Dias,
			Inicio:    ag.Inicio,
			Fim:       ag.Fim,
			Usos:      len(usos),
			UsosLista: usos,
		})
	}

	writeJSON(w, http.StatusOK, res)
}

// CriarAgendamento adiciona um novo agendamento à configuração em edição.
func (h *FirewallHandler) CriarAgendamento(w http.ResponseWriter, r *http.Request) {
	var ag fwmodel.Agendamento
	if err := decodeJSON(r, &ag); err != nil {
		writeError(w, http.StatusBadRequest, "corpo da requisição inválido")
		return
	}

	if ag.ID == "" {
		ag.ID = uuid.NewString()
	}
	if strings.TrimSpace(ag.Nome) == "" {
		writeError(w, http.StatusBadRequest, "nome do agendamento é obrigatório")
		return
	}

	err := h.fr.EditarConfigValidando(r.Context(), actingUser(r), func(db *storage.DB) error {
		return db.CriarAgendamentoFW(&ag)
	}, "agendamento:"+ag.ID)
	if err != nil {
		writeGuardError(w, err)
		return
	}

	auditAction(h.db, r, "fw.agendamento.criar", "firewall", ag.ID)
	writeJSON(w, http.StatusCreated, ag)
}

// AtualizarAgendamento atualiza os parâmetros de um agendamento existente.
func (h *FirewallHandler) AtualizarAgendamento(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id do agendamento é obrigatório")
		return
	}

	var ag fwmodel.Agendamento
	if err := decodeJSON(r, &ag); err != nil {
		writeError(w, http.StatusBadRequest, "corpo da requisição inválido")
		return
	}
	ag.ID = id

	err := h.fr.EditarConfigValidando(r.Context(), actingUser(r), func(db *storage.DB) error {
		return db.AtualizarAgendamentoFW(ag)
	}, "agendamento:"+id)
	if err != nil {
		writeGuardError(w, err)
		return
	}

	auditAction(h.db, r, "fw.agendamento.alterar", "firewall", id)
	writeJSON(w, http.StatusOK, ag)
}

// ApagarAgendamento remove um agendamento, recusando caso esteja em uso em alguma regra.
func (h *FirewallHandler) ApagarAgendamento(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id do agendamento é obrigatório")
		return
	}

	err := h.fr.EditarConfigValidando(r.Context(), actingUser(r), func(db *storage.DB) error {
		return db.ApagarAgendamentoFW(id)
	})
	if err != nil {
		writeGuardError(w, err)
		return
	}

	auditAction(h.db, r, "fw.agendamento.apagar", "firewall", id)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
