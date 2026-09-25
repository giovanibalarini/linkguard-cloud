package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/giovanibalarini/linkguard-cloud/internal/hosts"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
	"github.com/giovanibalarini/linkguard-cloud/internal/validate"
)

// HostsHandler expõe o inventário de máquinas (identificadas pelo IP).
type HostsHandler struct {
	svc *hosts.Service
	db  *storage.DB
}

// NewHostsHandler creates a HostsHandler.
func NewHostsHandler(svc *hosts.Service, db *storage.DB) *HostsHandler {
	return &HostsHandler{svc: svc, db: db}
}

// List returns the current host inventory.
func (h *HostsHandler) List(w http.ResponseWriter, r *http.Request) {
	hs, err := h.svc.List(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if hs == nil {
		hs = []hosts.Host{}
	}
	writeJSON(w, http.StatusOK, hs)
}

// SetAlias dá um apelido à máquina (pelo IP).
func (h *HostsHandler) SetAlias(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP    string `json:"ip"`
		Alias string `json:"alias"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.svc.SetAlias(body.IP, strings.TrimSpace(body.Alias)); err != nil {
		if errors.Is(err, hosts.ErrIPInvalido) {
			writeError(w, http.StatusBadRequest, "ip inválido")
			return
		}
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// SetBlocked bloqueia ou desbloqueia a máquina (pelo IP).
func (h *HostsHandler) SetBlocked(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP      string `json:"ip"`
		Blocked bool   `json:"blocked"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	ip := validate.IPv4Canonico(body.IP)
	if ip == "" {
		writeError(w, http.StatusBadRequest, "ip inválido")
		return
	}
	if err := h.svc.SetBlocked(r.Context(), ip, body.Blocked); err != nil {
		writeInternalError(w, err)
		return
	}
	action := "host.unblock"
	if body.Blocked {
		action = "host.block"
	}
	auditAction(h.db, r, action, "host:"+ip, "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
