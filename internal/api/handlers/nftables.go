package handlers

import (
	"net"
	"net/http"
	"strings"

	"github.com/giovanibalarini/linkguard-cloud/internal/firewallrules"
	"github.com/giovanibalarini/linkguard-cloud/internal/nftables"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

// NftablesHandler exposes native nftables operations (ruleset, managed, blocklist, abusers, pending).
type NftablesHandler struct {
	svc *nftables.Service
	db  *storage.DB
	fr  *firewallrules.Service
}

// NewNftablesHandler creates an NftablesHandler.
func NewNftablesHandler(svc *nftables.Service, db *storage.DB, fr *firewallrules.Service) *NftablesHandler {
	return &NftablesHandler{svc: svc, db: db, fr: fr}
}

// Ruleset returns the full live nftables ruleset.
func (h *NftablesHandler) Ruleset(w http.ResponseWriter, r *http.Request) {
	rs, err := h.svc.Ruleset(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ruleset": rs})
}

// Managed returns the editable element-level view (host_wan map + sets).
func (h *NftablesHandler) Managed(w http.ResponseWriter, r *http.Request) {
	m, err := h.svc.Managed(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, m)
}

// Blocklist adds (POST) or removes (DELETE) a destination CIDR/IP in the set.
func (h *NftablesHandler) Blocklist(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CIDR string `json:"cidr"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	cidr := strings.TrimSpace(body.CIDR)
	if !validCIDRorIP(cidr) {
		writeError(w, http.StatusBadRequest, "invalid CIDR or IP")
		return
	}
	var err error
	if r.Method == http.MethodDelete {
		_, err = h.svc.DelBlocklist(r.Context(), cidr)
		auditAction(h.db, r, "nft.blocklist.del", cidr, "")
	} else {
		_, err = h.svc.AddBlocklist(r.Context(), cidr)
		auditAction(h.db, r, "nft.blocklist.add", cidr, "")
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	saveNftSnapshot(r.Context(), h.db, h.svc)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func validCIDRorIP(v string) bool {
	if _, _, err := net.ParseCIDR(v); err == nil {
		return true
	}
	return net.ParseIP(v) != nil
}

// Contidos é a lista de origens sob contenção (issue #127).
func (h *NftablesHandler) Contidos(w http.ResponseWriter, r *http.Request) {
	lista, err := h.svc.Contidos(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"contidos": lista})
}

// LiberarContido tira uma origem da contenção.
func (h *NftablesHandler) LiberarContido(w http.ResponseWriter, r *http.Request) {
	var b struct {
		IP string `json:"ip"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "corpo inválido")
		return
	}
	if err := h.svc.Liberar(r.Context(), b.IP); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	auditAction(h.db, r, "nft.abusers.release", "input", b.IP)
	writeJSON(w, http.StatusOK, map[string]bool{"liberado": true})
}
