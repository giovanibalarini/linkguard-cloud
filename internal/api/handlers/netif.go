package handlers

import (
	"net/http"

	"github.com/giovanibalarini/linkguard-cloud/internal/netif"
)

// NetifHandler handles the read-only interface inventory.
type NetifHandler struct {
	svc *netif.Service
}

// NewNetifHandler creates a NetifHandler.
func NewNetifHandler(svc *netif.Service) *NetifHandler {
	return &NetifHandler{svc: svc}
}

// List returns every interface the kernel currently knows about.
func (h *NetifHandler) List(w http.ResponseWriter, r *http.Request) {
	views, err := h.svc.List(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if views == nil {
		views = []netif.IfaceView{}
	}
	writeJSON(w, http.StatusOK, views)
}
