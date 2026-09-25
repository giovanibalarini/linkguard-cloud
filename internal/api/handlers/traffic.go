package handlers

import (
	"net/http"

	"github.com/giovanibalarini/linkguard-cloud/internal/hosttraffic"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
	"github.com/giovanibalarini/linkguard-cloud/internal/tsdb"
	"github.com/giovanibalarini/linkguard-cloud/internal/validate"
)

// TrafficHandler exposes per-host bandwidth (top talkers) from conntrack.
type TrafficHandler struct {
	svc *hosttraffic.Service
	db  *storage.DB
	rrd *tsdb.Service
}

// NewTrafficHandler creates a TrafficHandler.
func NewTrafficHandler(svc *hosttraffic.Service, db *storage.DB, rrd *tsdb.Service) *TrafficHandler {
	return &TrafficHandler{svc: svc, db: db, rrd: rrd}
}

// HostHistory devolve o histórico de consumo de um host (issue #113).
//
// A máquina é identificada pelo IP, que é a identidade do inventário — a mesma
// que bloqueio, apelido e cota usam, e o rótulo com que a série é gravada.
func (h *TrafficHandler) HostHistory(w http.ResponseWriter, r *http.Request) {
	ip := validate.IPv4Canonico(r.URL.Query().Get("ip"))
	if ip == "" {
		writeError(w, http.StatusBadRequest, "ip inválido")
		return
	}
	resp, err := h.rrd.GetHostHistory(ip, r.URL.Query().Get("range"))
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// TopTalkers devolve as máquinas que mais consumiram no ciclo dos contadores.
func (h *TrafficHandler) TopTalkers(w http.ResponseWriter, r *http.Request) {
	talkers, err := h.svc.TopTalkers(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if len(talkers) > 20 {
		talkers = talkers[:20]
	}
	writeJSON(w, http.StatusOK, talkers)
}
