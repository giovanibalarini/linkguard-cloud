package handlers

import (
	"net/http"

	"github.com/giovanibalarini/linkguard-cloud/internal/iptables"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

// IptablesHandler handles iptables-related requests.
type IptablesHandler struct {
	svc *iptables.Service
	db  *storage.DB
}

// NewIptablesHandler creates an IptablesHandler.
func NewIptablesHandler(svc *iptables.Service, db *storage.DB) *IptablesHandler {
	return &IptablesHandler{svc: svc, db: db}
}

// ListAll returns all iptables tables.
func (h *IptablesHandler) ListAll(w http.ResponseWriter, r *http.Request) {
	tables, err := h.svc.ListAll(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tables)
}

// ListFilter returns the filter table.
func (h *IptablesHandler) ListFilter(w http.ResponseWriter, r *http.Request) {
	h.listTable(w, r, "filter")
}

// ListNat returns the nat table.
func (h *IptablesHandler) ListNat(w http.ResponseWriter, r *http.Request) {
	h.listTable(w, r, "nat")
}

// ListMangle returns the mangle table.
func (h *IptablesHandler) ListMangle(w http.ResponseWriter, r *http.Request) {
	h.listTable(w, r, "mangle")
}

func (h *IptablesHandler) listTable(w http.ResponseWriter, r *http.Request, table string) {
	t, err := h.svc.ListTable(r.Context(), table)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// Preview returns the commands that would be applied without executing them.
func (h *IptablesHandler) Preview(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Commands []string `json:"commands"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"preview":  true,
		"commands": body.Commands,
		"message":  "Dry-run preview — no changes applied",
	})
}

// Backup e Rollback FORAM REMOVIDOS daqui (2026-08-13). Ver o comentário em
// internal/api/server.go, onde as rotas viviam: eram do tempo do iptables,
// nenhuma tela as chamava, e juntas formavam um caminho sem trava para dar
// flush nas chains `ip filter/nat/mangle` (as do Docker) de uma máquina de
// produção. Backup e rollback do firewall são o par nftables.
//
// iptables.Service.Restore saiu junto: este era o único chamador dele.

// ListBackups returns iptables rule backups.
func (h *IptablesHandler) ListBackups(w http.ResponseWriter, r *http.Request) {
	backups, err := h.db.GetIptablesBackups(20)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if backups == nil {
		backups = []storage.IptablesBackup{}
	}
	writeJSON(w, http.StatusOK, backups)
}

// DeleteRule e UpdateRule foram removidos junto com iptables.Service.DeleteRule
// e ReplaceRule. O DeleteRule não passava por validateTableChain — ao contrário
// dos dois irmãos — e aceitava qualquer table/chain, então uma conta com
// firewall.write apagava regra viva de terceiros (filter/DOCKER-USER,
// nat/POSTROUTING). Nenhum dos dois tinha consumidor: o frontend só faz
// POST /api/firewall/rules, no assistente de balanceamento WAN — e esse POST
// saiu junto com o assistente, na versão cloud sem multi-WAN.
//
// Mesma decisão, e pelo mesmo motivo, que retirou o Restore e o rollback legado
// em 13/08: o LinkGuard só escreve na tabela inet linkguard, e superfície de
// escrita sem uso num appliance de firewall é só risco parado.
