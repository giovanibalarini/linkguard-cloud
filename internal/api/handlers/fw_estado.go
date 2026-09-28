package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/giovanibalarini/linkguard-cloud/internal/blocklog"
	"github.com/giovanibalarini/linkguard-cloud/internal/firewallrules"
	"github.com/giovanibalarini/linkguard-cloud/internal/fwmodel"
	"github.com/giovanibalarini/linkguard-cloud/internal/nftables"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

// FirewallHandler implementa os handlers da API nova do firewall por zonas (/api/firewall/*).
type FirewallHandler struct {
	db       *storage.DB
	fr       *firewallrules.Service
	nft      *nftables.Service
	blocklog *blocklog.Service
}

// NewFirewallHandler instancia o handler do firewall por zonas.
func NewFirewallHandler(db *storage.DB, fr *firewallrules.Service, nft *nftables.Service) *FirewallHandler {
	return &FirewallHandler{
		db:  db,
		fr:  fr,
		nft: nft,
	}
}

// WithBlockLog configura o serviço de blocklog no FirewallHandler.
func (h *FirewallHandler) WithBlockLog(bl *blocklog.Service) *FirewallHandler {
	h.blocklog = bl
	return h
}

func (h *FirewallHandler) pendingView(p *storage.PendingChange) *pendingView {
	if p == nil {
		return nil
	}
	v := &pendingView{
		ID:          p.ID,
		Summary:     p.Summary,
		AppliedBy:   p.AppliedBy,
		ExpiresAt:   p.ExpiresAt,
		SecondsLeft: h.fr.SecondsLeft(p),
		CreatedAt:   p.CreatedAt,
		Reverting:   p.Reverting(),
	}
	if p.Reverting() {
		at := p.RevertingAt
		v.RevertingAt = &at
	}
	return v
}

// EstadoView descreve a resposta do GET /api/firewall/estado.
type EstadoView struct {
	Pendente           bool                                   `json:"pendente"`
	NMudancas          int                                    `json:"n_mudancas"`
	Janela             *pendingView                           `json:"janela"`
	AplicadoEm         *time.Time                             `json:"aplicado_em"`
	AplicadoPor        string                                 `json:"aplicado_por"`
	UltimoErro         string                                 `json:"ultimo_erro"`
	Conversao          []firewallrules.ItemRelatorioConversao `json:"conversao"`
	BloqueiosAplicados bool                                   `json:"bloqueios_aplicados"`
}

// GetEstado responde com o estado corrente da configuração, pendências, janela e histórico.
func (h *FirewallHandler) GetEstado(w http.ResponseWriter, r *http.Request) {
	pendencias, err := h.fr.Pendencias(r.Context())
	if err != nil {
		writeInternalError(w, err)
		return
	}

	pendingChange, _ := h.db.GetPendingChange()
	janela := h.pendingView(pendingChange)

	aplicadoEmUnix, aplicadoPor, existe, _ := h.db.CarregarMetadadosAplicada()
	var aplicadoEm *time.Time
	if existe && aplicadoEmUnix > 0 {
		t := time.Unix(aplicadoEmUnix, 0).UTC()
		aplicadoEm = &t
	}

	var conversao []firewallrules.ItemRelatorioConversao
	if raw, err := h.db.GetSetting("fw_conversao_relatorio"); err == nil && raw != "" && raw != "null" {
		_ = json.Unmarshal([]byte(raw), &conversao)
	}

	res := EstadoView{
		Pendente:           pendencias.Pendente,
		NMudancas:          len(pendencias.Mudancas),
		Janela:             janela,
		AplicadoEm:         aplicadoEm,
		AplicadoPor:        aplicadoPor,
		UltimoErro:         h.fr.UltimoErro(),
		Conversao:          conversao,
		BloqueiosAplicados: existe,
	}

	writeJSON(w, http.StatusOK, res)
}

// EntendiConversao limpa o relatório de conversão persistido após confirmação do operador.
func (h *FirewallHandler) EntendiConversao(w http.ResponseWriter, r *http.Request) {
	if err := h.db.SetSetting("fw_conversao_relatorio", ""); err != nil {
		writeInternalError(w, err)
		return
	}
	auditAction(h.db, r, "fw.conversao.entendi", "firewall", "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// AjustesView expõe os ajustes de postura do firewall. RedesVCNExtras só sai
// na leitura: a escrita delas tem rota própria (PUT /api/firewall/aliases/sys:vcn/extras).
type AjustesView struct {
	AntiBloqueio        map[string]bool `json:"anti_bloqueio,omitempty"`
	RedesVCNExtras      []string        `json:"redes_vcn_extras,omitempty"`
	RegistrarBloqueados bool            `json:"registrar_bloqueados"`
	RegistrarDestinos   bool            `json:"registrar_destinos"`
	RegistrarPadrao     bool            `json:"registrar_padrao"`
	ContencaoBorda      bool            `json:"contencao_borda"`
}

// GetAjustes retorna as opções gerais de postura da configuração em edição.
func (h *FirewallHandler) GetAjustes(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.db.CarregarConfigEmEdicao()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	ab := make(map[string]bool)
	for z, v := range cfg.Ajustes.AntiBloqueio {
		ab[string(z)] = v
	}
	writeJSON(w, http.StatusOK, AjustesView{
		AntiBloqueio:        ab,
		RedesVCNExtras:      cfg.Ajustes.RedesVCNExtras,
		RegistrarBloqueados: cfg.Ajustes.RegistrarBloqueados,
		RegistrarDestinos:   cfg.Ajustes.RegistrarDestinos,
		RegistrarPadrao:     cfg.Ajustes.RegistrarPadrao,
		ContencaoBorda:      cfg.Ajustes.ContencaoBorda,
	})
}

// PutAjustes atualiza as opções de postura na configuração em edição.
func (h *FirewallHandler) PutAjustes(w http.ResponseWriter, r *http.Request) {
	var body AjustesView
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "corpo da requisição inválido")
		return
	}

	err := h.fr.EditarConfigValidando(r.Context(), actingUser(r), func(db *storage.DB) error {
		cfg, err := db.CarregarConfigEmEdicao()
		if err != nil {
			return err
		}
		ab := make(map[fwmodel.Zona]bool)
		for z, v := range body.AntiBloqueio {
			ab[fwmodel.Zona(z)] = v
		}
		novosAjustes := fwmodel.Ajustes{
			AntiBloqueio:        ab,
			RegistrarBloqueados: body.RegistrarBloqueados,
			RegistrarDestinos:   body.RegistrarDestinos,
			RegistrarPadrao:     body.RegistrarPadrao,
			ContencaoBorda:      body.ContencaoBorda,
			RedesVCNExtras:      cfg.Ajustes.RedesVCNExtras, // preserva extras
		}
		return db.SalvarAjustesFW(novosAjustes)
	}, "ajustes")

	if err != nil {
		writeGuardError(w, err)
		return
	}

	auditAction(h.db, r, "fw.ajustes", "firewall", "")
	writeJSON(w, http.StatusOK, body)
}
