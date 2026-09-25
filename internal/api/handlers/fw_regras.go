package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/giovanibalarini/linkguard-cloud/internal/fwmodel"
	"github.com/giovanibalarini/linkguard-cloud/internal/nftables"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

// LinhaView descreve a representação consumida pela tabela do painel web.
type LinhaView struct {
	Chave     string              `json:"chave"`
	Tipo      string              `json:"tipo"`
	Zona      fwmodel.Zona        `json:"zona"`
	Regra     fwmodel.Regra       `json:"regra"`
	Nomes     LinhaNomesView      `json:"nomes"`
	EditarEm  string              `json:"editar_em"`
	DescChave string              `json:"desc_chave"`
	DescVars  map[string]string   `json:"desc_vars,omitempty"`
	Contador  ContadorView        `json:"contador"`
	Mudanca   string              `json:"mudanca"`
	Nft       []nftables.LinhaNft `json:"nft"`
}

// LinhaNomesView resolve identificadores para nomes amigáveis na interface.
type LinhaNomesView struct {
	Origem      string `json:"origem"`
	Destino     string `json:"destino"`
	Porta       string `json:"porta"`
	Agendamento string `json:"agendamento"`
}

// ContadorView resume as métricas de pacotes e bytes medidos na regra aplicada.
type ContadorView struct {
	Pacotes uint64 `json:"pacotes"`
	Bytes   uint64 `json:"bytes"`
	Medido  bool   `json:"medido"`
}

// GetRegras devolve as linhas compiladas da zona solicitada com nomes resolvidos e contadores.
func (h *FirewallHandler) GetRegras(w http.ResponseWriter, r *http.Request) {
	zonaParam := r.URL.Query().Get("zona")
	if zonaParam == "" {
		zonaParam = string(fwmodel.ZonaInternet)
	}
	zona := fwmodel.Zona(zonaParam)

	valida := false
	for _, z := range fwmodel.Zonas {
		if z == zona {
			valida = true
			break
		}
	}
	if !valida {
		writeError(w, http.StatusBadRequest, "zona inválida")
		return
	}

	linhas, err := h.fr.Linhas(r.Context(), zona)
	if err != nil {
		writeInternalError(w, err)
		return
	}

	cfgEmEdicao, _ := h.db.CarregarConfigEmEdicao()
	cfgAplicada, _, _ := h.db.CarregarConfigAplicada()

	aliasNomes := map[string]string{
		fwmodel.AliasVCN:      "VCN",
		fwmodel.AliasVPN:      "VPN",
		fwmodel.AliasGerencia: "Gerência",
	}
	for _, a := range cfgEmEdicao.Aliases {
		aliasNomes[a.ID] = a.Nome
	}

	agendamentoNomes := make(map[string]string)
	for _, ag := range cfgEmEdicao.Agendamentos {
		agendamentoNomes[ag.ID] = ag.Nome
	}

	aplicadaMap := make(map[string]fwmodel.Regra)
	for _, reg := range cfgAplicada.Regras {
		aplicadaMap[reg.ID] = reg
	}

	linhasView := make([]LinhaView, 0, len(linhas))
	for _, l := range linhas {
		nomes := resolverNomesLinha(l.Regra, aliasNomes, agendamentoNomes)

		mudanca := ""
		if l.Tipo == "admin" {
			if ap, ok := aplicadaMap[l.Regra.ID]; !ok {
				mudanca = "nova"
			} else {
				// Compara a regra em edição com a aplicada
				regraNorm := l.Regra
				regraNorm.Posicao = 0
				apNorm := ap
				apNorm.Posicao = 0
				bEdicao, _ := json.Marshal(regraNorm)
				bAplicada, _ := json.Marshal(apNorm)
				if string(bEdicao) != string(bAplicada) {
					mudanca = "alterada"
				}
			}
		}

		nftList := l.Nft
		if nftList == nil {
			nftList = []nftables.LinhaNft{}
		}

		linhasView = append(linhasView, LinhaView{
			Chave:     l.Chave,
			Tipo:      l.Tipo,
			Zona:      l.Zona,
			Regra:     l.Regra,
			Nomes:     nomes,
			EditarEm:  l.EditarEm,
			DescChave: l.DescChave,
			DescVars:  l.DescVars,
			Contador: ContadorView{
				Pacotes: l.Pacotes,
				Bytes:   l.Bytes,
				Medido:  l.Medido,
			},
			Mudanca: mudanca,
			Nft:     nftList,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"zona":   zona,
		"linhas": linhasView,
	})
}

func resolverNomesLinha(r fwmodel.Regra, aliasNomes, agendamentoNomes map[string]string) LinhaNomesView {
	var nomes LinhaNomesView

	// Origem
	switch r.Origem.Tipo {
	case fwmodel.PontaQualquer:
		nomes.Origem = ""
	case fwmodel.PontaEste:
		nomes.Origem = "Este firewall"
	case fwmodel.PontaEndereco:
		nomes.Origem = r.Origem.Valor
	case fwmodel.PontaAlias:
		if nome, ok := aliasNomes[r.Origem.Valor]; ok {
			nomes.Origem = nome
		} else if strings.HasPrefix(r.Origem.Valor, fwmodel.AliasPessoaPref) {
			nomes.Origem = strings.TrimPrefix(r.Origem.Valor, fwmodel.AliasPessoaPref)
		} else {
			nomes.Origem = r.Origem.Valor
		}
	}

	// Destino
	switch r.Destino.Tipo {
	case fwmodel.PontaQualquer:
		nomes.Destino = ""
	case fwmodel.PontaEste:
		nomes.Destino = "Este firewall"
	case fwmodel.PontaEndereco:
		nomes.Destino = r.Destino.Valor
	case fwmodel.PontaAlias:
		if nome, ok := aliasNomes[r.Destino.Valor]; ok {
			nomes.Destino = nome
		} else if strings.HasPrefix(r.Destino.Valor, fwmodel.AliasPessoaPref) {
			nomes.Destino = strings.TrimPrefix(r.Destino.Valor, fwmodel.AliasPessoaPref)
		} else {
			nomes.Destino = r.Destino.Valor
		}
	}

	// Porta
	switch r.PortaDestino.Tipo {
	case fwmodel.PortaQualquer:
		nomes.Porta = ""
	case fwmodel.PortaValor:
		nomes.Porta = r.PortaDestino.Valor
	case fwmodel.PortaAlias:
		if nome, ok := aliasNomes[r.PortaDestino.Valor]; ok {
			nomes.Porta = nome
		} else {
			nomes.Porta = r.PortaDestino.Valor
		}
	}

	// Agendamento
	if r.AgendamentoID != "" {
		if nome, ok := agendamentoNomes[r.AgendamentoID]; ok {
			nomes.Agendamento = nome
		} else {
			nomes.Agendamento = r.AgendamentoID
		}
	}

	return nomes
}

// CriarRegra adiciona uma nova regra à configuração em edição.
func (h *FirewallHandler) CriarRegra(w http.ResponseWriter, r *http.Request) {
	var regra fwmodel.Regra
	if err := decodeJSON(r, &regra); err != nil {
		writeError(w, http.StatusBadRequest, "corpo da requisição inválido")
		return
	}

	if regra.ID == "" {
		regra.ID = uuid.NewString()
	}
	if regra.Zona == "" {
		regra.Zona = fwmodel.ZonaInternet
	}
	if regra.Acao == "" {
		regra.Acao = fwmodel.AcaoAccept
	}

	err := h.fr.EditarConfig(r.Context(), actingUser(r), func(db *storage.DB) error {
		return db.CriarRegraFW(&regra)
	})
	if err != nil {
		writeGuardError(w, err)
		return
	}

	auditAction(h.db, r, "fw.regra.criar", "firewall", regra.ID)
	writeJSON(w, http.StatusCreated, regra)
}

// AtualizarRegra modifica os campos de uma regra existente.
func (h *FirewallHandler) AtualizarRegra(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id da regra é obrigatório")
		return
	}

	var regra fwmodel.Regra
	if err := decodeJSON(r, &regra); err != nil {
		writeError(w, http.StatusBadRequest, "corpo da requisição inválido")
		return
	}
	regra.ID = id

	err := h.fr.EditarConfig(r.Context(), actingUser(r), func(db *storage.DB) error {
		return db.AtualizarRegraFW(regra)
	})
	if err != nil {
		writeGuardError(w, err)
		return
	}

	auditAction(h.db, r, "fw.regra.alterar", "firewall", id)
	writeJSON(w, http.StatusOK, regra)
}

// ApagarRegra remove uma regra da configuração em edição.
func (h *FirewallHandler) ApagarRegra(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id da regra é obrigatório")
		return
	}

	err := h.fr.EditarConfig(r.Context(), actingUser(r), func(db *storage.DB) error {
		return db.ApagarRegraFW(id)
	})
	if err != nil {
		writeGuardError(w, err)
		return
	}

	auditAction(h.db, r, "fw.regra.apagar", "firewall", id)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// AtivarRegra ativa ou desativa uma regra na configuração em edição.
func (h *FirewallHandler) AtivarRegra(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id da regra é obrigatório")
		return
	}

	var body struct {
		Ativa bool `json:"ativa"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "corpo da requisição inválido")
		return
	}

	err := h.fr.EditarConfig(r.Context(), actingUser(r), func(db *storage.DB) error {
		return db.AtivarRegraFW(id, body.Ativa)
	})
	if err != nil {
		writeGuardError(w, err)
		return
	}

	action := "fw.regra.desativar"
	if body.Ativa {
		action = "fw.regra.ativar"
	}
	auditAction(h.db, r, action, "firewall", id)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// DuplicarRegra clona uma regra existente, posicionando-a logo abaixo da original.
func (h *FirewallHandler) DuplicarRegra(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id da regra é obrigatório")
		return
	}

	var copia *fwmodel.Regra
	err := h.fr.EditarConfig(r.Context(), actingUser(r), func(db *storage.DB) error {
		var err error
		copia, err = db.DuplicarRegraFW(id)
		return err
	})
	if err != nil {
		writeGuardError(w, err)
		return
	}

	auditAction(h.db, r, "fw.regra.duplicar", "firewall", copia.ID)
	writeJSON(w, http.StatusCreated, copia)
}

// ReordenarRegras altera a ordem das regras de uma determinada zona.
func (h *FirewallHandler) ReordenarRegras(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Zona fwmodel.Zona `json:"zona"`
		IDs  []string     `json:"ids"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "corpo da requisição inválido")
		return
	}

	err := h.fr.EditarConfig(r.Context(), actingUser(r), func(db *storage.DB) error {
		return db.ReordenarRegrasFW(body.Zona, body.IDs)
	})
	if err != nil {
		writeGuardError(w, err)
		return
	}

	auditAction(h.db, r, "fw.regra.ordem", "firewall", string(body.Zona))
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// PreviaRegra avalia a regra e devolve os problemas de validação e comandos nftables correspondentes.
func (h *FirewallHandler) PreviaRegra(w http.ResponseWriter, r *http.Request) {
	var regra fwmodel.Regra
	if err := decodeJSON(r, &regra); err != nil {
		writeError(w, http.StatusBadRequest, "corpo da requisição inválido")
		return
	}

	nft, problemas, err := h.fr.PreviaRegra(r.Context(), regra)
	if err != nil {
		writeInternalError(w, fmt.Errorf("gerar prévia da regra: %w", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"nft":       nft,
		"problemas": problemas,
	})
}
