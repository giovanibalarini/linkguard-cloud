package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/giovanibalarini/linkguard-cloud/internal/fwmodel"
)

// RegistroEntryView descreve um evento de descarte ou registro de tráfego com contexto resolvido.
type RegistroEntryView struct {
	Time      string            `json:"time"`
	Tipo      string            `json:"tipo"` // regra | travada | padrao | legado
	Chave     string            `json:"chave"`
	Zona      string            `json:"zona,omitempty"`
	Acao      string            `json:"acao,omitempty"`
	Descricao string            `json:"descricao,omitempty"`
	DescChave string            `json:"desc_chave,omitempty"`
	DescVars  map[string]string `json:"desc_vars,omitempty"`
	In        string            `json:"in"`
	Out       string            `json:"out"`
	Src       string            `json:"src"`
	Dst       string            `json:"dst"`
	Proto     string            `json:"proto"`
	SPort     string            `json:"sport"`
	DPort     string            `json:"dport"`
}

// GetRegistro devolve os registros recentes de tráfego/descartes do firewall com as regras resolvidas.
func (h *FirewallHandler) GetRegistro(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if limStr := r.URL.Query().Get("limit"); limStr != "" {
		if n, err := strconv.Atoi(limStr); err == nil && n > 0 {
			limit = n
		}
	}
	q := r.URL.Query().Get("q")

	if h.blocklog == nil {
		writeJSON(w, http.StatusOK, map[string]any{"entradas": []RegistroEntryView{}})
		return
	}

	entries, err := h.blocklog.Recent(r.Context(), limit, q)
	if err != nil {
		writeInternalError(w, err)
		return
	}

	// Carrega a configuração aplicada para resolver os 12 hex da regra
	cfgAplicada, _, _ := h.db.CarregarConfigAplicada()
	regras12Hex := make(map[string]fwmodel.Regra)
	for _, reg := range cfgAplicada.Regras {
		clean := strings.ToLower(strings.ReplaceAll(reg.ID, "-", ""))
		if len(clean) > 12 {
			clean = clean[:12]
		}
		regras12Hex[clean] = reg
	}

	res := make([]RegistroEntryView, 0, len(entries))
	for _, e := range entries {
		v := RegistroEntryView{
			Time:  e.Time,
			Tipo:  e.Tipo,
			Chave: e.Chave,
			In:    e.In,
			Out:   e.Out,
			Src:   e.Src,
			Dst:   e.Dst,
			Proto: e.Proto,
			SPort: e.SPort,
			DPort: e.DPort,
		}

		switch e.Tipo {
		case "regra":
			if reg, ok := regras12Hex[e.Chave]; ok {
				v.Zona = string(reg.Zona)
				v.Acao = string(reg.Acao)
				v.Descricao = reg.Descricao
			} else {
				v.DescChave = "fwz.registro.regraDesconhecida"
				v.DescVars = map[string]string{"chave": e.Chave}
			}
		case "travada":
			switch e.Chave {
			case "hosts":
				v.DescChave = "fw.travada.hosts_bloqueados"
				v.Acao = "drop"
			case "destinos":
				v.DescChave = "fw.travada.destinos_bloqueados"
				v.Acao = "drop"
			case "dns", "dns-vpn":
				v.DescChave = "fw.travada.dns_vpn"
				v.Acao = "accept"
			default:
				v.DescChave = "fw.travada." + e.Chave
				v.Acao = "drop"
			}
		case "padrao":
			parts := strings.Split(e.Chave, ":")
			if len(parts) == 2 {
				v.Zona = parts[0]
				v.DescChave = fmt.Sprintf("fw.padrao.%s_%s", parts[0], parts[1])
			} else {
				v.DescChave = "fw.padrao." + e.Chave
			}
			v.Acao = "drop"
		case "legado":
			if e.Chave == "host" {
				v.DescChave = "fw.travada.hosts_bloqueados"
			} else {
				v.DescChave = "fw.travada.destinos_bloqueados"
			}
			v.Acao = "drop"
		}

		res = append(res, v)
	}

	writeJSON(w, http.StatusOK, map[string]any{"entradas": res})
}
