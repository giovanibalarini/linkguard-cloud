package handlers

import (
	"context"
	"net/http"
)

// O uplink na tela: por onde esta máquina sai para a Internet.
//
// SOMENTE LEITURA, e sem rota de escrita nenhuma: o que se muda aqui é a
// realidade da máquina (a VNIC, a rota default), não um registro.
type UplinkView struct {
	// Interface é a placa por onde esta máquina sai. "" quando não se sabe.
	Interface string `json:"interface"`
	// PathMTU é o que o CAMINHO suporta, não o que a placa anuncia. 0 =
	// desconhecido, e a tela tem de dizer "desconhecida" em vez de "0".
	PathMTU int `json:"path_mtu"`
	// Origem é "platform" (o IMDS do provedor confirmou), "kernel" (a placa da
	// rota default, quando a plataforma não respondeu) ou "none".
	Origem string `json:"source"`
	// Plataforma é o que a detecção diz ("oci", "onprem", "unknown"). É o que
	// permite ao operador contestar o veredito sem ler log.
	Plataforma string `json:"platform"`
}

// As três origens possíveis de um uplink.
const (
	UplinkOrigemPlataforma = "platform"
	UplinkOrigemKernel     = "kernel"
	UplinkOrigemNenhuma    = "none"
)

// UplinkHandler serve o uplink efetivo desta máquina.
//
// A FONTE ENTRA COMO FUNÇÃO, pelo mesmo motivo de SetFluxos e SetDomainRouting:
// quem sabe responder isto é cmd/linkguard-cloud, que tem o instantâneo da
// plataforma E o executor, e a camada HTTP não pode importar internal/platform
// para descobrir sozinha. Lida a cada requisição, nunca capturada no boot: a
// rota default pode mudar, e a tela tem de ver a mudança na próxima
// atualização.
type UplinkHandler struct {
	fonte func(context.Context) UplinkView
}

// NewUplinkHandler cria o handler. Fonte nil responde "não sei", que é o
// zero-value permissivo de sempre: um binário que esqueça de ligar a fonte
// mostra a tela sem o cartão, e não uma tela quebrada.
func NewUplinkHandler(fonte func(context.Context) UplinkView) *UplinkHandler {
	return &UplinkHandler{fonte: fonte}
}

func (h *UplinkHandler) Get(w http.ResponseWriter, r *http.Request) {
	if h.fonte == nil {
		writeJSON(w, http.StatusOK, UplinkView{Origem: UplinkOrigemNenhuma, Plataforma: "unknown"})
		return
	}
	writeJSON(w, http.StatusOK, h.fonte(r.Context()))
}
