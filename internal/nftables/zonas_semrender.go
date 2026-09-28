package nftables

import "github.com/giovanibalarini/linkguard-cloud/internal/fwmodel"

// LinhasSemRender lista as regras do admin de uma zona na ordem em que o
// firewall as avaliaria, sem o nft que cada uma geraria.
//
// É o que a tela mostra quando a configuração em edição não renderiza (um
// alias com item inválido, por exemplo): a lista de regras precisa continuar
// aberta para o operador conseguir consertar o que está quebrado, e o que ele
// edita são justamente as regras do admin. As linhas travadas, padrão e
// implícitas dependem do render e ficam de fora.
func LinhasSemRender(c fwmodel.Config, zona fwmodel.Zona) []Linha {
	regras, _ := coletarRegrasAdminDaZona(&contextoRender{config: c}, zona)
	linhas := make([]Linha, 0, len(regras))
	for _, r := range regras {
		linhas = append(linhas, Linha{
			Chave: "r:" + r.ID,
			Zona:  r.Zona,
			Tipo:  "admin",
			Regra: r,
			Nft:   []LinhaNft{},
		})
	}
	return linhas
}
