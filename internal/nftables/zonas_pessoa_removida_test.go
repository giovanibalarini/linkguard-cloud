package nftables

import (
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-cloud/internal/fwmodel"
)

func regraComPessoa(id string, pos int, origem, destino fwmodel.Ponta) fwmodel.Regra {
	return fwmodel.Regra{
		ID: id, Zona: fwmodel.ZonaVPN, Posicao: pos, Ativa: true, Acao: fwmodel.AcaoAccept,
		Origem: origem, Destino: destino,
		PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaQualquer},
	}
}

// Revogar uma VPN remove o peer; a regra que apontava para essa pessoa não
// pode travar o firewall inteiro, porque é justamente a revogação que precisa
// chegar às regras.
func TestRenderZonas_RegraDePessoaRemovidaSaiComAviso(t *testing.T) {
	qualquer := fwmodel.Ponta{Tipo: fwmodel.PontaQualquer}
	fantasma := fwmodel.Ponta{Tipo: fwmodel.PontaAlias, Valor: fwmodel.AliasPessoaPref + "u-fantasma"}
	c := fwmodel.Config{
		Formato: 1,
		Regras: []fwmodel.Regra{
			regraComPessoa("r-origem", 0, fantasma, qualquer),
			regraComPessoa("r-destino", 1, qualquer, fantasma),
			regraComPessoa("r-normal", 2, qualquer, qualquer),
		},
		Ajustes: fwmodel.AjustesPadrao(),
	}

	rs, err := RenderZonas(c, Insumos{PortasGerencia: []int{22}})
	if err != nil {
		t.Fatalf("a pessoa removida não pode impedir o render: %v", err)
	}
	if strings.Contains(rs.Script, "fantasma") {
		t.Fatalf("o script não pode citar a pessoa removida:\n%s", rs.Script)
	}
	if len(rs.Avisos) != 2 {
		t.Fatalf("um aviso por regra descartada; veio %+v", rs.Avisos)
	}
	for _, a := range rs.Avisos {
		if a.Severidade != "aviso" || a.Chave != "fwz.aviso.regraPessoaRemovida" {
			t.Fatalf("aviso inesperado: %+v", a)
		}
	}

	comTudo, err := RenderZonas(fwmodel.Config{
		Formato: 1,
		Regras:  []fwmodel.Regra{regraComPessoa("r-normal", 2, qualquer, qualquer)},
		Ajustes: fwmodel.AjustesPadrao(),
	}, Insumos{PortasGerencia: []int{22}})
	if err != nil {
		t.Fatal(err)
	}
	if rs.Script != comTudo.Script || rs.HashEntrada != comTudo.HashEntrada {
		t.Fatal("descartar as regras órfãs deve dar o mesmo ruleset de quem nunca as teve")
	}
}

// A regra volta a valer se a pessoa reaparecer, e a config armazenada não é
// tocada: o descarte vale só para o render.
func TestRenderZonas_RegraDePessoaPresenteContinua(t *testing.T) {
	qualquer := fwmodel.Ponta{Tipo: fwmodel.PontaQualquer}
	c := fwmodel.Config{
		Formato: 1,
		Regras: []fwmodel.Regra{regraComPessoa("r1", 0,
			fwmodel.Ponta{Tipo: fwmodel.PontaAlias, Valor: fwmodel.AliasPessoaPref + "u-1"}, qualquer)},
		Ajustes: fwmodel.AjustesPadrao(),
	}
	in := Insumos{PortasGerencia: []int{22}, RedeVPN: "10.7.0.0/24", PortaWireGuard: 51820,
		Pessoas: []PessoaVPN{{UserID: "u-1", Usuario: "ana", Total: true, Endereco: "10.7.0.2"}}}

	rs, err := RenderZonas(c, in)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Avisos) != 0 || !strings.Contains(rs.Script, "10.7.0.2") {
		t.Fatalf("avisos=%+v\n%s", rs.Avisos, rs.Script)
	}
	if len(c.Regras) != 1 {
		t.Fatal("o render não pode alterar a config recebida")
	}
}
