package nftables

import (
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-cloud/internal/fwmodel"
)

// O renderizador é quem monta o `nft -f`: o que vem do banco para dentro do
// script é validado aqui, e a falha é erro — nunca um script parcial.
func TestRenderZonas_PessoaComDadoInvalidoNaoGeraScript(t *testing.T) {
	casos := map[string]PessoaVPN{
		"porta não numérica":      {UserID: "u-1", Usuario: "ana", Endereco: "10.7.0.2", Portas: "22, abc"},
		"porta fora do intervalo": {UserID: "u-1", Usuario: "ana", Endereco: "10.7.0.2", Portas: "99999"},
		"faixa invertida":         {UserID: "u-1", Usuario: "ana", Endereco: "10.7.0.2", Portas: "90-80"},
		"injeção em portas":       {UserID: "u-1", Usuario: "ana", Endereco: "10.7.0.2", Portas: "22 } accept #"},
		"endereço inválido":       {UserID: "u-1", Usuario: "ana", Endereco: "10.7.0.2; flush ruleset", Total: true},
		"endereço vazio":          {UserID: "u-1", Usuario: "ana", Endereco: "", Total: true},
		"id com aspas":            {UserID: `u-1" accept #`, Usuario: "ana", Endereco: "10.7.0.2", Total: true},
	}
	for nome, p := range casos {
		t.Run(nome, func(t *testing.T) {
			rs, err := RenderZonas(
				fwmodel.Config{Formato: 1, Ajustes: fwmodel.AjustesPadrao()},
				Insumos{PortasGerencia: []int{22}, RedeVPN: "10.7.0.0/24", PortaWireGuard: 51820, Pessoas: []PessoaVPN{p}},
			)
			if err == nil {
				t.Fatalf("devia recusar; script:\n%s", rs.Script)
			}
			if rs.Script != "" {
				t.Fatal("erro não pode vir com script parcial")
			}
		})
	}
}

func TestRenderZonas_PortasDaPessoaValidasPassam(t *testing.T) {
	rs, err := RenderZonas(
		fwmodel.Config{Formato: 1, Ajustes: fwmodel.AjustesPadrao(), Aliases: []fwmodel.Alias{
			{ID: "hg-1", Nome: "k3s", Tipo: fwmodel.AliasTipoEnderecos, Itens: []string{"10.0.0.5"}},
		}},
		Insumos{PortasGerencia: []int{22}, RedeVPN: "10.7.0.0/24", PortaWireGuard: 51820, Pessoas: []PessoaVPN{
			{UserID: "u-1", Usuario: "ana", Endereco: "10.7.0.2", Aliases: []string{"hg-1"}, Portas: "22, 443,8000-8010"},
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rs.Script, "tcp dport { 22, 443, 8000-8010 }") {
		t.Fatalf("portas normalizadas ausentes:\n%s", rs.Script)
	}
}
