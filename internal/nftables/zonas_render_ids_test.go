package nftables

import (
	"testing"

	"github.com/giovanibalarini/linkguard-cloud/internal/fwmodel"
)

// Um ID com aspas ou quebra de linha, gravado por qualquer caminho (inclusive direto no banco),
// nunca pode chegar ao script que o nft executa como root.
func TestRenderZonas_IDInseguroNaoChegaAoScript(t *testing.T) {
	const injecao = "x\"\n flush ruleset\n#"

	base := func() fwmodel.Config {
		return fwmodel.Config{
			Formato: 1,
			Aliases: []fwmodel.Alias{
				{ID: "al-ok", Nome: "Servidores", Tipo: fwmodel.AliasTipoEnderecos, Itens: []string{"10.0.0.1"}},
			},
			Agendamentos: []fwmodel.Agendamento{
				{ID: "ag-ok", Nome: "Comercial", Dias: "mon", Inicio: "08:00", Fim: "18:00"},
			},
			Encaminhamentos: []fwmodel.Encaminhamento{
				{ID: "nat-ok", Nome: "Web", Ativo: true, Proto: "tcp", PortaExterna: 8080, IPDestino: "10.0.0.5", PortaDestino: 80},
			},
			Regras: []fwmodel.Regra{
				{
					ID: "r-ok", Zona: fwmodel.ZonaVCN, Ativa: true, Acao: fwmodel.AcaoAccept,
					Origem:       fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
					Destino:      fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
					PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaQualquer},
				},
			},
			Ajustes: fwmodel.AjustesPadrao(),
		}
	}
	insumos := Insumos{PortasGerencia: []int{22}}

	if _, err := RenderZonas(base(), insumos); err != nil {
		t.Fatalf("a configuração-base deveria renderizar: %v", err)
	}

	casos := map[string]func(c *fwmodel.Config){
		"regra":          func(c *fwmodel.Config) { c.Regras[0].ID = injecao },
		"alias":          func(c *fwmodel.Config) { c.Aliases[0].ID = injecao },
		"agendamento":    func(c *fwmodel.Config) { c.Agendamentos[0].ID = injecao },
		"encaminhamento": func(c *fwmodel.Config) { c.Encaminhamentos[0].ID = injecao },
	}
	for nome, troca := range casos {
		t.Run(nome, func(t *testing.T) {
			cfg := base()
			troca(&cfg)
			rs, err := RenderZonas(cfg, insumos)
			if err == nil {
				t.Fatal("esperava recusa do ID com aspas e quebra de linha")
			}
			if rs.Script != "" {
				t.Fatalf("nenhum script deveria sair de uma configuração recusada: %q", rs.Script)
			}
		})
	}
}
