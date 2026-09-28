package fwmodel

import (
	"encoding/json"
	"testing"
)

func clonarConfig(t *testing.T, c Config) Config {
	t.Helper()
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var out Config
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func comAlias(t *testing.T, c Config, a Alias) Config {
	t.Helper()
	out := clonarConfig(t, c)
	for i := range out.Aliases {
		if out.Aliases[i].ID == a.ID {
			out.Aliases[i] = a
			return out
		}
	}
	out.Aliases = append(out.Aliases, a)
	return out
}

func comRegra(t *testing.T, c Config, r Regra) Config {
	t.Helper()
	out := clonarConfig(t, c)
	for i := range out.Regras {
		if out.Regras[i].ID == r.ID {
			out.Regras[i] = r
			return out
		}
	}
	out.Regras = append(out.Regras, r)
	return out
}

func comEncaminhamento(t *testing.T, c Config, e Encaminhamento) Config {
	t.Helper()
	out := clonarConfig(t, c)
	for i := range out.Encaminhamentos {
		if out.Encaminhamentos[i].ID == e.ID {
			out.Encaminhamentos[i] = e
			return out
		}
	}
	out.Encaminhamentos = append(out.Encaminhamentos, e)
	return out
}

func TestProblemasDaMudancaSemMudancaNaoTemProblema(t *testing.T) {
	c := configBaseValida()
	if ps := ProblemasDaMudanca(c, c, nil); len(ps) != 0 {
		t.Fatalf("config válida sem mudança não devia ter problema, obteve %+v", ps)
	}
}

func TestProblemasDaMudancaRecusaObjetoNovoInvalido(t *testing.T) {
	antes := configBaseValida()
	depois := comAlias(t, antes, Alias{ID: "al-ruim", Nome: "ruim", Tipo: AliasTipoEnderecos, Itens: []string{"abc"}})

	ps := ProblemasDaMudanca(antes, depois, nil, "alias:al-ruim")
	if len(ps) == 0 {
		t.Fatal("um alias com item 'abc' devia ser recusado")
	}
	for _, p := range ps {
		if p.Severidade != "erro" {
			t.Errorf("só erros bloqueiam; veio %+v", p)
		}
		if p.Onde != "alias:al-ruim" {
			t.Errorf("o problema devia apontar o alias, veio %+v", p)
		}
	}
}

func TestProblemasDaMudancaIgnoraAvisos(t *testing.T) {
	antes := configBaseValida()
	// Origem sys:vcn na aba VPN é só aviso.
	depois := comRegra(t, antes, Regra{
		ID: "r-aviso", Zona: ZonaVPN, Posicao: 0, Ativa: true, Acao: AcaoAccept,
		Origem: Ponta{Tipo: PontaAlias, Valor: AliasVCN}, Destino: Ponta{Tipo: PontaQualquer},
		PortaDestino: Porta{Tipo: PortaQualquer},
	})

	if !hasAviso(Validar(depois, nil), "regra:r-aviso") {
		t.Fatal("premissa do teste: a regra devia gerar um aviso")
	}
	if ps := ProblemasDaMudanca(antes, depois, nil, "regra:r-aviso"); len(ps) != 0 {
		t.Fatalf("aviso não bloqueia a escrita, obteve %+v", ps)
	}
}

func hasAviso(ps []Problema, onde string) bool {
	for _, p := range ps {
		if p.Onde == onde && p.Severidade == "aviso" {
			return true
		}
	}
	return false
}

func TestProblemasDaMudancaNaoCulpaOOperadorPeloQueJaEstavaQuebrado(t *testing.T) {
	// Um alias que já estava ruim (veio de um banco antigo, de uma conversão)
	// não pode trancar a edição de outra regra.
	quebrada := comAlias(t, configBaseValida(), Alias{ID: "al-velho", Nome: "velho", Tipo: AliasTipoPortas, Itens: []string{"99999"}})
	depois := comRegra(t, quebrada, Regra{
		ID: "r-novo", Zona: ZonaInternet, Posicao: 1, Ativa: true, Acao: AcaoDrop,
		Origem: Ponta{Tipo: PontaQualquer}, Destino: Ponta{Tipo: PontaQualquer},
		PortaDestino: Porta{Tipo: PortaQualquer},
	})

	if !TemErro(Validar(quebrada, nil)) {
		t.Fatal("premissa do teste: a config de partida devia ter erro")
	}
	if ps := ProblemasDaMudanca(quebrada, depois, nil, "regra:r-novo"); len(ps) != 0 {
		t.Fatalf("o erro antigo do alias não é da mudança, obteve %+v", ps)
	}
}

func TestProblemasDaMudancaConsertarUmErroAntigoEPermitido(t *testing.T) {
	quebrada := comAlias(t, configBaseValida(), Alias{ID: "al-velho", Nome: "velho", Tipo: AliasTipoPortas, Itens: []string{"99999"}})
	consertada := comAlias(t, quebrada, Alias{ID: "al-velho", Nome: "velho", Tipo: AliasTipoPortas, Itens: []string{"9999"}})

	if ps := ProblemasDaMudanca(quebrada, consertada, nil, "alias:al-velho"); len(ps) != 0 {
		t.Fatalf("consertar o alias tem que passar, obteve %+v", ps)
	}
}

func TestProblemasDaMudancaObjetoEditadoTemQueFicarValidoMesmoJaEstandoRuim(t *testing.T) {
	// Salvar um alias que continua ruim é recusado, ainda que o erro "já
	// existisse": o objeto que o operador acabou de mexer tem que sair certo.
	quebrada := comAlias(t, configBaseValida(), Alias{ID: "al-velho", Nome: "velho", Tipo: AliasTipoPortas, Itens: []string{"99999"}})
	continua := comAlias(t, quebrada, Alias{ID: "al-velho", Nome: "velho", Tipo: AliasTipoPortas, Itens: []string{"99999"}, Descricao: "só mudei a descrição"})

	if ps := ProblemasDaMudanca(quebrada, continua, nil, "alias:al-velho"); len(ps) == 0 {
		t.Fatal("salvar o alias ainda inválido devia ser recusado")
	}
	// Sem apontar o objeto, o erro é antigo e passa.
	if ps := ProblemasDaMudanca(quebrada, continua, nil); len(ps) != 0 {
		t.Fatalf("sem objeto-alvo só valem os erros novos, obteve %+v", ps)
	}
}

func TestProblemasDaMudancaPegaOErroQueApareceEmOutroObjeto(t *testing.T) {
	// Trocar o tipo de um alias que uma regra usa quebra a REGRA, não o alias.
	antes := configBaseValida()
	depois := comAlias(t, antes, Alias{ID: "al-web", Nome: "servidores-web", Tipo: AliasTipoPortas, Itens: []string{"80"}})

	ps := ProblemasDaMudanca(antes, depois, nil, "alias:al-web")
	achou := false
	for _, p := range ps {
		if p.Onde == "regra:r-1" {
			achou = true
		}
	}
	if !achou {
		t.Fatalf("a regra r-1 usa o alias como destino e devia aparecer, obteve %+v", ps)
	}
}

func TestProblemasDaMudancaConflitoDeNATAoAtivar(t *testing.T) {
	antes := comEncaminhamento(t, configBaseValida(), Encaminhamento{
		ID: "nat-2", Nome: "outro", Ativo: false, Proto: "tcp", PortaExterna: 8080, IPDestino: "10.0.1.11", PortaDestino: 80,
	})
	depois := comEncaminhamento(t, antes, Encaminhamento{
		ID: "nat-2", Nome: "outro", Ativo: true, Proto: "tcp", PortaExterna: 8080, IPDestino: "10.0.1.11", PortaDestino: 80,
	})

	if ps := ProblemasDaMudanca(antes, depois, nil, "encaminhamento:nat-2"); len(ps) == 0 {
		t.Fatal("ativar um segundo DNAT na mesma porta externa devia ser recusado")
	}
}

func TestProblemasDaMudancaUsaAsPessoasInformadas(t *testing.T) {
	antes := configBaseValida()
	depois := comRegra(t, antes, Regra{
		ID: "r-pessoa", Zona: ZonaVPN, Posicao: 0, Ativa: true, Acao: AcaoAccept,
		Origem: Ponta{Tipo: PontaAlias, Valor: AliasPessoaPref + "user-1"}, Destino: Ponta{Tipo: PontaQualquer},
		PortaDestino: Porta{Tipo: PortaQualquer},
	})

	if ps := ProblemasDaMudanca(antes, depois, []string{"user-1"}, "regra:r-pessoa"); len(ps) != 0 {
		t.Fatalf("a pessoa existe, obteve %+v", ps)
	}
	if ps := ProblemasDaMudanca(antes, depois, nil, "regra:r-pessoa"); len(ps) == 0 {
		t.Fatal("pessoa desconhecida devia ser recusada")
	}
}
