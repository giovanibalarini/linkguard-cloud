package fwmodel

import (
	"strings"
	"testing"
)

var idsPerigosos = []string{
	`a"b`,
	`a;b`,
	"a\nb",
	"a\rb",
	"abc\n",
	"a b",
	"a\tb",
	`a:b`,
	`a/b`,
	`a\b`,
	`a{b}`,
	`a@b`,
	`a.b`,
	`é`,
	`x"; flush ruleset; #`,
	"x\"\n flush ruleset\n#",
	strings.Repeat("a", MaxIDObjeto+1),
}

var idsSeguros = []string{
	"r1",
	"r-wan-gerencia",
	"ag-1a2b3c4d",
	"9b2f6f60-7f4d-4e0e-8a53-5f8c3a1d2b77",
	"R1_x",
	"_",
	"-",
	strings.Repeat("a", MaxIDObjeto),
}

func TestIDValido(t *testing.T) {
	for _, id := range idsSeguros {
		if !IDValido(id) {
			t.Errorf("IDValido(%q) = false, esperava true", id)
		}
	}
	for _, id := range append([]string{""}, idsPerigosos...) {
		if IDValido(id) {
			t.Errorf("IDValido(%q) = true, esperava false", id)
		}
	}
}

func temChave(ps []Problema, chave, onde string) bool {
	for _, p := range ps {
		if p.Severidade == "erro" && p.Chave == chave && p.Onde == onde {
			return true
		}
	}
	return false
}

func TestValidarRecusaIDInseguroEmTodosOsObjetos(t *testing.T) {
	casos := []struct {
		nome  string
		chave string
		onde  func(id string) string
		troca func(c *Config, id string)
	}{
		{"regra", "fwz.problema.regraIdInvalido", func(id string) string { return "regra:" + id },
			func(c *Config, id string) { c.Regras[0].ID = id }},
		{"alias", "fwz.problema.aliasIdInvalido", func(id string) string { return "alias:" + id },
			func(c *Config, id string) { c.Aliases[1].ID = id }},
		{"agendamento", "fwz.problema.agendamentoIdInvalido", func(id string) string { return "agendamento:" + id },
			func(c *Config, id string) { c.Agendamentos[0].ID = id }},
		{"encaminhamento", "fwz.problema.encaminhamentoIdInvalido", func(id string) string { return "encaminhamento:" + id },
			func(c *Config, id string) { c.Encaminhamentos[0].ID = id }},
	}

	for _, cs := range casos {
		for _, id := range idsPerigosos {
			cfg := configBaseValida()
			cs.troca(&cfg, id)
			ps := Validar(cfg, nil)
			if !temChave(ps, cs.chave, cs.onde(id)) {
				t.Errorf("%s com ID %q: esperava o erro %s, veio %+v", cs.nome, id, cs.chave, ps)
			}
		}
		for _, id := range idsSeguros {
			cfg := configBaseValida()
			cs.troca(&cfg, id)
			for _, p := range Validar(cfg, nil) {
				if strings.HasSuffix(p.Chave, "IdInvalido") {
					t.Errorf("%s com ID %q: não esperava %s", cs.nome, id, p.Chave)
				}
			}
		}
	}
}

func TestValidarIDVazioNaoViraIDInvalido(t *testing.T) {
	cfg := configBaseValida()
	cfg.Regras[0].ID = ""
	ps := Validar(cfg, nil)
	if !temChave(ps, "fwz.problema.regraIdVazio", "regra:") {
		t.Fatalf("esperava regraIdVazio, veio %+v", ps)
	}
	for _, p := range ps {
		if p.Chave == "fwz.problema.regraIdInvalido" {
			t.Fatalf("ID vazio não deve gerar também regraIdInvalido: %+v", ps)
		}
	}
}

func TestValidarMensagemDoIDInvalidoTemTamanhoLimitado(t *testing.T) {
	cfg := configBaseValida()
	cfg.Regras[0].ID = strings.Repeat("x", 5000)
	for _, p := range Validar(cfg, nil) {
		if p.Chave != "fwz.problema.regraIdInvalido" {
			continue
		}
		if n := len([]rune(p.Vars["id"])); n > MaxIDObjeto+1 {
			t.Fatalf("o ID devolvido na mensagem tem %d caracteres, esperava no máximo %d", n, MaxIDObjeto+1)
		}
		return
	}
	t.Fatal("não achou regraIdInvalido")
}
