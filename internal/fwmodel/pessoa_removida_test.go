package fwmodel

import "testing"

func TestSemRegrasDePessoaRemovida(t *testing.T) {
	pessoa := func(id string) Ponta { return Ponta{Tipo: PontaAlias, Valor: AliasPessoaPref + id} }
	c := Config{Formato: 1, Regras: []Regra{
		{ID: "a", Origem: pessoa("viva")},
		{ID: "b", Destino: pessoa("morta"), Descricao: "acesso da morta"},
		{ID: "c", Origem: Ponta{Tipo: PontaAlias, Valor: "alias-comum"}},
	}}

	got, avisos := SemRegrasDePessoaRemovida(c, []string{"viva"})
	if len(got.Regras) != 2 || got.Regras[0].ID != "a" || got.Regras[1].ID != "c" {
		t.Fatalf("regras mantidas: %+v", got.Regras)
	}
	if len(avisos) != 1 || avisos[0].Onde != "regra:b" || avisos[0].Vars["regra"] != "acesso da morta" {
		t.Fatalf("avisos: %+v", avisos)
	}
	if len(c.Regras) != 3 {
		t.Fatal("a config de entrada não pode mudar")
	}

	same, avisos := SemRegrasDePessoaRemovida(c, []string{"viva", "morta"})
	if len(same.Regras) != 3 || avisos != nil {
		t.Fatalf("todas presentes: %+v %+v", same.Regras, avisos)
	}
}
