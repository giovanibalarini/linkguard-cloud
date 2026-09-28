package nftables

import (
	"strings"
	"testing"
)

func TestScheduleVaziaNaoGeraCondicao(t *testing.T) {
	// Todo grupo criado antes desta feature tem os três campos vazios, e tem
	// de continuar saindo byte a byte como sempre saiu.
	s := Schedule{}
	if !s.Empty() {
		t.Error("janela vazia não foi reconhecida como vazia")
	}
	if len(s.Tokens()) != 0 {
		t.Errorf("janela vazia gerou condição: %v", s.Tokens())
	}
}

func TestScheduleHoraGeraFaixa(t *testing.T) {
	got := strings.Join(Schedule{Start: "22:00", End: "06:00"}.Tokens(), " ")
	if got != `meta hour "22:00"-"06:00"` {
		t.Errorf("condição de hora: %q", got)
	}
}

func TestScheduleDiasSaoCapitalizadosEmIngles(t *testing.T) {
	// Medido: com minúscula o nft recusa a regra inteira, e o grupo
	// simplesmente não entra no firewall.
	got := strings.Join(Schedule{Days: "mon,wed"}.Tokens(), " ")
	if got != `meta day { "Monday", "Wednesday" }` {
		t.Errorf("condição de dia: %q", got)
	}
}

func TestScheduleDiasSaemNaOrdemDaSemana(t *testing.T) {
	// A ordem do que o admin clicou não pode virar a ordem da regra: o texto
	// mudaria a cada edição sem mudança real nenhuma.
	got := strings.Join(Schedule{Days: "sun,mon,sat"}.Tokens(), " ")
	if got != `meta day { "Monday", "Saturday", "Sunday" }` {
		t.Errorf("ordem dos dias: %q", got)
	}
}

func TestSemanaInteiraNaoVirouCondicao(t *testing.T) {
	// Sete dias é o mesmo que dia nenhum: a condição nunca seria falsa, e só
	// deixaria a regra mais longa e mais difícil de ler.
	got := Schedule{Days: "mon,tue,wed,thu,fri,sat,sun"}.Tokens()
	if len(got) != 0 {
		t.Errorf("a semana inteira virou condição: %v", got)
	}
}

func TestOrdemCanonicaEhDiaDepoisHora(t *testing.T) {
	// É a ordem em que o nft reimprime. Fora dela, o texto guardado diverge do
	// lido de volta do kernel.
	got := strings.Join(Schedule{Days: "mon", Start: "08:00", End: "17:00"}.Tokens(), " ")
	if got != `meta day { "Monday" } meta hour "08:00"-"17:00"` {
		t.Errorf("ordem canônica: %q", got)
	}
}

func TestScheduleValidate(t *testing.T) {
	casos := []struct {
		nome string
		s    Schedule
		erro bool
	}{
		{"vazia", Schedule{}, false},
		{"faixa normal", Schedule{Start: "08:00", End: "17:00"}, false},
		{"faixa atravessando a meia-noite", Schedule{Start: "22:00", End: "06:00"}, false},
		{"só dias", Schedule{Days: "sat,sun"}, false},
		{"início sem fim", Schedule{Start: "22:00"}, true},
		{"fim sem início", Schedule{End: "06:00"}, true},
		{"hora fora do relógio", Schedule{Start: "25:00", End: "06:00"}, true},
		{"minuto inválido", Schedule{Start: "22:60", End: "06:00"}, true},
		{"formato errado", Schedule{Start: "22h", End: "06h"}, true},
		{"início igual ao fim", Schedule{Start: "22:00", End: "22:00"}, true},
		{"dia inventado", Schedule{Days: "seg"}, true},
	}
	for _, c := range casos {
		err := c.s.Validate()
		if (err != nil) != c.erro {
			t.Errorf("%s: erro=%v, queria erro=%v", c.nome, err, c.erro)
		}
	}
}
