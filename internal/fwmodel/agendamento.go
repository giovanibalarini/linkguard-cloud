package fwmodel

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
)

var (
	reHHMM = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)

	diasValidos = map[string]bool{
		"mon": true, "tue": true, "wed": true, "thu": true,
		"fri": true, "sat": true, "sun": true,
	}

	// OrdemDias define a ordenação canônica dos dias da semana (segunda a domingo).
	OrdemDias = []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}
)

// NormalizeDays devolve as chaves de dia em ordem canônica ("mon,tue,..."),
// sem duplicatas. Uma chave desconhecida não é descartada: vai para o fim, em
// minúsculas e ordem alfabética, para a validação ainda enxergá-la. Descartá-la
// em silêncio faria "monday" virar "todos os dias".
func NormalizeDays(raw string) string {
	presentes := map[string]bool{}
	var desconhecidas []string
	for _, d := range strings.Split(raw, ",") {
		d = strings.ToLower(strings.TrimSpace(d))
		switch {
		case d == "":
		case diasValidos[d]:
			presentes[d] = true
		case !slices.Contains(desconhecidas, d):
			desconhecidas = append(desconhecidas, d)
		}
	}
	sort.Strings(desconhecidas)
	var out []string
	for _, d := range OrdemDias {
		if presentes[d] {
			out = append(out, d)
		}
	}
	return strings.Join(append(out, desconhecidas...), ",")
}

// ValidarDias confere se todas as entradas de dias na string CSV pertencem ao conjunto conhecido.
func ValidarDias(raw string) error {
	for _, d := range strings.Split(raw, ",") {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if !diasValidos[d] {
			return fmt.Errorf("dia inválido: %q", d)
		}
	}
	return nil
}

// ValidarHorario confere se início e fim são no formato HH:MM e se início != fim.
// Se nenhum for informado, a janela é considerada livre de horário e não gera erro.
func ValidarHorario(inicio, fim string) error {
	inicio = strings.TrimSpace(inicio)
	fim = strings.TrimSpace(fim)
	temInicio := inicio != ""
	temFim := fim != ""
	if temInicio != temFim {
		return fmt.Errorf("a janela precisa de hora de início E de fim")
	}
	if temInicio {
		if !reHHMM.MatchString(inicio) || !reHHMM.MatchString(fim) {
			return fmt.Errorf("horário inválido (use HH:MM)")
		}
		if inicio == fim {
			return fmt.Errorf("início e fim não podem ser o mesmo horário")
		}
	}
	return nil
}

// ValidarJanela valida conjuntamente dias e horário de um agendamento.
func ValidarJanela(dias, inicio, fim string) error {
	if err := ValidarHorario(inicio, fim); err != nil {
		return err
	}
	if err := ValidarDias(dias); err != nil {
		return err
	}
	return nil
}
