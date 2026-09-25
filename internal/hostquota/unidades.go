package hostquota

import (
	"fmt"
	"time"
)

// Formatação e ciclo mensal. Moravam no linkquota (a cota por link WAN), que
// saiu da versão cloud junto com o multi-WAN; a cota por aparelho ficou, e
// estas são as peças que ela usava de lá.

const (
	// bytesPerMB é DECIMAL (10^6), como bytesPerGB e como na fatura.
	bytesPerMB = 1_000_000.0

	// maxCycleDay é 28 porque todo mês tem dia 28. Fechamento em 29, 30 ou 31
	// simplesmente não existe em fevereiro, e a alternativa (deslizar para o
	// último dia do mês) faria o ciclo mudar de tamanho e o admin não
	// conseguir prever quando ele vira.
	maxCycleDay = 28
)

// humanBytes escreve o consumo na unidade que ele tem. Uma cota de 500 MB
// receberia um alerta "0.3 GB de 0.5 GB", que não informa nada.
func humanBytes(b float64) string {
	switch {
	case b >= bytesPerGB:
		return fmt.Sprintf("%.1f GB", b/bytesPerGB)
	case b >= bytesPerMB:
		return fmt.Sprintf("%.1f MB", b/bytesPerMB)
	default:
		return fmt.Sprintf("%.0f KB", b/1000)
	}
}

// humanGB formata a franquia declarada, que vem em GB decimais e pode ser
// fracionária (0,5 GB = 500 MB).
func humanGB(gb float64) string {
	return humanBytes(gb * bytesPerGB)
}

// inicioDoCicloMensal devolve meia-noite local do dia `day` deste mês, se já
// passou; do mês anterior, se ainda não. Hora LOCAL porque o ciclo que o admin
// lê na fatura é o do fuso dele.
func inicioDoCicloMensal(now time.Time, day int) time.Time {
	if day < 1 {
		day = 1
	}
	if day > maxCycleDay {
		day = maxCycleDay
	}
	start := time.Date(now.Year(), now.Month(), day, 0, 0, 0, 0, now.Location())
	if now.Before(start) {
		start = start.AddDate(0, -1, 0)
	}
	return start
}
