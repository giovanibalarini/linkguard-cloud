package metrics

import (
	"strings"
	"testing"
)

// As séries por aparelho (issue #118).
//
// A asserção que atravessa este arquivo é a mesma da regra escrita em
// exposicao.go: este dado identifica a rede do cliente, e por isso ele existe
// FORA do registro aberto do Prometheus — não filtrado na saída, mas ausente
// por construção.

func TestSeriesPorHostNaoEntramNoRegistroAberto(t *testing.T) {
	// O teste de exposicao.go já varre o registro aberto. Este afirma a outra
	// metade: o PorHost não é um Collector do client_golang, então não HÁ como
	// registrá-lo lá por engano.
	p := NovoPorHost()
	if _, ehCollector := any(p).(interface{ Describe(chan<- *struct{}) }); ehCollector {
		t.Error("PorHost virou um Collector: alguém pode registrá-lo no /metrics aberto")
	}
}

func TestExposicaoTemOsDoisSentidosEEhOrdenada(t *testing.T) {
	p := NovoPorHost()
	p.Registrar("10.0.1.10", "api", 200, 20)
	p.Registrar("10.0.1.9", "banco", 100, 10)

	out := p.Exposicao()
	for _, quer := range []string{
		`linkguard_host_rx_bytes_per_second{ip="10.0.1.9",nome="banco"} 100`,
		`linkguard_host_tx_bytes_per_second{ip="10.0.1.10",nome="api"} 20`,
		"# TYPE linkguard_host_rx_bytes_per_second gauge",
	} {
		if !strings.Contains(out, quer) {
			t.Errorf("falta na exposição: %q\n%s", quer, out)
		}
	}
	// Ordem estável: um coletor que recebe as séries em ordem diferente a cada
	// raspagem produz diff inútil em toda revisão de configuração.
	// E por endereço, não como texto.
	if strings.Index(out, `"10.0.1.9"`) > strings.Index(out, `"10.0.1.10"`) {
		t.Error("a exposição não está ordenada por endereço")
	}
}

func TestApelidoComAspaNaoCorrompeAExposicao(t *testing.T) {
	// Apelido é texto livre digitado pelo admin. Uma aspa ali quebraria o
	// formato e o coletor descartaria TODAS as séries — não só a linha ruim.
	p := NovoPorHost()
	p.Registrar("10.0.1.9", `TV da "sala"`+"\nfalsa", 1, 2)
	out := p.Exposicao()
	if strings.Contains(out, "\"sala\"") {
		t.Errorf("aspa não escapada na exposição:\n%s", out)
	}
	linhas := strings.Split(strings.TrimSpace(out), "\n")
	for _, l := range linhas {
		if strings.HasPrefix(l, "linkguard_host_") && strings.Count(l, "{") != 1 {
			t.Errorf("linha malformada: %q", l)
		}
	}
}

func TestMaquinaQueSaiuParaDePublicar(t *testing.T) {
	// Métrica que não morre é métrica que mente: uma máquina que saiu da rede
	// continuaria publicando o último valor para sempre, e o gráfico mostraria
	// uma linha reta perpétua onde deveria haver uma série que acaba.
	p := NovoPorHost()
	p.Registrar("10.0.1.9", "banco", 100, 10)
	p.Registrar("10.0.1.10", "api", 200, 20)

	p.Limpar(map[string]bool{"10.0.1.9": true})

	out := p.Exposicao()
	if strings.Contains(out, `"10.0.1.10"`) {
		t.Error("a máquina que saiu da rede continua publicando")
	}
	if !strings.Contains(out, `"10.0.1.9"`) {
		t.Error("a máquina presente sumiu junto")
	}
}
