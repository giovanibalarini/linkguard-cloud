package hosttraffic

import (
	"context"
	"testing"

	"github.com/giovanibalarini/linkguard-cloud/internal/nftables"
)

const ipTeste = "192.168.3.50"

// dt<=0 é preocupação de TAXA — dividir por zero, ou por um número negativo
// depois de um passo de NTP para trás, corriqueiro numa caixa sem RTC logo
// depois do boot. A contabilidade de BYTES não precisa de dt para nada, e a
// guarda vazava para ela: um passo de relógio descartava o intervalo inteiro de
// cota de todos os endereços de uma vez.
func TestPassoDeRelogioParaTrasNaoApagaOsBytesDaCota(t *testing.T) {
	c := &contadoresFalso{dados: map[string]nftables.HostCounter{
		"192.168.3.50": {RxBytes: 1000},
	}}
	s := NewSampler(c, &vistosFalso{}, &gravadorFalso{})
	sink := novoSink()
	s.SetUsageSink(sink)

	s.SampleOnce(context.Background(), 100)
	c.dados = map[string]nftables.HostCounter{"192.168.3.50": {RxBytes: 51000}}
	s.SampleOnce(context.Background(), 95) // o NTP puxou o relógio para trás

	if got := sink.bytes[ipTeste]; got[0] != 50000 {
		t.Errorf("a cota recebeu %d bytes, queria 50000: um passo de relógio apagou a medição", got[0])
	}
}

// O ciclo a que um byte pertence é função do momento em que ele foi MEDIDO. O
// sink recebe o instante junto para o acumulador da cota poder decidir isso —
// ver internal/hostquota, seção O TEMPO.
func TestOSinkRecebeOInstanteDaMedicao(t *testing.T) {
	c := &contadoresFalso{dados: map[string]nftables.HostCounter{
		"192.168.3.50": {RxBytes: 1000},
	}}
	s := NewSampler(c, &vistosFalso{}, &gravadorFalso{})
	sink := novoSink()
	s.SetUsageSink(sink)

	s.SampleOnce(context.Background(), 100)
	c.dados = map[string]nftables.HostCounter{"192.168.3.50": {RxBytes: 2000}}
	s.SampleOnce(context.Background(), 110)

	ts := sink.instantes[ipTeste]
	if len(ts) != 1 || ts[0] != 110 {
		t.Errorf("o sink recebeu os instantes %v, queria [110]", ts)
	}
}
