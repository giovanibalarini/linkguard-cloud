package nftables

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// A caixa migrada do linkguard-fw: as quatro chains e o map existem. Saem
// todos, e as chains antes do map (mark_hosts consulta @host_wan).
func TestRemoverHerancaMultiWANApagaAsChainsAntesDoMap(t *testing.T) {
	e := &fakeReconcileExec{}
	n, err := NewService(e).RemoverHerancaMultiWAN(context.Background())
	if err != nil {
		t.Fatalf("RemoverHerancaMultiWAN: %v", err)
	}
	if n != 5 {
		t.Fatalf("removeu %d estruturas, quero 5", n)
	}
	var apagou []string
	for _, c := range e.executed {
		if strings.HasPrefix(c, "nft delete ") {
			apagou = append(apagou, strings.TrimPrefix(c, "nft delete "))
		}
	}
	want := []string{
		"chain inet linkguard mark_hosts",
		"chain inet linkguard conn_mark",
		"chain inet linkguard conn_mark_out",
		"chain inet linkguard output_mark",
		"map inet linkguard host_wan",
	}
	if strings.Join(apagou, "|") != strings.Join(want, "|") {
		t.Fatalf("apagou %v, quero %v nesta ordem", apagou, want)
	}
}

// A caixa nova: nada existe, nada é apagado, e nada é persistido à toa.
func TestRemoverHerancaMultiWANNaCaixaLimpaNaoFazNada(t *testing.T) {
	e := &fakeReconcileExec{readFailOn: func(string) error { return errors.New("No such file or directory") }}
	n, err := NewService(e).RemoverHerancaMultiWAN(context.Background())
	if err != nil || n != 0 {
		t.Fatalf("n=%d err=%v, quero 0 e nil", n, err)
	}
	if len(e.executed) != 0 {
		t.Fatalf("executou %v numa caixa limpa", e.executed)
	}
}

// Erro ao apagar algo que existe volta: a estrutura velha continua valendo.
func TestRemoverHerancaMultiWANDevolveErroDeApagar(t *testing.T) {
	e := &fakeReconcileExec{failOn: func(cmd string) error {
		if strings.Contains(cmd, "delete chain inet linkguard conn_mark") {
			return errors.New("Device or resource busy")
		}
		return nil
	}}
	if _, err := NewService(e).RemoverHerancaMultiWAN(context.Background()); err == nil {
		t.Fatal("o erro ao apagar conn_mark virou sucesso")
	}
}

func TestRemoverHerancaMultiWANEmDryRunNaoMexe(t *testing.T) {
	e := &fakeReconcileExec{dryRun: true}
	if n, err := NewService(e).RemoverHerancaMultiWAN(context.Background()); err != nil || n != 0 || len(e.executed) != 0 {
		t.Fatalf("dry-run mexeu: n=%d err=%v executou=%v", n, err, e.executed)
	}
}
