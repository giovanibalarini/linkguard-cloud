package hosts

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestNomeCurtoFicaComOPrimeiroRotulo(t *testing.T) {
	for in, want := range map[string]string{
		"k3s-server-1.private.vcn.oraclevcn.com.": "k3s-server-1",
		"bastion.": "bastion",
		"":         "",
	} {
		if got := nomeCurto(in); got != want {
			t.Errorf("nomeCurto(%q) = %q, quero %q", in, got, want)
		}
	}
}

// O nome encontrado é gravado; quem não tem nome não é perguntado de novo a
// cada abertura da tela, e a tela nunca espera pela consulta.
func TestNomesResolveEmSegundoPlanoEGrava(t *testing.T) {
	var mu sync.Mutex
	gravados := map[string]string{}
	consultas := 0
	n := NovosNomes("", func(m map[string]string) error {
		mu.Lock()
		defer mu.Unlock()
		for k, v := range m {
			gravados[k] = v
		}
		return nil
	})
	n.consultar = func(_ context.Context, ip string) (string, error) {
		mu.Lock()
		consultas++
		mu.Unlock()
		if ip == "10.0.1.20" {
			return "k3s-server-1", nil
		}
		return "", errors.New("NXDOMAIN")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Run(ctx)

	n.Pedir([]string{"10.0.1.20", "10.0.1.99"})
	prazo := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		pronto := gravados["10.0.1.20"] == "k3s-server-1" && consultas >= 2
		mu.Unlock()
		if pronto {
			break
		}
		if time.Now().After(prazo) {
			t.Fatalf("o nome não foi resolvido e gravado: %v (consultas %d)", gravados, consultas)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Pedir de novo logo em seguida não consulta de novo: vale o cache.
	n.Pedir([]string{"10.0.1.20", "10.0.1.99"})
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if consultas != 2 {
		t.Errorf("perguntou de novo antes de o cache vencer: %d consultas", consultas)
	}
	if _, ok := gravados["10.0.1.99"]; ok {
		t.Error("gravou nome para quem não tem")
	}
}
