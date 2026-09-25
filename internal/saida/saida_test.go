package saida

import (
	"context"
	"errors"
	"testing"
	"time"
)

type gravacao struct{ gauges, estados int }

func (g *gravacao) Gauge(string, string, float64) { g.gauges++ }
func (g *gravacao) State(string, string, string)  { g.estados++ }

type alertasFake struct{ quedas, voltas int }

func (a *alertasFake) SaidaOffline(string) error { a.quedas++; return nil }
func (a *alertasFake) SaidaOnline(string) error  { a.voltas++; return nil }

func sondaCom(responde func(host string) (time.Duration, error)) (*Sonda, *alertasFake, *gravacao) {
	g := &gravacao{}
	a := &alertasFake{}
	s := Nova(g, a)
	s.conectar = func(_ context.Context, host string) (time.Duration, error) { return responde(host) }
	return s, a, g
}

func semResposta(string) (time.Duration, error)    { return 0, errors.New("timeout") }
func respondeRapido(string) (time.Duration, error) { return 20 * time.Millisecond, nil }

// Uma verificação sem resposta não é queda: são precisas três seguidas. Um
// alerta crítico por causa de um pacote perdido ensina a ignorar alerta.
func TestSoTresVerificacoesSemRespostaViramQueda(t *testing.T) {
	s, a, _ := sondaCom(semResposta)
	ctx := context.Background()
	s.Verificar(ctx)
	s.Verificar(ctx)
	if s.Atual().Estado == Offline || a.quedas != 0 {
		t.Fatalf("caiu antes da terceira verificação: %+v quedas=%d", s.Atual(), a.quedas)
	}
	s.Verificar(ctx)
	if s.Atual().Estado != Offline || a.quedas != 1 {
		t.Fatalf("três sem resposta tinham de virar queda com UM alerta: %+v quedas=%d", s.Atual(), a.quedas)
	}
	s.Verificar(ctx)
	if a.quedas != 1 {
		t.Errorf("a queda continuada não pode repetir o alerta: %d", a.quedas)
	}
}

// Voltar exige duas verificações seguidas com resposta, e fecha o alerta.
func TestAVoltaFechaOAlerta(t *testing.T) {
	falhar := true
	s, a, _ := sondaCom(func(h string) (time.Duration, error) {
		if falhar {
			return semResposta(h)
		}
		return respondeRapido(h)
	})
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		s.Verificar(ctx)
	}
	falhar = false
	s.Verificar(ctx)
	if s.Atual().Estado != Offline {
		t.Fatalf("uma resposta só não é volta: %+v", s.Atual())
	}
	s.Verificar(ctx)
	if s.Atual().Estado != Online || a.voltas != 1 {
		t.Fatalf("duas respostas seguidas tinham de trazer a saída de volta: %+v voltas=%d", s.Atual(), a.voltas)
	}
}

// Um alvo fora e os outros respondendo não é Internet fora: é perda, e perda
// acima do limite é saída degradada, sem alerta crítico.
func TestUmAlvoForaEPerdaNaoQueda(t *testing.T) {
	s, a, g := sondaCom(func(h string) (time.Duration, error) {
		if h == "8.8.8.8" {
			return semResposta(h)
		}
		return respondeRapido(h)
	})
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		s.Verificar(ctx)
	}
	l := s.Atual()
	if l.Estado != Degradada {
		t.Fatalf("33%% de perda tinha de ser saída degradada: %+v", l)
	}
	if a.quedas != 0 {
		t.Errorf("perda parcial abriu alerta de queda")
	}
	if l.PerdaPct < 33 || l.PerdaPct > 34 {
		t.Errorf("perda = %.1f, quero ~33.3", l.PerdaPct)
	}
	if g.gauges == 0 || g.estados == 0 {
		t.Error("a sonda não gravou as séries")
	}
}

func TestAntesDeMedirAEstadoEDesconhecido(t *testing.T) {
	s := Nova(nil, nil)
	if s.Atual().Estado != Desconhecida {
		t.Fatalf("estado inicial = %q", s.Atual().Estado)
	}
}
