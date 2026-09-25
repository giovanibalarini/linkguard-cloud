// Package saida vigia a saída desta máquina para a Internet.
//
// Numa caixa de NAT de nuvem a saída é uma só, e ela é a Internet de todas as
// instâncias que apontam a rota para cá. O monitor de link da versão on-prem
// fazia isto por link, amarrado a cada WAN cadastrada; sem links, a pergunta
// fica uma: daqui, a Internet responde?
//
// COMO MEDE. A cada intervalo, uma conexão TCP para cada alvo público (porta
// 443). Conexão estabelecida conta como resposta e dá a latência do handshake;
// falha ou prazo estourado conta como perda. TCP e não ICMP porque é o que o
// tráfego real usa, e porque um ICMP bloqueado no caminho não é Internet fora.
//
// QUANDO DIZ QUE CAIU. Uma verificação em que NENHUM alvo respondeu não basta:
// três seguidas, sim. Voltar exige duas seguidas com resposta. É a mesma
// histerese do monitor de link: um alerta crítico por causa de um pacote
// perdido treina quem opera a ignorar alerta crítico.
package saida

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	// Estados da saída.
	Desconhecida = "desconhecida"
	Online       = "online"
	Degradada    = "degradada"
	Offline      = "offline"

	falhasParaOffline   = 3     // verificações seguidas sem nenhuma resposta
	acertosParaOnline   = 2     // verificações seguidas com resposta
	perdaDegradada      = 25.0  // % acima disto: degradada
	latenciaDegradadaMs = 300.0 // média acima disto: degradada

	// Intervalo e prazo de cada conexão.
	Intervalo = 10 * time.Second
	prazo     = 5 * time.Second
)

// AlvosPadrao são resolvedores públicos de três operadores diferentes: a saída
// só é dada como fora quando os três somem juntos.
var AlvosPadrao = []string{"1.1.1.1", "8.8.8.8", "9.9.9.9"}

// Leitura é o último retrato da saída.
type Leitura struct {
	Estado       string    `json:"status"`
	LatenciaMs   float64   `json:"latency_ms"`
	PerdaPct     float64   `json:"loss_pct"`
	VerificadoEm time.Time `json:"checked_at"`
	Alvos        []string  `json:"targets"`
}

// Gravador é o pedaço do tsdb que a sonda usa.
type Gravador interface {
	Gauge(series, label string, v float64)
	State(kind, label, state string)
}

// Alertas é o pedaço do alerts.Service que a sonda usa.
type Alertas interface {
	SaidaOffline(detalhe string) error
	SaidaOnline(detalhe string) error
}

// Sonda mede a saída em intervalo fixo.
type Sonda struct {
	alvos    []string
	gravador Gravador
	alertas  Alertas
	// conectar é trocado nos testes; em produção abre TCP na 443.
	conectar func(ctx context.Context, host string) (time.Duration, error)

	mu      sync.Mutex
	atual   Leitura
	falhas  int
	acertos int
}

// Nova cria a sonda. gravador e alertas podem ser nil.
func Nova(gravador Gravador, alertas Alertas) *Sonda {
	return &Sonda{
		alvos:    AlvosPadrao,
		gravador: gravador,
		alertas:  alertas,
		conectar: conectarTCP,
		atual:    Leitura{Estado: Desconhecida, Alvos: AlvosPadrao},
	}
}

// Atual devolve o último retrato.
func (s *Sonda) Atual() Leitura {
	s.mu.Lock()
	defer s.mu.Unlock()
	l := s.atual
	l.Alvos = append([]string(nil), s.atual.Alvos...)
	return l
}

// Run verifica em intervalo fixo até o contexto acabar.
func (s *Sonda) Run(ctx context.Context) {
	t := time.NewTicker(Intervalo)
	defer t.Stop()
	s.Verificar(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Verificar(ctx)
		}
	}
}

// Verificar faz uma rodada: tenta cada alvo, resume e avança a máquina de
// estados. As conexões ficam FORA do lock; dentro dele só aritmética.
func (s *Sonda) Verificar(ctx context.Context) {
	type resultado struct {
		lat time.Duration
		ok  bool
	}
	res := make([]resultado, len(s.alvos))
	var wg sync.WaitGroup
	for i, alvo := range s.alvos {
		wg.Add(1)
		go func(i int, alvo string) {
			defer wg.Done()
			lat, err := s.conectar(ctx, alvo)
			res[i] = resultado{lat: lat, ok: err == nil}
		}(i, alvo)
	}
	wg.Wait()

	var soma time.Duration
	ok := 0
	for _, r := range res {
		if r.ok {
			ok++
			soma += r.lat
		}
	}
	perda := 100.0
	latencia := 0.0
	if len(res) > 0 {
		perda = float64(len(res)-ok) / float64(len(res)) * 100
	}
	if ok > 0 {
		latencia = float64(soma/time.Duration(ok)) / float64(time.Millisecond)
	}

	s.mu.Lock()
	anterior := s.atual.Estado
	novo := s.avancar(ok > 0, perda, latencia, anterior)
	s.atual = Leitura{Estado: novo, LatenciaMs: latencia, PerdaPct: perda, VerificadoEm: time.Now(), Alvos: s.alvos}
	s.mu.Unlock()

	if s.gravador != nil {
		s.gravador.Gauge("saida.latency_ms", "internet", latencia)
		s.gravador.Gauge("saida.loss_pct", "internet", perda)
		s.gravador.State("saida", "internet", novo)
	}
	s.avisar(anterior, novo)
}

// avancar é a máquina de estados; chamada sob o lock.
func (s *Sonda) avancar(alcancou bool, perda, latencia float64, anterior string) string {
	if !alcancou {
		s.falhas++
		s.acertos = 0
	} else {
		s.falhas = 0
		s.acertos++
	}
	switch {
	case s.falhas >= falhasParaOffline:
		return Offline
	case alcancou && (perda > perdaDegradada || latencia > latenciaDegradadaMs):
		return Degradada
	case s.acertos >= acertosParaOnline:
		return Online
	}
	if anterior == "" {
		return Desconhecida
	}
	return anterior
}

// avisar abre o alerta na queda e fecha na volta. Degradada não alerta: é a
// Internet lenta, não a Internet fora, e o painel já mostra.
func (s *Sonda) avisar(anterior, novo string) {
	if s.alertas == nil || anterior == novo {
		return
	}
	detalhe := strings.Join(s.alvos, ", ")
	switch {
	case novo == Offline:
		if err := s.alertas.SaidaOffline(detalhe); err != nil {
			slog.Warn("saída: não foi possível abrir o alerta de queda", "err", err)
		}
	case anterior == Offline && (novo == Online || novo == Degradada):
		if err := s.alertas.SaidaOnline(detalhe); err != nil {
			slog.Warn("saída: não foi possível avisar a volta", "err", err)
		}
	}
}

func conectarTCP(ctx context.Context, host string) (time.Duration, error) {
	d := net.Dialer{Timeout: prazo}
	inicio := time.Now()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		return 0, fmt.Errorf("conectar em %s: %w", host, err)
	}
	lat := time.Since(inicio)
	conn.Close()
	return lat, nil
}
