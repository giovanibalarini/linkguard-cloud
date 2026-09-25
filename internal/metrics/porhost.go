package metrics

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
)

// Métricas por máquina, para o coletor do cliente (issue #118).
//
// A ISSUE PEDE ISTO NO /metrics, E ISSO NÃO PODE SER FEITO. O /metrics está
// registrado fora do grupo autenticado, e a suíte de validação exige que essa
// porta responda pela WAN — a proteção de entrada não pode fechá-la, porque
// fechar a porta do painel é tranca. Publicar IP, nome e consumo por máquina
// ali seria um endpoint público de inventário da rede do cliente.
//
// Não é hipótese: a mesma leitura que apontou isso mostrou que a #115 propõe
// permissão RBAC nova para VER esse dado na tela. O produto ficaria exigindo
// senha para mostrar o que já estaria publicando sem senha.
//
// A ENTREGA HONESTA É A INTENÇÃO DA ISSUE SEM O ENDEREÇO ERRADO: as séries por
// aparelho existem, em formato Prometheus, numa rota PRÓPRIA e AUTENTICADA por
// um token que o admin gera. O Prometheus do cliente raspa com bearer token, que
// é configuração de uma linha no scrape_config dele.
//
// E é opt-in: sem token configurado, a rota não existe. Um recurso que publica
// inventário não pode nascer ligado porque alguém atualizou o pacote.

// PorHost guarda o último valor conhecido de cada máquina, para render em
// formato de exposição do Prometheus.
//
// GUARDA, E NÃO COLETA: quem mede é o amostrador de #113, que já grava a série
// no RRD a cada dez segundos. Duplicar a medição aqui daria dois números para a
// mesma pergunta, que é como painéis passam a discordar entre si.
type PorHost struct {
	mu     sync.RWMutex
	linhas map[string]amostraHost
}

type amostraHost struct {
	rotulo string
	rx, tx float64
}

// NovoPorHost cria o registro.
func NovoPorHost() *PorHost {
	return &PorHost{linhas: map[string]amostraHost{}}
}

// Registrar guarda a última leitura de uma máquina, chaveada pelo IP.
//
// O rótulo é o que a tela chama de máquina — apelido, nome da instância ou o
// IP. Ele identifica, e é justamente por isso que esta rota é autenticada.
func (p *PorHost) Registrar(ip, rotulo string, rx, tx float64) {
	if ip == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.linhas[ip] = amostraHost{rotulo: rotulo, rx: rx, tx: tx}
}

// Limpar esquece as máquinas que não estão mais na lista.
//
// Sem isto, uma máquina que saiu da rede continuaria publicando o último valor
// para sempre — e um gráfico no Grafana mostraria uma linha reta perpétua onde
// deveria haver uma série que acaba. Métrica que não morre é métrica que mente.
func (p *PorHost) Limpar(vivos map[string]bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for ip := range p.linhas {
		if !vivos[ip] {
			delete(p.linhas, ip)
		}
	}
}

// Exposicao renderiza no formato de texto do Prometheus.
//
// Escrito à mão, e não com o registry do client_golang, por uma razão de
// segurança e não de gosto: o registry aberto é varrido por um teste que FALHA
// se qualquer série com identidade de máquina estiver nele. Registrar estas
// séries lá para depois filtrar na saída seria confiar num filtro; mantê-las
// fora do registry torna o vazamento impossível por construção.
func (p *PorHost) Exposicao() string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	ips := make([]string, 0, len(p.linhas))
	for ip := range p.linhas {
		ips = append(ips, ip)
	}
	// Por endereço, e não como texto: "10.0.1.9" antes de "10.0.1.10".
	sort.Slice(ips, func(i, j int) bool {
		a, errA := netip.ParseAddr(ips[i])
		b, errB := netip.ParseAddr(ips[j])
		if errA != nil || errB != nil {
			return ips[i] < ips[j]
		}
		return a.Less(b)
	})

	var b strings.Builder
	b.WriteString("# HELP linkguard_host_rx_bytes_per_second Consumo de descida por máquina.\n")
	b.WriteString("# TYPE linkguard_host_rx_bytes_per_second gauge\n")
	for _, ip := range ips {
		l := p.linhas[ip]
		fmt.Fprintf(&b, "linkguard_host_rx_bytes_per_second{ip=%q,nome=%q} %g\n", ip, escapar(l.rotulo), l.rx)
	}
	b.WriteString("# HELP linkguard_host_tx_bytes_per_second Consumo de subida por máquina.\n")
	b.WriteString("# TYPE linkguard_host_tx_bytes_per_second gauge\n")
	for _, ip := range ips {
		l := p.linhas[ip]
		fmt.Fprintf(&b, "linkguard_host_tx_bytes_per_second{ip=%q,nome=%q} %g\n", ip, escapar(l.rotulo), l.tx)
	}
	return b.String()
}

// escapar tira do rótulo o que quebraria o formato de exposição. Apelido é
// texto livre digitado pelo admin: uma aspa ou uma quebra de linha ali
// corromperia a resposta inteira, e o coletor descartaria TODAS as séries — não
// só a linha ruim.
func escapar(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}
