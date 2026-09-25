// Package netsvc define o modelo do DNS que o gateway oferece e a interface
// que o backend (unbound) implementa.
//
// Na versão de nuvem este pacote descreve SÓ o DNS. O DHCP e tudo o que
// dependia de uma LAN servida por ele (faixa, gateway, reservas, sufixo de
// domínio, redirecionamento da porta 53 da LAN) saiu em 25/09/2026: numa VCN
// quem entrega endereço e DNS às máquinas é a própria Oracle, e esse tráfego
// nem passa pelo gateway. O resolvedor que fica atende a VPN — é para ele que
// a configuração de cada peer aponta — e é a fonte do log de consultas, do
// bloqueio de domínios e do mapa endereço → nome (dnstap).
package netsvc

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
)

// Config é o que o admin edita na tela de DNS.
//
// A chave do banco continua sendo "netsvc_config": um banco que veio do
// linkguard-fw traz os campos de DHCP junto, e o JSON os ignora ao ler.
type Config struct {
	// Upstreams são os encaminhadores; vazio resolve recursivamente a partir
	// da raiz, sem depender de ninguém.
	Upstreams []string `json:"upstreams"`
	// LogQueries grava cada consulta no journal do unbound (a tela de
	// consultas lê de lá). Custa I/O num resolvedor movimentado.
	LogQueries bool `json:"log_queries"`
	// DNSTapEnabled entrega as RESPOSTAS ao coletor do produto, que é o que
	// monta o mapa endereço → nome da análise de tráfego. Opt-in pelo mesmo
	// motivo do log.
	DNSTapEnabled bool `json:"dnstap_enabled"`

	// ExtraListenAddresses/ExtraAccessNetworks são ligações de tempo de
	// execução de outros serviços do produto (hoje, o WireGuard). Nunca entram
	// no JSON gravado nem no backup: o provedor as deriva de novo antes de
	// cada geração.
	ExtraListenAddresses []string `json:"-"`
	ExtraAccessNetworks  []string `json:"-"`
}

// DefaultConfig é o resolvedor recursivo, sem log e sem dnstap.
func DefaultConfig() Config {
	return Config{Upstreams: []string{}}
}

// MaxUpstreams limita a lista de encaminhadores. O unbound aceita mais, mas
// acima disso a lista vira sintoma de erro de digitação, não de desenho.
const MaxUpstreams = 8

// ValidaConfig recusa, no lugar onde o valor entra, o que o unbound recusaria
// depois: encaminhador que não é endereço IP, repetido ou lista longa demais.
// A mensagem nomeia o valor culpado, porque a do unbound não nomeia.
func ValidaConfig(c Config) error {
	if len(c.Upstreams) > MaxUpstreams {
		return fmt.Errorf("no máximo %d servidores DNS de encaminhamento", MaxUpstreams)
	}
	seen := map[string]bool{}
	for _, raw := range c.Upstreams {
		addr, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("o servidor DNS de encaminhamento %q não é um endereço IP", raw)
		}
		if seen[addr.String()] {
			return fmt.Errorf("o servidor DNS de encaminhamento %s aparece duas vezes", addr)
		}
		seen[addr.String()] = true
	}
	return nil
}

// ConfigFile é um arquivo de configuração renderizado, para a prévia.
type ConfigFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// ApplyResult é o que uma aplicação relata além de "falhou ou não".
//
// Warnings existe porque "aplicou" e "tudo o que você configurou está valendo"
// são afirmações diferentes: um backend que descarta uma entrada ruim (um
// domínio inválido na lista de bloqueio) faz as duas divergirem. Cada aviso é
// uma frase pronta para a tela. Installed nomeia os pacotes que precisaram ser
// instalados para esta aplicação acontecer (vazio em toda aplicação depois da
// primeira).
type ApplyResult struct {
	Output    string   `json:"output,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
	Installed []string `json:"installed,omitempty"`
}

// PrereqError é uma aplicação que não aconteceu porque falta um
// pré-requisito da máquina: o pacote não está instalado e não pôde ser, ou o
// diretório da configuração não é gravável por este processo. A mensagem é
// para o admin, em português, e diz o que falta e como resolver. Nada é
// escrito nem recarregado quando ele volta.
type PrereqError struct {
	Msg string
}

func (e *PrereqError) Error() string { return e.Msg }

// Provider é o backend de DNS.
type Provider interface {
	// GenerateConfigs renderiza a configuração (função pura, para a prévia).
	GenerateConfigs(c Config, blockedDomains []string) ([]ConfigFile, error)
	// ReloadConfigs grava a configuração e recarrega o daemon.
	ReloadConfigs(ctx context.Context, c Config, blockedDomains []string) (ApplyResult, error)
}
