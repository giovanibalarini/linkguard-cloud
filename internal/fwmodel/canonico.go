package fwmodel

import (
	"encoding/json"
	"net"
	"sort"
	"strings"
)

// normalizarEndereco aplica máscara nos CIDR e remove /32 de IPs soltos.
// Exemplo: "10.0.1.20/32" -> "10.0.1.20", "10.0.1.7/24" -> "10.0.1.0/24".
func normalizarEndereco(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if strings.HasSuffix(addr, "/32") {
		addr = strings.TrimSuffix(addr, "/32")
	}
	if strings.Contains(addr, "/") {
		ip, netw, err := net.ParseCIDR(addr)
		if err == nil && netw != nil {
			ones, bits := netw.Mask.Size()
			if ones == 32 && bits == 32 && ip.To4() != nil {
				return ip.To4().String()
			}
			return netw.String()
		}
	}
	ip := net.ParseIP(addr)
	if ip != nil && ip.To4() != nil {
		return ip.To4().String()
	}
	return addr
}

// zonaIndice devolve o índice da zona na lista canônica Zonas.
func zonaIndice(z Zona) int {
	for i, zn := range Zonas {
		if zn == z {
			return i
		}
	}
	return len(Zonas)
}

// Normalizar produz uma cópia canônica da configuração:
// - Formato fixado em 1 se 0;
// - Máscaras aplicadas aos CIDRs e /32 removido de IPs soltos;
// - Dias de agendamento em ordem canônica;
// - Aliases, agendamentos e encaminhamentos ordenados por ID;
// - Regras ordenadas por (zona na ordem de Zonas, posicao) e renumeradas de 0..n-1 por zona;
// - Slices nil convertidas em slices vazias.
func Normalizar(c Config) Config {
	out := c

	if out.Formato == 0 {
		out.Formato = 1
	}

	// 1. Ajustes
	if out.Ajustes.AntiBloqueio == nil {
		out.Ajustes.AntiBloqueio = make(map[Zona]bool)
	} else {
		novoAntiBloqueio := make(map[Zona]bool, len(out.Ajustes.AntiBloqueio))
		for k, v := range out.Ajustes.AntiBloqueio {
			novoAntiBloqueio[k] = v
		}
		out.Ajustes.AntiBloqueio = novoAntiBloqueio
	}

	if out.Ajustes.RedesVCNExtras == nil {
		out.Ajustes.RedesVCNExtras = []string{}
	} else {
		extras := make([]string, len(out.Ajustes.RedesVCNExtras))
		for i, rede := range out.Ajustes.RedesVCNExtras {
			extras[i] = normalizarEndereco(rede)
		}
		sort.Strings(extras)
		out.Ajustes.RedesVCNExtras = extras
	}

	// 2. Aliases
	if out.Aliases == nil {
		out.Aliases = []Alias{}
	} else {
		aliases := make([]Alias, len(out.Aliases))
		for i, a := range out.Aliases {
			cp := a
			if cp.Itens == nil {
				cp.Itens = []string{}
			} else {
				itens := make([]string, len(cp.Itens))
				for j, item := range cp.Itens {
					if cp.Tipo == AliasTipoEnderecos {
						itens[j] = normalizarEndereco(item)
					} else {
						itens[j] = strings.TrimSpace(item)
					}
				}
				sort.Strings(itens)
				cp.Itens = itens
			}
			aliases[i] = cp
		}
		sort.Slice(aliases, func(i, j int) bool {
			return aliases[i].ID < aliases[j].ID
		})
		out.Aliases = aliases
	}

	// 3. Agendamentos
	if out.Agendamentos == nil {
		out.Agendamentos = []Agendamento{}
	} else {
		agends := make([]Agendamento, len(out.Agendamentos))
		for i, ag := range out.Agendamentos {
			cp := ag
			cp.Dias = NormalizeDays(cp.Dias)
			cp.Inicio = strings.TrimSpace(cp.Inicio)
			cp.Fim = strings.TrimSpace(cp.Fim)
			agends[i] = cp
		}
		sort.Slice(agends, func(i, j int) bool {
			return agends[i].ID < agends[j].ID
		})
		out.Agendamentos = agends
	}

	// 4. Encaminhamentos
	if out.Encaminhamentos == nil {
		out.Encaminhamentos = []Encaminhamento{}
	} else {
		encs := make([]Encaminhamento, len(out.Encaminhamentos))
		for i, enc := range out.Encaminhamentos {
			cp := enc
			cp.Proto = strings.ToLower(strings.TrimSpace(cp.Proto))
			cp.IPDestino = normalizarEndereco(cp.IPDestino)
			encs[i] = cp
		}
		sort.Slice(encs, func(i, j int) bool {
			return encs[i].ID < encs[j].ID
		})
		out.Encaminhamentos = encs
	}

	// 5. Regras
	if out.Regras == nil {
		out.Regras = []Regra{}
	} else {
		regras := make([]Regra, len(out.Regras))
		for i, r := range out.Regras {
			cp := r
			if cp.Origem.Tipo == PontaEndereco {
				cp.Origem.Valor = normalizarEndereco(cp.Origem.Valor)
			}
			if cp.Destino.Tipo == PontaEndereco {
				cp.Destino.Valor = normalizarEndereco(cp.Destino.Valor)
			}
			regras[i] = cp
		}

		// Ordena por (zona na ordem de Zonas, posicao, id)
		sort.Slice(regras, func(i, j int) bool {
			zi := zonaIndice(regras[i].Zona)
			zj := zonaIndice(regras[j].Zona)
			if zi != zj {
				return zi < zj
			}
			if regras[i].Posicao != regras[j].Posicao {
				return regras[i].Posicao < regras[j].Posicao
			}
			return regras[i].ID < regras[j].ID
		})

		// Renumera posições 0..n-1 por zona
		posContadores := make(map[Zona]int)
		for i := range regras {
			z := regras[i].Zona
			regras[i].Posicao = posContadores[z]
			posContadores[z]++
		}
		out.Regras = regras
	}

	return out
}

// Canonico devolve o JSON serializado da configuração normalizada.
// Duas configurações são funcionalmente idênticas se e somente se seus canônicos forem iguais.
func Canonico(c Config) []byte {
	norm := Normalizar(c)
	b, err := json.Marshal(norm)
	if err != nil {
		return nil
	}
	return b
}
