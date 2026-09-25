package nftables

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/giovanibalarini/linkguard-cloud/internal/fwmodel"
)

// Linha representa uma linha exibida na tabela da interface web (travada, do admin, padrão ou implícita)
// contendo a lista completa de regras nftables que ela gera no kernel.
type Linha struct {
	Chave     string            `json:"chave"` // comentário nft: "r:<uuid>", "s:...", "d:...", "b:..."
	Zona      fwmodel.Zona      `json:"zona"`
	Tipo      string            `json:"tipo"`       // "admin" | "travada" | "padrao" | "implicita"
	Regra     fwmodel.Regra     `json:"regra"`      // forma normalizada (para as travadas/padrões, sintetizada)
	EditarEm  string            `json:"editar_em"`  // "" | "vpn" | "nat" | "maquinas" | "destinos" | "ajustes"
	DescChave string            `json:"desc_chave"` // chave i18n da descrição das travadas/padrões/implícitas
	DescVars  map[string]string `json:"desc_vars,omitempty"`
	Nft       []LinhaNft        `json:"nft"` // cada regra nft que esta linha gera
	Pacotes   uint64            `json:"pacotes,omitempty"`
	Bytes     uint64            `json:"bytes,omitempty"`
	Medido    bool              `json:"medido,omitempty"`
}

// LinhaNft descreve uma regra individual emitida no nftables, sem o prefixo "add rule inet linkguard <chain>".
type LinhaNft struct {
	Chain string `json:"chain"`
	Texto string `json:"texto"`
}

type contextoRender struct {
	config         fwmodel.Config
	insumos        Insumos
	aliasMap       map[string]fwmodel.Alias
	aliasSetNames  map[string]string
	agendamentoMap map[string]fwmodel.Agendamento
	pessoaMap      map[string]PessoaVPN
}

// montarLinhasFlutuante gera as linhas da aba Flutuantes (implícitas do despachante, travadas e regras do admin).
func montarLinhasFlutuante(ctx *contextoRender) ([]Linha, []string, []string, error) {
	var linhas []Linha
	var regrasIn []string
	var regrasFwd []string

	// 1. Implícitas do despachante
	lEstado := Linha{
		Chave:     "b:estado",
		Zona:      fwmodel.ZonaFlutuante,
		Tipo:      "implicita",
		Regra:     fwmodel.Regra{ID: "b:estado", Zona: fwmodel.ZonaFlutuante, Ativa: true, Acao: fwmodel.AcaoAccept, Descricao: "Conexões estabelecidas e relacionadas"},
		DescChave: "fw.implicita.estado",
		Nft: []LinhaNft{
			{Chain: "input", Texto: "ct state established,related counter accept comment \"b:estado\""},
			{Chain: "forward", Texto: "ct state established,related counter accept comment \"b:estado\""},
		},
	}
	linhas = append(linhas, lEstado)

	lLo := Linha{
		Chave:     "b:lo",
		Zona:      fwmodel.ZonaFlutuante,
		Tipo:      "implicita",
		Regra:     fwmodel.Regra{ID: "b:lo", Zona: fwmodel.ZonaFlutuante, Ativa: true, Acao: fwmodel.AcaoAccept, Descricao: "Tráfego na interface de loopback"},
		DescChave: "fw.implicita.lo",
		Nft: []LinhaNft{
			{Chain: "input", Texto: "iif \"lo\" counter accept comment \"b:lo\""},
		},
	}
	linhas = append(linhas, lLo)

	lNd := Linha{
		Chave:     "b:nd",
		Zona:      fwmodel.ZonaFlutuante,
		Tipo:      "implicita",
		Regra:     fwmodel.Regra{ID: "b:nd", Zona: fwmodel.ZonaFlutuante, Ativa: true, Acao: fwmodel.AcaoAccept, Descricao: "Descoberta de vizinhança IPv6 (ND)"},
		DescChave: "fw.implicita.nd",
		Nft: []LinhaNft{
			{Chain: "input", Texto: "icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } counter accept comment \"b:nd\""},
		},
	}
	linhas = append(linhas, lNd)

	lDhcp := Linha{
		Chave:     "b:dhcp",
		Zona:      fwmodel.ZonaFlutuante,
		Tipo:      "implicita",
		Regra:     fwmodel.Regra{ID: "b:dhcp", Zona: fwmodel.ZonaFlutuante, Ativa: true, Acao: fwmodel.AcaoAccept, Proto: fwmodel.ProtoUDP, PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaValor, Valor: "68"}, Descricao: "Cliente DHCP IPv4"},
		DescChave: "fw.implicita.dhcp",
		Nft: []LinhaNft{
			{Chain: "input", Texto: "udp sport 67 udp dport 68 counter accept comment \"b:dhcp\""},
		},
	}
	linhas = append(linhas, lDhcp)

	lDhcp6 := Linha{
		Chave:     "b:dhcp6",
		Zona:      fwmodel.ZonaFlutuante,
		Tipo:      "implicita",
		Regra:     fwmodel.Regra{ID: "b:dhcp6", Zona: fwmodel.ZonaFlutuante, Ativa: true, Acao: fwmodel.AcaoAccept, Proto: fwmodel.ProtoUDP, PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaValor, Valor: "546"}, Descricao: "Cliente DHCP IPv6"},
		DescChave: "fw.implicita.dhcp6",
		Nft: []LinhaNft{
			{Chain: "input", Texto: "udp dport 546 counter accept comment \"b:dhcp6\""},
		},
	}
	linhas = append(linhas, lDhcp6)

	// 2. Travadas do topo de Flutuantes
	// s:hosts-bloqueados
	var nftHosts []LinhaNft
	if ctx.config.Ajustes.RegistrarBloqueados {
		nftHosts = append(nftHosts,
			LinhaNft{Chain: "forward", Texto: "ip saddr @blocked_hosts limit rate 10/second log prefix \"lg:s:hosts \""},
			LinhaNft{Chain: "forward", Texto: "ip saddr @blocked_hosts counter drop comment \"s:hosts-bloqueados\""},
			LinhaNft{Chain: "forward", Texto: "ip daddr @blocked_hosts limit rate 10/second log prefix \"lg:s:hosts \""},
			LinhaNft{Chain: "forward", Texto: "ip daddr @blocked_hosts counter drop comment \"s:hosts-bloqueados\""},
		)
	} else {
		nftHosts = append(nftHosts,
			LinhaNft{Chain: "forward", Texto: "ip saddr @blocked_hosts counter drop comment \"s:hosts-bloqueados\""},
			LinhaNft{Chain: "forward", Texto: "ip daddr @blocked_hosts counter drop comment \"s:hosts-bloqueados\""},
		)
	}
	lHosts := Linha{
		Chave:     "s:hosts-bloqueados",
		Zona:      fwmodel.ZonaFlutuante,
		Tipo:      "travada",
		Regra:     fwmodel.Regra{ID: "s:hosts-bloqueados", Zona: fwmodel.ZonaFlutuante, Ativa: true, Acao: fwmodel.AcaoDrop, Registrar: ctx.config.Ajustes.RegistrarBloqueados, Descricao: "Máquinas com bloqueio ativo"},
		EditarEm:  "maquinas",
		DescChave: "fw.travada.hosts_bloqueados",
		Nft:       nftHosts,
	}
	linhas = append(linhas, lHosts)

	// s:destinos-bloqueados
	var nftDestinos []LinhaNft
	if ctx.config.Ajustes.RegistrarDestinos {
		nftDestinos = append(nftDestinos,
			LinhaNft{Chain: "forward", Texto: "ip daddr @blocklist limit rate 10/second log prefix \"lg:s:destinos \""},
			LinhaNft{Chain: "forward", Texto: "ip daddr @blocklist counter drop comment \"s:destinos-bloqueados\""},
			LinhaNft{Chain: "forward", Texto: "ip saddr @blocklist limit rate 10/second log prefix \"lg:s:destinos \""},
			LinhaNft{Chain: "forward", Texto: "ip saddr @blocklist counter drop comment \"s:destinos-bloqueados\""},
			LinhaNft{Chain: "forward", Texto: "ip daddr @dom_blocked limit rate 10/second log prefix \"lg:s:destinos \""},
			LinhaNft{Chain: "forward", Texto: "ip daddr @dom_blocked counter drop comment \"s:destinos-bloqueados\""},
			LinhaNft{Chain: "forward", Texto: "ip6 daddr @dom_blocked6 limit rate 10/second log prefix \"lg:s:destinos \""},
			LinhaNft{Chain: "forward", Texto: "ip6 daddr @dom_blocked6 counter drop comment \"s:destinos-bloqueados\""},
		)
	} else {
		nftDestinos = append(nftDestinos,
			LinhaNft{Chain: "forward", Texto: "ip daddr @blocklist counter drop comment \"s:destinos-bloqueados\""},
			LinhaNft{Chain: "forward", Texto: "ip saddr @blocklist counter drop comment \"s:destinos-bloqueados\""},
			LinhaNft{Chain: "forward", Texto: "ip daddr @dom_blocked counter drop comment \"s:destinos-bloqueados\""},
			LinhaNft{Chain: "forward", Texto: "ip6 daddr @dom_blocked6 counter drop comment \"s:destinos-bloqueados\""},
		)
	}
	lDestinos := Linha{
		Chave:     "s:destinos-bloqueados",
		Zona:      fwmodel.ZonaFlutuante,
		Tipo:      "travada",
		Regra:     fwmodel.Regra{ID: "s:destinos-bloqueados", Zona: fwmodel.ZonaFlutuante, Ativa: true, Acao: fwmodel.AcaoDrop, Registrar: ctx.config.Ajustes.RegistrarDestinos, Descricao: "Destinos com bloqueio ativo"},
		EditarEm:  "destinos",
		DescChave: "fw.travada.destinos_bloqueados",
		Nft:       nftDestinos,
	}
	linhas = append(linhas, lDestinos)

	// s:ping (sempre em zona_flut_in)
	txtPing := "icmp type echo-request limit rate 5/second counter accept comment \"s:ping\""
	lPing := Linha{
		Chave:     "s:ping",
		Zona:      fwmodel.ZonaFlutuante,
		Tipo:      "travada",
		Regra:     fwmodel.Regra{ID: "s:ping", Zona: fwmodel.ZonaFlutuante, Ativa: true, Acao: fwmodel.AcaoAccept, Proto: fwmodel.ProtoICMP, Descricao: "Ping (ICMP echo-request com limite de taxa)"},
		EditarEm:  "",
		DescChave: "fw.travada.ping",
		Nft: []LinhaNft{
			{Chain: "zona_flut_in", Texto: txtPing},
		},
	}
	linhas = append(linhas, lPing)
	regrasIn = append(regrasIn, txtPing)

	// 3. Regras do admin para a zona flutuante
	regrasAdmin, err := coletarRegrasAdminDaZona(ctx, fwmodel.ZonaFlutuante)
	if err != nil {
		return nil, nil, nil, err
	}
	for _, ra := range regrasAdmin {
		linha, rIn, rFwd, err := montarRegraAdminLinha(ctx, ra, "zona_flut_in", "zona_flut_fwd")
		if err != nil {
			return nil, nil, nil, err
		}
		linhas = append(linhas, linha)
		regrasIn = append(regrasIn, rIn...)
		regrasFwd = append(regrasFwd, rFwd...)
	}

	return linhas, regrasIn, regrasFwd, nil
}

// montarLinhasInternet gera as linhas da aba Internet (contenção, wireguard, nat, admin, padrões).
func montarLinhasInternet(ctx *contextoRender) ([]Linha, []string, []string, []string, error) {
	var linhas []Linha
	var regrasIn []string
	var regrasFwd []string
	var dnatRules []string

	// 1. s:contencao (se Ajustes.ContencaoBorda == true)
	if ctx.config.Ajustes.ContencaoBorda {
		txtDrop := "ip saddr @abusers counter drop comment \"s:contencao\""
		txtAdd := "tcp dport @fwp_gerencia ct state new limit rate over 10/minute counter add @abusers { ip saddr } comment \"s:contencao\""
		lContencao := Linha{
			Chave:     "s:contencao",
			Zona:      fwmodel.ZonaInternet,
			Tipo:      "travada",
			Regra:     fwmodel.Regra{ID: "s:contencao", Zona: fwmodel.ZonaInternet, Ativa: true, Acao: fwmodel.AcaoDrop, Proto: fwmodel.ProtoTCP, PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaAlias, Valor: fwmodel.AliasGerencia}, Descricao: "Contenção de força bruta nas portas de gerência"},
			EditarEm:  "ajustes",
			DescChave: "fw.travada.contencao",
			Nft: []LinhaNft{
				{Chain: "zona_inet_in", Texto: txtDrop},
				{Chain: "zona_inet_in", Texto: txtAdd},
			},
		}
		linhas = append(linhas, lContencao)
		regrasIn = append(regrasIn, txtDrop, txtAdd)
	}

	// 2. s:wireguard (se VPN ligada e porta configurada)
	if strings.TrimSpace(ctx.insumos.RedeVPN) != "" && ctx.insumos.PortaWireGuard > 0 {
		txtWG := fmt.Sprintf("udp dport %d counter accept comment \"s:wireguard\"", ctx.insumos.PortaWireGuard)
		lWG := Linha{
			Chave:     "s:wireguard",
			Zona:      fwmodel.ZonaInternet,
			Tipo:      "travada",
			Regra:     fwmodel.Regra{ID: "s:wireguard", Zona: fwmodel.ZonaInternet, Ativa: true, Acao: fwmodel.AcaoAccept, Proto: fwmodel.ProtoUDP, PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaValor, Valor: strconv.Itoa(ctx.insumos.PortaWireGuard)}, Descricao: "Túnel WireGuard VPN"},
			EditarEm:  "vpn",
			DescChave: "fw.travada.wireguard",
			DescVars:  map[string]string{"porta": strconv.Itoa(ctx.insumos.PortaWireGuard)},
			Nft: []LinhaNft{
				{Chain: "zona_inet_in", Texto: txtWG},
			},
		}
		linhas = append(linhas, lWG)
		regrasIn = append(regrasIn, txtWG)
	}

	// 3. s:nat:<id> para cada encaminhamento ativo
	encs := append([]fwmodel.Encaminhamento{}, ctx.config.Encaminhamentos...)
	sort.Slice(encs, func(i, j int) bool {
		if encs[i].Posicao != encs[j].Posicao {
			return encs[i].Posicao < encs[j].Posicao
		}
		return encs[i].ID < encs[j].ID
	})

	for _, pf := range encs {
		if !pf.Ativo {
			continue
		}
		txtFwd := fmt.Sprintf("ct status dnat ip daddr %s %s dport %d counter accept comment \"s:nat:%s\"",
			pf.IPDestino, pf.Proto, pf.PortaDestino, pf.ID)
		txtDnat := fmt.Sprintf("fib daddr type local %s dport %d counter dnat ip to %s:%d comment \"s:nat:%s\"",
			pf.Proto, pf.PortaExterna, pf.IPDestino, pf.PortaDestino, pf.ID)

		lNat := Linha{
			Chave:     "s:nat:" + pf.ID,
			Zona:      fwmodel.ZonaInternet,
			Tipo:      "travada",
			Regra:     fwmodel.Regra{ID: "s:nat:" + pf.ID, Zona: fwmodel.ZonaInternet, Ativa: true, Acao: fwmodel.AcaoAccept, Proto: fwmodel.Proto(pf.Proto), Destino: fwmodel.Ponta{Tipo: fwmodel.PontaEndereco, Valor: pf.IPDestino}, PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaValor, Valor: strconv.Itoa(pf.PortaDestino)}, Descricao: pf.Nome},
			EditarEm:  "nat",
			DescChave: "fw.travada.nat",
			DescVars: map[string]string{
				"nome":    pf.Nome,
				"porta":   strconv.Itoa(pf.PortaExterna),
				"destino": fmt.Sprintf("%s:%d", pf.IPDestino, pf.PortaDestino),
			},
			Nft: []LinhaNft{
				{Chain: "zona_inet_fwd", Texto: txtFwd},
				{Chain: "prerouting_dnat", Texto: txtDnat},
			},
		}
		linhas = append(linhas, lNat)
		regrasFwd = append(regrasFwd, txtFwd)
		dnatRules = append(dnatRules, txtDnat)
	}

	// 4. Regras do admin para a zona internet
	regrasAdmin, err := coletarRegrasAdminDaZona(ctx, fwmodel.ZonaInternet)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	for _, ra := range regrasAdmin {
		linha, rIn, rFwd, err := montarRegraAdminLinha(ctx, ra, "zona_inet_in", "zona_inet_fwd")
		if err != nil {
			return nil, nil, nil, nil, err
		}
		linhas = append(linhas, linha)
		regrasIn = append(regrasIn, rIn...)
		regrasFwd = append(regrasFwd, rFwd...)
	}

	// 5. Regras padrão da zona internet (d:internet:in e d:internet:fwd, ambas drop)
	var nftPadraoIn []LinhaNft
	if ctx.config.Ajustes.RegistrarPadrao {
		nftPadraoIn = append(nftPadraoIn, LinhaNft{Chain: "zona_inet_in", Texto: "limit rate 10/second log prefix \"lg:d:internet:in \""})
		regrasIn = append(regrasIn, "limit rate 10/second log prefix \"lg:d:internet:in \"")
	}
	txtDropIn := "counter drop comment \"d:internet:in\""
	nftPadraoIn = append(nftPadraoIn, LinhaNft{Chain: "zona_inet_in", Texto: txtDropIn})
	regrasIn = append(regrasIn, txtDropIn)

	lPadraoIn := Linha{
		Chave:     "d:internet:in",
		Zona:      fwmodel.ZonaInternet,
		Tipo:      "padrao",
		Regra:     fwmodel.Regra{ID: "d:internet:in", Zona: fwmodel.ZonaInternet, Ativa: true, Acao: fwmodel.AcaoDrop, Registrar: ctx.config.Ajustes.RegistrarPadrao, Descricao: "Regra padrão da zona Internet (entrada)"},
		EditarEm:  "",
		DescChave: "fw.padrao.internet_in",
		Nft:       nftPadraoIn,
	}
	linhas = append(linhas, lPadraoIn)

	var nftPadraoFwd []LinhaNft
	if ctx.config.Ajustes.RegistrarPadrao {
		nftPadraoFwd = append(nftPadraoFwd, LinhaNft{Chain: "zona_inet_fwd", Texto: "limit rate 10/second log prefix \"lg:d:internet:fwd \""})
		regrasFwd = append(regrasFwd, "limit rate 10/second log prefix \"lg:d:internet:fwd \"")
	}
	txtDropFwd := "counter drop comment \"d:internet:fwd\""
	nftPadraoFwd = append(nftPadraoFwd, LinhaNft{Chain: "zona_inet_fwd", Texto: txtDropFwd})
	regrasFwd = append(regrasFwd, txtDropFwd)

	lPadraoFwd := Linha{
		Chave:     "d:internet:fwd",
		Zona:      fwmodel.ZonaInternet,
		Tipo:      "padrao",
		Regra:     fwmodel.Regra{ID: "d:internet:fwd", Zona: fwmodel.ZonaInternet, Ativa: true, Acao: fwmodel.AcaoDrop, Registrar: ctx.config.Ajustes.RegistrarPadrao, Descricao: "Regra padrão da zona Internet (passagem)"},
		EditarEm:  "",
		DescChave: "fw.padrao.internet_fwd",
		Nft:       nftPadraoFwd,
	}
	linhas = append(linhas, lPadraoFwd)

	return linhas, regrasIn, regrasFwd, dnatRules, nil
}

// montarLinhasVCN gera as linhas da aba VCN (anti-bloqueio, admin, padrões).
func montarLinhasVCN(ctx *contextoRender) ([]Linha, []string, []string, error) {
	var linhas []Linha
	var regrasIn []string
	var regrasFwd []string

	// 1. s:antibloqueio:vcn (se Ajustes.AntiBloqueio[ZonaVCN] == true)
	if ctx.config.Ajustes.AntiBloqueio[fwmodel.ZonaVCN] {
		txtAnti := "tcp dport @fwp_gerencia counter accept comment \"s:antibloqueio:vcn\""
		lAnti := Linha{
			Chave:     "s:antibloqueio:vcn",
			Zona:      fwmodel.ZonaVCN,
			Tipo:      "travada",
			Regra:     fwmodel.Regra{ID: "s:antibloqueio:vcn", Zona: fwmodel.ZonaVCN, Ativa: true, Acao: fwmodel.AcaoAccept, Proto: fwmodel.ProtoTCP, Destino: fwmodel.Ponta{Tipo: fwmodel.PontaEste}, PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaAlias, Valor: fwmodel.AliasGerencia}, Descricao: "Anti-bloqueio VCN (SSH e painel)"},
			EditarEm:  "ajustes",
			DescChave: "fw.travada.antibloqueio_vcn",
			Nft: []LinhaNft{
				{Chain: "zona_vcn_in", Texto: txtAnti},
			},
		}
		linhas = append(linhas, lAnti)
		regrasIn = append(regrasIn, txtAnti)
	}

	// 2. Regras do admin para a zona VCN
	regrasAdmin, err := coletarRegrasAdminDaZona(ctx, fwmodel.ZonaVCN)
	if err != nil {
		return nil, nil, nil, err
	}
	for _, ra := range regrasAdmin {
		linha, rIn, rFwd, err := montarRegraAdminLinha(ctx, ra, "zona_vcn_in", "zona_vcn_fwd")
		if err != nil {
			return nil, nil, nil, err
		}
		linhas = append(linhas, linha)
		regrasIn = append(regrasIn, rIn...)
		regrasFwd = append(regrasFwd, rFwd...)
	}

	// 3. Regras padrão da zona VCN: d:vcn:in (drop) e d:vcn:fwd (accept)
	var nftPadraoIn []LinhaNft
	if ctx.config.Ajustes.RegistrarPadrao {
		nftPadraoIn = append(nftPadraoIn, LinhaNft{Chain: "zona_vcn_in", Texto: "limit rate 10/second log prefix \"lg:d:vcn:in \""})
		regrasIn = append(regrasIn, "limit rate 10/second log prefix \"lg:d:vcn:in \"")
	}
	txtDropIn := "counter drop comment \"d:vcn:in\""
	nftPadraoIn = append(nftPadraoIn, LinhaNft{Chain: "zona_vcn_in", Texto: txtDropIn})
	regrasIn = append(regrasIn, txtDropIn)

	lPadraoIn := Linha{
		Chave:     "d:vcn:in",
		Zona:      fwmodel.ZonaVCN,
		Tipo:      "padrao",
		Regra:     fwmodel.Regra{ID: "d:vcn:in", Zona: fwmodel.ZonaVCN, Ativa: true, Acao: fwmodel.AcaoDrop, Registrar: ctx.config.Ajustes.RegistrarPadrao, Descricao: "Regra padrão da zona VCN (entrada)"},
		EditarEm:  "",
		DescChave: "fw.padrao.vcn_in",
		Nft:       nftPadraoIn,
	}
	linhas = append(linhas, lPadraoIn)

	// d:vcn:fwd é counter accept (não gera log mesmo com RegistrarPadrao ligado)
	txtAcceptFwd := "counter accept comment \"d:vcn:fwd\""
	lPadraoFwd := Linha{
		Chave:     "d:vcn:fwd",
		Zona:      fwmodel.ZonaVCN,
		Tipo:      "padrao",
		Regra:     fwmodel.Regra{ID: "d:vcn:fwd", Zona: fwmodel.ZonaVCN, Ativa: true, Acao: fwmodel.AcaoAccept, Descricao: "Regra padrão da zona VCN (passagem)"},
		EditarEm:  "",
		DescChave: "fw.padrao.vcn_fwd",
		Nft: []LinhaNft{
			{Chain: "zona_vcn_fwd", Texto: txtAcceptFwd},
		},
	}
	linhas = append(linhas, lPadraoFwd)
	regrasFwd = append(regrasFwd, txtAcceptFwd)

	return linhas, regrasIn, regrasFwd, nil
}

// montarLinhasVPN gera as linhas da aba VPN (anti-bloqueio, dns-vpn, pessoas total/restrito, admin, padrões).
func montarLinhasVPN(ctx *contextoRender, pessoasProntas []pessoaPronta) ([]Linha, []string, []string, error) {
	var linhas []Linha
	var regrasIn []string
	var regrasFwd []string

	// 1. s:antibloqueio:vpn (se Ajustes.AntiBloqueio[ZonaVPN] == true, padrão desligado)
	if ctx.config.Ajustes.AntiBloqueio[fwmodel.ZonaVPN] {
		txtAnti := "tcp dport @fwp_gerencia counter accept comment \"s:antibloqueio:vpn\""
		lAnti := Linha{
			Chave:     "s:antibloqueio:vpn",
			Zona:      fwmodel.ZonaVPN,
			Tipo:      "travada",
			Regra:     fwmodel.Regra{ID: "s:antibloqueio:vpn", Zona: fwmodel.ZonaVPN, Ativa: true, Acao: fwmodel.AcaoAccept, Proto: fwmodel.ProtoTCP, Destino: fwmodel.Ponta{Tipo: fwmodel.PontaEste}, PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaAlias, Valor: fwmodel.AliasGerencia}, Descricao: "Anti-bloqueio VPN (SSH e painel)"},
			EditarEm:  "ajustes",
			DescChave: "fw.travada.antibloqueio_vpn",
			Nft: []LinhaNft{
				{Chain: "zona_vpn_in", Texto: txtAnti},
			},
		}
		linhas = append(linhas, lAnti)
		regrasIn = append(regrasIn, txtAnti)
	}

	// 2. s:dns-vpn (se VPN ligada)
	vpnLigada := strings.TrimSpace(ctx.insumos.RedeVPN) != "" && ctx.insumos.PortaWireGuard > 0
	if vpnLigada {
		txtDNS := "meta l4proto { tcp, udp } th dport 53 counter accept comment \"s:dns-vpn\""
		lDNS := Linha{
			Chave:     "s:dns-vpn",
			Zona:      fwmodel.ZonaVPN,
			Tipo:      "travada",
			Regra:     fwmodel.Regra{ID: "s:dns-vpn", Zona: fwmodel.ZonaVPN, Ativa: true, Acao: fwmodel.AcaoAccept, Proto: fwmodel.ProtoTCPUDP, Destino: fwmodel.Ponta{Tipo: fwmodel.PontaEste}, PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaValor, Valor: "53"}, Descricao: "DNS para quem está na VPN"},
			EditarEm:  "",
			DescChave: "fw.travada.dns_vpn",
			Nft: []LinhaNft{
				{Chain: "zona_vpn_in", Texto: txtDNS},
			},
		}
		linhas = append(linhas, lDNS)
		regrasIn = append(regrasIn, txtDNS)

		// 3. Regras derivadas dos perfis das pessoas da VPN
		// Primeiro pessoas com acesso Total (in e fwd)
		for _, pr := range pessoasProntas {
			p := pr.p
			if p.Total {
				txtIn := fmt.Sprintf("ip saddr %s counter accept comment \"s:vpn:%s:total\"", p.Endereco, p.UserID)
				txtFwd := fmt.Sprintf("ip saddr %s counter accept comment \"s:vpn:%s:total\"", p.Endereco, p.UserID)

				lTotal := Linha{
					Chave:     "s:vpn:" + p.UserID + ":total",
					Zona:      fwmodel.ZonaVPN,
					Tipo:      "travada",
					Regra:     fwmodel.Regra{ID: "s:vpn:" + p.UserID + ":total", Zona: fwmodel.ZonaVPN, Ativa: true, Acao: fwmodel.AcaoAccept, Origem: fwmodel.Ponta{Tipo: fwmodel.PontaEndereco, Valor: p.Endereco}, Destino: fwmodel.Ponta{Tipo: fwmodel.PontaQualquer}, Descricao: "Acesso total: " + p.Usuario},
					EditarEm:  "vpn",
					DescChave: "fw.travada.vpn_total",
					DescVars:  map[string]string{"usuario": p.Usuario},
					Nft: []LinhaNft{
						{Chain: "zona_vpn_in", Texto: txtIn},
						{Chain: "zona_vpn_fwd", Texto: txtFwd},
					},
				}
				linhas = append(linhas, lTotal)
				regrasIn = append(regrasIn, txtIn)
				regrasFwd = append(regrasFwd, txtFwd)
			}
		}

		// Depois pessoas restritas (só fwd, ordenadas por usuario e depois por nome do alias)
		for _, pr := range pessoasProntas {
			p := pr.p
			if p.Total {
				continue
			}
			portasFormatadas := formatarPortasVPN(p.Portas)

			for _, av := range pr.aliases {
				var nftList []LinhaNft
				if portasFormatadas == "" {
					// Sem restrição de portas: IP + alias
					txtFwd := fmt.Sprintf("ip saddr %s ip daddr @%s counter accept comment \"s:vpn:%s:%s\"",
						p.Endereco, av.set, p.UserID, av.id)
					nftList = append(nftList, LinhaNft{Chain: "zona_vpn_fwd", Texto: txtFwd})
					regrasFwd = append(regrasFwd, txtFwd)
				} else {
					// Com portas: TCP + ICMP (ZTNA)
					txtTCP := fmt.Sprintf("ip saddr %s ip daddr @%s tcp dport { %s } counter accept comment \"s:vpn:%s:%s\"",
						p.Endereco, av.set, portasFormatadas, p.UserID, av.id)
					txtICMP := fmt.Sprintf("ip saddr %s ip daddr @%s meta l4proto icmp counter accept comment \"s:vpn:%s:%s:icmp\"",
						p.Endereco, av.set, p.UserID, av.id)
					nftList = append(nftList,
						LinhaNft{Chain: "zona_vpn_fwd", Texto: txtTCP},
						LinhaNft{Chain: "zona_vpn_fwd", Texto: txtICMP},
					)
					regrasFwd = append(regrasFwd, txtTCP, txtICMP)
				}

				protoRegra := fwmodel.ProtoQualquer
				var portaRegra fwmodel.Porta
				if portasFormatadas != "" {
					protoRegra = fwmodel.ProtoTCP
					portaRegra = fwmodel.Porta{Tipo: fwmodel.PortaValor, Valor: p.Portas}
				}

				lRestrito := Linha{
					Chave:     fmt.Sprintf("s:vpn:%s:%s", p.UserID, av.id),
					Zona:      fwmodel.ZonaVPN,
					Tipo:      "travada",
					Regra:     fwmodel.Regra{ID: fmt.Sprintf("s:vpn:%s:%s", p.UserID, av.id), Zona: fwmodel.ZonaVPN, Ativa: true, Acao: fwmodel.AcaoAccept, Proto: protoRegra, Origem: fwmodel.Ponta{Tipo: fwmodel.PontaEndereco, Valor: p.Endereco}, Destino: fwmodel.Ponta{Tipo: fwmodel.PontaAlias, Valor: av.id}, PortaDestino: portaRegra, Descricao: fmt.Sprintf("Acesso restrito: %s (%s)", p.Usuario, av.nome)},
					EditarEm:  "vpn",
					DescChave: "fw.travada.vpn_restrito",
					DescVars: map[string]string{
						"usuario": p.Usuario,
						"alias":   av.nome,
					},
					Nft: nftList,
				}
				linhas = append(linhas, lRestrito)
			}
		}
	}

	// 4. Regras do admin para a zona VPN
	regrasAdmin, err := coletarRegrasAdminDaZona(ctx, fwmodel.ZonaVPN)
	if err != nil {
		return nil, nil, nil, err
	}
	for _, ra := range regrasAdmin {
		linha, rIn, rFwd, err := montarRegraAdminLinha(ctx, ra, "zona_vpn_in", "zona_vpn_fwd")
		if err != nil {
			return nil, nil, nil, err
		}
		linhas = append(linhas, linha)
		regrasIn = append(regrasIn, rIn...)
		regrasFwd = append(regrasFwd, rFwd...)
	}

	// 5. Regras padrão da zona VPN (d:vpn:in e d:vpn:fwd, ambas drop)
	var nftPadraoIn []LinhaNft
	if ctx.config.Ajustes.RegistrarPadrao {
		nftPadraoIn = append(nftPadraoIn, LinhaNft{Chain: "zona_vpn_in", Texto: "limit rate 10/second log prefix \"lg:d:vpn:in \""})
		regrasIn = append(regrasIn, "limit rate 10/second log prefix \"lg:d:vpn:in \"")
	}
	txtDropIn := "counter drop comment \"d:vpn:in\""
	nftPadraoIn = append(nftPadraoIn, LinhaNft{Chain: "zona_vpn_in", Texto: txtDropIn})
	regrasIn = append(regrasIn, txtDropIn)

	lPadraoIn := Linha{
		Chave:     "d:vpn:in",
		Zona:      fwmodel.ZonaVPN,
		Tipo:      "padrao",
		Regra:     fwmodel.Regra{ID: "d:vpn:in", Zona: fwmodel.ZonaVPN, Ativa: true, Acao: fwmodel.AcaoDrop, Registrar: ctx.config.Ajustes.RegistrarPadrao, Descricao: "Regra padrão da zona VPN (entrada)"},
		EditarEm:  "",
		DescChave: "fw.padrao.vpn_in",
		Nft:       nftPadraoIn,
	}
	linhas = append(linhas, lPadraoIn)

	var nftPadraoFwd []LinhaNft
	if ctx.config.Ajustes.RegistrarPadrao {
		nftPadraoFwd = append(nftPadraoFwd, LinhaNft{Chain: "zona_vpn_fwd", Texto: "limit rate 10/second log prefix \"lg:d:vpn:fwd \""})
		regrasFwd = append(regrasFwd, "limit rate 10/second log prefix \"lg:d:vpn:fwd \"")
	}
	txtDropFwd := "counter drop comment \"d:vpn:fwd\""
	nftPadraoFwd = append(nftPadraoFwd, LinhaNft{Chain: "zona_vpn_fwd", Texto: txtDropFwd})
	regrasFwd = append(regrasFwd, txtDropFwd)

	lPadraoFwd := Linha{
		Chave:     "d:vpn:fwd",
		Zona:      fwmodel.ZonaVPN,
		Tipo:      "padrao",
		Regra:     fwmodel.Regra{ID: "d:vpn:fwd", Zona: fwmodel.ZonaVPN, Ativa: true, Acao: fwmodel.AcaoDrop, Registrar: ctx.config.Ajustes.RegistrarPadrao, Descricao: "Regra padrão da zona VPN (passagem)"},
		EditarEm:  "",
		DescChave: "fw.padrao.vpn_fwd",
		Nft:       nftPadraoFwd,
	}
	linhas = append(linhas, lPadraoFwd)

	return linhas, regrasIn, regrasFwd, nil
}

// formatarPortasVPN normaliza a lista de portas em string CSV para o conjunto nftables.
func formatarPortasVPN(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, ",")
	var ordenadas []string
	for _, p := range parts {
		item := strings.TrimSpace(p)
		if item != "" {
			ordenadas = append(ordenadas, item)
		}
	}
	if len(ordenadas) == 0 {
		return ""
	}
	return strings.Join(ordenadas, ", ")
}

// coletarRegrasAdminDaZona filtra e ordena as regras do admin por posição.
func coletarRegrasAdminDaZona(ctx *contextoRender, zona fwmodel.Zona) ([]fwmodel.Regra, error) {
	var filtradas []fwmodel.Regra
	for _, r := range ctx.config.Regras {
		if r.Zona == zona {
			filtradas = append(filtradas, r)
		}
	}
	sort.Slice(filtradas, func(i, j int) bool {
		if filtradas[i].Posicao != filtradas[j].Posicao {
			return filtradas[i].Posicao < filtradas[j].Posicao
		}
		return filtradas[i].ID < filtradas[j].ID
	})
	return filtradas, nil
}

// montarRegraAdminLinha sintetiza a Linha de interface e os comandos nftables correspondentes.
func montarRegraAdminLinha(ctx *contextoRender, r fwmodel.Regra, chainIn, chainFwd string) (Linha, []string, []string, error) {
	linha := Linha{
		Chave:    "r:" + r.ID,
		Zona:     r.Zona,
		Tipo:     "admin",
		Regra:    r,
		EditarEm: "",
		Nft:      []LinhaNft{},
	}

	if !r.Ativa {
		return linha, nil, nil, nil
	}

	aplicaIn := r.Destino.Tipo == fwmodel.PontaEste || r.Destino.Tipo == fwmodel.PontaQualquer
	aplicaFwd := r.Destino.Tipo != fwmodel.PontaEste

	var regrasIn []string
	var regrasFwd []string
	hex12 := aliasUUIDHex12(r.ID)

	// Montagem para a chain _in
	if aplicaIn {
		tokensMatch, err := buildAdminMatchTokens(ctx, r, true)
		if err != nil {
			return Linha{}, nil, nil, err
		}
		matchStr := strings.Join(tokensMatch, " ")
		if matchStr != "" {
			matchStr += " "
		}

		verdictStr := buildAdminVerdict(r)

		if r.Registrar {
			txtLog := fmt.Sprintf("%slimit rate 10/second log prefix \"lg:r:%s \"", matchStr, hex12)
			linha.Nft = append(linha.Nft, LinhaNft{Chain: chainIn, Texto: txtLog})
			regrasIn = append(regrasIn, txtLog)
		}

		txtRule := fmt.Sprintf("%scounter %s comment \"r:%s\"", matchStr, verdictStr, r.ID)
		linha.Nft = append(linha.Nft, LinhaNft{Chain: chainIn, Texto: txtRule})
		regrasIn = append(regrasIn, txtRule)
	}

	// Montagem para a chain _fwd
	if aplicaFwd {
		tokensMatch, err := buildAdminMatchTokens(ctx, r, false)
		if err != nil {
			return Linha{}, nil, nil, err
		}
		matchStr := strings.Join(tokensMatch, " ")
		if matchStr != "" {
			matchStr += " "
		}

		verdictStr := buildAdminVerdict(r)

		if r.Registrar {
			txtLog := fmt.Sprintf("%slimit rate 10/second log prefix \"lg:r:%s \"", matchStr, hex12)
			linha.Nft = append(linha.Nft, LinhaNft{Chain: chainFwd, Texto: txtLog})
			regrasFwd = append(regrasFwd, txtLog)
		}

		txtRule := fmt.Sprintf("%scounter %s comment \"r:%s\"", matchStr, verdictStr, r.ID)
		linha.Nft = append(linha.Nft, LinhaNft{Chain: chainFwd, Texto: txtRule})
		regrasFwd = append(regrasFwd, txtRule)
	}

	return linha, regrasIn, regrasFwd, nil
}

// buildAdminMatchTokens constrói os critérios de casamento de uma regra administrativa.
func buildAdminMatchTokens(ctx *contextoRender, r fwmodel.Regra, isInChain bool) ([]string, error) {
	var t []string

	// 1. Agendamento
	if r.AgendamentoID != "" {
		ag, ok := ctx.agendamentoMap[r.AgendamentoID]
		if !ok {
			return nil, fmt.Errorf("agendamento %q não encontrado", r.AgendamentoID)
		}
		sched := Schedule{
			Days:  ag.Dias,
			Start: ag.Inicio,
			End:   ag.Fim,
		}
		t = append(t, sched.Tokens()...)
	}

	// 2. Origem
	switch r.Origem.Tipo {
	case fwmodel.PontaQualquer:
		// Qualquer origem: sem filtro ip saddr
	case fwmodel.PontaEndereco:
		t = append(t, "ip", "saddr", r.Origem.Valor)
	case fwmodel.PontaAlias:
		if r.Origem.Valor == fwmodel.AliasVCN {
			t = append(t, "ip", "saddr", "@fwa_vcn")
		} else if r.Origem.Valor == fwmodel.AliasVPN {
			t = append(t, "ip", "saddr", "@fwa_vpn")
		} else if strings.HasPrefix(r.Origem.Valor, fwmodel.AliasPessoaPref) {
			uid := strings.TrimPrefix(r.Origem.Valor, fwmodel.AliasPessoaPref)
			p, ok := ctx.pessoaMap[uid]
			if !ok {
				return nil, fmt.Errorf("pessoa %q não encontrada", uid)
			}
			t = append(t, "ip", "saddr", p.Endereco)
		} else {
			sName, ok := ctx.aliasSetNames[r.Origem.Valor]
			if !ok {
				return nil, fmt.Errorf("alias %q não encontrado", r.Origem.Valor)
			}
			t = append(t, "ip", "saddr", "@"+sName)
		}
	}

	// 3. Destino
	if isInChain {
		// Na chain de entrada, PontaEste e PontaQualquer não emitem ip daddr
	} else {
		// Na chain de passagem
		switch r.Destino.Tipo {
		case fwmodel.PontaQualquer, fwmodel.PontaEste:
			// Sem filtro ip daddr
		case fwmodel.PontaEndereco:
			t = append(t, "ip", "daddr", r.Destino.Valor)
		case fwmodel.PontaAlias:
			if r.Destino.Valor == fwmodel.AliasVCN {
				t = append(t, "ip", "daddr", "@fwa_vcn")
			} else if r.Destino.Valor == fwmodel.AliasVPN {
				t = append(t, "ip", "daddr", "@fwa_vpn")
			} else if strings.HasPrefix(r.Destino.Valor, fwmodel.AliasPessoaPref) {
				uid := strings.TrimPrefix(r.Destino.Valor, fwmodel.AliasPessoaPref)
				p, ok := ctx.pessoaMap[uid]
				if !ok {
					return nil, fmt.Errorf("pessoa %q não encontrada", uid)
				}
				t = append(t, "ip", "daddr", p.Endereco)
			} else {
				sName, ok := ctx.aliasSetNames[r.Destino.Valor]
				if !ok {
					return nil, fmt.Errorf("alias %q não encontrado", r.Destino.Valor)
				}
				t = append(t, "ip", "daddr", "@"+sName)
			}
		}
	}

	// 4. Protocolo e porta de destino
	portExpr := ""
	if r.PortaDestino.Tipo == fwmodel.PortaValor {
		portExpr = r.PortaDestino.Valor
	} else if r.PortaDestino.Tipo == fwmodel.PortaAlias {
		if r.PortaDestino.Valor == fwmodel.AliasGerencia {
			portExpr = "@fwp_gerencia"
		} else {
			sName, ok := ctx.aliasSetNames[r.PortaDestino.Valor]
			if !ok {
				return nil, fmt.Errorf("alias de portas %q não encontrado", r.PortaDestino.Valor)
			}
			portExpr = "@" + sName
		}
	}

	switch r.Proto {
	case fwmodel.ProtoTCP:
		if portExpr != "" {
			t = append(t, "tcp", "dport", portExpr)
		} else {
			t = append(t, "meta", "l4proto", "tcp")
		}
	case fwmodel.ProtoUDP:
		if portExpr != "" {
			t = append(t, "udp", "dport", portExpr)
		} else {
			t = append(t, "meta", "l4proto", "udp")
		}
	case fwmodel.ProtoTCPUDP:
		if portExpr != "" {
			t = append(t, "meta", "l4proto", "{ tcp, udp }", "th", "dport", portExpr)
		} else {
			t = append(t, "meta", "l4proto", "{ tcp, udp }")
		}
	case fwmodel.ProtoICMP:
		t = append(t, "meta", "l4proto", "icmp")
	case fwmodel.ProtoQualquer:
		// Qualquer protocolo: sem filtro de camada 4
	}

	return t, nil
}

// buildAdminVerdict formata a ação final de uma regra (accept, drop ou reject).
func buildAdminVerdict(r fwmodel.Regra) string {
	switch r.Acao {
	case fwmodel.AcaoAccept:
		return "accept"
	case fwmodel.AcaoDrop:
		return "drop"
	case fwmodel.AcaoReject:
		if r.Proto == fwmodel.ProtoTCP {
			return "reject with tcp reset"
		}
		return "reject"
	}
	return "drop"
}

// montarRegrasInput monta as regras da chain base input (despachante para as zonas).
func montarRegrasInput(in Insumos) []string {
	ifaceVPN := in.InterfaceVPN
	if ifaceVPN == "" {
		ifaceVPN = "linkguard"
	}
	return []string{
		"ct state established,related counter accept comment \"b:estado\"",
		"iif \"lo\" counter accept comment \"b:lo\"",
		"icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } counter accept comment \"b:nd\"",
		"udp sport 67 udp dport 68 counter accept comment \"b:dhcp\"",
		"udp dport 546 counter accept comment \"b:dhcp6\"",
		"jump zona_flut_in",
		fmt.Sprintf("iifname %q jump zona_vpn_in", ifaceVPN),
		"ip saddr @fwa_vcn jump zona_vcn_in",
		"jump zona_inet_in",
	}
}

// montarRegrasForward monta as regras da chain base forward (bloqueios, despachante para as zonas).
func montarRegrasForward(ajustes fwmodel.Ajustes, in Insumos) []string {
	var rules []string

	// Bloqueios administrativos ANTES do established para derrubar conexões ativas
	if ajustes.RegistrarBloqueados {
		rules = append(rules,
			"ip saddr @blocked_hosts limit rate 10/second log prefix \"lg:s:hosts \"",
			"ip saddr @blocked_hosts counter drop comment \"s:hosts-bloqueados\"",
			"ip daddr @blocked_hosts limit rate 10/second log prefix \"lg:s:hosts \"",
			"ip daddr @blocked_hosts counter drop comment \"s:hosts-bloqueados\"",
		)
	} else {
		rules = append(rules,
			"ip saddr @blocked_hosts counter drop comment \"s:hosts-bloqueados\"",
			"ip daddr @blocked_hosts counter drop comment \"s:hosts-bloqueados\"",
		)
	}

	if ajustes.RegistrarDestinos {
		rules = append(rules,
			"ip daddr @blocklist limit rate 10/second log prefix \"lg:s:destinos \"",
			"ip daddr @blocklist counter drop comment \"s:destinos-bloqueados\"",
			"ip saddr @blocklist limit rate 10/second log prefix \"lg:s:destinos \"",
			"ip saddr @blocklist counter drop comment \"s:destinos-bloqueados\"",
			"ip daddr @dom_blocked limit rate 10/second log prefix \"lg:s:destinos \"",
			"ip daddr @dom_blocked counter drop comment \"s:destinos-bloqueados\"",
			"ip6 daddr @dom_blocked6 limit rate 10/second log prefix \"lg:s:destinos \"",
			"ip6 daddr @dom_blocked6 counter drop comment \"s:destinos-bloqueados\"",
		)
	} else {
		rules = append(rules,
			"ip daddr @blocklist counter drop comment \"s:destinos-bloqueados\"",
			"ip saddr @blocklist counter drop comment \"s:destinos-bloqueados\"",
			"ip daddr @dom_blocked counter drop comment \"s:destinos-bloqueados\"",
			"ip6 daddr @dom_blocked6 counter drop comment \"s:destinos-bloqueados\"",
		)
	}

	rules = append(rules, "ct state established,related counter accept comment \"b:estado\"")
	rules = append(rules, "jump zona_flut_fwd")

	ifaceVPN := in.InterfaceVPN
	if ifaceVPN == "" {
		ifaceVPN = "linkguard"
	}
	rules = append(rules, fmt.Sprintf("iifname %q jump zona_vpn_fwd", ifaceVPN))
	rules = append(rules, "ip saddr @fwa_vcn jump zona_vcn_fwd")
	rules = append(rules, "jump zona_inet_fwd")

	return rules
}
