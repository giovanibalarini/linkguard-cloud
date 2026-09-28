package nftables

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/giovanibalarini/linkguard-cloud/internal/fwmodel"
)

// Insumos são os fatos que não passam pelo botão Aplicar (§2.8).
type Insumos struct {
	RedesVCN       []string // redesLocais(plat); as extras vêm de Config.Ajustes
	RedeVPN        string   // "10.7.0.0/24"; "" com a VPN desligada
	PortaWireGuard int      // 0 = VPN desligada
	InterfaceVPN   string   // "linkguard"
	PortasGerencia []int    // SSH + painel + extras, já ordenadas e sem repetição
	Pessoas        []PessoaVPN
	Existentes     Existentes // o que já existe na tabela (para a limpeza)
}

// PessoaVPN contém o perfil de acesso de um peer WireGuard para sintetizar regras.
type PessoaVPN struct {
	UserID   string
	Usuario  string
	Endereco string   // "10.7.0.3" (sem /32)
	Total    bool     // access_mode == "full"
	Aliases  []string // IDs de alias de endereços
	Portas   string   // CSV, como hoje em allowed_ports
}

// Existentes guarda chains e sets atualmente presentes no kernel para limpeza do legado.
type Existentes struct {
	Chains []string
	Sets   []string
}

// Ruleset agrega o script gerado, as linhas da tabela da interface, hash de entrada e avisos.
type Ruleset struct {
	Script      string                   `json:"script"`
	Linhas      map[fwmodel.Zona][]Linha `json:"linhas"`
	HashEntrada string                   `json:"hash_entrada"`
	Avisos      []fwmodel.Problema       `json:"avisos"`
}

type userSet struct {
	id        string
	nomeSet   string
	tipo      fwmodel.AliasTipo
	elementos []string
}

type aliasValidoPessoa struct {
	id   string
	nome string
	set  string
}

type pessoaPronta struct {
	p       PessoaVPN
	aliases []aliasValidoPessoa
}

var reHexUUID = regexp.MustCompile(`^[0-9a-fA-F-]+$`)

// aliasSetName calcula o nome do set nftables para um alias:
// "fwa_" (endereços) ou "fwp_" (portas) + os 12 primeiros caracteres hexadecimais sem traços.
func aliasSetName(tipo fwmodel.AliasTipo, id string) string {
	clean := strings.ToLower(strings.ReplaceAll(id, "-", ""))
	if len(clean) > 12 {
		clean = clean[:12]
	}
	if tipo == fwmodel.AliasTipoPortas {
		return "fwp_" + clean
	}
	return "fwa_" + clean
}

// aliasUUIDHex12 extrai os 12 primeiros hex de um UUID sem traços, para o prefixo de log.
func aliasUUIDHex12(id string) string {
	clean := strings.ToLower(strings.ReplaceAll(id, "-", ""))
	if len(clean) > 12 {
		clean = clean[:12]
	}
	return clean
}

// RenderZonas é o renderizador puro do firewall por zonas.
// Produz o script atômico para `nft -f`, a representação em linhas da interface,
// o hash das regras de entrada para controle da janela de confirmação de 90s,
// e eventuais avisos não bloqueantes (ex: alias removido de perfil de VPN).
func RenderZonas(c fwmodel.Config, in Insumos) (Ruleset, error) {
	var userIDs []string
	for _, p := range in.Pessoas {
		userIDs = append(userIDs, p.UserID)
	}
	c, avisosPessoa := semRegrasDePessoaRemovida(c, userIDs)
	erros := fwmodel.Validar(c, userIDs)
	if fwmodel.TemErro(erros) {
		var msgs []string
		for _, e := range erros {
			if e.Severidade == "erro" {
				msgs = append(msgs, fmt.Sprintf("%s: %s", e.Onde, e.Chave))
			}
		}
		return Ruleset{}, fmt.Errorf("configuração do firewall inválida: %s", strings.Join(msgs, "; "))
	}

	if in.InterfaceVPN == "" {
		in.InterfaceVPN = "linkguard"
	}
	if !reIface.MatchString(in.InterfaceVPN) {
		return Ruleset{}, fmt.Errorf("interface VPN inválida: %q", in.InterfaceVPN)
	}

	// 1. Mapeamento e validação de aliases de usuário para evitar colisão nos 12 hex
	aliasMap := make(map[string]fwmodel.Alias)
	aliasSetNames := make(map[string]string)  // alias.ID -> nome do set nftables
	setNameToAlias := make(map[string]string) // nome do set nftables -> alias.ID

	for _, a := range c.Aliases {
		aliasMap[a.ID] = a
		sName := aliasSetName(a.Tipo, a.ID)
		if outroID, existe := setNameToAlias[sName]; existe && outroID != a.ID {
			return Ruleset{}, fmt.Errorf("colisão de nome de set nftables %q entre os aliases %q e %q", sName, outroID, a.ID)
		}
		setNameToAlias[sName] = a.ID
		aliasSetNames[a.ID] = sName
	}

	// Mapeamento de agendamentos
	agendamentoMap := make(map[string]fwmodel.Agendamento)
	for _, ag := range c.Agendamentos {
		agendamentoMap[ag.ID] = ag
	}

	// Mapeamento de pessoas da VPN para busca inline em regras sys:pessoa:<uid>
	pessoaMap := make(map[string]PessoaVPN)
	for _, p := range in.Pessoas {
		pessoaMap[p.UserID] = p
	}

	// Verificar se todas as regras apontam para aliases e agendamentos existentes
	for _, r := range c.Regras {
		if r.AgendamentoID != "" {
			if _, ok := agendamentoMap[r.AgendamentoID]; !ok {
				return Ruleset{}, fmt.Errorf("regra %q referencia agendamento inexistente %q", r.ID, r.AgendamentoID)
			}
		}
		if r.Origem.Tipo == fwmodel.PontaAlias {
			if err := validarUsoAliasEndereco(r.Origem.Valor, aliasMap, pessoaMap); err != nil {
				return Ruleset{}, fmt.Errorf("regra %q: origem: %w", r.ID, err)
			}
		}
		if r.Destino.Tipo == fwmodel.PontaAlias {
			if err := validarUsoAliasEndereco(r.Destino.Valor, aliasMap, pessoaMap); err != nil {
				return Ruleset{}, fmt.Errorf("regra %q: destino: %w", r.ID, err)
			}
		}
		if r.PortaDestino.Tipo == fwmodel.PortaAlias {
			if r.PortaDestino.Valor != fwmodel.AliasGerencia {
				a, ok := aliasMap[r.PortaDestino.Valor]
				if !ok {
					return Ruleset{}, fmt.Errorf("regra %q: porta de destino referencia alias inexistente %q", r.ID, r.PortaDestino.Valor)
				}
				if a.Tipo != fwmodel.AliasTipoPortas {
					return Ruleset{}, fmt.Errorf("regra %q: porta de destino referencia alias %q que não é de portas", r.ID, r.PortaDestino.Valor)
				}
			}
		}
	}

	// 2. Processar elementos dos sets
	// fwa_vcn
	redesVCNBrutas := append([]string{}, in.RedesVCN...)
	redesVCNBrutas = append(redesVCNBrutas, c.Ajustes.RedesVCNExtras...)
	elementosVCN, err := normalizarEOptimizarSubredes(redesVCNBrutas)
	if err != nil {
		return Ruleset{}, fmt.Errorf("erro ao processar redes da VCN: %w", err)
	}

	// fwa_vpn
	var elementosVPN []string
	if strings.TrimSpace(in.RedeVPN) != "" {
		elVPN, err := normalizarEOptimizarSubredes([]string{in.RedeVPN})
		if err != nil {
			return Ruleset{}, fmt.Errorf("erro ao processar rede da VPN: %w", err)
		}
		elementosVPN = elVPN
	}

	// fwp_gerencia
	elementosGerencia := normalizarPortasGerencia(in.PortasGerencia)

	// Sets dos aliases de usuário ordenados pelo nome do set para determinismo
	var userSets []userSet
	for _, a := range c.Aliases {
		sName := aliasSetNames[a.ID]
		var elems []string
		if a.Tipo == fwmodel.AliasTipoEnderecos {
			el, err := normalizarEOptimizarSubredes(a.Itens)
			if err != nil {
				return Ruleset{}, fmt.Errorf("alias %q (%s): %w", a.Nome, a.ID, err)
			}
			elems = el
		} else {
			el, err := normalizarPortasAlias(a.Itens)
			if err != nil {
				return Ruleset{}, fmt.Errorf("alias %q (%s): %w", a.Nome, a.ID, err)
			}
			elems = el
		}
		userSets = append(userSets, userSet{
			id:        a.ID,
			nomeSet:   sName,
			tipo:      a.Tipo,
			elementos: elems,
		})
	}
	sort.Slice(userSets, func(i, j int) bool {
		return userSets[i].nomeSet < userSets[j].nomeSet
	})

	// Mapa com os elementos de cada set para computação de HashEntrada
	conteudoSets := make(map[string]string)
	conteudoSets["fwa_vcn"] = strings.Join(elementosVCN, ", ")
	conteudoSets["fwa_vpn"] = strings.Join(elementosVPN, ", ")
	conteudoSets["fwp_gerencia"] = strings.Join(elementosGerencia, ", ")
	for _, us := range userSets {
		conteudoSets[us.nomeSet] = strings.Join(us.elementos, ", ")
	}

	// 3. Processar pessoas da VPN e coletar avisos de aliases faltantes
	avisos := avisosPessoa
	pessoasOrdenadas := append([]PessoaVPN{}, in.Pessoas...)
	sort.Slice(pessoasOrdenadas, func(i, j int) bool {
		return strings.ToLower(pessoasOrdenadas[i].Usuario) < strings.ToLower(pessoasOrdenadas[j].Usuario)
	})

	// Filtrar e preparar os perfis das pessoas
	var pessoasProntas []pessoaPronta
	for _, p := range pessoasOrdenadas {
		pronta := pessoaPronta{p: p}
		if !p.Total {
			for _, aID := range p.Aliases {
				if aID == fwmodel.AliasVCN {
					pronta.aliases = append(pronta.aliases, aliasValidoPessoa{id: aID, nome: "VCN", set: "fwa_vcn"})
				} else if aID == fwmodel.AliasVPN {
					pronta.aliases = append(pronta.aliases, aliasValidoPessoa{id: aID, nome: "VPN", set: "fwa_vpn"})
				} else if a, ok := aliasMap[aID]; ok && a.Tipo == fwmodel.AliasTipoEnderecos {
					pronta.aliases = append(pronta.aliases, aliasValidoPessoa{id: aID, nome: a.Nome, set: aliasSetNames[aID]})
				} else {
					// Alias inexistente ou inválido no perfil da pessoa: emite aviso e não gera linha
					avisos = append(avisos, fwmodel.Problema{
						Severidade: "aviso",
						Onde:       "vpn:pessoa:" + p.UserID,
						Chave:      "fw.aviso.alias_inexistente",
						Vars: map[string]string{
							"alias":   aID,
							"usuario": p.Usuario,
						},
					})
				}
			}
			sort.Slice(pronta.aliases, func(i, j int) bool {
				return strings.ToLower(pronta.aliases[i].nome) < strings.ToLower(pronta.aliases[j].nome)
			})
		}
		pessoasProntas = append(pessoasProntas, pronta)
	}

	// 4. Construir as Linhas de cada zona (representação unificada para a tela e para o script)
	linhasPorZona := make(map[fwmodel.Zona][]Linha)
	for _, z := range fwmodel.Zonas {
		linhasPorZona[z] = []Linha{}
	}

	ctxRender := &contextoRender{
		config:         c,
		insumos:        in,
		aliasMap:       aliasMap,
		aliasSetNames:  aliasSetNames,
		agendamentoMap: agendamentoMap,
		pessoaMap:      pessoaMap,
	}

	linhasFlut, regrasFlutIn, regrasFlutFwd, err := montarLinhasFlutuante(ctxRender)
	if err != nil {
		return Ruleset{}, err
	}
	linhasPorZona[fwmodel.ZonaFlutuante] = linhasFlut

	linhasInet, regrasInetIn, regrasInetFwd, dnatRules, err := montarLinhasInternet(ctxRender)
	if err != nil {
		return Ruleset{}, err
	}
	linhasPorZona[fwmodel.ZonaInternet] = linhasInet

	linhasVCN, regrasVCNIn, regrasVCNFwd, err := montarLinhasVCN(ctxRender)
	if err != nil {
		return Ruleset{}, err
	}
	linhasPorZona[fwmodel.ZonaVCN] = linhasVCN

	linhasVPN, regrasVPNIn, regrasVPNFwd, err := montarLinhasVPN(ctxRender, pessoasProntas)
	if err != nil {
		return Ruleset{}, err
	}
	linhasPorZona[fwmodel.ZonaVPN] = linhasVPN

	// Regras das chains base input e forward (despachante)
	regrasInput := montarRegrasInput(in)
	regrasForward := montarRegrasForward(c.Ajustes, in)

	// 5. Montar o script final em formato atômico para `nft -f`
	var b strings.Builder

	b.WriteString("add table inet linkguard\n")
	b.WriteString("add set inet linkguard blocklist { type ipv4_addr; flags interval; }\n")
	b.WriteString("add set inet linkguard blocked_hosts { type ipv4_addr; }\n")
	b.WriteString("add set inet linkguard dom_blocked { type ipv4_addr; flags timeout; timeout 1h; size 8192; }\n")
	b.WriteString("add set inet linkguard dom_blocked6 { type ipv6_addr; flags timeout; timeout 1h; size 8192; }\n")
	b.WriteString("add set inet linkguard abusers { type ipv4_addr; flags dynamic,timeout; timeout 1h; }\n")

	// Set fwa_vcn
	b.WriteString("add set inet linkguard fwa_vcn { type ipv4_addr; flags interval; }\n")
	b.WriteString("flush set inet linkguard fwa_vcn\n")
	if len(elementosVCN) > 0 {
		b.WriteString(fmt.Sprintf("add element inet linkguard fwa_vcn { %s }\n", strings.Join(elementosVCN, ", ")))
	}

	// Set fwa_vpn
	b.WriteString("add set inet linkguard fwa_vpn { type ipv4_addr; flags interval; }\n")
	b.WriteString("flush set inet linkguard fwa_vpn\n")
	if len(elementosVPN) > 0 {
		b.WriteString(fmt.Sprintf("add element inet linkguard fwa_vpn { %s }\n", strings.Join(elementosVPN, ", ")))
	}

	// Set fwp_gerencia
	b.WriteString("add set inet linkguard fwp_gerencia { type inet_service; flags interval; }\n")
	b.WriteString("flush set inet linkguard fwp_gerencia\n")
	if len(elementosGerencia) > 0 {
		b.WriteString(fmt.Sprintf("add element inet linkguard fwp_gerencia { %s }\n", strings.Join(elementosGerencia, ", ")))
	}

	// Sets dos aliases do usuário
	for _, us := range userSets {
		tipoSet := "ipv4_addr"
		if us.tipo == fwmodel.AliasTipoPortas {
			tipoSet = "inet_service"
		}
		b.WriteString(fmt.Sprintf("add set inet linkguard %s { type %s; flags interval; }\n", us.nomeSet, tipoSet))
		b.WriteString(fmt.Sprintf("flush set inet linkguard %s\n", us.nomeSet))
		if len(us.elementos) > 0 {
			b.WriteString(fmt.Sprintf("add element inet linkguard %s { %s }\n", us.nomeSet, strings.Join(us.elementos, ", ")))
		}
	}

	// Chains de zona: flutuante
	b.WriteString("\nadd chain inet linkguard zona_flut_in\n")
	b.WriteString("flush chain inet linkguard zona_flut_in\n")
	for _, r := range regrasFlutIn {
		b.WriteString("add rule inet linkguard zona_flut_in " + r + "\n")
	}

	b.WriteString("add chain inet linkguard zona_flut_fwd\n")
	b.WriteString("flush chain inet linkguard zona_flut_fwd\n")
	for _, r := range regrasFlutFwd {
		b.WriteString("add rule inet linkguard zona_flut_fwd " + r + "\n")
	}

	// Chains de zona: internet
	b.WriteString("\nadd chain inet linkguard zona_inet_in\n")
	b.WriteString("flush chain inet linkguard zona_inet_in\n")
	for _, r := range regrasInetIn {
		b.WriteString("add rule inet linkguard zona_inet_in " + r + "\n")
	}

	b.WriteString("add chain inet linkguard zona_inet_fwd\n")
	b.WriteString("flush chain inet linkguard zona_inet_fwd\n")
	for _, r := range regrasInetFwd {
		b.WriteString("add rule inet linkguard zona_inet_fwd " + r + "\n")
	}

	// Chains de zona: vcn
	b.WriteString("\nadd chain inet linkguard zona_vcn_in\n")
	b.WriteString("flush chain inet linkguard zona_vcn_in\n")
	for _, r := range regrasVCNIn {
		b.WriteString("add rule inet linkguard zona_vcn_in " + r + "\n")
	}

	b.WriteString("add chain inet linkguard zona_vcn_fwd\n")
	b.WriteString("flush chain inet linkguard zona_vcn_fwd\n")
	for _, r := range regrasVCNFwd {
		b.WriteString("add rule inet linkguard zona_vcn_fwd " + r + "\n")
	}

	// Chains de zona: vpn
	b.WriteString("\nadd chain inet linkguard zona_vpn_in\n")
	b.WriteString("flush chain inet linkguard zona_vpn_in\n")
	for _, r := range regrasVPNIn {
		b.WriteString("add rule inet linkguard zona_vpn_in " + r + "\n")
	}

	b.WriteString("add chain inet linkguard zona_vpn_fwd\n")
	b.WriteString("flush chain inet linkguard zona_vpn_fwd\n")
	for _, r := range regrasVPNFwd {
		b.WriteString("add rule inet linkguard zona_vpn_fwd " + r + "\n")
	}

	// Base chain input
	b.WriteString("\nadd chain inet linkguard input { type filter hook input priority filter; policy accept; }\n")
	b.WriteString("flush chain inet linkguard input\n")
	for _, r := range regrasInput {
		b.WriteString("add rule inet linkguard input " + r + "\n")
	}

	// Base chain forward
	b.WriteString("\nadd chain inet linkguard forward { type filter hook forward priority filter; policy accept; }\n")
	b.WriteString("flush chain inet linkguard forward\n")
	for _, r := range regrasForward {
		b.WriteString("add rule inet linkguard forward " + r + "\n")
	}

	// Base chain prerouting_dnat (com fib daddr type local - defeito 6)
	b.WriteString("\nadd chain inet linkguard prerouting_dnat { type nat hook prerouting priority dstnat; policy accept; }\n")
	b.WriteString("flush chain inet linkguard prerouting_dnat\n")
	for _, r := range dnatRules {
		b.WriteString("add rule inet linkguard prerouting_dnat " + r + "\n")
	}

	// Limpeza do legado no final do mesmo script
	limpeza := montarLimpezaLegado(in.Existentes, userSets)
	if len(limpeza) > 0 {
		b.WriteString("\n" + strings.Join(limpeza, "\n") + "\n")
	}

	script := b.String()

	// 6. Computar HashEntrada: sha256 das linhas de input, zona_*_in e dos sets referenciados por elas
	hashEntrada := calcularHashEntrada(regrasInput, regrasFlutIn, regrasInetIn, regrasVCNIn, regrasVPNIn, conteudoSets)

	return Ruleset{
		Script:      script,
		Linhas:      linhasPorZona,
		HashEntrada: hashEntrada,
		Avisos:      avisos,
	}, nil
}

// validarUsoAliasEndereco confere se a referência a um alias de endereço em regra é válida.
func validarUsoAliasEndereco(val string, aliases map[string]fwmodel.Alias, pessoas map[string]PessoaVPN) error {
	if val == fwmodel.AliasVCN || val == fwmodel.AliasVPN {
		return nil
	}
	if strings.HasPrefix(val, fwmodel.AliasPessoaPref) {
		uid := strings.TrimPrefix(val, fwmodel.AliasPessoaPref)
		if _, ok := pessoas[uid]; !ok {
			return fmt.Errorf("referencia pessoa inexistente %q", uid)
		}
		return nil
	}
	a, ok := aliases[val]
	if !ok {
		return fmt.Errorf("referencia alias inexistente %q", val)
	}
	if a.Tipo != fwmodel.AliasTipoEnderecos {
		return fmt.Errorf("alias %q não é de endereços", val)
	}
	return nil
}

// normalizarEOptimizarSubredes parseia IPs e CIDRs, aplica a máscara de rede,
// remove sub-redes contidas em outras (ex: 10.0.0.0/24 some se 10.0.0.0/8 existe),
// deduplica e ordena de forma determinística por IP e comprimento de máscara.
func normalizarEOptimizarSubredes(entradas []string) ([]string, error) {
	type itemNet struct {
		ip       net.IP
		ipnet    *net.IPNet
		isSingle bool
	}

	var parsed []itemNet
	for _, raw := range entradas {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if strings.Contains(s, "/") {
			_, netw, err := net.ParseCIDR(s)
			if err != nil || netw == nil || netw.IP.To4() == nil {
				return nil, fmt.Errorf("endereço/sub-rede IPv4 inválido: %q", s)
			}
			ones, bits := netw.Mask.Size()
			if bits == 32 && ones == 32 {
				parsed = append(parsed, itemNet{ip: netw.IP.To4(), ipnet: netw, isSingle: true})
			} else {
				parsed = append(parsed, itemNet{ip: netw.IP.To4(), ipnet: netw, isSingle: false})
			}
		} else {
			ip := net.ParseIP(s)
			if ip == nil || ip.To4() == nil {
				return nil, fmt.Errorf("endereço IPv4 inválido: %q", s)
			}
			ip4 := ip.To4()
			mask := net.CIDRMask(32, 32)
			parsed = append(parsed, itemNet{ip: ip4, ipnet: &net.IPNet{IP: ip4, Mask: mask}, isSingle: true})
		}
	}

	if len(parsed) == 0 {
		return []string{}, nil
	}

	// Deduplicar equivalentes
	dedup := make([]itemNet, 0, len(parsed))
	for _, it := range parsed {
		duplicado := false
		for _, ex := range dedup {
			if it.ipnet.IP.Equal(ex.ipnet.IP) && it.ipnet.Mask.String() == ex.ipnet.Mask.String() {
				duplicado = true
				break
			}
		}
		if !duplicado {
			dedup = append(dedup, it)
		}
	}

	// Remover prefixos contidos em outros maiores
	// Se A contém B e o prefixo de A é menor ou igual ao de B, B é redundante
	var filtrados []itemNet
	for i, a := range dedup {
		contido := false
		onesA, _ := a.ipnet.Mask.Size()
		for j, b := range dedup {
			if i == j {
				continue
			}
			onesB, _ := b.ipnet.Mask.Size()
			if onesB <= onesA && b.ipnet.Contains(a.ipnet.IP) {
				// b é maior ou igual e engloba a
				contido = true
				break
			}
		}
		if !contido {
			filtrados = append(filtrados, a)
		}
	}

	// Ordenar por valor IP e depois por tamanho da máscara
	sort.Slice(filtrados, func(i, j int) bool {
		cmp := compareIPv4(filtrados[i].ipnet.IP, filtrados[j].ipnet.IP)
		if cmp != 0 {
			return cmp < 0
		}
		onesI, _ := filtrados[i].ipnet.Mask.Size()
		onesJ, _ := filtrados[j].ipnet.Mask.Size()
		return onesI < onesJ
	})

	resultado := make([]string, 0, len(filtrados))
	for _, it := range filtrados {
		if it.isSingle {
			resultado = append(resultado, it.ip.String())
		} else {
			resultado = append(resultado, it.ipnet.String())
		}
	}
	return resultado, nil
}

func compareIPv4(a, b net.IP) int {
	a4 := a.To4()
	b4 := b.To4()
	if a4 == nil || b4 == nil {
		return 0
	}
	for k := 0; k < 4; k++ {
		if a4[k] < b4[k] {
			return -1
		}
		if a4[k] > b4[k] {
			return 1
		}
	}
	return 0
}

func normalizarPortasGerencia(portas []int) []string {
	if len(portas) == 0 {
		return []string{}
	}
	vistos := make(map[int]bool)
	var ordenadas []int
	for _, p := range portas {
		if p >= 1 && p <= 65535 && !vistos[p] {
			vistos[p] = true
			ordenadas = append(ordenadas, p)
		}
	}
	sort.Ints(ordenadas)
	out := make([]string, 0, len(ordenadas))
	for _, p := range ordenadas {
		out = append(out, strconv.Itoa(p))
	}
	return out
}

func normalizarPortasAlias(itens []string) ([]string, error) {
	type portRange struct {
		original string
		start    int
		end      int
	}
	var ranges []portRange
	vistos := make(map[string]bool)

	for _, raw := range itens {
		s := strings.TrimSpace(raw)
		if s == "" || vistos[s] {
			continue
		}
		if !validPort(s) {
			return nil, fmt.Errorf("porta ou intervalo de portas inválido: %q", s)
		}
		vistos[s] = true

		if strings.Contains(s, "-") {
			parts := strings.Split(s, "-")
			a, _ := strconv.Atoi(parts[0])
			b, _ := strconv.Atoi(parts[1])
			ranges = append(ranges, portRange{original: s, start: a, end: b})
		} else {
			p, _ := strconv.Atoi(s)
			ranges = append(ranges, portRange{original: s, start: p, end: p})
		}
	}

	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].start != ranges[j].start {
			return ranges[i].start < ranges[j].start
		}
		return ranges[i].end < ranges[j].end
	})

	out := make([]string, 0, len(ranges))
	for _, r := range ranges {
		out = append(out, r.original)
	}
	return out, nil
}

// montarLimpezaLegado gera os comandos de exclusão e flush para chains e sets legados.
func montarLimpezaLegado(existentes Existentes, userSets []userSet) []string {
	var linhas []string

	// Chains a limpar: grp_* e user_rules
	var chainsParaApagar []string
	for _, ch := range existentes.Chains {
		if strings.HasPrefix(ch, "grp_") || ch == "user_rules" {
			chainsParaApagar = append(chainsParaApagar, ch)
		}
	}
	sort.Strings(chainsParaApagar)
	for _, ch := range chainsParaApagar {
		linhas = append(linhas, fmt.Sprintf("flush chain inet linkguard %s", ch))
		linhas = append(linhas, fmt.Sprintf("delete chain inet linkguard %s", ch))
	}

	// Sets a apagar: blocked_macs e sets fwa_*/fwp_* que não estão mais na configuração
	setsAtuais := map[string]bool{
		"fwa_vcn":       true,
		"fwa_vpn":       true,
		"fwp_gerencia":  true,
		"blocklist":     true,
		"blocked_hosts": true,
		"dom_blocked":   true,
		"dom_blocked6":  true,
		"abusers":       true,
	}
	for _, us := range userSets {
		setsAtuais[us.nomeSet] = true
	}

	var setsParaApagar []string
	for _, st := range existentes.Sets {
		if st == "blocked_macs" {
			setsParaApagar = append(setsParaApagar, st)
			continue
		}
		if (strings.HasPrefix(st, "fwa_") || strings.HasPrefix(st, "fwp_")) && !setsAtuais[st] {
			setsParaApagar = append(setsParaApagar, st)
		}
	}
	sort.Strings(setsParaApagar)
	for _, st := range setsParaApagar {
		linhas = append(linhas, fmt.Sprintf("delete set inet linkguard %s", st))
	}

	return linhas
}

// calcularHashEntrada calcula o SHA256 em hexadecimal de todas as regras de entrada
// (input e zona_*_in) e dos elementos dos sets que elas consultam.
func calcularHashEntrada(regrasInput, flutIn, inetIn, vcnIn, vpnIn []string, sets map[string]string) string {
	var sb strings.Builder

	adicionarRegras := func(nomeChain string, regras []string) {
		sb.WriteString("chain:" + nomeChain + "\n")
		for _, r := range regras {
			sb.WriteString(r + "\n")
		}
	}

	adicionarRegras("zona_flut_in", flutIn)
	adicionarRegras("zona_inet_in", inetIn)
	adicionarRegras("zona_vcn_in", vcnIn)
	adicionarRegras("zona_vpn_in", vpnIn)
	adicionarRegras("input", regrasInput)

	// Achar todos os sets referenciados (@nome_do_set)
	textoEntrada := sb.String()
	reSetRef := regexp.MustCompile(`@([a-zA-Z0-9_]+)`)
	matches := reSetRef.FindAllStringSubmatch(textoEntrada, -1)
	setsReferenciados := make(map[string]bool)
	for _, m := range matches {
		if len(m) > 1 {
			setsReferenciados[m[1]] = true
		}
	}

	var nomesSets []string
	for sName := range setsReferenciados {
		nomesSets = append(nomesSets, sName)
	}
	sort.Strings(nomesSets)

	for _, sName := range nomesSets {
		sb.WriteString("set:" + sName + ":" + sets[sName] + "\n")
	}

	sum := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(sum[:])
}

// semRegrasDePessoaRemovida devolve uma cópia de c sem as regras cuja origem ou
// destino é uma pessoa que já não tem VPN. Revogar o acesso remove o peer, e a
// regra que apontava para ele não pode travar o firewall inteiro: é a
// revogação que precisa alcançar as regras. A config armazenada não muda; a
// regra fica na tela, e cada uma descartada vira um aviso.
func semRegrasDePessoaRemovida(c fwmodel.Config, userIDs []string) (fwmodel.Config, []fwmodel.Problema) {
	presentes := make(map[string]bool, len(userIDs))
	for _, id := range userIDs {
		presentes[id] = true
	}
	orfa := func(p fwmodel.Ponta) bool {
		if p.Tipo != fwmodel.PontaAlias || !strings.HasPrefix(p.Valor, fwmodel.AliasPessoaPref) {
			return false
		}
		return !presentes[strings.TrimPrefix(p.Valor, fwmodel.AliasPessoaPref)]
	}
	var avisos []fwmodel.Problema
	var mantidas []fwmodel.Regra
	descartou := false
	for _, r := range c.Regras {
		if orfa(r.Origem) || orfa(r.Destino) {
			descartou = true
			avisos = append(avisos, fwmodel.Problema{
				Severidade: "aviso",
				Onde:       "regra:" + r.ID,
				Chave:      "fwz.aviso.regraPessoaRemovida",
				Vars:       map[string]string{"regra": nomeDaRegra(r)},
			})
			continue
		}
		mantidas = append(mantidas, r)
	}
	if !descartou {
		return c, nil
	}
	c.Regras = mantidas
	return c, avisos
}

func nomeDaRegra(r fwmodel.Regra) string {
	if d := strings.TrimSpace(r.Descricao); d != "" {
		return d
	}
	return r.ID
}
