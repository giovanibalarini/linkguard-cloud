package fwmodel

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// MaxDescricaoRegra é o maior tamanho, em caracteres, da descrição de uma regra.
const MaxDescricaoRegra = 200

// MaxIDObjeto é o maior tamanho do identificador de uma regra, alias, agendamento ou encaminhamento.
const MaxIDObjeto = 64

// Os identificadores entram no script do nft (comentário da regra e nome do set do alias);
// só letras, dígitos, "_" e "-" garantem que nenhum deles escapa das aspas ou vira outro comando.
var reIDObjeto = regexp.MustCompile(`^[A-Za-z0-9_-]{1,` + strconv.Itoa(MaxIDObjeto) + `}$`)

// IDValido diz se o identificador pode entrar no script do nft.
func IDValido(id string) bool {
	return reIDObjeto.MatchString(id)
}

func idParaMensagem(id string) string {
	r := []rune(id)
	if len(r) > MaxIDObjeto {
		return string(r[:MaxIDObjeto]) + "…"
	}
	return id
}

// Problema descreve um erro ou aviso encontrado durante a validação da configuração.
type Problema struct {
	Severidade string            `json:"severidade"` // "erro" | "aviso"
	Onde       string            `json:"onde"`       // "regra:<id>", "alias:<id>", "agendamento:<id>", "encaminhamento:<id>", "ajustes"
	Chave      string            `json:"chave"`      // chave i18n
	Vars       map[string]string `json:"vars,omitempty"`
}

// TemErro verifica se há algum problema com severidade de erro na lista.
func TemErro(ps []Problema) bool {
	for _, p := range ps {
		if p.Severidade == "erro" {
			return true
		}
	}
	return false
}

// isIPv4 verifica se a string representa um endereço IPv4 único válido.
func isIPv4(s string) bool {
	s = strings.TrimSpace(s)
	a, err := netip.ParseAddr(s)
	return err == nil && a.Is4()
}

// isIPv4CIDR verifica se a string representa uma sub-rede IPv4 CIDR válida.
func isIPv4CIDR(s string) bool {
	s = strings.TrimSpace(s)
	p, err := netip.ParsePrefix(s)
	return err == nil && p.Addr().Is4()
}

// isIPv4OrCIDR verifica se a string é IPv4 ou sub-rede IPv4 CIDR válida.
func isIPv4OrCIDR(s string) bool {
	return isIPv4(s) || isIPv4CIDR(s)
}

// isValidPortOrRange valida se o valor é uma porta individual (1-65535) ou faixa "a-b" (1 <= a < b <= 65535).
func isValidPortOrRange(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if strings.Contains(s, "-") {
		parts := strings.Split(s, "-")
		if len(parts) != 2 {
			return false
		}
		a, errA := strconv.Atoi(strings.TrimSpace(parts[0]))
		b, errB := strconv.Atoi(strings.TrimSpace(parts[1]))
		if errA != nil || errB != nil {
			return false
		}
		return a >= 1 && b <= 65535 && a < b
	}
	p, err := strconv.Atoi(s)
	if err != nil {
		return false
	}
	return p >= 1 && p <= 65535
}

// isNomeAliasReservado confere se o nome conflita com nomes reservados pelo sistema.
func isNomeAliasReservado(nome string) bool {
	low := strings.ToLower(strings.TrimSpace(nome))
	if strings.HasPrefix(low, "sys:") {
		return true
	}
	switch low {
	case "vcn", "vpn", "gerência", "gerencia", "este firewall":
		return true
	}
	return false
}

// Validar confere a configuração inteira e devolve os problemas encontrados.
// pessoas recebe a lista de user_ids dos clientes VPN para validação de sys:pessoa:<id>.
func Validar(c Config, pessoas []string) []Problema {
	var prob []Problema

	addErro := func(onde, chave string, vars map[string]string) {
		prob = append(prob, Problema{
			Severidade: "erro",
			Onde:       onde,
			Chave:      chave,
			Vars:       vars,
		})
	}

	addAviso := func(onde, chave string, vars map[string]string) {
		prob = append(prob, Problema{
			Severidade: "aviso",
			Onde:       onde,
			Chave:      chave,
			Vars:       vars,
		})
	}

	// Mapeia pessoas da VPN
	pessoasMap := make(map[string]bool, len(pessoas))
	for _, p := range pessoas {
		pessoasMap[p] = true
	}

	// 1. Validar Aliases
	aliasMap := make(map[string]Alias, len(c.Aliases))
	nomesAlias := make(map[string]string, len(c.Aliases))

	for _, a := range c.Aliases {
		onde := "alias:" + a.ID
		if a.ID == "" {
			addErro(onde, "fwz.problema.aliasIdVazio", nil)
		} else if !IDValido(a.ID) {
			addErro(onde, "fwz.problema.aliasIdInvalido", map[string]string{"id": idParaMensagem(a.ID)})
		}

		nomeTrim := strings.TrimSpace(a.Nome)
		nomeRuneLen := len([]rune(nomeTrim))
		if nomeRuneLen < 1 || nomeRuneLen > 64 {
			addErro(onde, "fwz.problema.aliasNomeTamanhoInvalido", map[string]string{"nome": a.Nome})
		}
		if isNomeAliasReservado(nomeTrim) {
			addErro(onde, "fwz.problema.aliasNomeReservado", map[string]string{"nome": a.Nome})
		}
		nomeChave := strings.ToLower(nomeTrim)
		if outroID, existe := nomesAlias[nomeChave]; existe {
			addErro(onde, "fwz.problema.aliasNomeDuplicado", map[string]string{"nome": a.Nome, "outro_id": outroID})
		} else {
			nomesAlias[nomeChave] = a.ID
		}

		if a.Tipo != AliasTipoEnderecos && a.Tipo != AliasTipoPortas {
			addErro(onde, "fwz.problema.aliasTipoInvalido", map[string]string{"tipo": string(a.Tipo)})
		}

		if len(a.Itens) > 4096 {
			addErro(onde, "fwz.problema.aliasMuitosItens", map[string]string{"qtd": strconv.Itoa(len(a.Itens))})
		}

		for _, item := range a.Itens {
			if a.Tipo == AliasTipoEnderecos {
				if !isIPv4OrCIDR(item) {
					addErro(onde, "fwz.problema.aliasItemEnderecoInvalido", map[string]string{"item": item})
				}
			} else if a.Tipo == AliasTipoPortas {
				if !isValidPortOrRange(item) {
					addErro(onde, "fwz.problema.aliasItemPortaInvalido", map[string]string{"item": item})
				}
			}
		}

		aliasMap[a.ID] = a
	}

	// 2. Validar Agendamentos
	agendamentoMap := make(map[string]Agendamento, len(c.Agendamentos))
	nomesAgendamento := make(map[string]string, len(c.Agendamentos))

	for _, ag := range c.Agendamentos {
		onde := "agendamento:" + ag.ID
		if ag.ID == "" {
			addErro(onde, "fwz.problema.agendamentoIdVazio", nil)
		} else if !IDValido(ag.ID) {
			addErro(onde, "fwz.problema.agendamentoIdInvalido", map[string]string{"id": idParaMensagem(ag.ID)})
		}

		nomeTrim := strings.TrimSpace(ag.Nome)
		if nomeTrim == "" {
			addErro(onde, "fwz.problema.agendamentoNomeVazio", nil)
		}
		nomeChave := strings.ToLower(nomeTrim)
		if outroID, existe := nomesAgendamento[nomeChave]; existe {
			addErro(onde, "fwz.problema.agendamentoNomeDuplicado", map[string]string{"nome": ag.Nome, "outro_id": outroID})
		} else {
			nomesAgendamento[nomeChave] = ag.ID
		}

		if err := ValidarDias(ag.Dias); err != nil {
			addErro(onde, "fwz.problema.agendamentoDiasInvalidos", map[string]string{"erro": err.Error()})
		}

		// Para agendamentos cadastrados, início e fim são horários explícitos
		if strings.TrimSpace(ag.Inicio) == "" || strings.TrimSpace(ag.Fim) == "" {
			addErro(onde, "fwz.problema.agendamentoHorarioObrigatorio", nil)
		} else if err := ValidarHorario(ag.Inicio, ag.Fim); err != nil {
			addErro(onde, "fwz.problema.agendamentoHorarioInvalido", map[string]string{"erro": err.Error()})
		}

		agendamentoMap[ag.ID] = ag
	}

	// 3. Validar Regras
	posicoesPorZona := make(map[Zona]map[int]bool)
	type regraAssinatura struct {
		acao         Acao
		proto        Proto
		origem       Ponta
		destino      Ponta
		portaDestino Porta
		agendamento  string
	}
	regrasAtivasPorZona := make(map[Zona]map[regraAssinatura]bool)

	for _, z := range Zonas {
		posicoesPorZona[z] = make(map[int]bool)
		regrasAtivasPorZona[z] = make(map[regraAssinatura]bool)
	}

	for _, r := range c.Regras {
		onde := "regra:" + r.ID
		if r.ID == "" {
			addErro(onde, "fwz.problema.regraIdVazio", nil)
		} else if !IDValido(r.ID) {
			addErro(onde, "fwz.problema.regraIdInvalido", map[string]string{"id": idParaMensagem(r.ID)})
		}

		// Zona
		switch r.Zona {
		case ZonaFlutuante, ZonaInternet, ZonaVCN, ZonaVPN:
		default:
			addErro(onde, "fwz.problema.zonaInvalida", map[string]string{"zona": string(r.Zona)})
		}

		// Acao
		switch r.Acao {
		case AcaoAccept, AcaoDrop, AcaoReject:
		default:
			addErro(onde, "fwz.problema.acaoInvalida", map[string]string{"acao": string(r.Acao)})
		}

		// Proto
		switch r.Proto {
		case ProtoQualquer, ProtoTCP, ProtoUDP, ProtoTCPUDP, ProtoICMP:
		default:
			addErro(onde, "fwz.problema.protoInvalido", map[string]string{"proto": string(r.Proto)})
		}

		// Origem
		switch r.Origem.Tipo {
		case PontaQualquer:
		case PontaEndereco:
			if !isIPv4OrCIDR(r.Origem.Valor) {
				addErro(onde, "fwz.problema.origemEnderecoInvalido", map[string]string{"valor": r.Origem.Valor})
			}
		case PontaAlias:
			val := r.Origem.Valor
			switch {
			case val == AliasVCN || val == AliasVPN:
				// Válido
			case strings.HasPrefix(val, AliasPessoaPref):
				uid := strings.TrimPrefix(val, AliasPessoaPref)
				if !pessoasMap[uid] {
					addErro(onde, "fwz.problema.origemPessoaInexistente", map[string]string{"pessoa": uid})
				}
			default:
				a, ok := aliasMap[val]
				if !ok {
					addErro(onde, "fwz.problema.origemAliasInexistente", map[string]string{"alias": val})
				} else if a.Tipo != AliasTipoEnderecos {
					addErro(onde, "fwz.problema.origemAliasTipoInvalido", map[string]string{"alias": val})
				}
			}
		case PontaEste:
			addErro(onde, "fwz.problema.origemSelfInvalida", nil)
		default:
			addErro(onde, "fwz.problema.origemTipoInvalido", map[string]string{"tipo": string(r.Origem.Tipo)})
		}

		// Destino
		switch r.Destino.Tipo {
		case PontaQualquer, PontaEste:
		case PontaEndereco:
			if !isIPv4OrCIDR(r.Destino.Valor) {
				addErro(onde, "fwz.problema.destinoEnderecoInvalido", map[string]string{"valor": r.Destino.Valor})
			}
		case PontaAlias:
			val := r.Destino.Valor
			switch {
			case val == AliasVCN || val == AliasVPN:
				// Válido
			case strings.HasPrefix(val, AliasPessoaPref):
				uid := strings.TrimPrefix(val, AliasPessoaPref)
				if !pessoasMap[uid] {
					addErro(onde, "fwz.problema.destinoPessoaInexistente", map[string]string{"pessoa": uid})
				}
			default:
				a, ok := aliasMap[val]
				if !ok {
					addErro(onde, "fwz.problema.destinoAliasInexistente", map[string]string{"alias": val})
				} else if a.Tipo != AliasTipoEnderecos {
					addErro(onde, "fwz.problema.destinoAliasTipoInvalido", map[string]string{"alias": val})
				}
			}
		default:
			addErro(onde, "fwz.problema.destinoTipoInvalido", map[string]string{"tipo": string(r.Destino.Tipo)})
		}

		// Porta de Destino
		switch r.PortaDestino.Tipo {
		case PortaQualquer:
		case PortaValor:
			if r.Proto != ProtoTCP && r.Proto != ProtoUDP && r.Proto != ProtoTCPUDP {
				addErro(onde, "fwz.problema.portaSemProtocoloValido", map[string]string{"proto": string(r.Proto)})
			}
			if !isValidPortOrRange(r.PortaDestino.Valor) {
				addErro(onde, "fwz.problema.portaValorInvalido", map[string]string{"valor": r.PortaDestino.Valor})
			}
		case PortaAlias:
			if r.Proto != ProtoTCP && r.Proto != ProtoUDP && r.Proto != ProtoTCPUDP {
				addErro(onde, "fwz.problema.portaSemProtocoloValido", map[string]string{"proto": string(r.Proto)})
			}
			val := r.PortaDestino.Valor
			if val == AliasGerencia {
				// Válido
			} else {
				a, ok := aliasMap[val]
				if !ok {
					addErro(onde, "fwz.problema.portaAliasInexistente", map[string]string{"alias": val})
				} else if a.Tipo != AliasTipoPortas {
					addErro(onde, "fwz.problema.portaAliasTipoInvalido", map[string]string{"alias": val})
				}
			}
		default:
			addErro(onde, "fwz.problema.portaTipoInvalido", map[string]string{"tipo": string(r.PortaDestino.Tipo)})
		}

		// Agendamento
		if r.AgendamentoID != "" {
			if _, ok := agendamentoMap[r.AgendamentoID]; !ok {
				addErro(onde, "fwz.problema.regraAgendamentoInexistente", map[string]string{"agendamento": r.AgendamentoID})
			}
		}

		// Descrição
		if len([]rune(r.Descricao)) > MaxDescricaoRegra {
			addErro(onde, "fwz.problema.descricaoMuitoLonga", map[string]string{"tamanho": strconv.Itoa(len([]rune(r.Descricao)))})
		}

		// Posição única por zona
		if posicoes, ok := posicoesPorZona[r.Zona]; ok {
			if posicoes[r.Posicao] {
				addErro(onde, "fwz.problema.posicaoDuplicada", map[string]string{"posicao": strconv.Itoa(r.Posicao), "zona": string(r.Zona)})
			} else {
				posicoes[r.Posicao] = true
			}
		}

		// Avisos (não bloqueiam aplicação):
		// 1. Origem sys:vcn na aba VPN
		if r.Zona == ZonaVPN && r.Origem.Tipo == PontaAlias && r.Origem.Valor == AliasVCN {
			addAviso(onde, "fwz.problema.origemVCNEmVPN", nil)
		}
		// 2. Origem sys:vpn na aba VCN
		if r.Zona == ZonaVCN && r.Origem.Tipo == PontaAlias && r.Origem.Valor == AliasVPN {
			addAviso(onde, "fwz.problema.origemVPNEmVCN", nil)
		}
		// 3. Regra ativa idêntica a outra na mesma zona
		if r.Ativa {
			ass := regraAssinatura{
				acao:         r.Acao,
				proto:        r.Proto,
				origem:       r.Origem,
				destino:      r.Destino,
				portaDestino: r.PortaDestino,
				agendamento:  r.AgendamentoID,
			}
			if ativas, ok := regrasAtivasPorZona[r.Zona]; ok {
				if ativas[ass] {
					addAviso(onde, "fwz.problema.regraIdentica", map[string]string{"zona": string(r.Zona)})
				} else {
					ativas[ass] = true
				}
			}
		}
	}

	// 4. Validar Encaminhamentos
	ativosDNAT := make(map[string]bool)
	for _, enc := range c.Encaminhamentos {
		onde := "encaminhamento:" + enc.ID
		if enc.ID == "" {
			addErro(onde, "fwz.problema.encaminhamentoIdVazio", nil)
		} else if !IDValido(enc.ID) {
			addErro(onde, "fwz.problema.encaminhamentoIdInvalido", map[string]string{"id": idParaMensagem(enc.ID)})
		}
		proto := strings.ToLower(enc.Proto)
		if proto != "tcp" && proto != "udp" {
			addErro(onde, "fwz.problema.encaminhamentoProtoInvalido", map[string]string{"proto": enc.Proto})
		}
		if enc.PortaExterna < 1 || enc.PortaExterna > 65535 {
			addErro(onde, "fwz.problema.encaminhamentoPortaExternaInvalida", map[string]string{"porta": strconv.Itoa(enc.PortaExterna)})
		}
		if !isIPv4(enc.IPDestino) {
			addErro(onde, "fwz.problema.encaminhamentoIPDestinoInvalido", map[string]string{"ip": enc.IPDestino})
		}
		if enc.PortaDestino < 1 || enc.PortaDestino > 65535 {
			addErro(onde, "fwz.problema.encaminhamentoPortaDestinoInvalida", map[string]string{"porta": strconv.Itoa(enc.PortaDestino)})
		}

		if enc.Ativo {
			chaveDNAT := fmt.Sprintf("%s:%d", proto, enc.PortaExterna)
			if ativosDNAT[chaveDNAT] {
				addErro(onde, "fwz.problema.encaminhamentoPortaExternaConflito", map[string]string{
					"proto": proto,
					"porta": strconv.Itoa(enc.PortaExterna),
				})
			} else {
				ativosDNAT[chaveDNAT] = true
			}
		}
	}

	// 5. Validar Ajustes
	ondeAjustes := "ajustes"
	for z := range c.Ajustes.AntiBloqueio {
		if z != ZonaVCN && z != ZonaVPN {
			addErro(ondeAjustes, "fwz.problema.ajustesAntiBloqueioZonaInvalida", map[string]string{"zona": string(z)})
		}
	}
	for _, r := range c.Ajustes.RedesVCNExtras {
		if !isIPv4CIDR(r) {
			addErro(ondeAjustes, "fwz.problema.ajustesRedeVCNInvalida", map[string]string{"rede": r})
		}
	}

	return prob
}
