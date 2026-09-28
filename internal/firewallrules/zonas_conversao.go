package firewallrules

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strings"

	"github.com/google/uuid"

	"github.com/giovanibalarini/linkguard-cloud/internal/fwmodel"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

// FatosConversao reúne informações do ambiente de rede necessárias para converter
// as regras e grupos legados para as quatro zonas do novo modelo.
type FatosConversao struct {
	RedesVCN     []string
	RedeVPN      string
	InterfaceVPN string
	PlacasWAN    []string
}

// ItemRelatorioConversao descreve uma decisão tomada durante a conversão do legado
// que requer atenção do administrador.
type ItemRelatorioConversao struct {
	Tipo     string            `json:"tipo"`            // "flutuante" | "politica" | "aviso"
	Origem   string            `json:"origem"`          // ex: "regra:<id>", "grupo:<id>", "politica:input"
	Mensagem string            `json:"mensagem"`        // texto em português, para relatórios já gravados e logs
	Chave    string            `json:"chave,omitempty"` // chave i18n do painel; vence Mensagem quando presente
	Vars     map[string]string `json:"vars,omitempty"`
	Detalhes string            `json:"detalhes,omitempty"` // detalhes adicionais
}

// ConverterLegadoUmaVez converte grupos e regras do modelo legado para a configuração
// em edição por zonas, gerando os agendamentos necessários, ajustes de postura e relatório
// de decisões tomadas. Não chama o nftables: quem aplica no boot é RenderizarNoBoot.
//
// A operação é idempotente protegida pelo setting "fw_zonas_convertido" = "1".
func (s *Service) ConverterLegadoUmaVez(ctx context.Context, f FatosConversao) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	convertido, err := s.db.GetSetting("fw_zonas_convertido")
	if err != nil {
		return fmt.Errorf("ler a trava fw_zonas_convertido: %w", err)
	}
	if convertido != "" {
		return nil
	}

	if f.InterfaceVPN == "" {
		f.InterfaceVPN = "linkguard"
	}
	if f.RedeVPN == "" {
		if val, err := s.db.GetSetting("wireguard_network"); err == nil && val != "" {
			f.RedeVPN = val
		}
	}

	grupos, err := s.db.ListFirewallGroups()
	if err != nil {
		return fmt.Errorf("listar grupos de firewall: %w", err)
	}
	regrasLegadas, err := s.db.ListFirewallRules()
	if err != nil {
		return fmt.Errorf("listar regras de firewall: %w", err)
	}

	regrasPorGrupo := make(map[string][]storage.FirewallRule)
	for _, r := range regrasLegadas {
		if r.GroupID != "" {
			regrasPorGrupo[r.GroupID] = append(regrasPorGrupo[r.GroupID], r)
		}
	}

	var regrasFlutuante []fwmodel.Regra
	var regrasInternet []fwmodel.Regra
	var regrasVCN []fwmodel.Regra
	var regrasVPN []fwmodel.Regra

	var agendamentos []fwmodel.Agendamento
	schedMap := make(map[string]string) // "dias|inicio|fim" -> agendamento ID
	var relatorio []ItemRelatorioConversao

	// 1. Regra de gerência na Internet (SSH e painel web)
	wanClosedVal, _ := s.db.GetSetting("firewall_wan_mgmt_closed")
	wanClosed := wanClosedVal == "1"

	regraWanMgmt := fwmodel.Regra{
		ID:           "r-wan-gerencia",
		Zona:         fwmodel.ZonaInternet,
		Posicao:      1,
		Ativa:        !wanClosed,
		Acao:         fwmodel.AcaoAccept,
		Proto:        fwmodel.ProtoTCP,
		Origem:       fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
		Destino:      fwmodel.Ponta{Tipo: fwmodel.PontaEste},
		PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaAlias, Valor: fwmodel.AliasGerencia},
		Descricao:    "Gerência (SSH e painel) aberta para a Internet — restrinja a origem",
	}
	regrasInternet = append(regrasInternet, regraWanMgmt)

	// 2. Mapeamento dos grupos do admin e suas regras
	for _, g := range grupos {
		// Ignora os grupos do sistema (kind blocked_hosts/blocklist: viram linhas
		// travadas do modelo novo) e os de VPN (derivados dos perfis).
		if g.Kind == "blocked_hosts" || g.Kind == "blocklist" || g.Kind == "wireguard_peer" {
			continue
		}

		// Agendamento do grupo (deduplicado pela tripla dias|inicio|fim)
		var agID string
		if g.SchedDays != "" || g.SchedStart != "" || g.SchedEnd != "" {
			tripla := fmt.Sprintf("%s|%s|%s", g.SchedDays, g.SchedStart, g.SchedEnd)
			if existingID, ok := schedMap[tripla]; ok {
				agID = existingID
			} else {
				agID = fmt.Sprintf("ag-%s", uuid.NewString()[:8])
				schedMap[tripla] = agID
				agendamentos = append(agendamentos, fwmodel.Agendamento{
					ID:        agID,
					Nome:      "Horário de " + g.Name,
					Descricao: "Agendamento migrado do grupo " + g.Name,
					Dias:      g.SchedDays,
					Inicio:    g.SchedStart,
					Fim:       g.SchedEnd,
				})
			}
		}

		regrasDoGrupo := regrasPorGrupo[g.ID]
		for _, r := range regrasDoGrupo {
			if strings.HasPrefix(r.Description, "ZTNA:") {
				continue
			}

			origemEfetiva := r.Saddr
			if origemEfetiva == "" {
				origemEfetiva = g.CondSaddr
			}
			ifaceEfetiva := r.Iif
			if ifaceEfetiva == "" {
				ifaceEfetiva = g.CondIif
			}

			desc := r.Description
			if desc == "" {
				desc = fmt.Sprintf("Regra do grupo %s", g.Name)
			}

			daddrDif := r.Daddr != "" && g.CondDaddr != "" && r.Daddr != g.CondDaddr

			zona, revisar := classificarZona(origemEfetiva, ifaceEfetiva, r.Oif, daddrDif, f)
			ativa := r.Enabled && g.Enabled
			if revisar {
				ativa = false
				if !strings.HasPrefix(desc, "[revisar] ") {
					desc = "[revisar] " + desc
				}
				relatorio = append(relatorio, ItemRelatorioConversao{
					Tipo:     "flutuante",
					Origem:   "regra:" + r.ID,
					Mensagem: fmt.Sprintf("Regra %q movida para Flutuantes (desativada) para revisão manual", desc),
					Chave:    "fwz.conversao.msg.regraFlutuante",
					Vars:     map[string]string{"regra": desc},
				})
			}

			// Destino
			var pontaDestino fwmodel.Ponta
			if g.Scope == "input" {
				pontaDestino = fwmodel.Ponta{Tipo: fwmodel.PontaEste}
			} else {
				daddr := r.Daddr
				if daddr == "" {
					daddr = g.CondDaddr
				}
				pontaDestino = parsePontaEndereco(daddr)
			}

			// Origem
			pontaOrigem := parsePontaEndereco(origemEfetiva)

			// Ação
			acao := fwmodel.Acao(strings.ToLower(r.Action))
			if acao == "" {
				acao = fwmodel.AcaoAccept
			}

			// Proto
			proto := fwmodel.Proto(strings.ToLower(r.Proto))
			if proto == "" || proto == "any" {
				proto = fwmodel.ProtoQualquer
			}

			// Porta
			var portaDestino fwmodel.Porta
			if r.Dport != "" && r.Dport != "any" {
				portaDestino = fwmodel.Porta{Tipo: fwmodel.PortaValor, Valor: r.Dport}
			} else {
				portaDestino = fwmodel.Porta{Tipo: fwmodel.PortaQualquer}
			}

			regraNova := fwmodel.Regra{
				ID:            r.ID,
				Zona:          zona,
				Ativa:         ativa,
				Acao:          acao,
				Proto:         proto,
				Origem:        pontaOrigem,
				Destino:       pontaDestino,
				PortaDestino:  portaDestino,
				AgendamentoID: agID,
				Registrar:     false,
				Descricao:     desc,
			}

			switch zona {
			case fwmodel.ZonaInternet:
				regrasInternet = append(regrasInternet, regraNova)
			case fwmodel.ZonaVCN:
				regrasVCN = append(regrasVCN, regraNova)
			case fwmodel.ZonaVPN:
				regrasVPN = append(regrasVPN, regraNova)
			default:
				regrasFlutuante = append(regrasFlutuante, regraNova)
			}
		}

		// Sobra do grupo se fallthrough for accept, drop ou reject
		fall := strings.ToLower(g.Fallthrough)
		if fall == "accept" || fall == "drop" || fall == "reject" {
			sobraZona, revisar := classificarZona(g.CondSaddr, g.CondIif, "", false, f)
			sobraDesc := "Sobra do grupo " + g.Name
			sobraAtiva := g.Enabled
			if revisar {
				sobraAtiva = false
				sobraDesc = "[revisar] " + sobraDesc
				relatorio = append(relatorio, ItemRelatorioConversao{
					Tipo:     "flutuante",
					Origem:   "grupo:" + g.ID,
					Mensagem: fmt.Sprintf("Sobra do grupo %q movida para Flutuantes (desativada) para revisão manual", g.Name),
					Chave:    "fwz.conversao.msg.sobraFlutuante",
					Vars:     map[string]string{"grupo": g.Name},
				})
			}

			var sobraDestino fwmodel.Ponta
			if g.Scope == "input" {
				sobraDestino = fwmodel.Ponta{Tipo: fwmodel.PontaEste}
			} else {
				sobraDestino = parsePontaEndereco(g.CondDaddr)
			}

			regraSobra := fwmodel.Regra{
				ID:            "r-sobra-" + g.ID,
				Zona:          sobraZona,
				Ativa:         sobraAtiva,
				Acao:          fwmodel.Acao(fall),
				Proto:         fwmodel.ProtoQualquer,
				Origem:        parsePontaEndereco(g.CondSaddr),
				Destino:       sobraDestino,
				PortaDestino:  fwmodel.Porta{Tipo: fwmodel.PortaQualquer},
				AgendamentoID: agID,
				Descricao:     sobraDesc,
			}

			switch sobraZona {
			case fwmodel.ZonaInternet:
				regrasInternet = append(regrasInternet, regraSobra)
			case fwmodel.ZonaVCN:
				regrasVCN = append(regrasVCN, regraSobra)
			case fwmodel.ZonaVPN:
				regrasVPN = append(regrasVPN, regraSobra)
			default:
				regrasFlutuante = append(regrasFlutuante, regraSobra)
			}
		}
	}

	// 3. Numerar posições por zona (1-based contíguo)
	var todasRegras []fwmodel.Regra

	for i := range regrasFlutuante {
		regrasFlutuante[i].Posicao = i + 1
	}
	todasRegras = append(todasRegras, regrasFlutuante...)

	for i := range regrasInternet {
		regrasInternet[i].Posicao = i + 1
	}
	todasRegras = append(todasRegras, regrasInternet...)

	for i := range regrasVCN {
		regrasVCN[i].Posicao = i + 1
	}
	todasRegras = append(todasRegras, regrasVCN...)

	for i := range regrasVPN {
		regrasVPN[i].Posicao = i + 1
	}
	todasRegras = append(todasRegras, regrasVPN...)

	// 4. Ajustes do firewall
	ajustes := fwmodel.AjustesPadrao()
	if val, _ := s.db.GetSetting("firewall_edge_containment"); val == "1" {
		ajustes.ContencaoBorda = true
	}
	if val, _ := s.db.GetSetting("firewall_log_blocks"); val == "1" {
		ajustes.RegistrarBloqueados = true
		ajustes.RegistrarDestinos = true
	}

	// 5. Avaliações de políticas e usuários restritos no relatório
	if pIn, _ := s.db.GetSetting("firewall_input_policy"); pIn == "drop" {
		relatorio = append(relatorio, ItemRelatorioConversao{
			Tipo:     "politica",
			Origem:   "politica:input",
			Mensagem: "Política de entrada anterior era drop; substituída pelos padrões das zonas",
			Chave:    "fwz.conversao.msg.politicaEntrada",
		})
	}
	if pFwd, _ := s.db.GetSetting("firewall_forward_policy"); pFwd == "drop" {
		relatorio = append(relatorio, ItemRelatorioConversao{
			Tipo:     "politica",
			Origem:   "politica:forward",
			Mensagem: "Política de passagem anterior era drop; substituída pelos padrões das zonas",
			Chave:    "fwz.conversao.msg.politicaPassagem",
		})
	}

	if peers, err := s.db.ListWireGuardPeers(); err == nil {
		temRestrito := false
		for _, p := range peers {
			if p.AccessMode != "full" {
				temRestrito = true
				break
			}
		}
		if temRestrito {
			relatorio = append(relatorio, ItemRelatorioConversao{
				Tipo:     "aviso",
				Origem:   "vpn",
				Mensagem: "Pessoas da VPN sem acesso total não têm mais acesso ao SSH e painel da caixa (portas de gerência)",
				Chave:    "fwz.conversao.msg.vpnRestrita",
			})
		}
	}

	// 6. Preserva aliases e encaminhamentos já criados/migrados no banco
	cfgAtual, _ := s.db.CarregarConfigEmEdicao()
	novaConfig := fwmodel.Config{
		Formato:         1,
		Regras:          todasRegras,
		Aliases:         cfgAtual.Aliases,
		Agendamentos:    agendamentos,
		Encaminhamentos: cfgAtual.Encaminhamentos,
		Ajustes:         ajustes,
	}

	if err := s.db.SubstituirConfigEmEdicao(novaConfig); err != nil {
		return fmt.Errorf("gravar configuração em edição convertida: %w", err)
	}

	relBytes, err := json.Marshal(relatorio)
	if err != nil {
		return fmt.Errorf("serializar relatório de conversão: %w", err)
	}
	if err := s.db.SetSetting("fw_conversao_relatorio", string(relBytes)); err != nil {
		return fmt.Errorf("gravar setting fw_conversao_relatorio: %w", err)
	}
	if err := s.db.SetSetting("fw_zonas_convertido", "1"); err != nil {
		return fmt.Errorf("gravar trava fw_zonas_convertido: %w", err)
	}

	slog.Info("conversão do firewall legado para o modelo por zonas concluída",
		"regras", len(todasRegras),
		"agendamentos", len(agendamentos),
		"avisos_relatorio", len(relatorio),
	)

	return nil
}

// classificarZona define em qual zona uma regra deve pousar de acordo com as regras do §3.2.
// Retorna a zona e um booleano `revisar` indicando se deve ir desativada com prefixo [revisar].
func classificarZona(origemEfetiva, ifaceEfetiva, oif string, daddrDif bool, f FatosConversao) (fwmodel.Zona, bool) {
	origem := strings.TrimSpace(origemEfetiva)
	iface := strings.TrimSpace(ifaceEfetiva)

	// Regra 4 — exceções que exigem revisão manual em Flutuantes:
	// - possui oif preenchida
	// - daddr da regra e do grupo são diferentes e ambos preenchidos
	// - interface da WAN (em hairpin mistura VCN e Internet)
	// - sem origem e sem interface
	if oif != "" || daddrDif {
		return fwmodel.ZonaFlutuante, true
	}
	for _, wan := range f.PlacasWAN {
		if wan != "" && iface == wan {
			return fwmodel.ZonaFlutuante, true
		}
	}
	if (origem == "" || origem == "any") && iface == "" {
		return fwmodel.ZonaFlutuante, true
	}

	// Regra 1 — Interface VPN ou origem contida na rede da VPN
	if (f.InterfaceVPN != "" && iface == f.InterfaceVPN) || (f.RedeVPN != "" && ipOuRedeContidaEm(origem, f.RedeVPN)) {
		return fwmodel.ZonaVPN, false
	}

	// Regra 2 — Origem contida em alguma rede da VCN
	if len(f.RedesVCN) > 0 && ipOuRedeContidaEm(origem, f.RedesVCN...) {
		return fwmodel.ZonaVCN, false
	}

	// Regra 3 — Origem preenchida e fora de todas as redes locais
	redesLocais := append([]string{}, f.RedesVCN...)
	if f.RedeVPN != "" {
		redesLocais = append(redesLocais, f.RedeVPN)
	}
	// Faixas privadas padrão (RFC 1918, CGNAT, link-local)
	redesLocais = append(redesLocais, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16")

	if origem != "" && origem != "any" && !ipOuRedeContidaEm(origem, redesLocais...) {
		return fwmodel.ZonaInternet, false
	}

	// Qualquer outro caso cai em Flutuantes desativada
	return fwmodel.ZonaFlutuante, true
}

// parsePontaEndereco interpreta uma string de endereço/rede legado como fwmodel.Ponta.
func parsePontaEndereco(val string) fwmodel.Ponta {
	val = strings.TrimSpace(val)
	if val == "" || val == "any" {
		return fwmodel.Ponta{Tipo: fwmodel.PontaQualquer}
	}
	if strings.HasSuffix(val, "/32") {
		val = strings.TrimSuffix(val, "/32")
	}
	return fwmodel.Ponta{Tipo: fwmodel.PontaEndereco, Valor: val}
}

// ipOuRedeContidaEm avalia se o IP ou subrede alvo está contido dentro de alguma das subredes fornecidas.
func ipOuRedeContidaEm(alvo string, subredes ...string) bool {
	alvo = strings.TrimSpace(alvo)
	if alvo == "" || alvo == "any" {
		return false
	}
	if strings.HasSuffix(alvo, "/32") {
		alvo = strings.TrimSuffix(alvo, "/32")
	}

	var alvoIP net.IP
	var alvoNet *net.IPNet
	if strings.Contains(alvo, "/") {
		var err error
		alvoIP, alvoNet, err = net.ParseCIDR(alvo)
		if err != nil {
			return false
		}
	} else {
		alvoIP = net.ParseIP(alvo)
		if alvoIP == nil {
			return false
		}
	}

	for _, sub := range subredes {
		sub = strings.TrimSpace(sub)
		if sub == "" {
			continue
		}
		if !strings.Contains(sub, "/") {
			sub = sub + "/32"
		}
		_, netSub, err := net.ParseCIDR(sub)
		if err != nil {
			continue
		}

		if alvoNet != nil {
			onesAlvo, _ := alvoNet.Mask.Size()
			onesSub, _ := netSub.Mask.Size()
			if onesAlvo >= onesSub && netSub.Contains(alvoIP) {
				return true
			}
		} else {
			if netSub.Contains(alvoIP) {
				return true
			}
		}
	}
	return false
}
