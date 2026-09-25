package nftables

import (
	"encoding/json"
	"math/rand"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-cloud/internal/fwmodel"
)

func jsonIndented(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	return string(b) + "\n"
}

// cenariosDeTeste define os 7 cenários mínimos exigidos para os goldens.
func cenariosDeTeste() map[string]struct {
	config  fwmodel.Config
	insumos Insumos
} {
	// Cenário 1: instalacao_nova
	cInstalacao := fwmodel.Config{
		Formato: 1,
		Regras: []fwmodel.Regra{
			{
				ID:           "uuid-gerencia-wan",
				Zona:         fwmodel.ZonaInternet,
				Posicao:      0,
				Ativa:        true,
				Acao:         fwmodel.AcaoAccept,
				Proto:        fwmodel.ProtoTCP,
				Origem:       fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
				Destino:      fwmodel.Ponta{Tipo: fwmodel.PontaEste},
				PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaAlias, Valor: fwmodel.AliasGerencia},
				Descricao:    "Gerência (SSH e painel) aberta para a Internet — restrinja a origem",
			},
		},
		Aliases:         []fwmodel.Alias{},
		Agendamentos:    []fwmodel.Agendamento{},
		Encaminhamentos: []fwmodel.Encaminhamento{},
		Ajustes:         fwmodel.AjustesPadrao(),
	}
	inInstalacao := Insumos{
		RedesVCN:       []string{"10.0.0.0/24"},
		RedeVPN:        "",
		PortaWireGuard: 0,
		InterfaceVPN:   "linkguard",
		PortasGerencia: []int{22, 9997},
		Pessoas:        []PessoaVPN{},
		Existentes:     Existentes{},
	}

	// Cenário 2: oci_tipico (exemplo do §2.7)
	aliasCasa := fwmodel.Alias{
		ID:        "casa-0000000-0000-0000-0000-000000000000",
		Nome:      "admin-casa",
		Tipo:      fwmodel.AliasTipoEnderecos,
		Descricao: "IP da casa do admin",
		Itens:     []string{"189.1.2.3"},
	}
	aliasK3S := fwmodel.Alias{
		ID:        "k3s-00000000-0000-0000-0000-000000000000",
		Nome:      "k3s-api",
		Tipo:      fwmodel.AliasTipoEnderecos,
		Descricao: "API do cluster K3s",
		Itens:     []string{"10.0.1.20"},
	}

	cOCI := fwmodel.Config{
		Formato: 1,
		Regras: []fwmodel.Regra{
			{
				ID:           "uuid-casa",
				Zona:         fwmodel.ZonaInternet,
				Posicao:      0,
				Ativa:        true,
				Acao:         fwmodel.AcaoAccept,
				Proto:        fwmodel.ProtoTCP,
				Origem:       fwmodel.Ponta{Tipo: fwmodel.PontaAlias, Valor: aliasCasa.ID},
				Destino:      fwmodel.Ponta{Tipo: fwmodel.PontaEste},
				PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaAlias, Valor: fwmodel.AliasGerencia},
				Descricao:    "SSH e painel só da minha casa",
			},
			{
				ID:           "uuid-smtp",
				Zona:         fwmodel.ZonaVCN,
				Posicao:      0,
				Ativa:        true,
				Acao:         fwmodel.AcaoDrop,
				Proto:        fwmodel.ProtoTCP,
				Origem:       fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
				Destino:      fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
				PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaValor, Valor: "25"},
				Descricao:    "Nada de SMTP direto",
			},
		},
		Aliases: []fwmodel.Alias{aliasK3S, aliasCasa},
		Encaminhamentos: []fwmodel.Encaminhamento{
			{
				ID:           "pf",
				Nome:         "HTTPS",
				Ativo:        true,
				Proto:        "tcp",
				PortaExterna: 443,
				IPDestino:    "10.0.1.30",
				PortaDestino: 443,
				Posicao:      0,
			},
		},
		Ajustes: fwmodel.AjustesPadrao(),
	}
	inOCI := Insumos{
		RedesVCN:       []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
		RedeVPN:        "10.7.0.0/24",
		PortaWireGuard: 51820,
		InterfaceVPN:   "linkguard",
		PortasGerencia: []int{22, 9997},
		Pessoas: []PessoaVPN{
			{
				UserID:   "uid-admin",
				Usuario:  "admin",
				Endereco: "10.7.0.2",
				Total:    true,
			},
			{
				UserID:   "uid-diego",
				Usuario:  "diego",
				Endereco: "10.7.0.3",
				Total:    false,
				Aliases:  []string{aliasK3S.ID},
				Portas:   "6443",
			},
		},
		Existentes: Existentes{
			Chains: []string{"grp_0a1b2c3d4e5f", "user_rules"},
			Sets:   []string{"blocked_macs"},
		},
	}

	// Cenário 3: registro_e_agenda
	agComercial := fwmodel.Agendamento{
		ID:        "sched-comercial",
		Nome:      "Horário comercial",
		Descricao: "Seg a Sex 08:00 às 18:00",
		Dias:      "mon,tue,wed,thu,fri",
		Inicio:    "08:00",
		Fim:       "18:00",
	}
	cRegistro := fwmodel.Config{
		Formato:      1,
		Agendamentos: []fwmodel.Agendamento{agComercial},
		Regras: []fwmodel.Regra{
			{
				ID:            "uuid-regra-log",
				Zona:          fwmodel.ZonaVCN,
				Posicao:       0,
				Ativa:         true,
				Acao:          fwmodel.AcaoAccept,
				Proto:         fwmodel.ProtoTCP,
				Origem:        fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
				Destino:       fwmodel.Ponta{Tipo: fwmodel.PontaEndereco, Valor: "10.0.2.0/24"},
				PortaDestino:  fwmodel.Porta{Tipo: fwmodel.PortaValor, Valor: "80"},
				AgendamentoID: agComercial.ID,
				Registrar:     true,
				Descricao:     "Web com log e horário",
			},
		},
		Aliases: []fwmodel.Alias{},
		Ajustes: fwmodel.Ajustes{
			AntiBloqueio: map[fwmodel.Zona]bool{
				fwmodel.ZonaVCN: true,
				fwmodel.ZonaVPN: false,
			},
			RegistrarBloqueados: true,
			RegistrarDestinos:   true,
			RegistrarPadrao:     true,
			ContencaoBorda:      false,
		},
	}
	inRegistro := Insumos{
		RedesVCN:       []string{"10.0.0.0/24"},
		RedeVPN:        "10.7.0.0/24",
		PortaWireGuard: 51820,
		InterfaceVPN:   "linkguard",
		PortasGerencia: []int{22, 9997},
		Pessoas:        []PessoaVPN{},
		Existentes:     Existentes{},
	}

	// Cenário 4: contencao
	cContencao := fwmodel.Config{
		Formato: 1,
		Ajustes: fwmodel.Ajustes{
			AntiBloqueio: map[fwmodel.Zona]bool{
				fwmodel.ZonaVCN: true,
				fwmodel.ZonaVPN: false,
			},
			ContencaoBorda: true,
		},
	}
	inContencao := Insumos{
		RedesVCN:       []string{"10.0.0.0/24"},
		RedeVPN:        "",
		PortasGerencia: []int{22, 9997},
	}

	// Cenário 5: limpeza_legado
	aliasValido := fwmodel.Alias{
		ID:        "alias-valido-1",
		Nome:      "Servidores",
		Tipo:      fwmodel.AliasTipoEnderecos,
		Descricao: "Servidores internos",
		Itens:     []string{"10.0.1.0/24"},
	}
	cLimpeza := fwmodel.Config{
		Formato: 1,
		Aliases: []fwmodel.Alias{aliasValido},
		Ajustes: fwmodel.AjustesPadrao(),
	}
	inLimpeza := Insumos{
		RedesVCN:       []string{"10.0.0.0/24"},
		PortasGerencia: []int{22, 9997},
		Existentes: Existentes{
			Chains: []string{"grp_111111111111", "grp_222222222222", "user_rules"},
			Sets:   []string{"blocked_macs", "fwa_orfao000000"},
		},
	}

	// Cenário 6: vpn_sem_aliases_validos
	cVPNSemAlias := fwmodel.Config{
		Formato: 1,
		Aliases: []fwmodel.Alias{}, // Nenhum alias cadastrado
		Ajustes: fwmodel.AjustesPadrao(),
	}
	inVPNSemAlias := Insumos{
		RedesVCN:       []string{"10.0.0.0/24"},
		RedeVPN:        "10.7.0.0/24",
		PortaWireGuard: 51820,
		PortasGerencia: []int{22, 9997},
		Pessoas: []PessoaVPN{
			{
				UserID:   "uid-restrito-orfao",
				Usuario:  "usuario_orfao",
				Endereco: "10.7.0.5",
				Total:    false,
				Aliases:  []string{"alias-que-foi-apagado"},
				Portas:   "80, 443",
			},
		},
	}

	// Cenário 7: sem_redes_vcn
	cSemVCN := fwmodel.Config{
		Formato: 1,
		Ajustes: fwmodel.AjustesPadrao(),
	}
	inSemVCN := Insumos{
		RedesVCN:       []string{}, // Vazio: sem VNICs detectadas e sem redes extras
		PortasGerencia: []int{22, 9997},
	}

	return map[string]struct {
		config  fwmodel.Config
		insumos Insumos
	}{
		"instalacao_nova":         {config: cInstalacao, insumos: inInstalacao},
		"oci_tipico":              {config: cOCI, insumos: inOCI},
		"registro_e_agenda":       {config: cRegistro, insumos: inRegistro},
		"contencao":               {config: cContencao, insumos: inContencao},
		"limpeza_legado":          {config: cLimpeza, insumos: inLimpeza},
		"vpn_sem_aliases_validos": {config: cVPNSemAlias, insumos: inVPNSemAlias},
		"sem_redes_vcn":           {config: cSemVCN, insumos: inSemVCN},
	}
}

// TestRenderZonas_Goldens valida a renderização contra os 7 arquivos golden v2.
func TestRenderZonas_Goldens(t *testing.T) {
	cenarios := cenariosDeTeste()

	for nome, c := range cenarios {
		t.Run(nome, func(t *testing.T) {
			rs, err := RenderZonas(c.config, c.insumos)
			if err != nil {
				t.Fatalf("RenderZonas falhou no cenário %s: %v", nome, err)
			}

			dirCenario := filepath.Join("testdata", "zonas_v2", nome)
			conferirArquivo(t, filepath.Join(dirCenario, "script.nft"), rs.Script)
			conferirArquivo(t, filepath.Join(dirCenario, "linhas.json"), jsonIndented(rs.Linhas))

			if nome == "vpn_sem_aliases_validos" {
				if len(rs.Avisos) == 0 {
					t.Errorf("esperava aviso de alias inexistente no perfil da VPN, nenhum retornado")
				}
				// Não deve ter linhas geradas em zona_vpn_fwd para esse peer
				for _, l := range rs.Linhas[fwmodel.ZonaVPN] {
					if strings.Contains(l.Chave, "uid-restrito-orfao") {
						t.Errorf("não esperava linhas em zona_vpn_fwd para usuário sem alias válido, gerou: %v", l)
					}
				}
			}

			if nome == "sem_redes_vcn" {
				// Set fwa_vcn não deve ter 'add element'
				if strings.Contains(rs.Script, "add element inet linkguard fwa_vcn") {
					t.Errorf("set fwa_vcn não deveria ter add element quando vazio: %s", rs.Script)
				}
			}
		})
	}
}

// TestRenderZonas_Defeito6_DNATFibDaddrTypeLocal garante que toda regra em prerouting_dnat
// contém obrigatoriamente a restrição `fib daddr type local`, evitando sequestro de tráfego de saída da VCN.
func TestRenderZonas_Defeito6_DNATFibDaddrTypeLocal(t *testing.T) {
	cenarios := cenariosDeTeste()
	rs, err := RenderZonas(cenarios["oci_tipico"].config, cenarios["oci_tipico"].insumos)
	if err != nil {
		t.Fatalf("RenderZonas falhou: %v", err)
	}

	linhas := strings.Split(rs.Script, "\n")
	emDNAT := false
	regrasDNAT := 0

	for _, l := range linhas {
		if strings.Contains(l, "add chain inet linkguard prerouting_dnat") {
			emDNAT = true
			continue
		}
		if emDNAT && strings.HasPrefix(l, "add chain") {
			emDNAT = false
		}
		if emDNAT && strings.HasPrefix(l, "add rule inet linkguard prerouting_dnat") {
			regrasDNAT++
			if !strings.Contains(l, "fib daddr type local") {
				t.Fatalf("defeito 6 reintroduzido: regra de DNAT sem 'fib daddr type local': %s", l)
			}
		}
	}

	if regrasDNAT == 0 {
		t.Fatalf("nenhuma regra de DNAT encontrada no cenário oci_tipico")
	}
}

// TestRenderZonas_Determinismo executa 50 vezes com slices e mapas embaralhados
// e valida que Script e HashEntrada continuam 100% idênticos.
func TestRenderZonas_Determinismo(t *testing.T) {
	cenarios := cenariosDeTeste()
	baseConfig := cenarios["oci_tipico"].config
	baseInsumos := cenarios["oci_tipico"].insumos

	baseRS, err := RenderZonas(baseConfig, baseInsumos)
	if err != nil {
		t.Fatalf("RenderZonas base falhou: %v", err)
	}

	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := 0; i < 50; i++ {
		cfg := baseConfig
		ins := baseInsumos

		// Embaralhar aliases
		cfg.Aliases = append([]fwmodel.Alias{}, baseConfig.Aliases...)
		r.Shuffle(len(cfg.Aliases), func(i, j int) {
			cfg.Aliases[i], cfg.Aliases[j] = cfg.Aliases[j], cfg.Aliases[i]
		})

		// Embaralhar redes VCN
		ins.RedesVCN = append([]string{}, baseInsumos.RedesVCN...)
		r.Shuffle(len(ins.RedesVCN), func(i, j int) {
			ins.RedesVCN[i], ins.RedesVCN[j] = ins.RedesVCN[j], ins.RedesVCN[i]
		})

		// Embaralhar portas de gerência
		ins.PortasGerencia = append([]int{}, baseInsumos.PortasGerencia...)
		r.Shuffle(len(ins.PortasGerencia), func(i, j int) {
			ins.PortasGerencia[i], ins.PortasGerencia[j] = ins.PortasGerencia[j], ins.PortasGerencia[i]
		})

		// Embaralhar pessoas
		ins.Pessoas = append([]PessoaVPN{}, baseInsumos.Pessoas...)
		r.Shuffle(len(ins.Pessoas), func(i, j int) {
			ins.Pessoas[i], ins.Pessoas[j] = ins.Pessoas[j], ins.Pessoas[i]
		})

		rs, err := RenderZonas(cfg, ins)
		if err != nil {
			t.Fatalf("iteração %d falhou: %v", i, err)
		}

		if rs.Script != baseRS.Script {
			t.Fatalf("iteração %d: Script diverge da base", i)
		}
		if rs.HashEntrada != baseRS.HashEntrada {
			t.Fatalf("iteração %d: HashEntrada diverge da base", i)
		}
	}
}

// TestRenderZonas_HashEntrada_Janela comprova que mudanças em regras de passagem pura NÃO
// alteram HashEntrada (sem janela de 90s), enquanto mudanças na entrada/acesso à caixa ALTERAM.
func TestRenderZonas_HashEntrada_Janela(t *testing.T) {
	cenarios := cenariosDeTeste()
	baseConfig := cenarios["oci_tipico"].config
	baseInsumos := cenarios["oci_tipico"].insumos

	baseRS, err := RenderZonas(baseConfig, baseInsumos)
	if err != nil {
		t.Fatalf("base falhou: %v", err)
	}

	// 1. Mudar APENAS uma regra de passagem (destino addr na VCN)
	cfgPassagem := baseConfig
	cfgPassagem.Regras = append([]fwmodel.Regra{}, baseConfig.Regras...)
	cfgPassagem.Regras = append(cfgPassagem.Regras, fwmodel.Regra{
		ID:           "uuid-fwd-only",
		Zona:         fwmodel.ZonaVCN,
		Posicao:      1,
		Ativa:        true,
		Acao:         fwmodel.AcaoDrop,
		Proto:        fwmodel.ProtoTCP,
		Origem:       fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
		Destino:      fwmodel.Ponta{Tipo: fwmodel.PontaEndereco, Valor: "192.168.1.50"},
		PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaValor, Valor: "8080"},
		Descricao:    "Bloqueia serviço interno",
	})
	rsPassagem, err := RenderZonas(cfgPassagem, baseInsumos)
	if err != nil {
		t.Fatalf("passagem falhou: %v", err)
	}
	if rsPassagem.HashEntrada != baseRS.HashEntrada {
		t.Fatalf("regra de passagem pura alterou HashEntrada! Base: %s, Novo: %s", baseRS.HashEntrada, rsPassagem.HashEntrada)
	}

	// 2. Mudar porta de gerência (muda elementos do set fwp_gerencia consultado na entrada)
	insGerencia := baseInsumos
	insGerencia.PortasGerencia = []int{22, 9997, 8443}
	rsGerencia, err := RenderZonas(baseConfig, insGerencia)
	if err != nil {
		t.Fatalf("gerência falhou: %v", err)
	}
	if rsGerencia.HashEntrada == baseRS.HashEntrada {
		t.Fatalf("mudança em porta de gerência NÃO alterou HashEntrada!")
	}

	// 3. Mudar anti-bloqueio VCN (muda regra na chain zona_vcn_in)
	cfgAnti := baseConfig
	cfgAnti.Ajustes.AntiBloqueio = map[fwmodel.Zona]bool{
		fwmodel.ZonaVCN: false,
		fwmodel.ZonaVPN: false,
	}
	rsAnti, err := RenderZonas(cfgAnti, baseInsumos)
	if err != nil {
		t.Fatalf("anti-bloqueio falhou: %v", err)
	}
	if rsAnti.HashEntrada == baseRS.HashEntrada {
		t.Fatalf("mudança em anti-bloqueio VCN NÃO alterou HashEntrada!")
	}

	// 4. Mudar alias usado em regra de entrada (admin-casa muda IP)
	cfgAlias := baseConfig
	cfgAlias.Aliases = []fwmodel.Alias{
		baseConfig.Aliases[0],
		{
			ID:        baseConfig.Aliases[1].ID,
			Nome:      baseConfig.Aliases[1].Nome,
			Tipo:      baseConfig.Aliases[1].Tipo,
			Descricao: baseConfig.Aliases[1].Descricao,
			Itens:     []string{"200.200.200.200"}, // IP mudou
		},
	}
	rsAlias, err := RenderZonas(cfgAlias, baseInsumos)
	if err != nil {
		t.Fatalf("alias falhou: %v", err)
	}
	if rsAlias.HashEntrada == baseRS.HashEntrada {
		t.Fatalf("mudança em alias de entrada NÃO alterou HashEntrada!")
	}

	// 5. Mudar perfil de pessoa com acesso total (admin passa para restrito)
	insPessoa := baseInsumos
	insPessoa.Pessoas = []PessoaVPN{
		{
			UserID:   "uid-admin",
			Usuario:  "admin",
			Endereco: "10.7.0.2",
			Total:    false, // Não é mais total: perde regra na zona_vpn_in
		},
		baseInsumos.Pessoas[1],
	}
	rsPessoa, err := RenderZonas(baseConfig, insPessoa)
	if err != nil {
		t.Fatalf("pessoa total falhou: %v", err)
	}
	if rsPessoa.HashEntrada == baseRS.HashEntrada {
		t.Fatalf("mudança de pessoa com acesso total para restrito NÃO alterou HashEntrada!")
	}
}

// TestRenderZonas_SimulacaoPacotes estende o simulador de regras para seguir jumps e comentários,
// comprovando que o script produzido resolve os defeitos 1, 2 e 3.
func TestRenderZonas_SimulacaoPacotes(t *testing.T) {
	cenarios := cenariosDeTeste()
	rs, err := RenderZonas(cenarios["oci_tipico"].config, cenarios["oci_tipico"].insumos)
	if err != nil {
		t.Fatalf("RenderZonas falhou: %v", err)
	}

	sim := novoSimulador(rs.Script)

	testes := []struct {
		nome        string
		pct         simPacote
		esperaChave string
		esperaAcao  string
	}{
		{
			nome: "Defeito 1 corrigido: pessoa restrita da VPN (10.7.0.3) NÃO acessa porta 22 do firewall",
			pct: simPacote{
				iif:          "linkguard",
				saddr:        "10.7.0.3",
				daddr:        "10.0.0.1",
				daddrIsLocal: true,
				proto:        "tcp",
				dport:        22,
			},
			esperaChave: "d:vpn:in",
			esperaAcao:  "drop",
		},
		{
			nome: "Defeito 2 corrigido: pessoa com acesso total (10.7.0.2) alcança a Internet na porta 443",
			pct: simPacote{
				iif:          "linkguard",
				saddr:        "10.7.0.2",
				daddr:        "1.1.1.1",
				daddrIsLocal: false,
				proto:        "tcp",
				dport:        443,
			},
			esperaChave: "s:vpn:uid-admin:total",
			esperaAcao:  "accept",
		},
		{
			nome: "VCN (10.0.0.5) saindo para a Internet na porta 443 é aceita pelo padrão da VCN",
			pct: simPacote{
				iif:          "ens3",
				saddr:        "10.0.0.5",
				daddr:        "1.1.1.1",
				daddrIsLocal: false,
				proto:        "tcp",
				dport:        443,
			},
			esperaChave: "d:vcn:fwd",
			esperaAcao:  "accept",
		},
		{
			nome: "VCN (10.0.0.5) acessa painel 9997 pelo anti-bloqueio da VCN",
			pct: simPacote{
				iif:          "ens3",
				saddr:        "10.0.0.5",
				daddr:        "10.0.0.1",
				daddrIsLocal: true,
				proto:        "tcp",
				dport:        9997,
			},
			esperaChave: "s:antibloqueio:vcn",
			esperaAcao:  "accept",
		},
		{
			nome: "Internet (198.51.100.1) acessa porta 443 encaminhada via DNAT",
			pct: simPacote{
				iif:          "ens3",
				saddr:        "198.51.100.1",
				daddr:        "10.0.1.30",
				daddrIsLocal: false,
				ctStatusDnat: true,
				proto:        "tcp",
				dport:        443,
			},
			esperaChave: "s:nat:pf",
			esperaAcao:  "accept",
		},
		{
			nome: "Defeito 3 corrigido: pessoa da VPN (10.7.0.3) alcança DNS (porta 53) no firewall",
			pct: simPacote{
				iif:          "linkguard",
				saddr:        "10.7.0.3",
				daddr:        "10.0.0.1",
				daddrIsLocal: true,
				proto:        "udp",
				dport:        53,
			},
			esperaChave: "s:dns-vpn",
			esperaAcao:  "accept",
		},
	}

	for _, tt := range testes {
		t.Run(tt.nome, func(t *testing.T) {
			acao, chave := sim.avaliar(tt.pct)
			if acao != tt.esperaAcao || chave != tt.esperaChave {
				t.Fatalf("pacote tomou %s (%s); esperava %s (%s)", acao, chave, tt.esperaAcao, tt.esperaChave)
			}
		})
	}
}

// TestRenderZonas_Erros valida rejeições precoces com descrições claras de erro.
func TestRenderZonas_Erros(t *testing.T) {
	// 1. Colisão de nomes de set (12 hex)
	cColisao := fwmodel.Config{
		Formato: 1,
		Aliases: []fwmodel.Alias{
			{ID: "00000000-0000-0000-0000-000000000001", Nome: "A1", Tipo: fwmodel.AliasTipoEnderecos, Itens: []string{"10.0.0.1"}},
			{ID: "00000000-0000-0000-0000-000000000002", Nome: "A2", Tipo: fwmodel.AliasTipoEnderecos, Itens: []string{"10.0.0.2"}},
		},
		Ajustes: fwmodel.AjustesPadrao(),
	}
	// Ambos têm prefixo hex "000000000000"
	_, err := RenderZonas(cColisao, Insumos{PortasGerencia: []int{22}})
	if err == nil || !strings.Contains(err.Error(), "colisão de nome de set") {
		t.Fatalf("esperava erro de colisão de set, veio: %v", err)
	}

	// 2. Regra com agendamento inexistente
	cAgendamento := fwmodel.Config{
		Formato: 1,
		Regras: []fwmodel.Regra{
			{
				ID:            "r1",
				Zona:          fwmodel.ZonaVCN,
				Posicao:       0,
				Ativa:         true,
				Acao:          fwmodel.AcaoAccept,
				Origem:        fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
				Destino:       fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
				PortaDestino:  fwmodel.Porta{Tipo: fwmodel.PortaQualquer},
				AgendamentoID: "fantasma",
			},
		},
		Ajustes: fwmodel.AjustesPadrao(),
	}
	_, err = RenderZonas(cAgendamento, Insumos{PortasGerencia: []int{22}})
	if err == nil || (!strings.Contains(err.Error(), "referencia agendamento inexistente") && !strings.Contains(err.Error(), "regraAgendamentoInexistente")) {
		t.Fatalf("esperava erro de agendamento inexistente, veio: %v", err)
	}
}

// ─── Simulador simplificado de regras nftables ───────────────────────────────

type simPacote struct {
	iif          string
	saddr        string
	daddr        string
	daddrIsLocal bool
	ctStatusDnat bool
	proto        string
	dport        int
}

type simulador struct {
	sets   map[string][]string
	chains map[string][]string
}

func novoSimulador(script string) *simulador {
	s := &simulador{
		sets:   make(map[string][]string),
		chains: make(map[string][]string),
	}

	linhas := strings.Split(script, "\n")
	for _, l := range linhas {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if strings.HasPrefix(l, "add element inet linkguard ") {
			// add element inet linkguard fwa_vcn { 10.0.0.0/8, 172.16.0.0/12 }
			parts := strings.SplitN(strings.TrimPrefix(l, "add element inet linkguard "), " ", 2)
			sName := parts[0]
			elemsStr := strings.Trim(parts[1], "{ }")
			for _, e := range strings.Split(elemsStr, ",") {
				item := strings.TrimSpace(e)
				if item != "" {
					s.sets[sName] = append(s.sets[sName], item)
				}
			}
		} else if strings.HasPrefix(l, "add rule inet linkguard ") {
			// add rule inet linkguard <chain> <rule...>
			resto := strings.TrimPrefix(l, "add rule inet linkguard ")
			parts := strings.SplitN(resto, " ", 2)
			chain := parts[0]
			rule := parts[1]
			s.chains[chain] = append(s.chains[chain], rule)
		}
	}
	return s
}

func (s *simulador) avaliar(p simPacote) (acao, chave string) {
	chainInicial := "forward"
	if p.daddrIsLocal {
		chainInicial = "input"
	}
	return s.executarChain(chainInicial, p)
}

func (s *simulador) executarChain(chain string, p simPacote) (string, string) {
	regras := s.chains[chain]
	for _, r := range regras {
		casou, jumpChain, veredito, chave := s.casaRegra(r, p)
		if !casou {
			continue
		}
		if jumpChain != "" {
			subAcao, subChave := s.executarChain(jumpChain, p)
			if subAcao != "" {
				return subAcao, subChave
			}
			// Se a subchain não deu veredito terminal, continua na chain atual
			continue
		}
		if veredito != "" {
			return veredito, chave
		}
	}
	return "", ""
}

func (s *simulador) casaRegra(r string, p simPacote) (casou bool, jumpChain, veredito, chave string) {
	// Extrair chave do comentário: comment "..."
	chave = ""
	if idx := strings.Index(r, "comment \""); idx >= 0 {
		end := strings.Index(r[idx+9:], "\"")
		if end >= 0 {
			chave = r[idx+9 : idx+9+end]
		}
	}

	// Ignorar regras de log (não têm veredito nem jump)
	if strings.Contains(r, "limit rate") && strings.Contains(r, "log prefix") {
		return false, "", "", ""
	}

	// Ignorar IPv6 na simulação de pacotes IPv4
	if strings.Contains(r, "ip6 ") || strings.Contains(r, "icmpv6 ") {
		return false, "", "", ""
	}

	// ct state established,related: simulamos sempre conexões novas
	if strings.Contains(r, "ct state established,related") {
		return false, "", "", ""
	}

	// loopback
	if strings.Contains(r, `iif "lo"`) {
		if p.iif != "lo" {
			return false, "", "", ""
		}
	}

	// DHCP
	if strings.Contains(r, "udp sport 67") || strings.Contains(r, "udp dport 546") {
		return false, "", "", ""
	}

	// Casamento de interface: iifname "linkguard"
	if strings.Contains(r, "iifname ") {
		parts := strings.Split(r, "iifname ")
		ifaceVal := strings.Fields(parts[1])[0]
		ifaceVal = strings.Trim(ifaceVal, "\"")
		if p.iif != ifaceVal {
			return false, "", "", ""
		}
	}

	// Casamento ip saddr
	if strings.Contains(r, "ip saddr ") {
		parts := strings.Split(r, "ip saddr ")
		alvo := strings.Fields(parts[1])[0]
		if strings.HasPrefix(alvo, "@") {
			sName := alvo[1:]
			if !s.ipNoSet(p.saddr, sName) {
				return false, "", "", ""
			}
		} else {
			if !s.ipCasa(p.saddr, alvo) {
				return false, "", "", ""
			}
		}
	}

	// Casamento ip daddr
	if strings.Contains(r, "ip daddr ") {
		parts := strings.Split(r, "ip daddr ")
		alvo := strings.Fields(parts[1])[0]
		if strings.HasPrefix(alvo, "@") {
			sName := alvo[1:]
			if !s.ipNoSet(p.daddr, sName) {
				return false, "", "", ""
			}
		} else {
			if !s.ipCasa(p.daddr, alvo) {
				return false, "", "", ""
			}
		}
	}

	// Casamento ct status dnat
	if strings.Contains(r, "ct status dnat") {
		if !p.ctStatusDnat {
			return false, "", "", ""
		}
	}

	// Casamento tcp dport
	if strings.Contains(r, "tcp dport ") {
		if p.proto != "tcp" {
			return false, "", "", ""
		}
		parts := strings.Split(r, "tcp dport ")
		resto := parts[1]
		if strings.HasPrefix(resto, "@") {
			sName := strings.Fields(resto)[0][1:]
			if !s.portaNoSet(p.dport, sName) {
				return false, "", "", ""
			}
		} else if strings.HasPrefix(resto, "{") {
			end := strings.Index(resto, "}")
			corpo := strings.Trim(resto[1:end], " ")
			if !s.portaNaLista(p.dport, corpo) {
				return false, "", "", ""
			}
		} else {
			portStr := strings.Fields(resto)[0]
			prt, _ := strconv.Atoi(portStr)
			if p.dport != prt {
				return false, "", "", ""
			}
		}
	}

	// Casamento udp dport
	if strings.Contains(r, "udp dport ") {
		if p.proto != "udp" {
			return false, "", "", ""
		}
		parts := strings.Split(r, "udp dport ")
		resto := parts[1]
		if strings.HasPrefix(resto, "@") {
			sName := strings.Fields(resto)[0][1:]
			if !s.portaNoSet(p.dport, sName) {
				return false, "", "", ""
			}
		} else {
			portStr := strings.Fields(resto)[0]
			prt, _ := strconv.Atoi(portStr)
			if p.dport != prt {
				return false, "", "", ""
			}
		}
	}

	// Casamento meta l4proto { tcp, udp } th dport 53
	if strings.Contains(r, "meta l4proto { tcp, udp } th dport 53") {
		if (p.proto != "tcp" && p.proto != "udp") || p.dport != 53 {
			return false, "", "", ""
		}
	}

	// Casamento meta l4proto icmp
	if strings.Contains(r, "meta l4proto icmp") {
		if p.proto != "icmp" {
			return false, "", "", ""
		}
	}

	// Casamento icmp type echo-request
	if strings.Contains(r, "icmp type echo-request") {
		if p.proto != "icmp" {
			return false, "", "", ""
		}
	}

	// Casamento jump
	if strings.Contains(r, "jump ") {
		parts := strings.Split(r, "jump ")
		jChain := strings.Fields(parts[1])[0]
		return true, jChain, "", ""
	}

	// Veredito
	if strings.Contains(r, "counter accept") {
		return true, "", "accept", chave
	}
	if strings.Contains(r, "counter drop") {
		return true, "", "drop", chave
	}
	if strings.Contains(r, "counter reject") {
		return true, "", "reject", chave
	}

	return false, "", "", ""
}

func (s *simulador) ipNoSet(ipStr, sName string) bool {
	elems := s.sets[sName]
	for _, e := range elems {
		if s.ipCasa(ipStr, e) {
			return true
		}
	}
	return false
}

func (s *simulador) ipCasa(ipStr, pattern string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if strings.Contains(pattern, "/") {
		_, netw, err := net.ParseCIDR(pattern)
		if err == nil && netw.Contains(ip) {
			return true
		}
	} else {
		patIP := net.ParseIP(pattern)
		if patIP != nil && patIP.Equal(ip) {
			return true
		}
	}
	return false
}

func (s *simulador) portaNoSet(port int, sName string) bool {
	elems := s.sets[sName]
	for _, e := range elems {
		p, err := strconv.Atoi(e)
		if err == nil && p == port {
			return true
		}
	}
	return false
}

func (s *simulador) portaNaLista(port int, csv string) bool {
	for _, part := range strings.Split(csv, ",") {
		p, err := strconv.Atoi(strings.TrimSpace(part))
		if err == nil && p == port {
			return true
		}
	}
	return false
}
