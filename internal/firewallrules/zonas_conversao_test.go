package firewallrules

import (
	"context"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-cloud/internal/fwmodel"
	"github.com/giovanibalarini/linkguard-cloud/internal/nftables"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

func newConversaoTestService(t *testing.T) (*Service, *storage.DB) {
	t.Helper()
	db := newTestDB(t)
	svc := NewService(db, nil)
	return svc, db
}

func TestConversaoTabela(t *testing.T) {
	svc, db := newConversaoTestService(t)
	ctx := context.Background()

	f := FatosConversao{
		RedesVCN:     []string{"10.0.0.0/16"},
		RedeVPN:      "10.7.0.0/24",
		InterfaceVPN: "linkguard",
		PlacasWAN:    []string{"ens3"},
	}

	// Grupo do admin com 5 regras exercitando cada classificação de zona
	g := &storage.FirewallGroup{
		ID:          "grp-admin",
		Name:        "Regras do Administrador",
		ChainName:   "grp_admin",
		Position:    1,
		Enabled:     true,
		Fallthrough: "continue",
		Kind:        "admin",
		Scope:       "forward",
	}
	_ = db.CreateFirewallGroup(g)

	regras := []*storage.FirewallRule{
		{
			ID:          "r-vpn-saddr",
			GroupID:     g.ID,
			Position:    1,
			Enabled:     true,
			Action:      "accept",
			Saddr:       "10.7.0.5",
			Proto:       "tcp",
			Dport:       "80",
			Description: "Origem VPN",
		},
		{
			ID:          "r-vpn-iface",
			GroupID:     g.ID,
			Position:    2,
			Enabled:     true,
			Action:      "accept",
			Iif:         "linkguard",
			Proto:       "tcp",
			Dport:       "443",
			Description: "Interface VPN",
		},
		{
			ID:          "r-vcn",
			GroupID:     g.ID,
			Position:    3,
			Enabled:     true,
			Action:      "accept",
			Saddr:       "10.0.1.15",
			Proto:       "tcp",
			Dport:       "8080",
			Description: "Origem VCN",
		},
		{
			ID:          "r-internet",
			GroupID:     g.ID,
			Position:    4,
			Enabled:     true,
			Action:      "accept",
			Saddr:       "203.0.113.8",
			Proto:       "tcp",
			Dport:       "25",
			Description: "Origem Internet",
		},
		{
			ID:          "r-sem-origem",
			GroupID:     g.ID,
			Position:    5,
			Enabled:     true,
			Action:      "accept",
			Proto:       "tcp",
			Dport:       "53",
			Description: "Sem origem nem iface",
		},
	}
	for _, r := range regras {
		_ = db.CreateFirewallRule(r)
	}

	if err := svc.ConverterLegadoUmaVez(ctx, f); err != nil {
		t.Fatalf("ConverterLegadoUmaVez: %v", err)
	}

	cfg, err := db.CarregarConfigEmEdicao()
	if err != nil {
		t.Fatalf("CarregarConfigEmEdicao: %v", err)
	}

	// Mapeia regras por ID
	rm := make(map[string]fwmodel.Regra)
	for _, r := range cfg.Regras {
		rm[r.ID] = r
	}

	// 1. Regra com saddr da VPN -> aba VPN
	r1, ok := rm["r-vpn-saddr"]
	if !ok || r1.Zona != fwmodel.ZonaVPN || !r1.Ativa {
		t.Errorf("r-vpn-saddr deveria estar na ZonaVPN e ativa; veio: zona=%s ativa=%v", r1.Zona, r1.Ativa)
	}

	// 2. Regra com iif linkguard -> aba VPN
	r2, ok := rm["r-vpn-iface"]
	if !ok || r2.Zona != fwmodel.ZonaVPN || !r2.Ativa {
		t.Errorf("r-vpn-iface deveria estar na ZonaVPN e ativa; veio: zona=%s ativa=%v", r2.Zona, r2.Ativa)
	}

	// 3. Regra com saddr 10.0.1.15 -> aba VCN
	r3, ok := rm["r-vcn"]
	if !ok || r3.Zona != fwmodel.ZonaVCN || !r3.Ativa {
		t.Errorf("r-vcn deveria estar na ZonaVCN e ativa; veio: zona=%s ativa=%v", r3.Zona, r3.Ativa)
	}

	// 4. Regra com saddr público -> aba Internet
	r4, ok := rm["r-internet"]
	if !ok || r4.Zona != fwmodel.ZonaInternet || !r4.Ativa {
		t.Errorf("r-internet deveria estar na ZonaInternet e ativa; veio: zona=%s ativa=%v", r4.Zona, r4.Ativa)
	}

	// 5. Regra sem origem nem interface -> Flutuantes desativada com prefixo [revisar]
	r5, ok := rm["r-sem-origem"]
	if !ok {
		t.Fatalf("r-sem-origem não encontrada")
	}
	if r5.Zona != fwmodel.ZonaFlutuante {
		t.Errorf("r-sem-origem deveria estar em Flutuantes, veio: %s", r5.Zona)
	}
	if r5.Ativa {
		t.Errorf("r-sem-origem deveria estar desativada")
	}
	if !strings.HasPrefix(r5.Descricao, "[revisar] ") {
		t.Errorf("r-sem-origem deveria ter prefixo [revisar], veio: %q", r5.Descricao)
	}

	// Relatório deve conter a menção da regra enviada para Flutuantes
	relStr, _ := db.GetSetting("fw_conversao_relatorio")
	if !strings.Contains(relStr, "r-sem-origem") {
		t.Errorf("relatório deveria mencionar r-sem-origem: %s", relStr)
	}
	var itens []ItemRelatorioConversao
	if err := json.Unmarshal([]byte(relStr), &itens); err != nil {
		t.Fatalf("relatório ilegível: %v", err)
	}
	for _, it := range itens {
		if it.Chave == "" {
			t.Errorf("item do relatório sem chave de texto para o painel: %+v", it)
		}
	}
}

func TestConversaoDestino(t *testing.T) {
	svc, db := newConversaoTestService(t)
	ctx := context.Background()

	f := FatosConversao{
		RedesVCN:     []string{"10.0.0.0/16"},
		RedeVPN:      "10.7.0.0/24",
		InterfaceVPN: "linkguard",
	}

	// Grupo com escopo input
	gInput := &storage.FirewallGroup{
		ID:        "grp-input",
		Name:      "Serviços Locais",
		ChainName: "grp_input",
		Position:  1,
		Enabled:   true,
		Kind:      "admin",
		Scope:     "input",
		CondSaddr: "10.0.0.0/16",
	}
	if err := db.CreateFirewallGroup(gInput); err != nil {
		t.Fatalf("CreateFirewallGroup gInput: %v", err)
	}
	if err := db.CreateFirewallRule(&storage.FirewallRule{
		ID:          "r-input-1",
		GroupID:     gInput.ID,
		Position:    1,
		Enabled:     true,
		Action:      "accept",
		Proto:       "tcp",
		Dport:       "22",
		Description: "SSH local",
	}); err != nil {
		t.Fatalf("CreateFirewallRule r-input-1: %v", err)
	}

	// Grupo com escopo forward e cond_daddr
	gFwd := &storage.FirewallGroup{
		ID:        "grp-fwd",
		Name:      "Passagem para Servidor",
		ChainName: "grp_fwd",
		Position:  2,
		Enabled:   true,
		Kind:      "admin",
		Scope:     "forward",
		CondSaddr: "10.0.0.0/16",
		CondDaddr: "192.168.1.100",
	}
	if err := db.CreateFirewallGroup(gFwd); err != nil {
		t.Fatalf("CreateFirewallGroup gFwd: %v", err)
	}
	if err := db.CreateFirewallRule(&storage.FirewallRule{
		ID:          "r-fwd-1",
		GroupID:     gFwd.ID,
		Position:    1,
		Enabled:     true,
		Action:      "accept",
		Proto:       "tcp",
		Dport:       "80",
		Description: "HTTP servidor",
	}); err != nil {
		t.Fatalf("CreateFirewallRule r-fwd-1: %v", err)
	}

	if err := svc.ConverterLegadoUmaVez(ctx, f); err != nil {
		t.Fatalf("ConverterLegadoUmaVez: %v", err)
	}

	cfg, _ := db.CarregarConfigEmEdicao()
	rm := make(map[string]fwmodel.Regra)
	for _, r := range cfg.Regras {
		rm[r.ID] = r
	}

	// Grupo de entrada vira destino PontaEste
	rIn := rm["r-input-1"]
	if rIn.Destino.Tipo != fwmodel.PontaEste {
		t.Errorf("r-input-1 deveria ter destino PontaEste, obteve: %v", rIn.Destino)
	}

	// Grupo de forward com cond_daddr vira destino PontaEndereco
	rFwd := rm["r-fwd-1"]
	if rFwd.Destino.Tipo != fwmodel.PontaEndereco || rFwd.Destino.Valor != "192.168.1.100" {
		t.Errorf("r-fwd-1 deveria ter destino PontaEndereco 192.168.1.100, obteve: %v", rFwd.Destino)
	}
}

func TestConversaoFallthroughSobra(t *testing.T) {
	svc, db := newConversaoTestService(t)
	ctx := context.Background()

	f := FatosConversao{
		RedesVCN: []string{"10.0.0.0/16"},
	}

	g := &storage.FirewallGroup{
		ID:          "grp-sobra",
		Name:        "Acesso Restrito",
		ChainName:   "grp_sobra",
		Position:    1,
		Enabled:     true,
		CondSaddr:   "10.0.2.0/24",
		Fallthrough: "drop",
		Kind:        "admin",
		Scope:       "forward",
	}
	_ = db.CreateFirewallGroup(g)
	_ = db.CreateFirewallRule(&storage.FirewallRule{
		ID:          "r-permite-80",
		GroupID:     g.ID,
		Position:    1,
		Enabled:     true,
		Action:      "accept",
		Proto:       "tcp",
		Dport:       "80",
		Description: "Permite 80",
	})

	if err := svc.ConverterLegadoUmaVez(ctx, f); err != nil {
		t.Fatalf("ConverterLegadoUmaVez: %v", err)
	}

	cfg, _ := db.CarregarConfigEmEdicao()
	var encontrouSobra bool
	for _, r := range cfg.Regras {
		if r.ID == "r-sobra-"+g.ID {
			encontrouSobra = true
			if r.Acao != fwmodel.AcaoDrop {
				t.Errorf("sobra deveria ter AcaoDrop, veio: %s", r.Acao)
			}
			if r.Zona != fwmodel.ZonaVCN {
				t.Errorf("sobra deveria estar na ZonaVCN, veio: %s", r.Zona)
			}
			if r.Descricao != "Sobra do grupo "+g.Name {
				t.Errorf("descrição da sobra incorreta: %s", r.Descricao)
			}
		}
	}
	if !encontrouSobra {
		t.Fatalf("regra de sobra não foi criada")
	}
}

func TestConversaoAgendamentosDeduplicados(t *testing.T) {
	svc, db := newConversaoTestService(t)
	ctx := context.Background()

	f := FatosConversao{
		RedesVCN: []string{"10.0.0.0/16"},
	}

	g1 := &storage.FirewallGroup{
		ID:         "grp-1",
		Name:       "Horário Comercial 1",
		ChainName:  "grp_1",
		Position:   1,
		Enabled:    true,
		Kind:       "admin",
		SchedDays:  "mon,tue,wed,thu,fri",
		SchedStart: "08:00",
		SchedEnd:   "18:00",
		CondSaddr:  "10.0.1.0/24",
	}
	g2 := &storage.FirewallGroup{
		ID:         "grp-2",
		Name:       "Horário Comercial 2",
		ChainName:  "grp_2",
		Position:   2,
		Enabled:    true,
		Kind:       "admin",
		SchedDays:  "mon,tue,wed,thu,fri",
		SchedStart: "08:00",
		SchedEnd:   "18:00",
		CondSaddr:  "10.0.2.0/24",
	}
	if err := db.CreateFirewallGroup(g1); err != nil {
		t.Fatalf("CreateFirewallGroup g1: %v", err)
	}
	if err := db.CreateFirewallGroup(g2); err != nil {
		t.Fatalf("CreateFirewallGroup g2: %v", err)
	}

	_ = db.CreateFirewallRule(&storage.FirewallRule{
		ID:       "r1",
		GroupID:  g1.ID,
		Position: 1,
		Enabled:  true,
		Action:   "accept",
	})
	_ = db.CreateFirewallRule(&storage.FirewallRule{
		ID:       "r2",
		GroupID:  g2.ID,
		Position: 1,
		Enabled:  true,
		Action:   "accept",
	})

	if err := svc.ConverterLegadoUmaVez(ctx, f); err != nil {
		t.Fatalf("ConverterLegadoUmaVez: %v", err)
	}

	cfg, _ := db.CarregarConfigEmEdicao()
	if len(cfg.Agendamentos) != 1 {
		t.Fatalf("esperava exatamente 1 agendamento deduplicado, obteve: %d", len(cfg.Agendamentos))
	}

	ag := cfg.Agendamentos[0]
	rm := make(map[string]fwmodel.Regra)
	for _, r := range cfg.Regras {
		rm[r.ID] = r
	}

	if rm["r1"].AgendamentoID != ag.ID || rm["r2"].AgendamentoID != ag.ID {
		t.Errorf("ambas as regras devem apontar para o mesmo agendamento %s; r1=%s r2=%s",
			ag.ID, rm["r1"].AgendamentoID, rm["r2"].AgendamentoID)
	}
}

func TestConversaoIgnoraGruposSistemaEVPN(t *testing.T) {
	svc, db := newConversaoTestService(t)
	ctx := context.Background()

	f := FatosConversao{
		RedesVCN: []string{"10.0.0.0/16"},
	}

	// Os grupos do sistema como o legado os criava: quem os identifica é o
	// kind, e o nome é só o de exibição. Cada um leva uma regra de bloqueio
	// para provar que a exclusão é por kind e não por o grupo estar vazio.
	_ = db.CreateFirewallGroup(&storage.FirewallGroup{
		ID:          "grp-sys-1",
		Name:        "Hosts bloqueados",
		ChainName:   "grp_sys_1",
		Position:    1,
		Enabled:     true,
		Fallthrough: "continue",
		Kind:        "blocked_hosts",
	})
	_ = db.CreateFirewallGroup(&storage.FirewallGroup{
		ID:          "grp-sys-2",
		Name:        "Destinos bloqueados",
		ChainName:   "grp_sys_2",
		Position:    2,
		Enabled:     true,
		Fallthrough: "continue",
		Kind:        "blocklist",
	})
	for _, grupo := range []string{"grp-sys-1", "grp-sys-2"} {
		_ = db.CreateFirewallRule(&storage.FirewallRule{
			ID:          "r-" + grupo,
			GroupID:     grupo,
			Position:    1,
			Enabled:     true,
			Action:      "drop",
			Saddr:       "203.0.113.9",
			Description: "bloqueio do sistema",
		})
	}

	// Grupo de peer WireGuard e regra ZTNA
	_ = db.CreateFirewallGroup(&storage.FirewallGroup{
		ID:        "grp-wg",
		Name:      "VPN - alice",
		ChainName: "grp_wg",
		Position:  3,
		Enabled:   true,
		Kind:      "wireguard_peer",
	})
	_ = db.CreateFirewallRule(&storage.FirewallRule{
		ID:          "r-ztna",
		GroupID:     "grp-wg",
		Position:    1,
		Enabled:     true,
		Action:      "accept",
		Description: "ZTNA: acesso a servicos",
	})

	if err := svc.ConverterLegadoUmaVez(ctx, f); err != nil {
		t.Fatalf("ConverterLegadoUmaVez: %v", err)
	}

	cfg, _ := db.CarregarConfigEmEdicao()
	// Somente a regra de gerência da WAN deve existir
	for _, r := range cfg.Regras {
		if r.ID != "r-wan-gerencia" {
			t.Errorf("nenhuma regra adicional deveria ter sido gerada, encontrou: %+v", r)
		}
	}
}

func TestConversaoWanMgmtClosed(t *testing.T) {
	ctx := context.Background()
	f := FatosConversao{RedesVCN: []string{"10.0.0.0/16"}}

	// Caso 1: firewall_wan_mgmt_closed ausente -> regra ativa
	{
		svc, db := newConversaoTestService(t)
		if err := svc.ConverterLegadoUmaVez(ctx, f); err != nil {
			t.Fatalf("ConverterLegadoUmaVez: %v", err)
		}
		cfg, _ := db.CarregarConfigEmEdicao()
		var found bool
		for _, r := range cfg.Regras {
			if r.ID == "r-wan-gerencia" {
				found = true
				if !r.Ativa {
					t.Errorf("r-wan-gerencia deveria estar ativa por padrão")
				}
			}
		}
		if !found {
			t.Fatalf("r-wan-gerencia não encontrada")
		}
	}

	// Caso 2: firewall_wan_mgmt_closed = "1" -> regra desativada
	{
		svc, db := newConversaoTestService(t)
		_ = db.SetSetting("firewall_wan_mgmt_closed", "1")
		if err := svc.ConverterLegadoUmaVez(ctx, f); err != nil {
			t.Fatalf("ConverterLegadoUmaVez: %v", err)
		}
		cfg, _ := db.CarregarConfigEmEdicao()
		var found bool
		for _, r := range cfg.Regras {
			if r.ID == "r-wan-gerencia" {
				found = true
				if r.Ativa {
					t.Errorf("r-wan-gerencia deveria estar desativada quando firewall_wan_mgmt_closed=1")
				}
			}
		}
		if !found {
			t.Fatalf("r-wan-gerencia não encontrada")
		}
	}
}

func TestConversaoIdempotente(t *testing.T) {
	svc, db := newConversaoTestService(t)
	ctx := context.Background()

	f := FatosConversao{
		RedesVCN: []string{"10.0.0.0/16"},
	}

	g := &storage.FirewallGroup{
		ID:        "grp-1",
		Name:      "Grupo 1",
		ChainName: "grp_idem",
		Position:  1,
		Enabled:   true,
		Kind:      "admin",
		CondSaddr: "10.0.1.0/24",
	}
	_ = db.CreateFirewallGroup(g)
	_ = db.CreateFirewallRule(&storage.FirewallRule{
		ID:       "r1",
		GroupID:  g.ID,
		Position: 1,
		Enabled:  true,
		Action:   "accept",
	})

	if err := svc.ConverterLegadoUmaVez(ctx, f); err != nil {
		t.Fatalf("primeira conversao: %v", err)
	}

	cfg1, _ := db.CarregarConfigEmEdicao()

	// Segunda conversão não deve fazer nada
	if err := svc.ConverterLegadoUmaVez(ctx, f); err != nil {
		t.Fatalf("segunda conversao: %v", err)
	}

	cfg2, _ := db.CarregarConfigEmEdicao()
	if len(cfg1.Regras) != len(cfg2.Regras) {
		t.Errorf("segunda execução modificou regras: antes=%d depois=%d", len(cfg1.Regras), len(cfg2.Regras))
	}
}

func TestConversaoCaminhosPreservados(t *testing.T) {
	svc, db := newConversaoTestService(t)
	ctx := context.Background()

	f := FatosConversao{
		RedesVCN:     []string{"10.0.0.0/16"},
		RedeVPN:      "10.7.0.0/24",
		InterfaceVPN: "linkguard",
		PlacasWAN:    []string{"ens3"},
	}

	// Banco simulando produção:
	// - Um usuário admin na VPN com acesso total (10.7.0.2)
	// - Um usuário restrito na VPN (10.7.0.3)
	// - Grupos wireguard_peer correspondentes
	// - Nenhuma regra de admin
	// - Políticas accept
	_ = db.SetSetting("firewall_input_policy", "accept")
	_ = db.SetSetting("firewall_forward_policy", "accept")

	uAdmin := &storage.User{ID: "uid-admin", Username: "admin"}
	_ = db.CreateUser(uAdmin, "hash", nil)
	gAdmin := &storage.FirewallGroup{
		ID:        "grp-admin",
		Name:      "VPN - admin",
		Position:  1,
		Enabled:   true,
		CondSaddr: "10.7.0.2/32",
		Kind:      "wireguard_peer",
	}
	pAdmin := &storage.WireGuardPeer{
		UserID:            uAdmin.ID,
		PublicKey:         "pubkey-admin",
		Address:           "10.7.0.2/32",
		AccessMode:        "full",
		AllowedHostGroups: []string{},
	}
	_ = db.CreateFirewallGroup(gAdmin)
	_, _ = db.UpsertWireGuardPeer(pAdmin)

	uRestrito := &storage.User{ID: "uid-restrito", Username: "restrito"}
	_ = db.CreateUser(uRestrito, "hash", nil)
	gRestrito := &storage.FirewallGroup{
		ID:        "grp-restrito",
		Name:      "VPN - restrito",
		Position:  2,
		Enabled:   true,
		CondSaddr: "10.7.0.3/32",
		Kind:      "wireguard_peer",
	}
	pRestrito := &storage.WireGuardPeer{
		UserID:            uRestrito.ID,
		PublicKey:         "pubkey-restrito",
		Address:           "10.7.0.3/32",
		AccessMode:        "restricted",
		AllowedHostGroups: []string{},
	}
	_ = db.CreateFirewallGroup(gRestrito)
	_, _ = db.UpsertWireGuardPeer(pRestrito)

	// Executa a conversão
	if err := svc.ConverterLegadoUmaVez(ctx, f); err != nil {
		t.Fatalf("ConverterLegadoUmaVez: %v", err)
	}

	cfg, err := db.CarregarConfigEmEdicao()
	if err != nil {
		t.Fatalf("CarregarConfigEmEdicao: %v", err)
	}

	// Renderiza com RenderZonas
	ins := nftables.Insumos{
		RedesVCN:       f.RedesVCN,
		RedeVPN:        f.RedeVPN,
		InterfaceVPN:   f.InterfaceVPN,
		PortaWireGuard: 51820,
		PortasGerencia: []int{22, 9997},
		Pessoas: []nftables.PessoaVPN{
			{
				UserID:   uAdmin.ID,
				Usuario:  uAdmin.Username,
				Endereco: "10.7.0.2",
				Total:    true,
			},
			{
				UserID:   uRestrito.ID,
				Usuario:  uRestrito.Username,
				Endereco: "10.7.0.3",
				Total:    false,
			},
		},
	}

	ruleset, err := nftables.RenderZonas(cfg, ins)
	if err != nil {
		t.Fatalf("RenderZonas: %v", err)
	}

	sim := novoSimulador(ruleset.Script)

	// 1. Internet -> porta 22 da caixa: Aceito (gerência aberta pela Internet)
	acao, chave := sim.avaliar(simPacote{
		iif:          "ens3",
		saddr:        "198.51.100.20",
		daddr:        "10.0.0.1",
		daddrIsLocal: true,
		proto:        "tcp",
		dport:        22,
	})
	if acao != "accept" || chave != "r:r-wan-gerencia" {
		t.Errorf("Internet -> 22: esperava accept r:r-wan-gerencia; veio %s %s", acao, chave)
	}

	// 2. VCN (10.0.0.50) -> porta 9997 da caixa: Aceito (anti-bloqueio VCN)
	acao, chave = sim.avaliar(simPacote{
		iif:          "ens3",
		saddr:        "10.0.0.50",
		daddr:        "10.0.0.1",
		daddrIsLocal: true,
		proto:        "tcp",
		dport:        9997,
	})
	if acao != "accept" || chave != "s:antibloqueio:vcn" {
		t.Errorf("VCN -> 9997: esperava accept s:antibloqueio:vcn; veio %s %s", acao, chave)
	}

	// 3. Pessoa total da VPN (10.7.0.2) -> Internet: Aceito
	acao, chave = sim.avaliar(simPacote{
		iif:          "linkguard",
		saddr:        "10.7.0.2",
		daddr:        "1.1.1.1",
		daddrIsLocal: false,
		proto:        "tcp",
		dport:        443,
	})
	if acao != "accept" || chave != "s:vpn:uid-admin:total" {
		t.Errorf("Pessoa total -> Internet: esperava accept s:vpn:uid-admin:total; veio %s %s", acao, chave)
	}

	// 4. Pessoa total da VPN (10.7.0.2) -> Caixa (SSH 22): Aceito
	acao, chave = sim.avaliar(simPacote{
		iif:          "linkguard",
		saddr:        "10.7.0.2",
		daddr:        "10.0.0.1",
		daddrIsLocal: true,
		proto:        "tcp",
		dport:        22,
	})
	if acao != "accept" || chave != "s:vpn:uid-admin:total" {
		t.Errorf("Pessoa total -> Caixa 22: esperava accept s:vpn:uid-admin:total; veio %s %s", acao, chave)
	}

	// 5. Pessoa restrita da VPN (10.7.0.3) -> Porta 22 da caixa: DROP! (Defeito 1 corrigido)
	acao, chave = sim.avaliar(simPacote{
		iif:          "linkguard",
		saddr:        "10.7.0.3",
		daddr:        "10.0.0.1",
		daddrIsLocal: true,
		proto:        "tcp",
		dport:        22,
	})
	if acao != "drop" || chave != "d:vpn:in" {
		t.Errorf("Pessoa restrita -> Caixa 22: esperava drop d:vpn:in; veio %s %s", acao, chave)
	}

	// 6. Pessoa restrita da VPN (10.7.0.3) -> Porta 9997 da caixa: DROP! (Defeito 1 corrigido)
	acao, chave = sim.avaliar(simPacote{
		iif:          "linkguard",
		saddr:        "10.7.0.3",
		daddr:        "10.0.0.1",
		daddrIsLocal: true,
		proto:        "tcp",
		dport:        9997,
	})
	if acao != "drop" || chave != "d:vpn:in" {
		t.Errorf("Pessoa restrita -> Caixa 9997: esperava drop d:vpn:in; veio %s %s", acao, chave)
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
			continue
		}
		if veredito != "" {
			return veredito, chave
		}
	}
	return "", ""
}

func (s *simulador) casaRegra(r string, p simPacote) (casou bool, jumpChain, veredito, chave string) {
	chave = ""
	if idx := strings.Index(r, "comment \""); idx >= 0 {
		end := strings.Index(r[idx+9:], "\"")
		if end >= 0 {
			chave = r[idx+9 : idx+9+end]
		}
	}

	if strings.Contains(r, "limit rate") && strings.Contains(r, "log prefix") {
		return false, "", "", ""
	}
	if strings.Contains(r, "ip6 ") || strings.Contains(r, "icmpv6 ") {
		return false, "", "", ""
	}
	if strings.Contains(r, "ct state established,related") {
		return false, "", "", ""
	}
	if strings.Contains(r, `iif "lo"`) {
		if p.iif != "lo" {
			return false, "", "", ""
		}
	}
	if strings.Contains(r, "udp sport 67") || strings.Contains(r, "udp dport 546") {
		return false, "", "", ""
	}

	if strings.Contains(r, "iifname ") {
		parts := strings.Split(r, "iifname ")
		ifaceVal := strings.Fields(parts[1])[0]
		ifaceVal = strings.Trim(ifaceVal, "\"")
		if p.iif != ifaceVal {
			return false, "", "", ""
		}
	}

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

	if strings.Contains(r, "ct status dnat") {
		if !p.ctStatusDnat {
			return false, "", "", ""
		}
	}

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

	if strings.Contains(r, "meta l4proto { tcp, udp } th dport 53") {
		if (p.proto != "tcp" && p.proto != "udp") || p.dport != 53 {
			return false, "", "", ""
		}
	}

	if strings.Contains(r, "meta l4proto icmp") || strings.Contains(r, "icmp type echo-request") {
		if p.proto != "icmp" {
			return false, "", "", ""
		}
	}

	if strings.Contains(r, "jump ") {
		parts := strings.Split(r, "jump ")
		jChain := strings.Fields(parts[1])[0]
		return true, jChain, "", ""
	}

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
