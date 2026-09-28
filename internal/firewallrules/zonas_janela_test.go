package firewallrules

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-cloud/internal/fwmodel"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

func createTestPeer(t *testing.T, db *storage.DB, userID, username, ip, accessMode string, aliases []string, ports string) {
	t.Helper()
	u := &storage.User{ID: userID, Username: username}
	_ = db.CreateUser(u, "hash", nil)
	g := &storage.FirewallGroup{
		ID:          "grp-" + userID,
		Name:        "VPN - " + username,
		ChainName:   "grp_" + strings.ReplaceAll(userID, "-", ""),
		Enabled:     true,
		CondSaddr:   ip + "/32",
		Fallthrough: "continue",
		Kind:        "wireguard_peer",
		Scope:       "forward",
	}
	p := &storage.WireGuardPeer{
		UserID:            userID,
		PublicKey:         "pubkey-" + userID,
		Address:           ip + "/32",
		SecretName:        "sec-" + userID,
		FirewallGroupID:   g.ID,
		AccessMode:        accessMode,
		AllowedHostGroups: aliases,
		AllowedPorts:      ports,
	}
	_, err := db.UpsertWireGuardPeer(p)
	if err != nil {
		t.Fatalf("UpsertWireGuardPeer: %v", err)
	}
}

func definirMTU(t *testing.T, db *storage.DB, userID string, mtu int) {
	t.Helper()
	peer, err := db.GetWireGuardPeer(userID)
	if err != nil || peer == nil {
		t.Fatalf("GetWireGuardPeer(%s): peer=%v err=%v", userID, peer, err)
	}
	err = db.UpdateWireGuardPeerAccess(userID, storage.WireGuardPeerAccess{
		AccessMode:        peer.AccessMode,
		AllowedHostGroups: peer.AllowedHostGroups,
		AllowedPorts:      peer.AllowedPorts,
		TunnelMode:        peer.TunnelMode,
		ExtraRoutes:       peer.ExtraRoutes,
		MTU:               mtu,
	})
	if err != nil {
		t.Fatalf("UpdateWireGuardPeerAccess(%s): %v", userID, err)
	}
}

func TestJanelaVenceReverte(t *testing.T) {
	svc, db, exec := newZonasTestService(t)
	ctx := context.Background()

	base := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	clock := newFakeClock(base)
	clock.wire(svc)

	cfg := fwmodel.Config{
		Formato: 1,
		Ajustes: fwmodel.AjustesPadrao(),
		Regras: []fwmodel.Regra{
			{
				ID:           "r-base",
				Zona:         fwmodel.ZonaInternet,
				Posicao:      1,
				Ativa:        true,
				Acao:         fwmodel.AcaoAccept,
				Proto:        fwmodel.ProtoTCP,
				Origem:       fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
				Destino:      fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
				PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaQualquer},
				Descricao:    "Base",
			},
		},
	}
	_ = db.SubstituirConfigEmEdicao(cfg)
	_ = db.SalvarAplicadaERevisao(cfg, "sistema", "inicial", "conversao", clock.wall)

	// Altera regra na VCN afetando a gerência (porta 22), abrindo janela
	_ = db.CriarRegraFW(&fwmodel.Regra{
		ID:           "r-bloqueio-ssh",
		Zona:         fwmodel.ZonaVCN,
		Posicao:      1,
		Ativa:        true,
		Acao:         fwmodel.AcaoDrop,
		Proto:        fwmodel.ProtoTCP,
		Origem:       fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
		Destino:      fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
		PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaValor, Valor: "22"},
		Descricao:    "Trava SSH",
	})

	applied, err := svc.Aplicar(ctx, "admin")
	if err != nil {
		t.Fatalf("Aplicar: %v", err)
	}
	if applied.WindowID == "" {
		t.Fatal("esperava abertura de janela")
	}

	exec.executed = nil

	// Avança o relógio além dos 90 segundos
	clock.advance(ConfirmWindow + time.Second)

	if err := svc.CheckPendingExpired(ctx); err != nil {
		t.Fatalf("CheckPendingExpired: %v", err)
	}

	// Janela deve estar limpa
	p, _ := db.GetPendingChange()
	if p != nil {
		t.Errorf("janela deveria ter sido limpa após reversão, ainda há: %+v", p)
	}

	// emEdicao e aplicada devem ter voltado ao estado do snapshot (apenas 1 regra r-base)
	emEdicao, _ := svc.EmEdicao()
	if len(emEdicao.Regras) != 1 || emEdicao.Regras[0].ID != "r-base" {
		t.Errorf("emEdicao deveria ter sido revertida para r-base, tem: %+v", emEdicao.Regras)
	}
	aplicada, _, _ := svc.Aplicada()
	if len(aplicada.Regras) != 1 || aplicada.Regras[0].ID != "r-base" {
		t.Errorf("aplicada deveria ter sido revertida para r-base, tem: %+v", aplicada.Regras)
	}

	// Revisão gravada com motivo 'reverter'
	revisoes, err := db.ListarRevisoes(5)
	if err != nil || len(revisoes) == 0 {
		t.Fatalf("listar revisões: %v", err)
	}
	if revisoes[0].Motivo != "reverter" {
		t.Errorf("última revisão deveria ter motivo 'reverter', obtido: %s", revisoes[0].Motivo)
	}

	// nft -f deve ter sido chamado para reaplicar o estado anterior
	var nftFCount int
	for _, cmd := range exec.executed {
		if len(cmd) > 1 && cmd[1] == "-f" {
			nftFCount++
		}
	}
	if nftFCount == 0 {
		t.Errorf("esperava execução de nft -f na reversão")
	}
}

func TestReversaoComPessoaNovaFicaRestrita(t *testing.T) {
	svc, db, _ := newZonasTestService(t)
	ctx := context.Background()

	base := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	clock := newFakeClock(base)
	clock.wire(svc)

	// Pessoa A já cadastrada antes da mudança com acesso total
	createTestPeer(t, db, "user-a", "ana", "10.7.0.2", "full", []string{"alias-1"}, "22,443")
	definirMTU(t, db, "user-a", 1380)

	cfg := fwmodel.Config{
		Formato: 1,
		Ajustes: fwmodel.AjustesPadrao(),
	}
	_ = db.SubstituirConfigEmEdicao(cfg)
	_ = db.SalvarAplicadaERevisao(cfg, "sistema", "inicial", "conversao", clock.wall)

	// Mudança que abre janela (afeta gerência / input)
	_ = db.CriarRegraFW(&fwmodel.Regra{
		ID:           "r-porta",
		Zona:         fwmodel.ZonaVCN,
		Posicao:      1,
		Ativa:        true,
		Acao:         fwmodel.AcaoDrop,
		Proto:        fwmodel.ProtoTCP,
		Origem:       fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
		Destino:      fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
		PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaValor, Valor: "22"},
		Descricao:    "Bloquear SSH",
	})

	applied, err := svc.Aplicar(ctx, "admin")
	if err != nil || applied.WindowID == "" {
		t.Fatalf("abrir janela: %v", err)
	}

	// Durante a janela, Pessoa B é cadastrada com acesso full e aliases
	createTestPeer(t, db, "user-b", "beto", "10.7.0.3", "full", []string{"alias-1", "alias-2"}, "80,443")
	definirMTU(t, db, "user-b", 1280)

	// Prazo da janela vence e reverte
	clock.advance(ConfirmWindow + time.Second)
	if err := svc.CheckPendingExpired(ctx); err != nil {
		t.Fatalf("CheckPendingExpired: %v", err)
	}

	// Confere Pessoa A: deve manter acesso full e aliases
	peers, err := db.ListWireGuardPeers()
	if err != nil {
		t.Fatalf("ListWireGuardPeers: %v", err)
	}

	var pA, pB *storage.WireGuardPeer
	for i := range peers {
		if peers[i].UserID == "user-a" {
			pA = &peers[i]
		}
		if peers[i].UserID == "user-b" {
			pB = &peers[i]
		}
	}

	if pA == nil || pA.AccessMode != "full" {
		t.Errorf("Pessoa A deveria manter access_mode=full, obtido: %+v", pA)
	}
	if pA != nil && pA.MTU != 1380 {
		t.Errorf("a reversão não pode mexer no MTU da Pessoa A: esperava 1380, obtido %d", pA.MTU)
	}

	// Confere Pessoa B: entrou durante a janela, deve ficar restrita e sem aliases (§2.8)
	if pB == nil {
		t.Fatal("Pessoa B deveria existir")
	}
	if pB.AccessMode != "restricted" {
		t.Errorf("Pessoa B (cadastrada durante a janela) DEVE ser restrita após reversão, obtido: %s", pB.AccessMode)
	}
	if len(pB.AllowedHostGroups) != 0 {
		t.Errorf("Pessoa B DEVE ficar sem aliases após reversão, obtido: %v", pB.AllowedHostGroups)
	}
	if pB.AllowedPorts != "" {
		t.Errorf("Pessoa B DEVE ficar com portas vazias após reversão, obtido: %q", pB.AllowedPorts)
	}
	if pB.MTU != 1280 {
		t.Errorf("a reversão não pode zerar o MTU da Pessoa B: esperava 1280, obtido %d", pB.MTU)
	}
}

func TestAplicarMudancaVPN(t *testing.T) {
	svc, db, exec := newZonasTestService(t)
	ctx := context.Background()

	cfg := fwmodel.Config{
		Formato: 1,
		Ajustes: fwmodel.AjustesPadrao(),
	}
	_ = db.SubstituirConfigEmEdicao(cfg)
	_ = db.SalvarAplicadaERevisao(cfg, "sistema", "inicial", "conversao", time.Now())

	// 1. Mudança VPN com sucesso
	var escrito bool
	applied, err := svc.AplicarMudancaVPN(ctx, "admin", "adicionar peer", func() error {
		escrito = true
		createTestPeer(t, db, "user-vpn", "valdo", "10.7.0.5", "full", nil, "")
		return nil
	}, nil)
	if err != nil {
		t.Fatalf("AplicarMudancaVPN sucesso: %v", err)
	}
	if !escrito {
		t.Fatal("função escrever deveria ter sido executada")
	}
	if applied == nil {
		t.Fatal("applied não pode ser nil")
	}

	// 2. Mudança VPN com falha no nft -c: chama desfazer e não aplica
	exec.failCheck = errors.New("simulando nft -c inválido")
	var desfeito bool
	_, err = svc.AplicarMudancaVPN(ctx, "admin", "mudança inválida", func() error {
		return nil
	}, func() error {
		desfeito = true
		return nil
	})
	if err == nil {
		t.Fatal("esperava erro de StagePreflight quando nft -c falha")
	}
	stage, ok := StageOf(err)
	if !ok || stage != StagePreflight {
		t.Errorf("esperava StagePreflight, obteve: %v", err)
	}
	if !desfeito {
		t.Errorf("desfazer DEVE ser chamado quando o pré-voo do nftables falha")
	}
}

func TestDescartarJanelaLegadaNoBootPosUpgrade(t *testing.T) {
	svc, db, _ := newZonasTestService(t)
	ctx := context.Background()

	// Marca que o firewall já foi convertido para zonas
	_ = db.SetSetting("fw_zonas_convertido", "true")

	// Grava um pendente legado (formato 1 / sem formato: 2)
	legacySnap := `{"groups":[{"id":"g-1","name":"Legado"}],"rules":[]}`
	_ = db.SavePendingChange(storage.PendingChange{
		ID:        "pendente-legado",
		AppliedBy: "admin",
		Summary:   "mudança antiga",
		Snapshot:  legacySnap,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(ConfirmWindow),
	})

	// No boot pós-upgrade, a janela legada deve ser descartada com aviso
	if err := svc.RevertPendingOnBoot(ctx); err != nil {
		t.Fatalf("RevertPendingOnBoot: %v", err)
	}

	p, err := db.GetPendingChange()
	if err != nil {
		t.Fatalf("GetPendingChange: %v", err)
	}
	if p != nil {
		t.Errorf("a janela legada pós-upgrade tinha que ter sido descartada, ainda há: %+v", p)
	}
}
