package wireguard

import (
	"context"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-cloud/internal/fwmodel"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Entrega de VPN pelo admin e isolamento do peer restrito (24/09/2026).
// No modelo de firewall por zonas, o serviço da VPN não escreve em firewall_rules
// nem em firewall_groups; as permissões vêm dos aliases da config aplicada.
// ─────────────────────────────────────────────────────────────────────────────

func preparaVPN(t *testing.T, svc *Service, db *storage.DB) string {
	t.Helper()
	c := DefaultConfig()
	c.Enabled = true
	c.EndpointHost = "vpn.example.net"
	if err := svc.UpdateConfig(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	cfg := fwmodel.Config{
		Formato: 1,
		Aliases: []fwmodel.Alias{
			{ID: "k3s-alias", Nome: "K3s API", Tipo: fwmodel.AliasTipoEnderecos, Itens: []string{"10.0.1.20"}},
		},
		Ajustes: fwmodel.AjustesPadrao(),
	}
	if err := db.SalvarAplicadaERevisao(cfg, "admin", "setup", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	return "k3s-alias"
}

func novoUsuario(t *testing.T, db *storage.DB, nome string) string {
	t.Helper()
	u := &storage.User{Username: nome}
	if err := db.CreateUser(u, "hash", nil); err != nil {
		t.Fatal(err)
	}
	return u.ID
}

func soK3s(aliasID string) PeerAccess {
	return PeerAccess{AccessMode: "restricted", AllowedHostGroups: []string{aliasID},
		AllowedPorts: "6443", TunnelMode: TunnelSplit}
}

func TestEntregaDoAdminJaNasceComOPerfilRestrito(t *testing.T) {
	svc, db, _, _ := newServiceTest(t)
	k3s := preparaVPN(t, svc, db)
	diego := novoUsuario(t, db, "diego")

	e, err := svc.EnrollFor(context.Background(), diego, soK3s(k3s))
	if err != nil {
		t.Fatalf("EnrollFor: %v", err)
	}
	// A primeira config entregue já é a definitiva: só o túnel e o k3s.
	if !strings.Contains(e.ClientConfig, "AllowedIPs = 10.7.0.0/24, 10.0.1.20/32") {
		t.Fatalf("a config não saiu com o perfil pedido:\n%s", e.ClientConfig)
	}
	peer, err := db.GetWireGuardPeer(diego)
	if err != nil || peer == nil {
		t.Fatalf("peer = %+v, %v", peer, err)
	}
	if peer.AccessMode != "restricted" || peer.AllowedPorts != "6443" || peer.TunnelMode != TunnelSplit {
		t.Fatalf("perfil gravado = %+v", peer)
	}
	if peer.ConfigStale {
		t.Fatal("a config acabou de ser entregue com este perfil; não pode nascer desatualizada")
	}
}

func TestVPNNaoEscreveEmRegrasDeFirewall(t *testing.T) {
	svc, db, _, _ := newServiceTest(t)
	k3s := preparaVPN(t, svc, db)
	diego := novoUsuario(t, db, "diego")

	contarLinhas := func() (int, int) {
		groups, err := db.ListFirewallGroups()
		if err != nil {
			t.Fatal(err)
		}
		rules, err := db.ListFirewallRules()
		if err != nil {
			t.Fatal(err)
		}
		return len(groups), len(rules)
	}

	g0, r0 := contarLinhas()

	// 1. EnrollFor não deve escrever regras nem grupos legados
	if _, err := svc.EnrollFor(context.Background(), diego, soK3s(k3s)); err != nil {
		t.Fatalf("EnrollFor: %v", err)
	}
	g1, r1 := contarLinhas()
	if g1 != g0 || r1 != r0 {
		t.Fatalf("EnrollFor escreveu no firewall legado: grupos=%d->%d regras=%d->%d", g0, g1, r0, r1)
	}

	// 2. SetPeerAccess não deve escrever regras nem grupos legados
	if err := svc.SetPeerAccess(context.Background(), diego, soK3s(k3s)); err != nil {
		t.Fatalf("SetPeerAccess: %v", err)
	}
	g2, r2 := contarLinhas()
	if g2 != g0 || r2 != r0 {
		t.Fatalf("SetPeerAccess escreveu no firewall legado: grupos=%d->%d regras=%d->%d", g0, g2, r0, r2)
	}

	// 3. Reconcile não deve escrever regras nem grupos legados
	if err := svc.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	g3, r3 := contarLinhas()
	if g3 != g0 || r3 != r0 {
		t.Fatalf("Reconcile escreveu no firewall legado: grupos=%d->%d regras=%d->%d", g0, g3, r0, r3)
	}

	// 4. Revoke não deve mexer no firewall legado
	if err := svc.Revoke(context.Background(), diego); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	g4, r4 := contarLinhas()
	if g4 != g0 || r4 != r0 {
		t.Fatalf("Revoke alterou o firewall legado: grupos=%d->%d regras=%d->%d", g0, g4, r0, r4)
	}
}

func TestTrocarAChaveDoPeerRestritoMantemARestricao(t *testing.T) {
	svc, db, _, _ := newServiceTest(t)
	k3s := preparaVPN(t, svc, db)
	diego := novoUsuario(t, db, "diego")
	if _, err := svc.EnrollFor(context.Background(), diego, soK3s(k3s)); err != nil {
		t.Fatalf("EnrollFor: %v", err)
	}

	rotacionada, err := svc.Enroll(context.Background(), diego)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	peer, _ := db.GetWireGuardPeer(diego)
	if peer.AccessMode != "restricted" {
		t.Fatalf("depois de trocar a chave o accessMode ficou %s", peer.AccessMode)
	}
	if peer.AllowedPorts != "6443" || !strings.Contains(rotacionada.ClientConfig, "10.0.1.20/32") ||
		strings.Contains(rotacionada.ClientConfig, "0.0.0.0/0") {
		t.Fatalf("trocar a chave mexeu no perfil: %+v\n%s", peer, rotacionada.ClientConfig)
	}
}

func TestEntregaEmPeerExistenteTrocaOPerfilPorInteiro(t *testing.T) {
	svc, db, _, _ := newServiceTest(t)
	k3s := preparaVPN(t, svc, db)
	bia := novoUsuario(t, db, "bia")
	if _, err := svc.EnrollFor(context.Background(), bia, PeerAccess{
		AccessMode: "full", TunnelMode: TunnelSplit, ExtraRoutes: []string{"192.168.50.0/24"},
	}); err != nil {
		t.Fatalf("EnrollFor: %v", err)
	}

	// Um perfil novo que ESVAZIA as rotas extras não pode herdar as antigas.
	e, err := svc.EnrollFor(context.Background(), bia, soK3s(k3s))
	if err != nil {
		t.Fatalf("EnrollFor: %v", err)
	}
	peer, _ := db.GetWireGuardPeer(bia)
	if len(peer.ExtraRoutes) != 0 || strings.Contains(e.ClientConfig, "192.168.50.0/24") {
		t.Fatalf("a rota antiga sobreviveu ao perfil novo: %+v\n%s", peer.ExtraRoutes, e.ClientConfig)
	}
}

func TestMinhaVPNMostraSoOProprioPeerEOQueEleAlcanca(t *testing.T) {
	svc, db, _, _ := newServiceTest(t)
	k3s := preparaVPN(t, svc, db)
	diego := novoUsuario(t, db, "diego")
	semVPN := novoUsuario(t, db, "carla")
	if _, err := svc.EnrollFor(context.Background(), diego, soK3s(k3s)); err != nil {
		t.Fatalf("EnrollFor: %v", err)
	}

	mine, err := svc.Mine(context.Background(), diego)
	if err != nil {
		t.Fatalf("Mine: %v", err)
	}
	if mine.Peer == nil || mine.Peer.Username != "diego" || mine.Endpoint != "vpn.example.net:51820" {
		t.Fatalf("minha VPN = %+v", mine)
	}
	if len(mine.Reach) != 1 || mine.Reach[0].Name != "K3s API" || mine.Reach[0].Ports != "6443" ||
		strings.Join(mine.Reach[0].Hosts, ",") != "10.0.1.20" {
		t.Fatalf("destinos = %+v", mine.Reach)
	}

	vazia, err := svc.Mine(context.Background(), semVPN)
	if err != nil || vazia.Peer != nil || !vazia.Enabled {
		t.Fatalf("quem não tem VPN: %+v, %v", vazia, err)
	}
}

func TestPerfilRecusaPortaQueONftRecusaria(t *testing.T) {
	for _, portas := range []string{"70000", "8080-80", "22; flush ruleset", "abc"} {
		if _, err := normalizeAccess(nil, PeerAccess{AccessMode: "restricted", AllowedPorts: portas}); err == nil {
			t.Errorf("aceitou portas %q", portas)
		}
	}
	a, err := normalizeAccess(nil, PeerAccess{AccessMode: "restricted", AllowedPorts: " 22 , 8000-8100,,"})
	if err != nil || a.AllowedPorts != "22,8000-8100" {
		t.Fatalf("normalizou para %q, %v", a.AllowedPorts, err)
	}
}

func TestPerfilRecusaAliasInexistente(t *testing.T) {
	_, db, _, _ := newServiceTest(t)
	// Com banco vazio (sem config aplicada)
	if _, err := normalizeAccess(db, PeerAccess{AccessMode: "restricted", AllowedHostGroups: []string{"inexistente"}}); err == nil {
		t.Fatal("deveria recusar alias inexistente")
	} else if !strings.Contains(err.Error(), "alias de endereços inexistente ou ainda não aplicado") {
		t.Fatalf("mensagem inesperada: %v", err)
	}

	// Com config aplicada contendo alias de portas e de endereços
	cfg := fwmodel.Config{
		Formato: 1,
		Aliases: []fwmodel.Alias{
			{ID: "alias-port", Nome: "Portas Web", Tipo: fwmodel.AliasTipoPortas, Itens: []string{"80", "443"}},
			{ID: "alias-addr", Nome: "Servidores", Tipo: fwmodel.AliasTipoEnderecos, Itens: []string{"10.0.1.10"}},
		},
		Ajustes: fwmodel.AjustesPadrao(),
	}
	if err := db.SalvarAplicadaERevisao(cfg, "admin", "setup", "", time.Now()); err != nil {
		t.Fatal(err)
	}

	// Alias de porta recusado para host group
	if _, err := normalizeAccess(db, PeerAccess{AccessMode: "restricted", AllowedHostGroups: []string{"alias-port"}}); err == nil {
		t.Fatal("deveria recusar alias do tipo portas como host group")
	}

	// Alias de endereço válido aceito
	acc, err := normalizeAccess(db, PeerAccess{AccessMode: "restricted", AllowedHostGroups: []string{"alias-addr"}})
	if err != nil {
		t.Fatalf("deveria aceitar alias de endereços: %v", err)
	}
	if len(acc.AllowedHostGroups) != 1 || acc.AllowedHostGroups[0] != "alias-addr" {
		t.Fatalf("AllowedHostGroups incorreto: %+v", acc.AllowedHostGroups)
	}

	// Aliases embutidos válidos aceitos
	for _, embutido := range []string{fwmodel.AliasVCN, fwmodel.AliasVPN} {
		acc, err := normalizeAccess(db, PeerAccess{AccessMode: "restricted", AllowedHostGroups: []string{embutido}})
		if err != nil {
			t.Fatalf("deveria aceitar alias embutido %s: %v", embutido, err)
		}
		if len(acc.AllowedHostGroups) != 1 || acc.AllowedHostGroups[0] != embutido {
			t.Fatalf("AllowedHostGroups incorreto para embutido: %+v", acc.AllowedHostGroups)
		}
	}
}

func TestPerfilComAliasEmbutidoNaoDependeDaConfigAplicada(t *testing.T) {
	svc, db, _, _ := newServiceTest(t)

	for _, embutido := range []string{fwmodel.AliasVCN, fwmodel.AliasVPN} {
		if _, err := normalizeAccess(db, PeerAccess{AccessMode: "restricted", AllowedHostGroups: []string{embutido}}); err != nil {
			t.Fatalf("%s deveria valer sem config aplicada: %v", embutido, err)
		}
	}
	if _, err := normalizeAccess(db, PeerAccess{AccessMode: "restricted", AllowedHostGroups: []string{fwmodel.AliasVCN, "inexistente"}}); err == nil {
		t.Fatal("um alias inexistente ao lado do embutido ainda precisa ser recusado")
	}

	svc.SetRedesVCN(func() []string { return []string{"10.0.0.0/16", "172.16.0.0/12"} })
	rotas, err := svc.resolveRoutes("restricted", []string{fwmodel.AliasVCN}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(rotas, ",") != "10.0.0.0/16,172.16.0.0/12" {
		t.Errorf("o alias sys:vcn precisa virar as redes da VCN no AllowedIPs, veio %v", rotas)
	}
}
