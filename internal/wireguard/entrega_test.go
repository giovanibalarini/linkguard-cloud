package wireguard

import (
	"context"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-cloud/internal/nftables"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

// ─────────────────────────────────────────────────────────────────────────────
// Entrega de VPN pelo admin e isolamento do peer restrito (24/09/2026).
//
// O caso real: dar a um colega acesso só à API do k3s (10.0.1.20:6443). Antes
// disto foi preciso logar como ele, enrolar, restringir e reemitir; e mesmo
// restrito ele ainda alcançava o SSH e o painel da própria caixa pelo 10.7.0.1.
// ─────────────────────────────────────────────────────────────────────────────

func preparaVPN(t *testing.T, svc *Service, db *storage.DB) *storage.HostGroup {
	t.Helper()
	c := DefaultConfig()
	c.Enabled = true
	c.EndpointHost = "vpn.example.net"
	if err := svc.UpdateConfig(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	k3s := &storage.HostGroup{Name: "K3s API", Hosts: []string{"10.0.1.20"}}
	if err := db.CreateHostGroup(k3s); err != nil {
		t.Fatal(err)
	}
	return k3s
}

func novoUsuario(t *testing.T, db *storage.DB, nome string) string {
	t.Helper()
	u := &storage.User{Username: nome}
	if err := db.CreateUser(u, "hash", nil); err != nil {
		t.Fatal(err)
	}
	return u.ID
}

func soK3s(k3s *storage.HostGroup) PeerAccess {
	return PeerAccess{AccessMode: "restricted", AllowedHostGroups: []string{k3s.ID},
		AllowedPorts: "6443", TunnelMode: TunnelSplit}
}

func grupoPorID(t *testing.T, db *storage.DB, id string) *storage.FirewallGroup {
	t.Helper()
	groups, err := db.ListFirewallGroups()
	if err != nil {
		t.Fatal(err)
	}
	for i := range groups {
		if groups[i].ID == id {
			return &groups[i]
		}
	}
	return nil
}

func regrasDoGrupo(t *testing.T, db *storage.DB, id string) []storage.FirewallRule {
	t.Helper()
	rules, err := db.ListFirewallRules()
	if err != nil {
		t.Fatal(err)
	}
	var out []storage.FirewallRule
	for _, r := range rules {
		if r.GroupID == id {
			out = append(out, r)
		}
	}
	return out
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
	if g := grupoPorID(t, db, peer.FirewallGroupID); g == nil || g.Fallthrough != nftables.FallthroughDrop {
		t.Fatalf("grupo de encaminhamento do peer restrito = %+v, queria drop no fim", g)
	}
}

func TestPeerRestritoNaoAlcancaAPropriaCaixa(t *testing.T) {
	svc, db, _, _ := newServiceTest(t)
	k3s := preparaVPN(t, svc, db)
	diego := novoUsuario(t, db, "diego")
	if _, err := svc.EnrollFor(context.Background(), diego, soK3s(k3s)); err != nil {
		t.Fatalf("EnrollFor: %v", err)
	}
	peer, _ := db.GetWireGuardPeer(diego)

	entrada := grupoPorID(t, db, inputGroupID(peer.FirewallGroupID))
	if entrada == nil {
		t.Fatal("o peer restrito ficou sem grupo de entrada: alcança SSH e painel da caixa")
	}
	if entrada.Scope != nftables.ScopeInput || entrada.Fallthrough != nftables.FallthroughDrop ||
		entrada.ConnState != nftables.ConnStateNew || entrada.CondSaddr != peer.Address {
		t.Fatalf("grupo de entrada mal formado: %+v", entrada)
	}
	var liberado []string
	for _, r := range regrasDoGrupo(t, db, entrada.ID) {
		if r.Action != "accept" {
			t.Fatalf("regra inesperada no grupo de entrada: %+v", r)
		}
		liberado = append(liberado, r.Proto+"/"+r.Dport)
	}
	if strings.Join(liberado, " ") != "udp/53 tcp/53 icmp/" {
		t.Fatalf("a caixa libera para o peer restrito: %v; queria só DNS e ping", liberado)
	}

	// Reconciliar de novo não duplica as regras.
	if err := svc.SetPeerAccess(context.Background(), diego, soK3s(k3s)); err != nil {
		t.Fatalf("SetPeerAccess: %v", err)
	}
	if n := len(regrasDoGrupo(t, db, entrada.ID)); n != 3 {
		t.Fatalf("depois de reconciliar o grupo de entrada tem %d regras, queria 3", n)
	}
}

func TestTrocarAChaveDoPeerRestritoMantemARestricao(t *testing.T) {
	svc, db, _, _ := newServiceTest(t)
	k3s := preparaVPN(t, svc, db)
	diego := novoUsuario(t, db, "diego")
	if _, err := svc.EnrollFor(context.Background(), diego, soK3s(k3s)); err != nil {
		t.Fatalf("EnrollFor: %v", err)
	}

	// O "Gerar configuração" da própria tela rotaciona a chave. Até 24/09/2026 o
	// grupo era regravado com "continue" e só voltava a drop se a reconciliação
	// chegasse até o fim.
	rotacionada, err := svc.Enroll(context.Background(), diego)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	peer, _ := db.GetWireGuardPeer(diego)
	if g := grupoPorID(t, db, peer.FirewallGroupID); g == nil || g.Fallthrough != nftables.FallthroughDrop {
		t.Fatalf("depois de trocar a chave o grupo ficou %+v", g)
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

func TestTirarARestricaoOuRevogarApagaOGrupoDeEntrada(t *testing.T) {
	svc, db, _, _ := newServiceTest(t)
	k3s := preparaVPN(t, svc, db)
	diego := novoUsuario(t, db, "diego")
	if _, err := svc.EnrollFor(context.Background(), diego, soK3s(k3s)); err != nil {
		t.Fatalf("EnrollFor: %v", err)
	}
	peer, _ := db.GetWireGuardPeer(diego)
	entradaID := inputGroupID(peer.FirewallGroupID)

	if err := svc.SetPeerAccess(context.Background(), diego, PeerAccess{AccessMode: "full"}); err != nil {
		t.Fatalf("SetPeerAccess: %v", err)
	}
	if grupoPorID(t, db, entradaID) != nil {
		t.Fatal("o peer liberado continuou barrado na entrada da caixa")
	}

	if err := svc.SetPeerAccess(context.Background(), diego, soK3s(k3s)); err != nil {
		t.Fatalf("SetPeerAccess: %v", err)
	}
	if err := svc.Revoke(context.Background(), diego); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if grupoPorID(t, db, entradaID) != nil || len(regrasDoGrupo(t, db, entradaID)) != 0 {
		t.Fatal("revogar deixou o grupo de entrada (ou as regras dele) para trás")
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
		if _, err := normalizeAccess(PeerAccess{AccessMode: "restricted", AllowedPorts: portas}); err == nil {
			t.Errorf("aceitou portas %q", portas)
		}
	}
	a, err := normalizeAccess(PeerAccess{AccessMode: "restricted", AllowedPorts: " 22 , 8000-8100,,"})
	if err != nil || a.AllowedPorts != "22,8000-8100" {
		t.Fatalf("normalizou para %q, %v", a.AllowedPorts, err)
	}
}
