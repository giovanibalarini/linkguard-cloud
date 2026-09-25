package storage_test

import (
	"testing"

	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

// Rede de segurança para o recorte da issue #26: reservas DHCP, blocklist DNS e
// políticas de roteamento saíram de repository.go para repo_netsvc.go, e sete
// dessas funções não eram tocadas por nenhum teste — nem direto, nem via
// handler. Numa máquina que serve DHCP e DNS para a LAN inteira, um erro de
// recorte aqui chega calado em produção.
//
// São testes de caracterização: descrevem o que o código JÁ faz, para que
// qualquer mudança futura de comportamento apareça como teste vermelho.

// ─── Reservas DHCP ───────────────────────────────────────────────────────────

// ─── Blocklist DNS ───────────────────────────────────────────────────────────

func TestAddDNSBlocklistIsIdempotentAndOrdersAlphabetically(t *testing.T) {
	db := newTestDB(t)

	for _, d := range []string{"zumbi.example", "ads.example", "ads.example"} {
		if err := db.AddDNSBlocklist(d); err != nil {
			t.Fatalf("AddDNSBlocklist(%s): %v", d, err)
		}
	}

	got, err := db.ListDNSBlocklist()
	if err != nil {
		t.Fatalf("ListDNSBlocklist: %v", err)
	}
	// INSERT OR IGNORE: o domínio repetido não duplica nem devolve erro.
	if len(got) != 2 {
		t.Fatalf("esperava 2 domínios, veio %d (%v)", len(got), got)
	}
	if got[0] != "ads.example" || got[1] != "zumbi.example" {
		t.Errorf("ordem alfabética esperada, veio %v", got)
	}
}

func TestDeleteDNSBlocklistRemovesOnlyThatDomain(t *testing.T) {
	db := newTestDB(t)

	if err := db.AddDNSBlocklist("fica.example"); err != nil {
		t.Fatalf("AddDNSBlocklist: %v", err)
	}
	if err := db.AddDNSBlocklist("sai.example"); err != nil {
		t.Fatalf("AddDNSBlocklist: %v", err)
	}
	if err := db.DeleteDNSBlocklist("sai.example"); err != nil {
		t.Fatalf("DeleteDNSBlocklist: %v", err)
	}

	got, err := db.ListDNSBlocklist()
	if err != nil {
		t.Fatalf("ListDNSBlocklist: %v", err)
	}
	if len(got) != 1 || got[0] != "fica.example" {
		t.Fatalf("esperava só fica.example, veio %v", got)
	}

	// Apagar domínio que não está na lista não é erro.
	if err := db.DeleteDNSBlocklist("nunca.example"); err != nil {
		t.Errorf("DeleteDNSBlocklist de domínio inexistente: %v", err)
	}
}

// ─── Políticas de roteamento ─────────────────────────────────────────────────

func TestCreateRoutingPolicyRoundTrip(t *testing.T) {
	db := newTestDB(t)

	p := &storage.RoutingPolicy{
		Name:       "voip pela vivo",
		SourceCIDR: "192.168.3.0/24",
		DestCIDR:   "0.0.0.0/0",
		LinkID:     "link-vivo",
		Priority:   10,
		Enabled:    true,
		Failover:   false,
	}
	if err := db.CreateRoutingPolicy(p); err != nil {
		t.Fatalf("CreateRoutingPolicy: %v", err)
	}
	if p.ID == "" {
		t.Error("esperava ID gerado")
	}
	if p.CreatedAt.IsZero() || p.UpdatedAt.IsZero() {
		t.Error("esperava created_at/updated_at preenchidos")
	}

	got, err := db.GetRoutingPolicies()
	if err != nil {
		t.Fatalf("GetRoutingPolicies: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("esperava 1 política, veio %d", len(got))
	}
	g := got[0]
	if g.ID != p.ID || g.Name != p.Name || g.SourceCIDR != p.SourceCIDR ||
		g.DestCIDR != p.DestCIDR || g.LinkID != p.LinkID || g.Priority != p.Priority {
		t.Errorf("política voltou diferente: %+v", g)
	}
	// enabled/failover são INTEGER no SQLite: o round-trip do bool é o que
	// boolToInt garante dos dois lados.
	if !g.Enabled || g.Failover {
		t.Errorf("esperava Enabled=true Failover=false, veio %v/%v", g.Enabled, g.Failover)
	}
}

func TestCreateRoutingPolicyKeepsTheGivenID(t *testing.T) {
	db := newTestDB(t)

	p := &storage.RoutingPolicy{ID: "id-escolhido", Name: "p", LinkID: "l", Priority: 1}
	if err := db.CreateRoutingPolicy(p); err != nil {
		t.Fatalf("CreateRoutingPolicy: %v", err)
	}
	if p.ID != "id-escolhido" {
		t.Errorf("esperava o ID informado, veio %s", p.ID)
	}
}

func TestGetRoutingPoliciesOrdersByPriority(t *testing.T) {
	db := newTestDB(t)

	for _, p := range []*storage.RoutingPolicy{
		{Name: "terceira", LinkID: "l", Priority: 30},
		{Name: "primeira", LinkID: "l", Priority: 10},
		{Name: "segunda", LinkID: "l", Priority: 20},
	} {
		if err := db.CreateRoutingPolicy(p); err != nil {
			t.Fatalf("CreateRoutingPolicy(%s): %v", p.Name, err)
		}
	}

	got, err := db.GetRoutingPolicies()
	if err != nil {
		t.Fatalf("GetRoutingPolicies: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("esperava 3 políticas, veio %d", len(got))
	}
	want := []string{"primeira", "segunda", "terceira"}
	for i, name := range want {
		if got[i].Name != name {
			t.Errorf("posição %d: esperava %s, veio %s", i, name, got[i].Name)
		}
	}
}

func TestGetRoutingPoliciesIsNilWhenEmpty(t *testing.T) {
	db := newTestDB(t)

	got, err := db.GetRoutingPolicies()
	if err != nil {
		t.Fatalf("GetRoutingPolicies: %v", err)
	}
	// Ao contrário de ListDHCPReservations/ListDNSBlocklist, esta devolve nil
	// (vira null no JSON). Está fixado aqui porque hoje nenhum handler chama
	// esta função — quando alguém ligar isso numa tela, a diferença aparece.
	if got != nil {
		t.Fatalf("esperava nil, veio %#v", got)
	}
}

func TestDeleteRoutingPolicyRemovesOnlyThatID(t *testing.T) {
	db := newTestDB(t)

	fica := &storage.RoutingPolicy{Name: "fica", LinkID: "l", Priority: 1}
	sai := &storage.RoutingPolicy{Name: "sai", LinkID: "l", Priority: 2}
	if err := db.CreateRoutingPolicy(fica); err != nil {
		t.Fatalf("CreateRoutingPolicy: %v", err)
	}
	if err := db.CreateRoutingPolicy(sai); err != nil {
		t.Fatalf("CreateRoutingPolicy: %v", err)
	}

	if err := db.DeleteRoutingPolicy(sai.ID); err != nil {
		t.Fatalf("DeleteRoutingPolicy: %v", err)
	}

	got, err := db.GetRoutingPolicies()
	if err != nil {
		t.Fatalf("GetRoutingPolicies: %v", err)
	}
	if len(got) != 1 || got[0].ID != fica.ID {
		t.Fatalf("esperava só a política que fica, veio %+v", got)
	}

	// Apagar ID inexistente não é erro.
	if err := db.DeleteRoutingPolicy("nao-existe"); err != nil {
		t.Errorf("DeleteRoutingPolicy de ID inexistente: %v", err)
	}
}
