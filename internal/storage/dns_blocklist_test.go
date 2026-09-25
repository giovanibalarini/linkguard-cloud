package storage_test

import (
	"testing"
)

// Esta máquina serve DHCP e DNS para a LAN inteira: uma reserva perdida tira um
// host do ar com IP trocado, e um domínio que fica na blocklist depois de
// removido derruba um serviço legítimo. Os testes abaixo olham só o que dá para
// observar de fora (o que a listagem devolve depois de cada escrita).

// ─── DHCP reservations ───────────────────────────────────────────────────────

// ─── DNS blocklist ───────────────────────────────────────────────────────────

func TestAddDNSBlocklistStoresTheDomain(t *testing.T) {
	db := newTestDB(t)

	if err := db.AddDNSBlocklist("ads.example.com"); err != nil {
		t.Fatalf("AddDNSBlocklist: %v", err)
	}

	list, err := db.ListDNSBlocklist()
	if err != nil {
		t.Fatalf("ListDNSBlocklist: %v", err)
	}
	if len(list) != 1 || list[0] != "ads.example.com" {
		t.Fatalf("esperava [ads.example.com], veio %v", list)
	}
}

// Bloquear o mesmo domínio duas vezes é operação corriqueira (dois cliques no
// painel): não pode explodir nem duplicar a linha.
func TestAddDNSBlocklistTwiceIsIdempotent(t *testing.T) {
	db := newTestDB(t)

	if err := db.AddDNSBlocklist("tracker.example.com"); err != nil {
		t.Fatalf("AddDNSBlocklist (1): %v", err)
	}
	if err := db.AddDNSBlocklist("tracker.example.com"); err != nil {
		t.Fatalf("AddDNSBlocklist (2) deveria ser no-op, veio erro: %v", err)
	}

	list, err := db.ListDNSBlocklist()
	if err != nil {
		t.Fatalf("ListDNSBlocklist: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("esperava 1 domínio, veio %d: %v", len(list), list)
	}
}

func TestAddDNSBlocklistKeepsTheListSortedAndAccumulates(t *testing.T) {
	db := newTestDB(t)

	for _, d := range []string{"zeta.example.com", "alfa.example.com", "meio.example.com"} {
		if err := db.AddDNSBlocklist(d); err != nil {
			t.Fatalf("AddDNSBlocklist %s: %v", d, err)
		}
	}

	list, err := db.ListDNSBlocklist()
	if err != nil {
		t.Fatalf("ListDNSBlocklist: %v", err)
	}
	want := []string{"alfa.example.com", "meio.example.com", "zeta.example.com"}
	if len(list) != len(want) {
		t.Fatalf("esperava %d domínios, veio %d: %v", len(want), len(list), list)
	}
	for i := range want {
		if list[i] != want[i] {
			t.Errorf("posição %d: esperava %s, veio %s", i, want[i], list[i])
		}
	}
}

// O storage guarda o domínio como veio: "Example.com" e "example.com" são duas
// linhas. Quem chama normaliza (o handler HTTP aplica ToLower antes de gravar).
func TestAddDNSBlocklistIsCaseSensitive(t *testing.T) {
	db := newTestDB(t)

	if err := db.AddDNSBlocklist("example.com"); err != nil {
		t.Fatalf("AddDNSBlocklist minúsculo: %v", err)
	}
	if err := db.AddDNSBlocklist("Example.com"); err != nil {
		t.Fatalf("AddDNSBlocklist capitalizado: %v", err)
	}

	list, err := db.ListDNSBlocklist()
	if err != nil {
		t.Fatalf("ListDNSBlocklist: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("esperava 2 linhas (domínio é case-sensitive no storage), veio %d: %v", len(list), list)
	}
}

func TestAddDNSBlocklistFailsOnClosedDB(t *testing.T) {
	db := newTestDB(t)
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := db.AddDNSBlocklist("ads.example.com"); err == nil {
		t.Fatal("esperava erro ao bloquear domínio com o banco fechado, veio nil")
	}
}

func TestDeleteDNSBlocklistRemovesOnlyTheGivenDomain(t *testing.T) {
	db := newTestDB(t)

	for _, d := range []string{"vai.example.com", "fica.example.com"} {
		if err := db.AddDNSBlocklist(d); err != nil {
			t.Fatalf("AddDNSBlocklist %s: %v", d, err)
		}
	}

	if err := db.DeleteDNSBlocklist("vai.example.com"); err != nil {
		t.Fatalf("DeleteDNSBlocklist: %v", err)
	}

	list, err := db.ListDNSBlocklist()
	if err != nil {
		t.Fatalf("ListDNSBlocklist: %v", err)
	}
	if len(list) != 1 || list[0] != "fica.example.com" {
		t.Fatalf("esperava [fica.example.com], veio %v", list)
	}
}

// Desbloquear um domínio que não está na lista não é erro — o desbloqueio é
// idempotente do ponto de vista de quem chama.
func TestDeleteDNSBlocklistUnknownDomainIsANoOp(t *testing.T) {
	db := newTestDB(t)

	if err := db.AddDNSBlocklist("fica.example.com"); err != nil {
		t.Fatalf("AddDNSBlocklist: %v", err)
	}
	if err := db.DeleteDNSBlocklist("nunca-bloqueado.example.com"); err != nil {
		t.Fatalf("DeleteDNSBlocklist (domínio ausente): %v", err)
	}

	list, err := db.ListDNSBlocklist()
	if err != nil {
		t.Fatalf("ListDNSBlocklist: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("esperava a lista intacta com 1 domínio, veio %v", list)
	}
}

// Bloquear de novo depois de desbloquear tem que voltar a valer — se o INSERT
// OR IGNORE deixasse resíduo, o domínio nunca mais entraria na lista.
func TestDNSBlocklistAddDeleteAddRoundTrip(t *testing.T) {
	db := newTestDB(t)

	if err := db.AddDNSBlocklist("volta.example.com"); err != nil {
		t.Fatalf("AddDNSBlocklist (1): %v", err)
	}
	if err := db.DeleteDNSBlocklist("volta.example.com"); err != nil {
		t.Fatalf("DeleteDNSBlocklist: %v", err)
	}
	if err := db.AddDNSBlocklist("volta.example.com"); err != nil {
		t.Fatalf("AddDNSBlocklist (2): %v", err)
	}

	list, err := db.ListDNSBlocklist()
	if err != nil {
		t.Fatalf("ListDNSBlocklist: %v", err)
	}
	if len(list) != 1 || list[0] != "volta.example.com" {
		t.Fatalf("esperava [volta.example.com] depois do ciclo, veio %v", list)
	}
}

func TestDeleteDNSBlocklistFailsOnClosedDB(t *testing.T) {
	db := newTestDB(t)
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := db.DeleteDNSBlocklist("ads.example.com"); err == nil {
		t.Fatal("esperava erro ao desbloquear domínio com o banco fechado, veio nil")
	}
}
