package storage_test

import (
	"testing"
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
