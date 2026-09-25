package storage_test

import (
	"testing"
)

// SetHostAlias é o único jeito de o operador dar nome a uma máquina do
// inventário.

func TestSetHostAliasCreatesTheRowWhenTheHostIsUnknown(t *testing.T) {
	db := newTestDB(t)

	if err := db.SetHostAlias("10.0.1.20", "api do k3s"); err != nil {
		t.Fatalf("SetHostAlias: %v", err)
	}
	got, err := db.ListHostInfo()
	if err != nil {
		t.Fatalf("ListHostInfo: %v", err)
	}
	if len(got) != 1 || got[0].IP != "10.0.1.20" || got[0].Alias != "api do k3s" {
		t.Fatalf("máquina gravada errado: %+v", got)
	}
}

func TestSightingPreservesAliasBlockAndName(t *testing.T) {
	db := newTestDB(t)
	if err := db.SetHostAlias("10.0.1.20", "api"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetHostBlocked("10.0.1.20", true); err != nil {
		t.Fatal(err)
	}
	if err := db.SetHostnames(map[string]string{"10.0.1.20": "k3s-server-1"}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertHostSightings([]string{"10.0.1.20", "10.0.1.21"}); err != nil {
		t.Fatal(err)
	}
	got, err := db.ListHostInfo()
	if err != nil {
		t.Fatal(err)
	}
	porIP := map[string]bool{}
	for _, h := range got {
		porIP[h.IP] = true
		if h.IP == "10.0.1.20" && (h.Alias != "api" || !h.Blocked || h.Hostname != "k3s-server-1") {
			t.Errorf("o avistamento apagou o que já se sabia: %+v", h)
		}
	}
	if !porIP["10.0.1.21"] {
		t.Error("máquina nova vista não entrou")
	}
}

// Nome resolvido para um IP que ninguém viu não cria linha: nome sem máquina
// não é informação.
func TestSetHostnamesOnlyUpdatesKnownHosts(t *testing.T) {
	db := newTestDB(t)
	if err := db.SetHostnames(map[string]string{"10.9.9.9": "fantasma"}); err != nil {
		t.Fatal(err)
	}
	got, _ := db.ListHostInfo()
	if len(got) != 0 {
		t.Fatalf("nome criou máquina: %+v", got)
	}
}
