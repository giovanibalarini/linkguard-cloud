package storage

import (
	"path/filepath"
	"testing"
)

// O papel que vem do linkguard-fw traz chaves que a versão cloud tirou do
// catálogo. Salvar um papel valida cada chave, então sem esta migração o papel
// ficaria impossível de salvar: 400 numa permissão que a tela nem mostra.
func TestMigrationRetiresCloudlessPermissionsAndKeepsTheRest(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	veio := &Role{Name: "Operador antigo", Permissions: []string{
		"dhcp.read", "dhcp.write", "ntp.read", "ntp.write",
		"interfaces.read", "interfaces.write", "dns.read", "dns.write",
	}}
	if err := db.CreateRole(veio); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}

	for i := 0; i < 2; i++ { // idempotente: o segundo boot não pode falhar
		if err := db.runOneMigrationForTest(upRetirePermissionsCloud); err != nil {
			t.Fatalf("passada %d: %v", i+1, err)
		}
	}

	perms := rolePerms(t, db, veio.ID)
	for _, saiu := range []string{"dhcp.read", "dhcp.write", "ntp.read", "ntp.write", "interfaces.write"} {
		if perms[saiu] {
			t.Errorf("%s continuou no papel; salvar o papel pela tela daria 400", saiu)
		}
	}
	for _, fica := range []string{"interfaces.read", "dns.read", "dns.write"} {
		if !perms[fica] {
			t.Errorf("%s sumiu do papel: a migração só pode tirar o que saiu do catálogo", fica)
		}
	}
}

func TestMigrationRetiresMultiWANPermissionsAndKeepsRoutesRead(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	veio := &Role{Name: "Operador antigo", Permissions: []string{
		"links.read", "links.write", "routes.read", "routes.write", "hosts.assign", "hosts.block",
	}}
	if err := db.CreateRole(veio); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if err := db.runOneMigrationForTest(upRetireMultiWANPermissions); err != nil {
		t.Fatalf("migração: %v", err)
	}
	perms := rolePerms(t, db, veio.ID)
	for _, saiu := range []string{"links.read", "links.write", "routes.write", "hosts.assign"} {
		if perms[saiu] {
			t.Errorf("%s continuou no papel", saiu)
		}
	}
	for _, fica := range []string{"routes.read", "hosts.block"} {
		if !perms[fica] {
			t.Errorf("%s sumiu do papel", fica)
		}
	}
}
