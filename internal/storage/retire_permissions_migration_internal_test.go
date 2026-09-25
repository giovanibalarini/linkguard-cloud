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

// A caixa que vem do linkguard-fw tem o inventário por MAC, e cota e consumo
// chaveados por MAC. A 102 passa tudo para IP pela correspondência que o
// inventário antigo guardava; o que não tem IPv4 fica de fora.
func TestMigrationHostsPorIPConverteInventarioCotaEConsumo(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// O estado de uma caixa migrada: host_info vazio e as tabelas no formato
	// antigo (a 102 já rodou no Open; refaz-se o antes à mão).
	for _, q := range []string{
		`DROP TABLE host_info`,
		`DROP TABLE host_quota`,
		`DROP TABLE host_usage`,
		createHostQuotaTable,
		createHostUsageTable,
		`INSERT INTO host_metadata (mac, ip, hostname, alias, blocked) VALUES
			('aa:00:00:00:00:01', '10.0.1.20', 'antigo', 'api', 1),
			('aa:00:00:00:00:02', 'fe80::1', '', 'só v6', 0)`,
		`INSERT INTO host_quota (mac, limit_gb) VALUES ('aa:00:00:00:00:01', 5), ('aa:00:00:00:00:02', 1)`,
		`INSERT INTO host_usage (mac, period, cycle_start, rx_bytes, tx_bytes, updated_at) VALUES
			('aa:00:00:00:00:01', 'monthly', 100, 10, 20, 1)`,
	} {
		if _, err := db.conn.Exec(q); err != nil {
			t.Fatalf("montar o estado antigo: %v\n%s", err, q)
		}
	}
	if err := db.runOneMigrationForTest(upHostsPorIP); err != nil {
		t.Fatalf("migração: %v", err)
	}

	hosts, err := db.ListHostInfo()
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || hosts[0].IP != "10.0.1.20" || hosts[0].Alias != "api" || !hosts[0].Blocked {
		t.Fatalf("inventário convertido errado (o só-IPv6 tinha de ficar de fora): %+v", hosts)
	}
	quotas, err := db.GetHostQuotas()
	if err != nil {
		t.Fatal(err)
	}
	if len(quotas) != 1 || quotas["10.0.1.20"].LimitGB != 5 {
		t.Fatalf("cota convertida errado: %+v", quotas)
	}
	u, err := db.GetHostUsage("10.0.1.20", HostPeriodMonthly, 100)
	if err != nil || u.RxBytes != 10 || u.TxBytes != 20 {
		t.Fatalf("consumo convertido errado: %+v %v", u, err)
	}
}
