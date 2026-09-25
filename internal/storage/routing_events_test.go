package storage_test

import (
	"testing"

	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

// ─── Routing policies ────────────────────────────────────────────────────────

// ─── Failover events ─────────────────────────────────────────────────────────

// ─── SearchAuditLogs ─────────────────────────────────────────────────────────

func seedAuditLogs(t *testing.T, db *storage.DB, actions ...string) {
	t.Helper()
	for _, a := range actions {
		if err := db.CreateAuditLog(&storage.AuditLog{
			User: "admin", Action: a, Resource: "recurso", Details: "detalhe", IP: "192.168.3.10",
		}); err != nil {
			t.Fatalf("CreateAuditLog %s: %v", a, err)
		}
	}
}

func TestSearchAuditLogsWithoutFilterReturnsEverythingNewestFirst(t *testing.T) {
	db := newTestDB(t)
	seedAuditLogs(t, db, "link.create", "dhcp.reservation.set", "dns.blocklist.add")

	logs, err := db.SearchAuditLogs("", 10)
	if err != nil {
		t.Fatalf("SearchAuditLogs: %v", err)
	}
	if len(logs) != 3 {
		t.Fatalf("esperava 3 registros, veio %d", len(logs))
	}
	if logs[0].Action != "dns.blocklist.add" {
		t.Errorf("esperava o mais recente primeiro (dns.blocklist.add), veio %s", logs[0].Action)
	}
	if logs[0].User != "admin" || logs[0].IP != "192.168.3.10" {
		t.Errorf("esperava user/ip preservados, veio %s / %s", logs[0].User, logs[0].IP)
	}
}

func TestSearchAuditLogsIgnoresCaseInTheFilter(t *testing.T) {
	db := newTestDB(t)
	seedAuditLogs(t, db, "dns.blocklist.add")

	logs, err := db.SearchAuditLogs("DNS.BLOCKLIST", 10)
	if err != nil {
		t.Fatalf("SearchAuditLogs: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("esperava 1 registro com filtro em maiúsculas, veio %d", len(logs))
	}
}

// O filtro é minusculado antes de virar LIKE, então acento em maiúscula também
// encontra a ação gravada em minúsculas.
func TestSearchAuditLogsLowercasesAccentedFilters(t *testing.T) {
	db := newTestDB(t)
	seedAuditLogs(t, db, "configuração.salvar")

	logs, err := db.SearchAuditLogs("CONFIGURAÇÃO", 10)
	if err != nil {
		t.Fatalf("SearchAuditLogs: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("esperava 1 registro com filtro acentuado em maiúsculas, veio %d", len(logs))
	}
}

// O filtro olha só a coluna action: procurar pelo usuário, pelo recurso ou pelo
// IP não devolve nada (contrato importante para quem monta a tela de auditoria).
func TestSearchAuditLogsOnlyMatchesTheActionColumn(t *testing.T) {
	db := newTestDB(t)
	seedAuditLogs(t, db, "link.create")

	for _, filter := range []string{"admin", "recurso", "192.168.3.10", "detalhe"} {
		logs, err := db.SearchAuditLogs(filter, 10)
		if err != nil {
			t.Fatalf("SearchAuditLogs(%q): %v", filter, err)
		}
		if len(logs) != 0 {
			t.Errorf("SearchAuditLogs(%q): esperava 0 registros (só action é pesquisada), veio %d", filter, len(logs))
		}
	}
}

func TestSearchAuditLogsWithNoMatchReturnsNothingWithoutError(t *testing.T) {
	db := newTestDB(t)
	seedAuditLogs(t, db, "link.create")

	logs, err := db.SearchAuditLogs("firewall", 10)
	if err != nil {
		t.Fatalf("SearchAuditLogs: %v", err)
	}
	if len(logs) != 0 {
		t.Fatalf("esperava nenhum registro, veio %d", len(logs))
	}
}

func TestSearchAuditLogsRespectsTheLimitAndDefaultsWhenNonPositive(t *testing.T) {
	db := newTestDB(t)
	seedAuditLogs(t, db, "link.create", "link.update", "link.delete")

	limited, err := db.SearchAuditLogs("link", 2)
	if err != nil {
		t.Fatalf("SearchAuditLogs(limite 2): %v", err)
	}
	if len(limited) != 2 {
		t.Fatalf("esperava 2 registros, veio %d", len(limited))
	}
	if limited[0].Action != "link.delete" {
		t.Errorf("esperava o mais recente primeiro (link.delete), veio %s", limited[0].Action)
	}

	for _, limit := range []int{0, -5} {
		all, err := db.SearchAuditLogs("link", limit)
		if err != nil {
			t.Fatalf("SearchAuditLogs(limite %d): %v", limit, err)
		}
		if len(all) != 3 {
			t.Errorf("SearchAuditLogs(limite %d): esperava 3 registros (default), veio %d", limit, len(all))
		}
	}
}

func TestSearchAuditLogsFailsOnACorruptTimestamp(t *testing.T) {
	db := newTestDB(t)
	seedAuditLogs(t, db, "link.create")
	if _, err := db.Conn().Exec(`
		INSERT INTO audit_logs (id, user, action, resource, details, ip, created_at)
		VALUES ('corrompido', 'admin', 'link.create', '', '', '', 'isto-nao-e-uma-data')`); err != nil {
		t.Fatalf("insert corrompido: %v", err)
	}

	logs, err := db.SearchAuditLogs("link", 10)
	if err == nil {
		t.Fatal("esperava erro de scan na linha corrompida, veio nil")
	}
	if len(logs) != 0 {
		t.Errorf("esperava nenhum registro junto com o erro, veio %d", len(logs))
	}
}

func TestSearchAuditLogsFailsOnClosedDB(t *testing.T) {
	db := newTestDB(t)
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := db.SearchAuditLogs("", 10); err == nil {
		t.Fatal("esperava erro ao pesquisar auditoria sem filtro com o banco fechado, veio nil")
	}
	if _, err := db.SearchAuditLogs("link", 10); err == nil {
		t.Fatal("esperava erro ao pesquisar auditoria com filtro com o banco fechado, veio nil")
	}
}

// ─── SetHostAlias ────────────────────────────────────────────────────────────

func hostByMAC(t *testing.T, db *storage.DB, mac string) *storage.HostMetadata {
	t.Helper()
	list, err := db.ListHostMetadata()
	if err != nil {
		t.Fatalf("ListHostMetadata: %v", err)
	}
	for i := range list {
		if list[i].MAC == mac {
			return &list[i]
		}
	}
	return nil
}

func TestSetHostAliasCreatesTheHostRowWhenItDoesNotExist(t *testing.T) {
	db := newTestDB(t)

	if err := db.SetHostAlias("aa:bb:cc:11:22:01", "notebook da recepção"); err != nil {
		t.Fatalf("SetHostAlias: %v", err)
	}

	got := hostByMAC(t, db, "aa:bb:cc:11:22:01")
	if got == nil {
		t.Fatal("esperava a linha do host criada pelo apelido")
	}
	if got.Alias != "notebook da recepção" {
		t.Errorf("esperava o apelido gravado, veio %q", got.Alias)
	}
	if got.FirstSeen.IsZero() || got.LastSeen.IsZero() {
		t.Errorf("esperava first_seen/last_seen preenchidos, veio %v / %v", got.FirstSeen, got.LastSeen)
	}
	if got.Blocked {
		t.Error("host novo não deveria nascer bloqueado")
	}
}

func TestSetHostAliasWithEmptyStringClearsTheAlias(t *testing.T) {
	db := newTestDB(t)

	if err := db.SetHostAlias("aa:bb:cc:11:22:03", "tinha apelido"); err != nil {
		t.Fatalf("SetHostAlias: %v", err)
	}
	if err := db.SetHostAlias("aa:bb:cc:11:22:03", ""); err != nil {
		t.Fatalf("SetHostAlias (limpar): %v", err)
	}

	got := hostByMAC(t, db, "aa:bb:cc:11:22:03")
	if got == nil {
		t.Fatal("esperava a linha do host ainda presente")
	}
	if got.Alias != "" {
		t.Errorf("esperava apelido vazio depois de limpar, veio %q", got.Alias)
	}
}

// Nomear um host não pode desbloqueá-lo nem apagar o IP visto na rede: o upsert
// só toca a coluna alias.
func TestSetHostAliasPreservesIPAndBlockedFlag(t *testing.T) {
	db := newTestDB(t)

	if err := db.UpsertHostSightings(map[string]string{"aa:bb:cc:11:22:04": "192.168.3.44"}); err != nil {
		t.Fatalf("UpsertHostSightings: %v", err)
	}
	if err := db.SetHostBlocked("aa:bb:cc:11:22:04", true); err != nil {
		t.Fatalf("SetHostBlocked: %v", err)
	}

	if err := db.SetHostAlias("aa:bb:cc:11:22:04", "tablet do estoque"); err != nil {
		t.Fatalf("SetHostAlias: %v", err)
	}

	got := hostByMAC(t, db, "aa:bb:cc:11:22:04")
	if got == nil {
		t.Fatal("esperava a linha do host")
	}
	if got.Alias != "tablet do estoque" {
		t.Errorf("esperava o apelido gravado, veio %q", got.Alias)
	}
	if !got.Blocked {
		t.Error("o apelido não pode desbloquear o host")
	}
	if got.IP != "192.168.3.44" {
		t.Errorf("o apelido não pode apagar o IP visto: esperava 192.168.3.44, veio %q", got.IP)
	}
}

// E o caminho inverso: bloquear depois de nomear mantém o apelido.
func TestSetHostBlockedPreservesTheAlias(t *testing.T) {
	db := newTestDB(t)

	if err := db.SetHostAlias("aa:bb:cc:11:22:05", "câmera do portão"); err != nil {
		t.Fatalf("SetHostAlias: %v", err)
	}
	if err := db.SetHostBlocked("aa:bb:cc:11:22:05", true); err != nil {
		t.Fatalf("SetHostBlocked: %v", err)
	}

	got := hostByMAC(t, db, "aa:bb:cc:11:22:05")
	if got == nil {
		t.Fatal("esperava a linha do host")
	}
	if got.Alias != "câmera do portão" {
		t.Errorf("esperava o apelido preservado, veio %q", got.Alias)
	}
	if !got.Blocked {
		t.Error("esperava o host bloqueado")
	}
}

// O MAC entra cru na chave: quem chama tem que normalizar antes (o handler HTTP
// aplica ToLower). Sem isso o apelido vai parar numa segunda linha e some da
// tela, que casa o host pelo MAC minúsculo.
func TestSetHostAliasIsCaseSensitiveOnMAC(t *testing.T) {
	db := newTestDB(t)

	if err := db.SetHostAlias("aa:bb:cc:11:22:06", "minúsculo"); err != nil {
		t.Fatalf("SetHostAlias minúsculo: %v", err)
	}
	if err := db.SetHostAlias("AA:BB:CC:11:22:06", "maiúsculo"); err != nil {
		t.Fatalf("SetHostAlias maiúsculo: %v", err)
	}

	list, err := db.ListHostMetadata()
	if err != nil {
		t.Fatalf("ListHostMetadata: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("esperava 2 linhas (MAC é case-sensitive no storage), veio %d", len(list))
	}
}

func TestSetHostAliasFailsOnClosedDB(t *testing.T) {
	db := newTestDB(t)
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := db.SetHostAlias("aa:bb:cc:11:22:07", "x"); err == nil {
		t.Fatal("esperava erro ao gravar apelido com o banco fechado, veio nil")
	}
}

// ─── CountAlerts ─────────────────────────────────────────────────────────────

func TestCountAlertsIsZeroOnAFreshDatabase(t *testing.T) {
	db := newTestDB(t)

	n, err := db.CountAlerts()
	if err != nil {
		t.Fatalf("CountAlerts: %v", err)
	}
	if n != 0 {
		t.Errorf("esperava 0 alertas, veio %d", n)
	}
}

// Um alerta já criado como resolvido não conta em nenhum momento.
func TestCountAlertsIgnoresAlertsCreatedAlreadyResolved(t *testing.T) {
	db := newTestDB(t)

	if err := db.CreateAlert(&storage.Alert{Type: "info", Severity: "info", Title: "já resolvido", Resolved: true}); err != nil {
		t.Fatalf("CreateAlert: %v", err)
	}

	n, err := db.CountAlerts()
	if err != nil {
		t.Fatalf("CountAlerts: %v", err)
	}
	if n != 0 {
		t.Errorf("esperava 0 alertas em aberto, veio %d", n)
	}
}

func TestCountAlertsFailsOnClosedDB(t *testing.T) {
	db := newTestDB(t)
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := db.CountAlerts(); err == nil {
		t.Fatal("esperava erro ao contar alertas com o banco fechado, veio nil")
	}
}
