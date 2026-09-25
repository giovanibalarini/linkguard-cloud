package monitoring

import (
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

func openTestDB(t *testing.T) *storage.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestLoadConfigDefaultsWhenAbsent(t *testing.T) {
	db := openTestDB(t) // shared helper defined in Global Constraints
	c := LoadConfig(db)
	if !c.Enabled {
		t.Error("expected Enabled=true by default (zero-config)")
	}
	if c.DiskThresholdPct != 90 {
		t.Errorf("disk threshold default = %d, want 90", c.DiskThresholdPct)
	}
	want := []string{"unbound", "nftables"}
	if len(c.Services) != len(want) {
		t.Fatalf("services = %v, want %v", c.Services, want)
	}
	for i := range want {
		if c.Services[i] != want[i] {
			t.Errorf("service[%d] = %q, want %q", i, c.Services[i], want[i])
		}
	}
}

func TestSaveThenLoadRoundTrips(t *testing.T) {
	db := openTestDB(t)
	in := Config{Enabled: false, Services: []string{"unbound"}, DiskThresholdPct: 80}
	if err := SaveConfig(db, in); err != nil {
		t.Fatal(err)
	}
	got := LoadConfig(db)
	if got.Enabled != false || got.DiskThresholdPct != 80 || len(got.Services) != 1 || got.Services[0] != "unbound" {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

func TestLoadConfigNewFieldDefaults(t *testing.T) {
	db := openTestDB(t)
	c := LoadConfig(db)
	if c.JournalVerifyIntervalDays != 7 {
		t.Errorf("JournalVerifyIntervalDays default = %d, want 7", c.JournalVerifyIntervalDays)
	}
}

func TestLoadConfigClampsInvalidNewThresholds(t *testing.T) {
	db := openTestDB(t)
	bad := Config{Enabled: true, DiskThresholdPct: 90, JournalVerifyIntervalDays: -1}
	if err := SaveConfig(db, bad); err != nil {
		t.Fatal(err)
	}
	got := LoadConfig(db)
	if got.JournalVerifyIntervalDays != 7 {
		t.Errorf("JournalVerifyIntervalDays should clamp to default 7, got %d", got.JournalVerifyIntervalDays)
	}
}

// A caixa migrada do linkguard-fw traz o kea-dhcp4-server na lista gravada, e
// a migração o para: vigiá-lo seria alertar queda de um serviço desligado de
// propósito.
func TestLoadConfigTiraOKeaDaListaGravada(t *testing.T) {
	db := openTestDB(t)
	if err := db.SetSetting(configKey, `{"enabled":true,"services":["kea-dhcp4-server","unbound","nftables","ssh"]}`); err != nil {
		t.Fatal(err)
	}
	got := LoadConfig(db).Services
	want := []string{"unbound", "nftables", "ssh"}
	if len(got) != len(want) {
		t.Fatalf("services = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("service[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
