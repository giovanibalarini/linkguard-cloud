package backup_test

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-cloud/internal/backup"
	"github.com/giovanibalarini/linkguard-cloud/internal/backupcrypt"
	"github.com/giovanibalarini/linkguard-cloud/internal/fwmodel"
	"github.com/giovanibalarini/linkguard-cloud/internal/secrets"
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

func newTestSecrets(t *testing.T, db *storage.DB) *secrets.Service {
	t.Helper()
	dir := t.TempDir()
	key, err := secrets.LoadOrGenerateKey(filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatalf("LoadOrGenerateKey: %v", err)
	}
	return secrets.NewService(db, key)
}

func TestEncryptSnapshotFailsWithoutPassphrase(t *testing.T) {
	db := openTestDB(t)
	sec := newTestSecrets(t, db)

	if _, err := backup.EncryptSnapshot(db, sec, "v-test"); err != backup.ErrPassphraseNotConfigured {
		t.Fatalf("expected ErrPassphraseNotConfigured, got %v", err)
	}
}

func TestEncryptSnapshotThenDecryptRestoreRoundTrip(t *testing.T) {
	db := openTestDB(t)
	sec := newTestSecrets(t, db)
	if err := sec.Set(backup.PassphraseSecretName, "senha-de-teste-123456"); err != nil {
		t.Fatalf("sec.Set: %v", err)
	}
	if err := db.SetSetting("some_key", "some_value"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}

	encrypted, err := backup.EncryptSnapshot(db, sec, "v-test")
	if err != nil {
		t.Fatalf("EncryptSnapshot: %v", err)
	}

	data, err := backup.DecryptRestore(encrypted, "senha-de-teste-123456")
	if err != nil {
		t.Fatalf("DecryptRestore: %v", err)
	}
	if data.Format != 2 {
		t.Fatalf("Format = %d, want 2", data.Format)
	}
	if data.Version != "v-test" {
		t.Fatalf("Version = %q, want v-test", data.Version)
	}
	if data.Kind != "linkguard-fw-backup" {
		t.Fatalf("Kind = %q, want linkguard-fw-backup", data.Kind)
	}
	if data.Settings["some_key"] != "some_value" {
		t.Fatalf("Settings[some_key] = %q, want some_value", data.Settings["some_key"])
	}
}

func TestDecryptRestoreRejectsNonBackupJSON(t *testing.T) {
	// A well-formed, correctly-encrypted file that just isn't a LinkGuard
	// backup (wrong "kind") must still be rejected, not silently accepted.
	plaintext, _ := json.Marshal(map[string]string{"kind": "something-else"})
	encrypted, err := backupcrypt.Encrypt(plaintext, "senha-1234567890ab")
	if err != nil {
		t.Fatalf("Encrypt fixture: %v", err)
	}
	if _, err := backup.DecryptRestore(encrypted, "senha-1234567890ab"); err == nil {
		t.Fatal("expected error for non-backup JSON, got nil")
	}
}

func TestDecryptRestoreWrongPassphraseFails(t *testing.T) {
	db := openTestDB(t)
	sec := newTestSecrets(t, db)
	if err := sec.Set(backup.PassphraseSecretName, "senha-certa-123456"); err != nil {
		t.Fatalf("sec.Set: %v", err)
	}
	encrypted, err := backup.EncryptSnapshot(db, sec, "v-test")
	if err != nil {
		t.Fatalf("EncryptSnapshot: %v", err)
	}
	if _, err := backup.DecryptRestore(encrypted, "senha-errada-123456"); err == nil {
		t.Fatal("expected error decrypting with wrong passphrase, got nil")
	}
}

func TestSnapshotIncludesAppliedFirewall(t *testing.T) {
	db := openTestDB(t)
	cfg := fwmodel.Config{
		Ajustes: fwmodel.Ajustes{RegistrarPadrao: true},
		Aliases: []fwmodel.Alias{
			{ID: "al-1", Nome: "lan_hosts", Tipo: fwmodel.AliasTipoEnderecos, Itens: []string{"10.0.0.1"}},
		},
	}
	if err := db.SalvarAplicadaERevisao(cfg, "admin", "teste", "teste", time.Now()); err != nil {
		t.Fatalf("SalvarAplicadaERevisao: %v", err)
	}

	snap, err := backup.Snapshot(db, "v-test")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if snap.Format != 2 {
		t.Fatalf("Format = %d, want 2", snap.Format)
	}
	if snap.Firewall == nil {
		t.Fatalf("Firewall is nil, want populated config")
	}
	if len(snap.Firewall.Aliases) != 1 || snap.Firewall.Aliases[0].Nome != "lan_hosts" {
		t.Errorf("Firewall aliases = %+v, want lan_hosts", snap.Firewall.Aliases)
	}
}
