package handlers

import (
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

// newTestDB abre um banco vazio num diretório temporário do teste.
func newTestDB(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}
