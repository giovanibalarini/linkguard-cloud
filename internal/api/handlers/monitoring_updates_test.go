package handlers_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-cloud/internal/alerts"
	"github.com/giovanibalarini/linkguard-cloud/internal/api/handlers"
	"github.com/giovanibalarini/linkguard-cloud/internal/monitoring"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

// fakeEmptyIfaceExec is a firewall.Executor test double that reports a
// kernel with no interfaces at all: every `ip` read answers a valid empty
// JSON array (an empty string would fail json.Unmarshal in the collectors).
type fakeEmptyIfaceExec struct{}

func (f *fakeEmptyIfaceExec) Execute(context.Context, string, ...string) (string, error) {
	return "", nil
}
func (f *fakeEmptyIfaceExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	if cmd == "ip" {
		return "[]", nil
	}
	return "", nil
}
func (f *fakeEmptyIfaceExec) IsDryRun() bool                              { return false }
func (_ *fakeEmptyIfaceExec) WriteFile(string, []byte, os.FileMode) error { return nil }

// TestUpdatesReturnsEmptyPackagesNotNull guards the same JSON contract the
// rest of this codebase follows: a nil slice marshals to `null` and breaks
// the frontend's .map(). A fresh box that has never run the check must
// return an empty list, not null.
func TestUpdatesReturnsEmptyPackagesNotNull(t *testing.T) {
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	col := monitoring.NewCollector(db, nil, alerts.NewService(db), &fakeEmptyIfaceExec{}, nil)
	h := handlers.NewMonitoringHandler(col, db)

	r := httptest.NewRequest("GET", "/api/system/updates", nil)
	w := httptest.NewRecorder()
	h.Updates(w, r)

	if w.Code != 200 {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var got struct {
		Total    int   `json:"total"`
		Security int   `json:"security"`
		Packages []any `json:"packages"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v — body: %s", err, w.Body.String())
	}
	if got.Packages == nil {
		t.Errorf("packages is null; expected [] — body: %s", w.Body.String())
	}
}
