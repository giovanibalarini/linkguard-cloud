package netif

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

// fakeExec is a minimal firewall.Executor test double that returns canned
// output per command, mirroring the pattern already used in
// internal/unbound/unbound_test.go's recExec. O inventário é só leitura:
// qualquer Execute é erro.
type fakeExec struct {
	linkJSON string
	addrJSON string
	netDev   string
}

func (e *fakeExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	return "", errors.New("unexpected write command in test: " + cmd)
}

func (e *fakeExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	// Match by scanning args rather than a fixed index: the real call uses
	// "ip -d -j link show" (two flags before the subcommand) while "ip -j
	// addr show" only has one, so a fixed-index check would only happen to
	// match one of the two.
	if cmd == "ip" && containsArg(args, "link") {
		return e.linkJSON, nil
	}
	if cmd == "ip" && containsArg(args, "addr") {
		return e.addrJSON, nil
	}
	if cmd == "cat" && containsArg(args, "/proc/net/dev") {
		return e.netDev, nil // empty string is fine: parseProcNetDev on "" yields no entries
	}
	return "", errors.New("unexpected read command in test: " + cmd)
}

func containsArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func (e *fakeExec) IsDryRun() bool                              { return false }
func (_ *fakeExec) WriteFile(string, []byte, os.FileMode) error { return nil }

func newTestDB(t *testing.T) *storage.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("storage.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestServiceListMarksTheUplinkAsWAN(t *testing.T) {
	exec := &fakeExec{linkJSON: sampleLinkJSON, addrJSON: sampleAddrJSON}
	db := newTestDB(t)

	svc := NewService(exec, db, func() ([]string, error) { return []string{"wlp2s0"}, nil })
	views, err := svc.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	byName := make(map[string]IfaceView, len(views))
	for _, v := range views {
		byName[v.Name] = v
	}
	if wl := byName["wlp2s0"]; wl.Role != RoleWAN {
		t.Errorf("wlp2s0: expected RoleWAN (it is the uplink), got %v", wl.Role)
	}
	if en := byName["enp0s31f6"]; en.Role != RoleUnassigned {
		t.Errorf("enp0s31f6: expected RoleUnassigned, got %v", en.Role)
	}
}

// A fonte de WANs falhar (a rota default não respondeu) não pode derrubar a
// listagem: o papel é rótulo de tela.
func TestServiceListSurvivesAFailingWANSource(t *testing.T) {
	exec := &fakeExec{linkJSON: sampleLinkJSON, addrJSON: sampleAddrJSON}
	db := newTestDB(t)

	svc := NewService(exec, db, func() ([]string, error) { return nil, errors.New("ip route falhou") })
	views, err := svc.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, v := range views {
		if v.Role == RoleWAN {
			t.Errorf("%s virou WAN sem fonte que respondesse", v.Name)
		}
	}
}

func TestServiceListAppliesStoredAlias(t *testing.T) {
	exec := &fakeExec{linkJSON: sampleLinkJSON, addrJSON: sampleAddrJSON}
	db := newTestDB(t)
	if err := db.SetSetting("interface_aliases", `{"wlp2s0":"WAN Principal"}`); err != nil {
		t.Fatalf("seed alias: %v", err)
	}
	svc := NewService(exec, db, nil)
	views, err := svc.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, v := range views {
		if v.Name == "wlp2s0" && v.Alias != "WAN Principal" {
			t.Errorf("expected alias 'WAN Principal', got %q", v.Alias)
		}
	}
}

func TestServiceListMergesErrorDroppedCounters(t *testing.T) {
	exec := &fakeExec{linkJSON: sampleLinkJSON, addrJSON: sampleAddrJSON, netDev: sampleProcNetDev}
	db := newTestDB(t)
	svc := NewService(exec, db, nil)
	views, err := svc.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	byName := make(map[string]IfaceView, len(views))
	for _, v := range views {
		byName[v.Name] = v
	}
	wl := byName["wlp2s0"]
	if wl.Live.RxDropped != 1 || wl.Live.TxDropped != 44 {
		t.Errorf("wlp2s0: expected RxDropped=1 TxDropped=44 from /proc/net/dev merge, got %+v", wl.Live)
	}
	en := byName["enp0s31f6"]
	if en.Live.TxDropped != 111 {
		t.Errorf("enp0s31f6: expected TxDropped=111 from /proc/net/dev merge, got %+v", en.Live)
	}
}
