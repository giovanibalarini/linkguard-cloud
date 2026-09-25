package netif

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/giovanibalarini/linkguard-cloud/internal/links"
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

func TestServiceListAssignsRoleFromConfiguredLinks(t *testing.T) {
	exec := &fakeExec{linkJSON: sampleLinkJSON, addrJSON: sampleAddrJSON}
	db := newTestDB(t)
	linkSvc := links.NewService(db)
	if err := linkSvc.Create(&storage.Link{ID: "wan1", Name: "WAN", Interface: "wlp2s0", Weight: 1}); err != nil {
		t.Fatalf("seed link: %v", err)
	}

	svc := NewService(exec, db, linkSvc)
	views, err := svc.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	byName := make(map[string]IfaceView, len(views))
	for _, v := range views {
		byName[v.Name] = v
	}
	if wl := byName["wlp2s0"]; wl.Role != RoleWAN {
		t.Errorf("wlp2s0: expected RoleWAN (matches configured Link.Interface), got %v", wl.Role)
	}
	if en := byName["enp0s31f6"]; en.Role != RoleUnassigned {
		t.Errorf("enp0s31f6: expected RoleUnassigned (no Link, not the LAN bridge), got %v", en.Role)
	}
}

// TestServiceListPopulatesGatewayFromConfiguredLink: o gateway não aparece no
// `ip addr`; quem o conhece é o Link cadastrado (usado pelo balanceador para
// montar a rota), e a tela mostraria o campo em branco sem este repasse.
func TestServiceListPopulatesGatewayFromConfiguredLink(t *testing.T) {
	exec := &fakeExec{linkJSON: sampleLinkJSON, addrJSON: sampleAddrJSON}
	db := newTestDB(t)
	linkSvc := links.NewService(db)
	if err := linkSvc.Create(&storage.Link{ID: "wan1", Name: "WAN", Interface: "wlp2s0", Weight: 1, Gateway: "192.168.3.1"}); err != nil {
		t.Fatalf("seed link: %v", err)
	}

	svc := NewService(exec, db, linkSvc)
	views, err := svc.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	byName := make(map[string]IfaceView, len(views))
	for _, v := range views {
		byName[v.Name] = v
	}
	if wl := byName["wlp2s0"]; wl.Gateway != "192.168.3.1" {
		t.Errorf("wlp2s0: esperava Gateway=192.168.3.1 (do Link configurado), veio %q", wl.Gateway)
	}
}

func TestServiceListAppliesStoredAlias(t *testing.T) {
	exec := &fakeExec{linkJSON: sampleLinkJSON, addrJSON: sampleAddrJSON}
	db := newTestDB(t)
	if err := db.SetSetting("interface_aliases", `{"wlp2s0":"WAN Principal"}`); err != nil {
		t.Fatalf("seed alias: %v", err)
	}
	linkSvc := links.NewService(db)

	svc := NewService(exec, db, linkSvc)
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
	linkSvc := links.NewService(db)

	svc := NewService(exec, db, linkSvc)
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
