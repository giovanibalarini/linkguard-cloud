package unbound

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-cloud/internal/netsvc"
)

// recExec records write commands and simulates the machine the provider asks about.
type recExec struct {
	wrote  []string
	writes []string

	// unboundEnabled controls the answer to `systemctl is-enabled unbound`,
	// which EnsureResolvConf gates on: unbound is only Recommends: in the
	// package, so on a box without it (or where it failed to start) taking
	// over resolv.conf would knock out the box's own name resolution.
	unboundEnabled bool

	// unboundCheckErr, when set, is returned by `unbound-checkconf <file>`.
	// unboundCheckPath records the file path validateUnbound passed to the
	// checker (empty when the checker was never run — which is how a test
	// tells "skipped because absent" from "ran and passed"). A missing
	// checker is no longer simulated here: it is a property of the binary
	// path the Service holds, not of what the executor answers (I-6).
	unboundCheckErr  error
	unboundCheckPath string

	// missingPkgs is dpkg's view of the box: the packages it reports as NOT
	// installed. Default (nil) is a machine that already has unbound and
	// dns-root-data,
	// so every test that is about the apply itself exercises the apply and
	// not the install. A test that wants the bare-machine case names the
	// packages here.
	//
	// installFails makes apt-get unable to resolve anything (no network, dead
	// mirror), which is the honesty path: LinkGuard has to say what is
	// missing instead of failing opaquely.
	missingPkgs  map[string]bool
	installFails bool

	// installFailsFor faz o apt-get falhar só quando o comando menciona um
	// destes pacotes — o caso real em que um pacote específico não está no
	// espelho (ou o índice está velho) e os outros entrariam sem problema.
	installFailsFor map[string]bool

	// failOn faz Execute falhar em qualquer comando que contenha esta
	// substring — usado para reproduzir o apply que escreve os arquivos e
	// morre no restart do unbound.
	failOn string
}

func (e *recExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	full := cmd + " " + strings.Join(args, " ")
	e.writes = append(e.writes, full)
	if e.failOn != "" && strings.Contains(full, e.failOn) {
		return "", errors.New("Job failed. See journalctl -xe")
	}
	if strings.Contains(full, "apt-get install") {
		if e.installFails {
			return "", errors.New("E: Unable to locate package")
		}
		for _, a := range args {
			if e.installFailsFor[a] {
				return "", errors.New("E: Unable to locate package " + a)
			}
		}
		for _, a := range args {
			delete(e.missingPkgs, a)
		}
	}
	return "", nil
}
func (e *recExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	// A máquina de mentira precisa TER o endereço em que o unbound vai escutar,
	// senão o apply é recusado antes de escrever (#161) — que é justamente o
	// comportamento novo. Um executor falso que não simula a máquina faz o teste
	// medir a guarda em vez do que ele quer medir.
	if cmd == "ip" {
		return "2: br10    inet 192.168.3.3/24 brd 192.168.3.255 scope global br10\n" +
			"1: lo    inet 127.0.0.1/8 scope host lo\n", nil
	}
	if cmd == "dpkg-query" && len(args) > 0 {
		pkg := args[len(args)-1]
		if e.missingPkgs[pkg] {
			return "", fmt.Errorf("dpkg-query: no packages found matching %s", pkg)
		}
		return "install ok installed", nil
	}
	if cmd == "systemctl" && len(args) == 2 && args[0] == "is-enabled" && args[1] == "unbound" {
		if e.unboundEnabled {
			return "enabled\n", nil
		}
		// mirrors systemctl's real behaviour: non-zero exit, "disabled" (or
		// a "no such unit" error) on stdout/stderr either way.
		return "disabled\n", fmt.Errorf("unit unbound.service is not enabled")
	}
	if strings.Contains(cmd, "unbound-checkconf") {
		if len(args) > 0 {
			e.unboundCheckPath = args[0]
		}
		if e.unboundCheckErr != nil {
			return "config error", e.unboundCheckErr
		}
		return "ok", nil
	}
	return "", nil
}
func (e *recExec) IsDryRun() bool { return false }

// Este executor NÃO é dry-run, então ele grava de verdade — os testes abaixo
// conferem o conteúdo dos arquivos gerados, em diretório temporário. É também
// o que mantém a asserção honesta: se WriteFile fosse no-op aqui, os testes
// passariam sem que nada tivesse sido escrito.
func (e *recExec) WriteFile(path string, data []byte, perm os.FileMode) error {
	e.wrote = append(e.wrote, path)
	return os.WriteFile(path, data, perm)
}

func newTestSvc(t *testing.T, e *recExec) *Service {
	t.Helper()
	dir := t.TempDir()
	s := NewService(e)
	s.unboundConf = filepath.Join(dir, "unbound.conf")
	s.unboundApplied = filepath.Join(dir, "unbound-applied.conf")
	// O checker é resolvido no sistema de arquivos antes de rodar (I-6),
	// então um serviço de teste precisa apontar para um arquivo que existe
	// de verdade: "instalado" e "ausente" viraram estados distintos, não
	// mais um palpite sobre o texto do erro. A máquina que roda o teste não
	// precisa ter o unbound instalado.
	s.unboundCheckBin = filepath.Join(dir, "unbound-checkconf")
	if err := os.WriteFile(s.unboundCheckBin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("criar checker falso: %v", err)
	}
	return s
}

func TestReloadConfigsValidatesWritesAndReloads(t *testing.T) {
	e := &recExec{}
	s := newTestSvc(t, e)

	if _, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil); err != nil {
		t.Fatalf("ReloadConfigs: %v", err)
	}
	// Config files written.
	if _, err := os.Stat(s.unboundConf); err != nil {
		t.Error("unbound config not written")
	}
	// Services reloaded via the canonical, systemd-tracked reload-or-restart.
	joined := strings.Join(e.writes, "\n")
	// unbound gets a real restart here, not the graceful reload: this apply
	// is the first time the LinkGuard drop-in exists, so the running daemon
	// has never had these `interface:` lines — and SIGHUP does not re-open
	// listening sockets (see unboundNeedsRestart).
	if !strings.Contains(joined, "systemctl restart unbound") {
		t.Errorf("missing unbound restart on the first apply; writes:\n%s", joined)
	}
}

func TestServiceAddsRuntimeDNSBindingSource(t *testing.T) {
	e := &recExec{}
	s := newTestSvc(t, e)
	s.SetDNSBindingSource(func() (string, string, bool, error) {
		return "10.7.0.1", "10.7.0.0/24", true, nil
	})

	files, err := s.GenerateConfigs(netsvc.DefaultConfig(), nil)
	if err != nil {
		t.Fatalf("GenerateConfigs: %v", err)
	}
	var unbound string
	for _, file := range files {
		if file.Path == s.unboundConf {
			unbound = file.Content
		}
	}
	if !strings.Contains(unbound, "interface: 10.7.0.1") {
		t.Fatalf("unbound config does not listen on the WireGuard address:\n%s", unbound)
	}
	if !strings.Contains(unbound, "access-control: 10.7.0.0/24 allow") {
		t.Fatalf("unbound config does not authorize the WireGuard network:\n%s", unbound)
	}
}

func TestReloadConfigsRejectsMissingRuntimeDNSAddressBeforeWrite(t *testing.T) {
	e := &recExec{}
	s := newTestSvc(t, e)
	s.SetDNSBindingSource(func() (string, string, bool, error) {
		return "10.7.0.1", "10.7.0.0/24", true, nil
	})

	if _, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil); err == nil {
		t.Fatal("expected missing WireGuard address to abort reload")
	}
	if _, err := os.Stat(s.unboundConf); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unbound config must not be written, stat err = %v", err)
	}
}

// ─── Finding 3 (S1): ReloadConfigs must validate the unbound candidate with
// unbound-checkconf before writing it — nothing written or reloaded on
// failure, the temp file next to the real config, and a missing checker must
// not block the DNS apply. Regression tests for .superpowers/sdd/input-validation-audit.md
// finding #3.

// TestReloadConfigsAbortsOnInvalidUnboundConfig: an unbound config that fails
// unbound-checkconf must abort the whole reload with nothing written
// and no service reloaded — a broken unbound.conf must never land on disk,
// since it would survive the next reboot and take DNS down (see this
// finding's motivating incident in the task brief).
func TestReloadConfigsAbortsOnInvalidUnboundConfig(t *testing.T) {
	e := &recExec{unboundCheckErr: fmt.Errorf("unbound config invalid")}
	s := newTestSvc(t, e)

	if _, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil); err == nil {
		t.Fatal("expected error when unbound config test fails")
	}
	if strings.Contains(strings.Join(e.writes, "\n"), "reload-or-restart") {
		t.Error("must not reload when unbound config validation fails")
	}
	if _, err := os.Stat(s.unboundConf); err == nil {
		t.Error("must not write unbound config when validation fails")
	}
}

// TestValidateUnboundWritesTempFileNextToRealConfig: the temp file must live
// in the same directory as the real unbound config (see validateUnbound for
// why).
func TestValidateUnboundWritesTempFileNextToRealConfig(t *testing.T) {
	e := &recExec{}
	s := newTestSvc(t, e)

	if _, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil); err != nil {
		t.Fatalf("ReloadConfigs: %v", err)
	}
	if e.unboundCheckPath == "" {
		t.Fatal("unbound-checkconf was never called")
	}
	wantDir := filepath.Dir(s.unboundConf)
	if gotDir := filepath.Dir(e.unboundCheckPath); gotDir != wantDir {
		t.Errorf("validate temp file dir = %q, want %q (same dir as the real unbound config)", gotDir, wantDir)
	}
}

// TestReloadConfigsProceedsWhenUnboundCheckconfMissing: unbound-checkconf
// not being installed must not block the DNS apply — Debian's unbound
// package (and its checker) is a Recommends:, not a Depends:, of this
// project. The absence is now established by resolving the binary (I-6),
// not by reading the error text of a command that did run, so the test
// points the service at a path that does not exist instead of asking the
// fake executor to imitate a "not found" message.
func TestReloadConfigsProceedsWhenUnboundCheckconfMissing(t *testing.T) {
	e := &recExec{}
	s := newTestSvc(t, e)
	s.unboundCheckBin = filepath.Join(t.TempDir(), "unbound-checkconf") // nunca criado

	if _, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil); err != nil {
		t.Fatalf("ReloadConfigs should proceed when unbound-checkconf is missing: %v", err)
	}
	if _, err := os.Stat(s.unboundConf); err != nil {
		t.Error("unbound config should still be written when the checker is merely absent")
	}
	joined := strings.Join(e.writes, "\n")
	if !strings.Contains(joined, "systemctl restart unbound") && !strings.Contains(joined, "systemctl reload-or-restart unbound") {
		t.Errorf("unbound should still be reloaded when the checker is merely absent; writes:\n%s", joined)
	}
}

func TestGenerateUnboundConfigRecursiveByDefault(t *testing.T) {
	cfg := netsvc.DefaultConfig() // empty upstreams = recursive
	out, _, _ := GenerateUnboundConfig(cfg, []string{"ads.example.com"})
	wants := []string{
		"server:",
		"interface: 127.0.0.1",
		"access-control: 127.0.0.0/8 allow",
		"num-threads: 2",
		"local-zone: \"ads.example.com.\" always_nxdomain",
	}
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("unbound config missing %q\n--- got ---\n%s", w, out)
		}
	}
	if strings.Contains(out, "forward-zone") {
		t.Errorf("default should be recursive (no forward-zone)\n%s", out)
	}
	if strings.Contains(out, "log-queries") {
		t.Errorf("log-queries should be off by default")
	}
}

func TestGenerateUnboundConfigListensOnAndAuthorizesWireGuardTunnel(t *testing.T) {
	cfg := netsvc.DefaultConfig()
	cfg.ExtraListenAddresses = []string{"10.7.0.1"}
	cfg.ExtraAccessNetworks = []string{"10.7.0.0/24"}
	out, _, err := GenerateUnboundConfig(cfg, nil)
	if err != nil {
		t.Fatalf("GenerateUnboundConfig: %v", err)
	}
	if !strings.Contains(out, "  interface: 10.7.0.1\n") {
		t.Fatalf("WireGuard listen address missing:\n%s", out)
	}
	if !strings.Contains(out, "  access-control: 10.7.0.0/24 allow\n") {
		t.Fatalf("WireGuard access-control missing:\n%s", out)
	}
}

func TestGenerateUnboundConfigRejectsInjectedExtraBindingAtSink(t *testing.T) {
	cfg := netsvc.DefaultConfig()
	cfg.ExtraListenAddresses = []string{"10.7.0.1\ninterface: 0.0.0.0"}
	if _, _, err := GenerateUnboundConfig(cfg, nil); err == nil {
		t.Fatal("injected WireGuard listen address reached unbound renderer")
	}
}

func TestGenerateUnboundConfigForwarding(t *testing.T) {
	cfg := netsvc.DefaultConfig()
	cfg.Upstreams = []string{"1.1.1.1", "8.8.8.8"}
	out, _, _ := GenerateUnboundConfig(cfg, nil)
	for _, w := range []string{"forward-zone:", "forward-addr: 1.1.1.1", "forward-addr: 8.8.8.8"} {
		if !strings.Contains(out, w) {
			t.Errorf("forwarding config missing %q\n%s", w, out)
		}
	}
}

// ─── Finding 1 (S1): GenerateUnboundConfig must revalidate every DB-sourced
// value at render time, not trust that the handler-level validator already
// ran (a restored backup, or a row written under an older/laxer rule,
// reaches this function with no handler in between). Regression tests for
// .superpowers/sdd/input-validation-audit.md finding #2/#3 (systemic
// pattern #4).

// TestGenerateUnboundConfigSkipsInjectedBlocklistEntry: a blocklist entry
// carrying a newline plus a directive must never reach unbound.conf — it
// must be dropped (not crash the render, not take down the other, valid
// entries), exactly like nftables.sanitizeNetworks and
// timesync.GenerateChronyConf already do for their own admin-supplied
// lists.
func TestGenerateUnboundConfigSkipsInjectedBlocklistEntry(t *testing.T) {
	cfg := netsvc.DefaultConfig()
	malicious := "evil.com.\"\ninclude: \"/etc/passwd"
	out, _, _ := GenerateUnboundConfig(cfg, []string{"good.example.com", malicious})

	if strings.Contains(out, "include:") {
		t.Errorf("injected directive reached unbound.conf:\n%s", out)
	}
	if strings.Contains(out, malicious) {
		t.Errorf("malicious blocklist entry was rendered verbatim:\n%s", out)
	}
	if !strings.Contains(out, `local-zone: "good.example.com." always_nxdomain`) {
		t.Errorf("valid blocklist entry must still be rendered even though a sibling entry was bad:\n%s", out)
	}
}

// TestGenerateUnboundConfigSkipsInvalidUpstream: Upstreams feed
// `forward-addr:` lines by string concatenation.
func TestGenerateUnboundConfigSkipsInvalidUpstream(t *testing.T) {
	cfg := netsvc.DefaultConfig()
	cfg.Upstreams = []string{"1.1.1.1", "evil\nforward-addr: 6.6.6.6"}
	out, _, _ := GenerateUnboundConfig(cfg, nil)

	if strings.Contains(out, "6.6.6.6") {
		t.Errorf("injected forward-addr via upstreams reached unbound.conf:\n%s", out)
	}
	if !strings.Contains(out, "forward-addr: 1.1.1.1") {
		t.Errorf("valid upstream must still be rendered even though a sibling entry was bad:\n%s", out)
	}
}

// TestEnsureResolvConfLeavesResolverAloneWhenUnboundNotEnabled: unbound is
// only `Recommends:` in the package, never `Depends:` — on a box without it
// installed (or where it failed to start), EnsureResolvConf must not touch
// either file. Seizing resolv.conf would knock out the box's own name
// resolution (updater, Telegram/webhook notifications, the AI digest,
// chrony pool hostnames) with no local resolver to fall back on.
func TestEnsureResolvConfLeavesResolverAloneWhenUnboundNotEnabled(t *testing.T) {
	dir := t.TempDir()
	resolv := filepath.Join(dir, "resolv.conf")
	resolvSeed := "nameserver 189.40.0.1\nnameserver 189.40.0.2\n"
	if err := os.WriteFile(resolv, []byte(resolvSeed), 0o644); err != nil {
		t.Fatalf("seed resolv.conf: %v", err)
	}
	dhclient := filepath.Join(dir, "dhclient.conf")
	dhclientSeed := "send host-name = gethostname();\n"
	if err := os.WriteFile(dhclient, []byte(dhclientSeed), 0o644); err != nil {
		t.Fatalf("seed dhclient.conf: %v", err)
	}

	s := NewService(&recExec{unboundEnabled: false})
	s.resolvConf = resolv
	s.dhclientConf = dhclient

	s.EnsureResolvConf(context.Background())

	gotResolv, err := os.ReadFile(resolv)
	if err != nil {
		t.Fatalf("ReadFile resolv.conf: %v", err)
	}
	if string(gotResolv) != resolvSeed {
		t.Errorf("resolv.conf was modified with unbound not enabled:\ngot:  %q\nwant: %q", gotResolv, resolvSeed)
	}
	gotDhclient, err := os.ReadFile(dhclient)
	if err != nil {
		t.Fatalf("ReadFile dhclient.conf: %v", err)
	}
	if string(gotDhclient) != dhclientSeed {
		t.Errorf("dhclient.conf was modified with unbound not enabled:\ngot:  %q\nwant: %q", gotDhclient, dhclientSeed)
	}
}

// TestEnsureResolvConfPointsAtLocalUnbound is the regression test for a real
// production finding on 2026-08-10: /etc/resolv.conf pointed at the ISP's
// nameservers instead of the local unbound. Nothing in the codebase managed
// that file at all — the WAN's dhclient rewrites it on every lease renewal —
// so the appliance silently stopped using its own resolver (losing the DNS
// blocklist and query visibility that unbound provides).
func TestEnsureResolvConfPointsAtLocalUnbound(t *testing.T) {
	dir := t.TempDir()
	resolv := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(resolv, []byte("nameserver 189.40.0.1\nnameserver 189.40.0.2\n"), 0o644); err != nil {
		t.Fatalf("seed resolv.conf: %v", err)
	}
	s := NewService(&recExec{unboundEnabled: true})
	s.resolvConf = resolv
	s.dhclientConf = filepath.Join(dir, "dhclient.conf")

	s.EnsureResolvConf(context.Background())

	got, err := os.ReadFile(resolv)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(got), "nameserver 127.0.0.1") {
		t.Errorf("resolv.conf does not point at the local resolver:\n%s", got)
	}
	if strings.Contains(string(got), "189.40.0.1") {
		t.Errorf("ISP nameserver survived:\n%s", got)
	}
	if !strings.Contains(string(got), "# managed by linkguard") {
		t.Errorf("missing the managed-by header:\n%s", got)
	}
}

// TestEnsureResolvConfSupersedesDhclient: rewriting resolv.conf alone is not
// enough — the next DHCP lease renewal would overwrite it again. The fix has
// to tell dhclient itself to stop proposing the ISP's servers.
func TestEnsureResolvConfSupersedesDhclient(t *testing.T) {
	dir := t.TempDir()
	dhclient := filepath.Join(dir, "dhclient.conf")
	if err := os.WriteFile(dhclient, []byte("send host-name = gethostname();\n"), 0o644); err != nil {
		t.Fatalf("seed dhclient.conf: %v", err)
	}
	s := NewService(&recExec{unboundEnabled: true})
	s.resolvConf = filepath.Join(dir, "resolv.conf")
	s.dhclientConf = dhclient

	s.EnsureResolvConf(context.Background())

	got, err := os.ReadFile(dhclient)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(got), "supersede domain-name-servers 127.0.0.1;") {
		t.Errorf("dhclient.conf missing the supersede directive:\n%s", got)
	}
	if !strings.Contains(string(got), "send host-name = gethostname();") {
		t.Errorf("pre-existing dhclient config was destroyed:\n%s", got)
	}
}

// TestEnsureResolvConfDoesNotDuplicateSupersede: it runs on every boot, so a
// second run must not keep appending the same line.
func TestEnsureResolvConfDoesNotDuplicateSupersede(t *testing.T) {
	dir := t.TempDir()
	s := NewService(&recExec{unboundEnabled: true})
	s.resolvConf = filepath.Join(dir, "resolv.conf")
	s.dhclientConf = filepath.Join(dir, "dhclient.conf")

	s.EnsureResolvConf(context.Background())
	s.EnsureResolvConf(context.Background())

	got, err := os.ReadFile(s.dhclientConf)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if n := strings.Count(string(got), "supersede domain-name-servers"); n != 1 {
		t.Errorf("supersede directive appears %d times, want 1:\n%s", n, got)
	}
}

// countActiveSupersedeLines counts lines that actually take effect as a
// `supersede domain-name-servers` dhclient directive: leading whitespace is
// stripped, comment lines (starting with `#`) never count.
func countActiveSupersedeLines(content string) int {
	n := 0
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 && fields[0] == "supersede" && fields[1] == "domain-name-servers" {
			n++
		}
	}
	return n
}

// TestEnsureResolvConfIgnoresCommentedOutSupersede is the false-positive case
// from the review: a commented-out directive (e.g. left over from a manual
// experiment) must NOT satisfy the idempotency check. A raw substring check
// matches it and returns early believing DNS is pinned, silently reproducing
// the exact production bug this feature exists to fix.
func TestEnsureResolvConfIgnoresCommentedOutSupersede(t *testing.T) {
	dir := t.TempDir()
	dhclient := filepath.Join(dir, "dhclient.conf")
	seed := "send host-name = gethostname();\n# supersede domain-name-servers 127.0.0.1;\n"
	if err := os.WriteFile(dhclient, []byte(seed), 0o644); err != nil {
		t.Fatalf("seed dhclient.conf: %v", err)
	}
	s := NewService(&recExec{unboundEnabled: true})
	s.resolvConf = filepath.Join(dir, "resolv.conf")
	s.dhclientConf = dhclient

	s.EnsureResolvConf(context.Background())

	got, err := os.ReadFile(dhclient)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if n := countActiveSupersedeLines(string(got)); n != 1 {
		t.Errorf("active supersede lines = %d, want 1 (commented line must not count):\n%s", n, got)
	}
	if !strings.Contains(string(got), "# supersede domain-name-servers 127.0.0.1;") {
		t.Errorf("the original comment line must survive untouched:\n%s", got)
	}
	if !strings.Contains(string(got), "send host-name = gethostname();") {
		t.Errorf("pre-existing dhclient config was destroyed:\n%s", got)
	}
}

// TestEnsureResolvConfReplacesConflictingValue is the false-negative case
// from the review: an active directive for the same option but a different
// value (e.g. left by the ISP's dhclient defaults, or a stale manual edit)
// must be replaced in place, not left alongside a second, conflicting
// `supersede domain-name-servers` statement — dhclient treats two modifier
// statements for one option as at best last-wins, at worst a parse failure
// that breaks DHCP on that WAN at lease renewal.
func TestEnsureResolvConfReplacesConflictingValue(t *testing.T) {
	dir := t.TempDir()
	dhclient := filepath.Join(dir, "dhclient.conf")
	seed := "send host-name = gethostname();\nsupersede domain-name-servers 8.8.8.8;\n"
	if err := os.WriteFile(dhclient, []byte(seed), 0o644); err != nil {
		t.Fatalf("seed dhclient.conf: %v", err)
	}
	s := NewService(&recExec{unboundEnabled: true})
	s.resolvConf = filepath.Join(dir, "resolv.conf")
	s.dhclientConf = dhclient

	s.EnsureResolvConf(context.Background())

	got, err := os.ReadFile(dhclient)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if n := countActiveSupersedeLines(string(got)); n != 1 {
		t.Errorf("active supersede lines = %d, want exactly 1 (no duplicate/conflicting statement):\n%s", n, got)
	}
	if !strings.Contains(string(got), "supersede domain-name-servers 127.0.0.1;") {
		t.Errorf("dhclient.conf missing the correct supersede directive:\n%s", got)
	}
	if strings.Contains(string(got), "8.8.8.8") {
		t.Errorf("conflicting ISP value survived:\n%s", got)
	}
	if !strings.Contains(string(got), "send host-name = gethostname();") {
		t.Errorf("pre-existing dhclient config was destroyed:\n%s", got)
	}
}

// TestEnsureResolvConfReplacesIrregularSpacing covers the same false-negative
// failure mode as above but triggered by whitespace instead of value: extra
// spaces between tokens still make the line an active
// `supersede domain-name-servers` statement, which a raw literal-string
// check misses.
func TestEnsureResolvConfReplacesIrregularSpacing(t *testing.T) {
	dir := t.TempDir()
	dhclient := filepath.Join(dir, "dhclient.conf")
	seed := "send host-name = gethostname();\nsupersede  domain-name-servers   127.0.0.1;\n"
	if err := os.WriteFile(dhclient, []byte(seed), 0o644); err != nil {
		t.Fatalf("seed dhclient.conf: %v", err)
	}
	s := NewService(&recExec{unboundEnabled: true})
	s.resolvConf = filepath.Join(dir, "resolv.conf")
	s.dhclientConf = dhclient

	s.EnsureResolvConf(context.Background())

	got, err := os.ReadFile(dhclient)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if n := countActiveSupersedeLines(string(got)); n != 1 {
		t.Errorf("active supersede lines = %d, want exactly 1 (no duplicate statement):\n%s", n, got)
	}
	if !strings.Contains(string(got), "supersede domain-name-servers 127.0.0.1;") {
		t.Errorf("dhclient.conf missing the correctly formatted supersede directive:\n%s", got)
	}
	if !strings.Contains(string(got), "send host-name = gethostname();") {
		t.Errorf("pre-existing dhclient config was destroyed:\n%s", got)
	}
}

// ─── I-5: o arquivo temporário de validação não pode cair no glob do unbound ──
//
// O unbound.conf do Debian faz `include-toplevel:
// "/etc/unbound/unbound.conf.d/*.conf"`, e é justamente esse diretório que
// o validador usa (mesmo sistema de arquivos que a config real). Se o
// processo morrer entre o CreateTemp e o Remove adiado, um sufixo .conf
// deixa para trás um segundo fragmento com `interface:`/`local-zone`
// duplicados — o unbound o carrega no próximo start e o DNS morre no boot
// seguinte, sem ninguém ter mexido em nada.
func TestValidateUnboundTempFileIsNotPickedUpByTheIncludeGlob(t *testing.T) {
	e := &recExec{}
	s := newTestSvc(t, e)

	if _, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil); err != nil {
		t.Fatalf("ReloadConfigs: %v", err)
	}
	if e.unboundCheckPath == "" {
		t.Fatal("unbound-checkconf nunca foi chamado")
	}
	if strings.HasSuffix(e.unboundCheckPath, ".conf") {
		t.Errorf("o temporário de validação não pode casar com o glob *.conf do include-toplevel, obtive %q", e.unboundCheckPath)
	}
}

// ─── I-6: uma rejeição real do checker não pode virar "checker ausente" ──────
//
// firewall.RealExecutor enfia o stderr do comando na string do erro, e
// muita mensagem legítima do unbound-checkconf cita um arquivo que falta
// ("... /var/lib/unbound/root.key: no such file or directory"). Casar essa
// substring em qualquer lugar do erro transformava a rejeição em "o
// checker não existe, siga em frente": fail-open numa validação cujo
// propósito inteiro é fail-closed.
func TestReloadConfigsFailsClosedWhenCheckerRejectsWithAMissingFileMessage(t *testing.T) {
	e := &recExec{unboundCheckErr: fmt.Errorf(`[1234:0] fatal error: /var/lib/unbound/root.key: no such file or directory`)}
	s := newTestSvc(t, e)

	if _, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil); err == nil {
		t.Fatal("uma rejeição do unbound-checkconf tem que abortar o apply, mesmo citando arquivo ausente")
	}
	if _, err := os.Stat(s.unboundConf); err == nil {
		t.Error("nada pode ser escrito quando a validação reprova")
	}
	if strings.Contains(strings.Join(e.writes, "\n"), "reload-or-restart") {
		t.Error("nada pode ser recarregado quando a validação reprova")
	}
}

// O outro lado da mesma moeda: com o checker de fato ausente (o pacote
// unbound é Recommends:, não Depends:), a validação é pulada e o apply
// segue — e o checker nem chega a ser executado.
func TestReloadConfigsSkipsValidationWhenCheckerIsReallyAbsent(t *testing.T) {
	e := &recExec{}
	s := newTestSvc(t, e)
	s.unboundCheckBin = filepath.Join(t.TempDir(), "nao-existe", "unbound-checkconf")

	if _, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil); err != nil {
		t.Fatalf("checker ausente não pode bloquear o apply: %v", err)
	}
	if e.unboundCheckPath != "" {
		t.Errorf("um checker inexistente não devia nem ser executado, mas recebeu %q", e.unboundCheckPath)
	}
	if _, err := os.Stat(s.unboundConf); err != nil {
		t.Error("a config devia ser escrita mesmo sem validação possível")
	}
}

// Entradas de lista continuam sendo puladas — mas contadas, e a contagem
// sai do apply para o painel poder mostrar. Sem isso, a blocklist encolhia
// em silêncio e o apply dizia "ok".
func TestReloadConfigsReportsSkippedListEntries(t *testing.T) {
	e := &recExec{}
	s := newTestSvc(t, e)
	c := netsvc.DefaultConfig()
	c.Upstreams = []string{"1.1.1.1", "não-é-ip"}

	res, err := s.ReloadConfigs(context.Background(), c, []string{"ads.example.com", "domínio inválido!"})
	if err != nil {
		t.Fatalf("uma entrada de lista ruim não pode afundar as boas: %v", err)
	}
	if len(res.Warnings) == 0 {
		t.Fatal("as entradas descartadas têm que sair no resultado do apply, não só no journal")
	}
	joined := strings.Join(res.Warnings, " | ")
	if !strings.Contains(joined, "1") {
		t.Errorf("o aviso tem que trazer a contagem das descartadas, obtive %q", joined)
	}
	content, rErr := os.ReadFile(s.unboundConf)
	if rErr != nil {
		t.Fatalf("a config devia ter sido escrita: %v", rErr)
	}
	if !strings.Contains(string(content), "forward-addr: 1.1.1.1") || !strings.Contains(string(content), "ads.example.com") {
		t.Errorf("as entradas válidas têm que continuar sendo renderizadas:\n%s", content)
	}
}

// ─── Instalação sob demanda (unbound) ────────────────────────────────────────

// O defeito que originou esta funcionalidade, ainda no tempo em que o produto
// servia DHCP: numa máquina onde o kea-dhcp4-server nunca foi instalado,
// ligar o DHCP pelo painel morria em
// `open /etc/kea/kea-validate-*.conf: no such file or directory` — o
// diretório só existia se algum humano tivesse rodado apt antes. A premissa
// do produto (FEATURES.md) é o contrário: instalar o LinkGuard é entregar a
// máquina a ele, e o pacote opcional entra quando o admin liga a
// funcionalidade.
func TestReloadConfigsInstallsMissingPackagesOnDemand(t *testing.T) {
	e := &recExec{missingPkgs: map[string]bool{unboundPackage: true}}
	s := newTestSvc(t, e)

	res, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil)
	if err != nil {
		t.Fatalf("ReloadConfigs numa máquina sem o unbound: %v", err)
	}
	joined := strings.Join(e.writes, "\n")
	if !strings.Contains(joined, "apt-get install") || !strings.Contains(joined, unboundPackage) {
		t.Errorf("o pacote ausente tinha que ser instalado; comandos:\n%s", joined)
	}
	if len(res.Installed) != 1 || res.Installed[0] != unboundPackage {
		t.Errorf("Installed = %v, quero [%s] (para o painel poder registrar a transição)", res.Installed, unboundPackage)
	}
	if _, sErr := os.Stat(s.unboundConf); sErr != nil {
		t.Errorf("depois de instalar, a config tinha que ser aplicada na mesma execução: %v", sErr)
	}
}

// O caminho normal — todo save de DNS passa por aqui. Numa máquina já
// provisionada isso não pode custar um apt: só um dpkg-query por pacote.
func TestReloadConfigsDoesNotRunAptWhenThePackagesAreThere(t *testing.T) {
	e := &recExec{}
	s := newTestSvc(t, e)

	res, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil)
	if err != nil {
		t.Fatalf("ReloadConfigs: %v", err)
	}
	if strings.Contains(strings.Join(e.writes, "\n"), "apt-get") {
		t.Errorf("nada de apt numa máquina que já tem os pacotes: %v", e.writes)
	}
	if len(res.Installed) != 0 {
		t.Errorf("Installed = %v, quero vazio", res.Installed)
	}
}

// A regra do "não finge": se o pacote não está lá e não dá para instalar
// (sem rede, espelho fora do ar), a resposta tem que dizer o que falta, por
// quê, o que deixa de funcionar e como resolver na mão — e nada pode ser
// escrito nem recarregado.
func TestReloadConfigsExplainsAPackageItCouldNotInstall(t *testing.T) {
	e := &recExec{missingPkgs: map[string]bool{unboundPackage: true}, installFails: true}
	s := newTestSvc(t, e)

	_, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil)
	if err == nil {
		t.Fatal("aplicar sem o pacote do DNS tem que falhar, não fingir sucesso")
	}
	var pre *netsvc.PrereqError
	if !errors.As(err, &pre) {
		t.Fatalf("o erro tem que ser um netsvc.PrereqError (para a API não devolver 'erro interno'), obtive %T: %v", err, err)
	}
	msg := err.Error()
	for _, want := range []string{unboundPackage, "Unable to locate package", "DNS", "apt-get install -y"} {
		t.Run(want, func(t *testing.T) {
			if !strings.Contains(msg, want) {
				t.Errorf("a mensagem tem que citar %q, obtive %q", want, msg)
			}
		})
	}
	if _, sErr := os.Stat(s.unboundConf); sErr == nil {
		t.Error("nada pode ser escrito quando o pré-requisito falta")
	}
	if strings.Contains(strings.Join(e.writes, "\n"), "reload-or-restart") {
		t.Errorf("nada pode ser recarregado quando o pré-requisito falta: %v", e.writes)
	}
}

// A armadilha do systemd: ProtectSystem=strict monta o namespace no start do
// serviço, então um diretório que não existia naquele momento fica
// somente-leitura (ou invisível) para o processo em execução mesmo depois de
// o apt criá-lo. O postinst deste pacote cria /etc/unbound/unbound.conf.d
// justamente para que isso não aconteça — mas se
// acontecer (instalação por `make install`, diretório apagado à mão), o
// admin tem que ler o que fazer, não um erro de escrita cru.
func TestReloadConfigsSaysToRestartWhenTheConfigDirIsOutsideTheSandbox(t *testing.T) {
	e := &recExec{}
	s := newTestSvc(t, e)
	s.unboundConf = filepath.Join(t.TempDir(), "nao-existe", "unbound.conf")

	_, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil)
	if err == nil {
		t.Fatal("escrever num diretório inacessível tem que falhar")
	}
	var pre *netsvc.PrereqError
	if !errors.As(err, &pre) {
		t.Fatalf("erro = %T (%v), quero um netsvc.PrereqError", err, err)
	}
	msg := err.Error()
	for _, want := range []string{filepath.Dir(s.unboundConf), "Reinicie o serviço", "systemctl restart linkguard-cloud"} {
		if !strings.Contains(msg, want) {
			t.Errorf("a mensagem tem que citar %q, obtive %q", want, msg)
		}
	}
}

// Visto na VM: unbound subiu quebrado uma vez (faltava a âncora DNSSEC), o
// systemd esgotou o contador de restart e, DEPOIS de a causa ser corrigida,
// todo apply passou a falhar com "Start request repeated too quickly" — uma
// mensagem que não fala do problema real e que só sai do lugar com um
// `systemctl reset-failed` no SSH. Limpar o estado de falha antes de
// recarregar devolve ao admin o erro verdadeiro (ou o serviço no ar).
func TestReloadConfigsClearsAFailedUnitBeforeReloading(t *testing.T) {
	e := &recExec{}
	s := newTestSvc(t, e)

	if _, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil); err != nil {
		t.Fatalf("ReloadConfigs: %v", err)
	}
	joined := strings.Join(e.writes, "\n")
	for _, svc := range []string{unboundService} {
		reset := strings.Index(joined, "systemctl reset-failed "+svc)
		act := strings.Index(joined, "systemctl reload-or-restart "+svc)
		if act < 0 {
			act = strings.Index(joined, "systemctl restart "+svc)
		}
		if reset < 0 || act < 0 {
			t.Errorf("faltou o reset-failed ou a ação em %s; comandos:\n%s", svc, joined)
			continue
		}
		if reset > act {
			t.Errorf("o reset-failed de %s tem que vir antes de recarregar/reiniciar; comandos:\n%s", svc, joined)
		}
	}
}

// Medido na VM: o unbound recarregado com SIGHUP (o ExecReload que o pacote
// Debian traz) relê a config mas NÃO reabre os sockets de escuta. Numa
// instalação nova isso é garantido de dar errado: o pacote sobe o unbound
// escutando só em 127.0.0.1, o LinkGuard escreve o drop-in com
// `interface: <IP da LAN>`, recarrega — e o painel diz "aplicado" enquanto a
// LAN inteira fica sem DNS. Quando o endereço de escuta muda, tem que ser
// restart de verdade.
func TestReloadRestartsUnboundWhenTheListenAddressChanges(t *testing.T) {
	e := &recExec{}
	s := newTestSvc(t, e)
	if err := os.WriteFile(s.unboundConf, []byte("server:\n  interface: 10.9.9.9\n"), 0o644); err != nil {
		t.Fatalf("preparar config antiga: %v", err)
	}

	c := netsvc.DefaultConfig()
	c.ExtraListenAddresses = []string{"192.168.3.3"}
	if _, err := s.ReloadConfigs(context.Background(), c, nil); err != nil {
		t.Fatalf("ReloadConfigs: %v", err)
	}
	joined := strings.Join(e.writes, "\n")
	if !strings.Contains(joined, "systemctl restart "+unboundService) {
		t.Errorf("mudou o endereço de escuta: o unbound precisa de restart, não de SIGHUP; comandos:\n%s", joined)
	}
}

// ...e o contrário: mexer só na blocklist não pode derrubar o resolvedor (e
// jogar fora o cache) a cada save. Aí o reload gracioso é o certo.
func TestReloadKeepsGracefulReloadWhenOnlyTheBlocklistChanges(t *testing.T) {
	e := &recExec{}
	s := newTestSvc(t, e)
	c := netsvc.DefaultConfig()
	if _, err := s.ReloadConfigs(context.Background(), c, nil); err != nil {
		t.Fatalf("primeiro apply: %v", err)
	}

	e.writes = nil
	if _, err := s.ReloadConfigs(context.Background(), c, []string{"ads.example.com"}); err != nil {
		t.Fatalf("segundo apply: %v", err)
	}
	joined := strings.Join(e.writes, "\n")
	if strings.Contains(joined, "systemctl restart "+unboundService) {
		t.Errorf("nada mudou na escuta: derrubar o unbound (e o cache) por uma blocklist é caro demais;\n%s", joined)
	}
	if !strings.Contains(joined, "reload-or-restart "+unboundService) {
		t.Errorf("faltou o reload gracioso do unbound;\n%s", joined)
	}
}

// Instalação sob demanda: o pacote acabou de subir o unbound com a config
// padrão dele (só 127.0.0.1). Mesmo que o arquivo do LinkGuard já estivesse
// no lugar, o processo em execução não é o que leu esse arquivo.
//
// O teste começa por um apply inteiro bem-sucedido de propósito: assim o
// marcador de "ativado" já bate com a config que será gerada de novo, e a
// ÚNICA coisa capaz de forçar o restart no segundo apply é o fato de o
// pacote ter sido (re)instalado. Antes, este teste passava pelo motivo
// errado — nele o arquivo antigo simplesmente não existia, então quem
// forçava o restart era o ramo "a config mudou", e remover a cláusula do
// pacote instalado não quebrava nada.
func TestReloadRestartsUnboundRightAfterInstallingIt(t *testing.T) {
	e := &recExec{}
	s := newTestSvc(t, e)
	if _, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil); err != nil {
		t.Fatalf("apply inicial: %v", err)
	}

	// O unbound foi removido e reinstalado (por fora, ou por um purge): o
	// daemon voltou com a config padrão do pacote, escutando só no loopback.
	e.missingPkgs = map[string]bool{unboundPackage: true}
	e.writes = nil
	if _, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil); err != nil {
		t.Fatalf("ReloadConfigs: %v", err)
	}
	if !strings.Contains(strings.Join(e.writes, "\n"), "systemctl restart "+unboundService) {
		t.Errorf("o unbound recém-instalado tem que ser reiniciado para valer a config do LinkGuard;\n%s", strings.Join(e.writes, "\n"))
	}
}

// A instalação sob demanda tem que sair pelo executor de pacote, não pelo
// executor de 30s da aplicação. Os dois trabalhos não têm nada em comum: um
// `nft`/`systemctl` que não respondeu em 30s está travado; um apt-get
// baixando unbound + dns-root-data num espelho lento passa disso num link de
// escritório sem nada estar errado. E quando o prazo estourava, o apt não
// morria junto — a unidade transiente do systemd-run terminava a instalação
// — então o LinkGuard devolvia 503 "não conseguiu instalar" e criava alerta
// crítico enquanto o pacote entrava com sucesso.
func TestInstalacaoSobDemandaUsaOExecutorDePacote(t *testing.T) {
	appExec := &recExec{missingPkgs: map[string]bool{"unbound": true, "dns-root-data": true}}
	pkgExec := &recExec{missingPkgs: map[string]bool{"unbound": true, "dns-root-data": true}}

	s := newTestSvc(t, appExec)
	s.SetInstallExecutor(pkgExec)

	if _, _, err := s.ensurePackages(context.Background()); err != nil {
		t.Fatalf("ensurePackages: %v", err)
	}

	if !slices.ContainsFunc(pkgExec.writes, func(c string) bool { return strings.Contains(c, "apt-get install") }) {
		t.Errorf("o apt não saiu pelo executor de pacote; comandos: %v", pkgExec.writes)
	}
	if slices.ContainsFunc(appExec.writes, func(c string) bool { return strings.Contains(c, "apt-get install") }) {
		t.Errorf("o apt saiu pelo executor de 30s da aplicação; comandos: %v", appExec.writes)
	}
}

// O defeito "painel diz aplicado, LAN sem DNS" voltando por outra porta.
//
// A decisão de reiniciar comparava o ARQUIVO EM DISCO com a config nova — e o
// arquivo é escrito ANTES do reload. Um apply que escreve o arquivo e morre
// no restart deixa o disco já com a config nova; o apply seguinte vê
// antigo == novo, decide que SIGHUP basta, e o unbound segue nos sockets em
// que subiu (127.0.0.1): VPN sem DNS, painel dizendo "aplicado".
//
// A cláusula slices.Contains(installed, unboundPackage) não protege este
// caso: o unbound já estava instalado nas duas tentativas.
func TestUnboundReiniciaQuandoOApplyAnteriorMorreuDepoisDeEscreverOsArquivos(t *testing.T) {
	// O unbound em execução subiu escutando só no loopback (padrão do
	// pacote), e é isso que o marcador de "ativado" registra.
	e := &recExec{failOn: "systemctl restart " + unboundService}
	s := newTestSvc(t, e)
	if err := os.WriteFile(s.unboundApplied, []byte("server:\n  interface: 127.0.0.1\n"), 0o600); err != nil {
		t.Fatalf("preparar marcador: %v", err)
	}

	c := netsvc.DefaultConfig()
	c.ExtraListenAddresses = []string{"192.168.3.3"}

	// Apply 1: escreve o arquivo e morre no restart do unbound.
	if _, err := s.ReloadConfigs(context.Background(), c, nil); err == nil {
		t.Fatal("esperava falha no restart do unbound")
	}
	if got := readFileOrEmpty(s.unboundConf); !strings.Contains(got, "interface: 192.168.3.3") {
		t.Fatalf("o teste depende de o arquivo já ter sido escrito no apply que falhou; conteúdo:\n%s", got)
	}

	// Apply 2: o restart volta a funcionar. O unbound em execução continua
	// nos sockets antigos, então TEM que ser restart.
	e.failOn = ""
	e.writes = nil
	if _, err := s.ReloadConfigs(context.Background(), c, nil); err != nil {
		t.Fatalf("segundo apply: %v", err)
	}
	joined := strings.Join(e.writes, "\n")
	if !strings.Contains(joined, "systemctl restart "+unboundService) {
		t.Errorf("o unbound nunca reabriu os sockets: SIGHUP não basta depois de um apply interrompido;\ncomandos:\n%s", joined)
	}
}

// E o marcador só pode ser escrito quando a config foi de fato ATIVADA —
// senão ele herda exatamente o defeito do arquivo em disco.
func TestOMarcadorDeAtivadoNaoEEscritoQuandoOApplyFalha(t *testing.T) {
	e := &recExec{failOn: "systemctl restart " + unboundService}
	s := newTestSvc(t, e)

	c := netsvc.DefaultConfig()
	c.ExtraListenAddresses = []string{"192.168.3.3"}
	if _, err := s.ReloadConfigs(context.Background(), c, nil); err == nil {
		t.Fatal("esperava falha no restart do unbound")
	}
	if _, err := os.Stat(s.unboundApplied); err == nil {
		t.Error("o apply falhou: nada pode ter sido registrado como ativado")
	}
}

// E o caso normal continua valendo: depois de um apply inteiro bem-sucedido o
// marcador existe, e o apply seguinte com a MESMA escuta não derruba o
// resolvedor.
func TestOMarcadorEvitaRestartDesnecessarioNoApplySeguinte(t *testing.T) {
	e := &recExec{}
	s := newTestSvc(t, e)
	c := netsvc.DefaultConfig()
	c.ExtraListenAddresses = []string{"192.168.3.3"}

	if _, err := s.ReloadConfigs(context.Background(), c, nil); err != nil {
		t.Fatalf("primeiro apply: %v", err)
	}
	if readFileOrEmpty(s.unboundApplied) == "" {
		t.Fatal("um apply bem-sucedido tem que registrar a config ativada")
	}

	e.writes = nil
	if _, err := s.ReloadConfigs(context.Background(), c, []string{"ads.example.com"}); err != nil {
		t.Fatalf("segundo apply: %v", err)
	}
	if strings.Contains(strings.Join(e.writes, "\n"), "systemctl restart "+unboundService) {
		t.Errorf("nada mudou na escuta: não pode derrubar o unbound;\n%s", strings.Join(e.writes, "\n"))
	}
}

// A sonda de escrita não pode virar lixo em /etc. Com os.CreateTemp, um
// processo morto entre criar e remover deixava um
// `.linkguard-write-probe-XXXX` para trás e nada nunca o recolhia.
func TestASondaDeEscritaNaoDeixaLixo(t *testing.T) {
	dir := t.TempDir()

	// Restos de versões anteriores (nome aleatório) e da atual.
	for _, name := range []string{".linkguard-write-probe-123456", ".linkguard-write-probe"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := writableDir(dir); err != nil {
		t.Fatalf("writableDir: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".linkguard-write-probe") {
			t.Errorf("sobrou lixo da sonda: %s", e.Name())
		}
	}
}

// E a sonda continua respondendo à pergunta que interessa.
func TestASondaDeEscritaAindaDetectaDiretorioNaoGravavel(t *testing.T) {
	if err := writableDir(filepath.Join(t.TempDir(), "nao-existe")); err == nil {
		t.Error("um diretório inexistente tem que ser reportado como não gravável")
	}
	if err := writableDir(t.TempDir()); err != nil {
		t.Errorf("um diretório gravável não pode ser reportado como falha: %v", err)
	}
}

// ─── dns-root-data: pré-requisito de instalar o unbound, não de aplicar ───
//
// I-2 da revisão final. ReloadConfigs começa em ensurePackages, que exigia
// unbound + dns-root-data; faltando QUALQUER um, devolvia PrereqError e nada
// era escrito nem recarregado. Numa máquina em que o unbound está instalado e
// servindo, mas dns-root-data não está, o admin ficava sem conseguir aplicar
// mudança nenhuma de DNS enquanto o apt não pudesse instalar — e a hora em
// que se mexe em DNS costuma ser exatamente a hora em que a WAN está ruim.
func TestFaltaDeDnsRootDataNaoImpedeOApplyComUnboundJaInstalado(t *testing.T) {
	e := &recExec{
		missingPkgs:  map[string]bool{dnsRootDataPackage: true},
		installFails: true, // o apt não consegue trazer nada: WAN ruim
	}
	s := newTestSvc(t, e)

	res, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil)
	if err != nil {
		t.Fatalf("o apply tinha que acontecer mesmo sem dns-root-data: %v", err)
	}

	// Aplicou de verdade: os dois daemons foram recarregados.
	joined := strings.Join(e.writes, "\n")
	for _, svc := range []string{unboundService} {
		if !strings.Contains(joined, svc) {
			t.Errorf("o serviço %s não foi recarregado; comandos: %s", svc, joined)
		}
	}
	// E o admin fica sabendo — sem aviso isto vira exatamente a "config
	// aplicada que não está funcionando" que o produto não aceita.
	if !slices.ContainsFunc(res.Warnings, func(w string) bool { return strings.Contains(w, dnsRootDataPackage) }) {
		t.Errorf("o apply passou calado sobre o dns-root-data ausente; avisos=%v", res.Warnings)
	}
}

// O outro lado: quando é o LinkGuard que vai instalar o unbound AGORA, o
// dns-root-data continua obrigatório. Um unbound recém-instalado sem a
// âncora DNSSEC da raiz nem sobe ("module init for module validator
// failed"): instalar um e não o outro entrega um resolvedor habilitado que
// não responde uma consulta — pior do que não instalar.
func TestDnsRootDataContinuaObrigatorioQuandoOLinkguardInstalaOUnbound(t *testing.T) {
	e := &recExec{
		missingPkgs:     map[string]bool{unboundPackage: true, dnsRootDataPackage: true},
		installFailsFor: map[string]bool{dnsRootDataPackage: true},
	}
	s := newTestSvc(t, e)

	_, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil)
	if err == nil {
		t.Fatal("instalar o unbound sem o dns-root-data tinha que abortar o apply")
	}
	var prereq *netsvc.PrereqError
	if !errors.As(err, &prereq) {
		t.Fatalf("o erro tinha que ser um PrereqError (acionável pelo admin), obtive %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), dnsRootDataPackage) {
		t.Errorf("a mensagem tem que nomear o pacote que faltou: %v", err)
	}
}

// E o caminho normal continua sendo o que era: máquina pelada, apt
// funcionando, os três pacotes entram e o apply segue.
func TestMaquinaPeladaInstalaOsTresPacotesESegue(t *testing.T) {
	e := &recExec{missingPkgs: map[string]bool{
		unboundPackage: true, dnsRootDataPackage: true,
	}}
	s := newTestSvc(t, e)

	res, err := s.ReloadConfigs(context.Background(), netsvc.DefaultConfig(), nil)
	if err != nil {
		t.Fatalf("ReloadConfigs: %v", err)
	}
	for _, pkg := range []string{unboundPackage, dnsRootDataPackage} {
		if !slices.Contains(res.Installed, pkg) {
			t.Errorf("%s tinha que constar como instalado nesta passada; installed=%v", pkg, res.Installed)
		}
	}
	if len(res.Warnings) != 0 {
		t.Errorf("nada faltou; não podia haver aviso: %v", res.Warnings)
	}
}
