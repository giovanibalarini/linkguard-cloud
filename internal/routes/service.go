// Package routes lê as tabelas de rota do kernel (ip route, ip rule) e liga o
// encaminhamento de IP. Não escreve rota: na nuvem a rota é da VCN.
package routes

import (
	"context"
	"log/slog"
	"os"
	"strings"

	"github.com/giovanibalarini/linkguard-cloud/internal/firewall"
)

// ForwardingSysctl is the kernel knob that lets the box route packets between
// interfaces. A firewall/router is useless with it off, and it defaults to 0 on
// a fresh system.
const ForwardingSysctl = "/proc/sys/net/ipv4/ip_forward"

// forwardingDropIn persists the sysctl so it survives reboots (the runtime
// /proc write is not persistent on its own).
const forwardingDropIn = "/etc/sysctl.d/99-linkguard-forwarding.conf"

// Route represents an entry from the kernel routing table.
type Route struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway,omitempty"`
	Interface   string `json:"interface,omitempty"`
	Metric      string `json:"metric,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	Scope       string `json:"scope,omitempty"`
	Raw         string `json:"raw"`
}

// Rule represents an ip rule entry.
type Rule struct {
	Priority string `json:"priority"`
	Selector string `json:"selector"`
	Action   string `json:"action"`
	Table    string `json:"table,omitempty"`
	FWMark   string `json:"fwmark,omitempty"`
	Raw      string `json:"raw"`
}

// Service wraps ip route / ip rule operations.
type Service struct {
	exec firewall.Executor

	// Paths are fields (not consts) so tests can point them at a temp dir.
	fwdPath        string
	fwdPersistPath string
}

// NewService creates a new routes Service.
func NewService(exec firewall.Executor) *Service {
	return &Service{
		exec:           exec,
		fwdPath:        ForwardingSysctl,
		fwdPersistPath: forwardingDropIn,
	}
}

// EnsureForwarding turns on IPv4 forwarding so the box can route between LAN and
// WAN, and persists it so it survives reboots. LinkGuard owns this runtime
// prerequisite rather than relying on external sysctl config (mirrors
// hosttraffic.EnsureAccounting). Best-effort: it logs and returns on failure
// instead of blocking startup, and is a no-op in dry-run mode. Requires root.
func (s *Service) EnsureForwarding() {
	if s.exec.IsDryRun() {
		slog.Info("dry-run: skipping ip_forward enable")
		return
	}
	if err := os.WriteFile(s.fwdPath, []byte("1\n"), 0o644); err != nil {
		slog.Warn("could not enable ip_forward; routing between interfaces will not work",
			"path", s.fwdPath, "err", err)
		return
	}
	drop := "# Managed by LinkGuard: required to route between LAN and WAN.\n" +
		"net.ipv4.ip_forward = 1\n"
	if err := os.WriteFile(s.fwdPersistPath, []byte(drop), 0o644); err != nil {
		slog.Warn("enabled ip_forward but could not persist it across reboots",
			"path", s.fwdPersistPath, "err", err)
	}
}

// ListRoutes returns the main routing table entries.
func (s *Service) ListRoutes(ctx context.Context) ([]Route, error) {
	out, err := s.exec.ExecuteRead(ctx, "ip", "route", "show")
	if err != nil {
		return nil, err
	}
	return parseRoutes(out), nil
}

// ListAllRoutes returns routes from all tables.
func (s *Service) ListAllRoutes(ctx context.Context) ([]Route, error) {
	out, err := s.exec.ExecuteRead(ctx, "ip", "route", "show", "table", "all")
	if err != nil {
		return nil, err
	}
	return parseRoutes(out), nil
}

// ListRules returns the ip rules.
func (s *Service) ListRules(ctx context.Context) ([]Rule, error) {
	out, err := s.exec.ExecuteRead(ctx, "ip", "rule", "list")
	if err != nil {
		return nil, err
	}
	return parseRules(out), nil
}

// ─── Parsers ─────────────────────────────────────────────────────────────────

func parseRoutes(output string) []Route {
	var routes []Route
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		routes = append(routes, parseRouteLine(line))
	}
	return routes
}

func parseRouteLine(line string) Route {
	r := Route{Raw: line}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return r
	}

	r.Destination = fields[0]

	for i := 1; i < len(fields); i++ {
		switch fields[i] {
		case "via":
			if i+1 < len(fields) {
				r.Gateway = fields[i+1]
				i++
			}
		case "dev":
			if i+1 < len(fields) {
				r.Interface = fields[i+1]
				i++
			}
		case "metric":
			if i+1 < len(fields) {
				r.Metric = fields[i+1]
				i++
			}
		case "proto":
			if i+1 < len(fields) {
				r.Protocol = fields[i+1]
				i++
			}
		case "scope":
			if i+1 < len(fields) {
				r.Scope = fields[i+1]
				i++
			}
		}
	}
	return r
}

func parseRules(output string) []Rule {
	var rules []Rule
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		rules = append(rules, parseRuleLine(line))
	}
	return rules
}

func parseRuleLine(line string) Rule {
	r := Rule{Raw: line}
	// Format: "0:	from all lookup local"
	colonIdx := strings.Index(line, ":")
	if colonIdx >= 0 {
		r.Priority = strings.TrimSpace(line[:colonIdx])
		rest := strings.TrimSpace(line[colonIdx+1:])
		fields := strings.Fields(rest)
		for i, f := range fields {
			switch f {
			case "lookup":
				if i+1 < len(fields) {
					r.Table = fields[i+1]
					r.Action = "lookup"
				}
			case "from":
				if i+1 < len(fields) {
					r.Selector = "from " + fields[i+1]
				}
			case "fwmark":
				if i+1 < len(fields) {
					r.FWMark = fields[i+1]
				}
			}
		}
		if r.Selector == "" {
			r.Selector = rest
		}
	}
	return r
}
