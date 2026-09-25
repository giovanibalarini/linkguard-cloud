package netif

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/giovanibalarini/linkguard-cloud/internal/firewall"
	"github.com/giovanibalarini/linkguard-cloud/internal/links"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

const interfaceAliasSettingKey = "interface_aliases" // same key as internal/api/handlers/system.go — do not duplicate the mechanism, only this small read

// Service builds the live interface inventory: kernel state (via `ip -j`)
// merged with configured Role (from links.Service) and stored aliases.
//
// Só leitura. A versão on-prem editava o endereçamento das placas
// (systemd-networkd, com janela de confirmar-ou-reverter) e fixava nomes por
// MAC; na nuvem a placa é da Oracle — endereço, rota e nome vêm da VCN — e
// editar isso por fora do console só produz divergência.
type Service struct {
	exec    firewall.Executor
	db      *storage.DB
	linkSvc *links.Service
}

// NewService creates a netif Service.
func NewService(exec firewall.Executor, db *storage.DB, linkSvc *links.Service) *Service {
	return &Service{exec: exec, db: db, linkSvc: linkSvc}
}

// List returns every interface the kernel currently knows about, with Role
// and Alias filled in.
func (s *Service) List(ctx context.Context) ([]IfaceView, error) {
	linkOut, err := s.exec.ExecuteRead(ctx, "ip", "-d", "-j", "link", "show")
	if err != nil {
		return nil, fmt.Errorf("ip link show: %w", err)
	}
	addrOut, err := s.exec.ExecuteRead(ctx, "ip", "-j", "addr", "show")
	if err != nil {
		return nil, fmt.Errorf("ip addr show: %w", err)
	}
	netDevOut, err := s.exec.ExecuteRead(ctx, "cat", "/proc/net/dev")
	if err != nil {
		return nil, fmt.Errorf("cat /proc/net/dev: %w", err)
	}

	links_, err := parseLinks(linkOut)
	if err != nil {
		return nil, err
	}
	addrs, err := parseAddrs(addrOut)
	if err != nil {
		return nil, err
	}
	counters := parseProcNetDev(netDevOut)
	views := mergeLinks(links_, addrs)

	wanNames, lanNames, linkGateways := s.roleSets()
	aliases := s.aliases()

	for i := range views {
		name := views[i].Name
		switch {
		case wanNames[name]:
			views[i].Role = RoleWAN
		case lanNames[name]:
			views[i].Role = RoleLAN
		}
		if a, ok := aliases[name]; ok {
			views[i].Alias = a
		}
		if c, ok := counters[name]; ok {
			views[i].Live.RxErrors = c.RxErrors
			views[i].Live.TxErrors = c.TxErrors
			views[i].Live.RxDropped = c.RxDropped
			views[i].Live.TxDropped = c.TxDropped
		}
		// O gateway não aparece no `ip addr`; quem o conhece é o Link
		// cadastrado, que o balanceador usa para montar a rota.
		if gw, ok := linkGateways[name]; ok {
			views[i].Gateway = gw
		}
	}

	return views, nil
}

// roleSets returns the interface names that count as WAN (any interface
// referenced by a configured Link) and LAN (none on the cloud gateway since
// DHCP left: the private network belongs to the VCN), plus the gateway each
// configured Link already knows
// (used by the balancer to build its routes) keyed by interface name. Role
// is a label — see spec §5.1 — so a lookup miss is not an error, it just
// leaves the interface Unassigned / the gateway empty.
func (s *Service) roleSets() (wan, lan map[string]bool, gateway map[string]string) {
	wan = map[string]bool{}
	lan = map[string]bool{}
	gateway = map[string]string{}

	if configuredLinks, err := s.linkSvc.List(); err == nil {
		for _, l := range configuredLinks {
			wan[l.Interface] = true
			if l.Gateway != "" {
				gateway[l.Interface] = l.Gateway
			}
		}
	}

	return wan, lan, gateway
}

// aliases returns the stored interface_aliases map. Reuses the exact same
// setting key /api/system/interface-aliases already writes to — spec §15
// explicitly forbids a second alias mechanism.
func (s *Service) aliases() map[string]string {
	raw, err := s.db.GetSetting(interfaceAliasSettingKey)
	if err != nil || raw == "" {
		return map[string]string{}
	}
	var aliases map[string]string
	if err := json.Unmarshal([]byte(raw), &aliases); err != nil {
		return map[string]string{}
	}
	return aliases
}
