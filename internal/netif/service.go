package netif

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/giovanibalarini/linkguard-cloud/internal/firewall"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

const interfaceAliasSettingKey = "interface_aliases" // same key as internal/api/handlers/system.go — do not duplicate the mechanism, only this small read

// Service builds the live interface inventory: kernel state (via `ip -j`)
// merged with Role (the uplink is the WAN) and stored aliases.
//
// Só leitura. A versão on-prem editava o endereçamento das placas
// (systemd-networkd, com janela de confirmar-ou-reverter) e fixava nomes por
// MAC; na nuvem a placa é da Oracle — endereço, rota e nome vêm da VCN — e
// editar isso por fora do console só produz divergência.
type Service struct {
	exec firewall.Executor
	db   *storage.DB
	// wans é a fonte única de "quais são as WANs desta máquina" (o uplink).
	// Nil = nenhuma placa marcada como WAN.
	wans func() ([]string, error)
}

// NewService creates a netif Service. wans is the product's single WAN source
// (cmd/linkguard-cloud's wansEfetivas).
func NewService(exec firewall.Executor, db *storage.DB, wans func() ([]string, error)) *Service {
	return &Service{exec: exec, db: db, wans: wans}
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

	wanNames := s.wanSet()
	aliases := s.aliases()

	for i := range views {
		name := views[i].Name
		if wanNames[name] {
			views[i].Role = RoleWAN
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
	}

	return views, nil
}

// wanSet devolve as placas que contam como WAN. Erro da fonte deixa o
// conjunto vazio: o papel é rótulo de tela (spec §5.1), e a listagem não pode
// falhar porque a rota default não respondeu.
func (s *Service) wanSet() map[string]bool {
	out := map[string]bool{}
	if s.wans == nil {
		return out
	}
	ifaces, err := s.wans()
	if err != nil {
		return out
	}
	for _, i := range ifaces {
		out[i] = true
	}
	return out
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
