// Package firewallrules gerencia a configuração, aplicação e janela de confirmação do firewall por zonas.
package firewallrules

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/giovanibalarini/linkguard-cloud/internal/nftables"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

// Alerter é o lado painel-facing do confirmar-ou-reverter.
type Alerter interface {
	FirewallChangeReverted(detail string) error
}

// Service combina o banco de dados (configuração em edição e aplicada) com o serviço nftables.
type Service struct {
	db      *storage.DB
	nft     *nftables.Service
	alerter Alerter
	now     func() time.Time
	monoNow func() time.Time

	monoDeadline   time.Time
	monoDeadlineID string
	lastRevert     *revertRecord
	mu             sync.Mutex

	fonteInsumos FonteInsumos
	ultimoErro   string
}

// UltimoErro devolve o último erro registrado durante a aplicação ou boot do firewall.
func (s *Service) UltimoErro() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ultimoErro
}

// FonteInsumos fornece os fatos dinâmicos do firewall por zonas (§2.8).
type FonteInsumos func(ctx context.Context) (nftables.Insumos, error)

// NewService cria uma nova instância de Service.
func NewService(db *storage.DB, nft *nftables.Service) *Service {
	return &Service{db: db, nft: nft, now: time.Now, monoNow: time.Now}
}

// SetFonteInsumos configura a fonte de insumos dinâmicos do firewall por zonas.
func (s *Service) SetFonteInsumos(f FonteInsumos) {
	s.fonteInsumos = f
}

// insumos carrega os fatos dinâmicos e preenche os objetos existentes no nftables.
func (s *Service) insumos(ctx context.Context) (nftables.Insumos, error) {
	var ins nftables.Insumos
	if s.fonteInsumos != nil {
		var err error
		ins, err = s.fonteInsumos(ctx)
		if err != nil {
			return ins, fmt.Errorf("obter insumos do firewall: %w", err)
		}
	}
	if s.nft != nil {
		existentes, err := s.nft.ObjetosExistentes(ctx)
		if err != nil {
			return ins, fmt.Errorf("ler objetos existentes do nftables: %w", err)
		}
		if len(ins.Existentes.Chains) == 0 && len(ins.Existentes.Sets) == 0 {
			ins.Existentes = existentes
		}
	}
	return ins, nil
}

// Insumos carrega os fatos dinâmicos e preenche os objetos existentes no nftables.
func (s *Service) Insumos(ctx context.Context) (nftables.Insumos, error) {
	return s.insumos(ctx)
}

// saveNftSnapshot guarda o ruleset vivo em disco via setting nft_live_snapshot.
func (s *Service) saveNftSnapshot(ctx context.Context) {
	if s.nft == nil || s.db == nil {
		return
	}
	rs, err := s.nft.PersistentRuleset(ctx)
	if err != nil {
		slog.Warn("não foi possível ler o ruleset do nftables para snapshot", "err", err)
		return
	}
	if err := s.db.SetSetting(nftables.LiveSnapshotSettingKey, rs); err != nil {
		slog.Warn("não foi possível salvar o snapshot do nftables", "err", err)
	}
}

// SetAlerter liga o serviço de alertas.
func (s *Service) SetAlerter(a Alerter) { s.alerter = a }
