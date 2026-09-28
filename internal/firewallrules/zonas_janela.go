package firewallrules

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/giovanibalarini/linkguard-cloud/internal/fwmodel"
	"github.com/giovanibalarini/linkguard-cloud/internal/nftables"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

// snapshotV2 é o estado anterior guardado quando a janela abre (§2.8).
type snapshotV2 struct {
	Formato   int            `json:"formato"` // sempre 2
	Config    fwmodel.Config `json:"config"`  // a config aplicada ANTES da mudança
	PerfisVPN []perfilVPN    `json:"perfis_vpn"`
}

type perfilVPN struct {
	UserID            string   `json:"user_id"`
	AccessMode        string   `json:"access_mode"`
	AllowedHostGroups []string `json:"allowed_host_groups"` // agora IDs de alias
	AllowedPorts      string   `json:"allowed_ports"`
}

type snapshotHeader struct {
	Formato int `json:"formato"`
}

func validateSnapshotV2(snap snapshotV2) error {
	if snap.Formato != 2 {
		return fmt.Errorf("formato do snapshot inválido: esperado 2, obtido %d", snap.Formato)
	}
	var userIDs []string
	for _, p := range snap.PerfisVPN {
		userIDs = append(userIDs, p.UserID)
	}
	// Mesma tolerância do render: a regra de quem já não tem VPN não impede reverter.
	cfg, _ := fwmodel.SemRegrasDePessoaRemovida(snap.Config, userIDs)
	problemas := fwmodel.Validar(cfg, userIDs)
	if fwmodel.TemErro(problemas) {
		var msgs []string
		for _, prob := range problemas {
			if prob.Severidade == "erro" {
				msgs = append(msgs, prob.Chave)
			}
		}
		return fmt.Errorf("snapshot v2 contém regra inválida: %s", strings.Join(msgs, "; "))
	}
	return nil
}

// revertV2 desfaz uma alteração pendente sob a arquitetura de firewall por zonas (§2.8):
// restaura em edição e aplicada a partir de snap.Config, restaura os perfis da VPN
// (novos usuários ficam restritos e sem aliases), renderiza o ruleset e o aplica de forma atômica.
func (s *Service) revertV2(ctx context.Context, p *storage.PendingChange, reason string, alert bool) error {
	var snap snapshotV2
	if err := json.Unmarshal([]byte(p.Snapshot), &snap); err != nil {
		return revertFailed(fmt.Errorf("snapshot v2 ilegível, nada foi revertido: %w", err))
	}
	if err := validateSnapshotV2(snap); err != nil {
		return revertFailed(fmt.Errorf("snapshot v2 inválido: %w", err))
	}

	if !p.Reverting() {
		// 1. Substituir em edição e aplicada pelo snapshot.Config
		if err := s.db.SubstituirConfigEmEdicao(snap.Config); err != nil {
			return revertFailed(fmt.Errorf("restaurar config em edição: %w", err))
		}
		if err := s.db.SalvarAplicadaERevisao(snap.Config, "linkguard", "reversão automática da janela", "reverter", s.now()); err != nil {
			return revertFailed(fmt.Errorf("restaurar config aplicada e gravar revisão: %w", err))
		}

		// 2. Restaurar perfis da VPN
		peers, err := s.db.ListWireGuardPeers()
		if err != nil {
			return revertFailed(fmt.Errorf("listar peers wireguard: %w", err))
		}
		perfisMap := make(map[string]perfilVPN, len(snap.PerfisVPN))
		for _, pv := range snap.PerfisVPN {
			perfisMap[pv.UserID] = pv
		}
		for _, peer := range peers {
			// pessoa cadastrada durante a janela: reverter nunca concede a mais (§2.8)
			acesso := storage.WireGuardPeerAccess{
				AccessMode:        "restricted",
				AllowedHostGroups: []string{},
				TunnelMode:        peer.TunnelMode,
				ExtraRoutes:       peer.ExtraRoutes,
				MTU:               peer.MTU,
			}
			if pv, ok := perfisMap[peer.UserID]; ok {
				acesso.AccessMode = pv.AccessMode
				acesso.AllowedHostGroups = pv.AllowedHostGroups
				acesso.AllowedPorts = pv.AllowedPorts
			}
			if err := s.db.UpdateWireGuardPeerAccess(peer.UserID, acesso); err != nil {
				slog.Warn("reversão: não foi possível restaurar o perfil da pessoa na VPN", "user_id", peer.UserID, "err", err)
			}
		}

		if err := s.db.MarkPendingReverting(p.ID, s.now()); err != nil {
			return revertFailed(fmt.Errorf("marcar pendente como revertendo: %w", err))
		}
	}

	// 3. Renderizar com os insumos atuais e aplicar
	ins, err := s.insumos(ctx)
	if err != nil {
		return revertFailed(fmt.Errorf("ler insumos na reversão: %w", err))
	}
	ruleset, err := nftables.RenderZonas(snap.Config, ins)
	if err != nil {
		return revertFailed(fmt.Errorf("renderizar snapshot v2 na reversão: %w", err))
	}
	if err := s.nft.AplicarScript(ctx, ruleset.Script); err != nil {
		return revertFailed(fmt.Errorf("aplicar script nftables na reversão: %w", err))
	}

	// 4. Limpar a janela
	if err := s.db.ClearPendingChange(); err != nil {
		return revertFailed(fmt.Errorf("limpar janela de confirmação: %w", err))
	}
	s.clearWindowMemory(p.ID)

	// 5. Persist, snapshot e alertas
	_ = s.nft.Persist(ctx)
	s.saveNftSnapshot(ctx)
	s.lastRevert = &revertRecord{summary: p.Summary, reason: reason, at: s.now()}

	slog.Warn("reversão v2 concluída: a configuração anterior está de volta no banco e no firewall vivo",
		"resumo", p.Summary, "aplicada_por", p.AppliedBy, "motivo", reason)

	if alert && s.alerter != nil {
		detail := fmt.Sprintf("A alteração %q, aplicada por %s, foi desfeita automaticamente porque %s. O estado anterior do firewall foi restaurado.",
			p.Summary, p.AppliedBy, reason)
		if err := s.alerter.FirewallChangeReverted(detail); err != nil {
			slog.Error("não foi possível registrar o alerta da reversão automática", "err", err)
		}
	}

	_ = s.db.CreateAuditLog(&storage.AuditLog{
		User:     "linkguard",
		Action:   "fw.reverter",
		Resource: "pending:" + p.ID,
		Details:  reason,
	})

	return nil
}
