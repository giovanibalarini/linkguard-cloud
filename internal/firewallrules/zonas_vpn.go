package firewallrules

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"

	"github.com/giovanibalarini/linkguard-cloud/internal/fwmodel"
	"github.com/giovanibalarini/linkguard-cloud/internal/nftables"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

// baseDaMudanca é o que se sabe do firewall ANTES de uma mudança da VPN: a
// configuração aplicada, o ruleset que ela gera com os insumos de hoje e o
// snapshot que a janela de confirmação guardaria. Cada parte falha por conta
// própria, porque quem decide o que fazer com o que ficou faltando é a
// mudança — e não pode confundir "não deu para ler" com "não há".
type baseDaMudanca struct {
	aplicada    fwmodel.Config
	temAplicada bool              // a aplicada foi lida (ou é a de fábrica)
	atual       *nftables.Ruleset // o que a aplicada renderiza hoje; nil se não renderiza ou se a leitura falhou
	quebrada    bool              // a aplicada não renderiza mais: não há estado anterior a que uma janela possa voltar
	snapshot    string            // o que a janela guardaria; "" se não deu para montar
	falha       error             // por que a base ficou incompleta (banco, insumos, perfis); nil se a aplicada só está quebrada
}

// baseAntesDaMudanca lê a base em etapas e devolve o que conseguiu.
func (s *Service) baseAntesDaMudanca(ctx context.Context) baseDaMudanca {
	var b baseDaMudanca

	aplicada, existe, err := s.db.CarregarConfigAplicada()
	if err != nil {
		b.falha = err
		return b
	}
	if !existe {
		aplicada = fwmodel.Config{Formato: 1, Ajustes: fwmodel.AjustesPadrao()}
	}
	b.aplicada, b.temAplicada = aplicada, true

	ins, err := s.insumos(ctx)
	if err != nil {
		b.falha = err
		return b
	}
	atual, err := nftables.RenderZonas(aplicada, ins)
	if err != nil {
		slog.Warn("a configuração aplicada não renderiza com os insumos de hoje; a mudança da VPN segue sem janela de confirmação", "err", err)
		b.quebrada = true
		return b
	}
	b.atual = &atual

	perfis, err := s.perfisVPN()
	if err != nil {
		b.falha = err
		return b
	}
	snap, err := json.Marshal(snapshotV2{Formato: 2, Config: aplicada, PerfisVPN: perfis})
	if err != nil {
		b.falha = err
		return b
	}
	b.snapshot = string(snap)
	return b
}

// precisaJanela diz se o ruleset novo mexe no acesso à caixa a ponto de exigir
// a janela de confirmação. Sem a base para comparar, na dúvida, sim; com a
// aplicada quebrada, não: não há estado anterior para onde reverter, e recusar
// seria trancar toda mudança da VPN — inclusive a revogação — por causa de
// uma regra velha.
func (b baseDaMudanca) precisaJanela(novo nftables.Ruleset) bool {
	switch {
	case b.quebrada:
		return false
	case b.atual == nil:
		return true
	}
	return novo.HashEntrada != b.atual.HashEntrada
}

// gravadaComoEtapa é a etapa de uma falha quando a escrita NÃO pode ser
// desfeita. O pré-voo e a trava falam de um pedido que foi recusado antes de
// mudar algo; depois de uma escrita que fica, o que se pode dizer é que o
// firewall não foi reconciliado.
func gravadaComoEtapa(etapa Stage) Stage {
	switch etapa {
	case StagePreflight:
		return StageReconcile
	case StageLocked:
		return StageWindow
	}
	return etapa
}

// AplicarMudancaVPN aplica alterações no WireGuard (perfis, usuários) imediatamente (§2.8, decisão fixa 3).
//
// escrever grava a mudança (e reconcilia o WireGuard, se é o caso); desfazer é
// a volta dela. Quando desfazer é nil a mudança NÃO TEM VOLTA — revogar um
// acesso, apagar um usuário, girar uma chave: voltar atrás ressuscitaria
// justamente o que o operador acabou de tirar. Nesse caso a escrita fica, e uma
// falha depois dela vira um GuardError com Gravada=true, para quem responde ao
// operador dizer a verdade em vez de "nada foi alterado".
//
// Um erro de escrever volta como veio (não é GuardError): quem o produziu sabe
// classificá-lo, e desfazer não roda — a escrita é responsável pela própria
// atomicidade.
//
// O nft -f é tudo-ou-nada, então quando o firewall recusa o ruleset o kernel
// segue como estava e não há o que reaplicar: só a janela (se armada) é
// descartada e, se a mudança tem volta, desfeita.
func (s *Service) AplicarMudancaVPN(ctx context.Context, por, resumo string,
	escrever func() error, desfazer func() error) (*Applied, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.guardWindowOpen(); err != nil {
		return nil, err
	}

	reversivel := desfazer != nil
	base := s.baseAntesDaMudanca(ctx)
	if reversivel && base.falha != nil {
		// Sem a base não se sabe se a mudança mexe no acesso à caixa nem o que
		// a janela restauraria; a escrita ainda não aconteceu, recusar é de graça.
		return nil, &GuardError{
			Stage:   StagePreflight,
			Message: "não foi possível ler o estado atual do firewall; nada foi alterado",
			Err:     base.falha,
		}
	}

	if escrever != nil {
		if err := escrever(); err != nil {
			return nil, err
		}
	}

	// falha encerra a mudança na etapa dada. Com volta, desfaz — e se desfazer
	// também falha o estado pode estar pela metade, e a frase manda conferir.
	// Sem volta, a escrita fica, e a frase diz isso.
	falha := func(etapa Stage, oQueFalhou string, causa error) (*Applied, error) {
		if !reversivel {
			return nil, &GuardError{
				Stage:   gravadaComoEtapa(etapa),
				Message: oQueFalhou + "; a mudança ficou gravada, mas o firewall não foi reconciliado",
				Err:     causa,
				Gravada: true,
			}
		}
		if errDesfazer := desfazer(); errDesfazer != nil {
			return nil, &GuardError{
				Stage:   StageStuck,
				Message: oQueFalhou + ", e a mudança da VPN não pôde ser desfeita: confira a VPN e o firewall",
				Err:     errors.Join(causa, errDesfazer),
				Gravada: true,
			}
		}
		return nil, &GuardError{Stage: etapa, Message: oQueFalhou + "; nada foi alterado", Err: causa}
	}

	if !base.temAplicada {
		return falha(StagePreflight, "não foi possível ler a configuração aplicada do firewall", base.falha)
	}
	insumosNovos, err := s.insumos(ctx)
	if err != nil {
		return falha(StagePreflight, "não foi possível ler os dados da máquina para montar o firewall", err)
	}
	// Renderiza a configuração aplicada com os insumos novos: é o que a VPN
	// muda (peers, portas, endereços); as regras do admin não mudaram.
	novo, err := nftables.RenderZonas(base.aplicada, insumosNovos)
	if err != nil {
		return falha(StagePreflight, "o firewall não pôde ser montado com o estado novo da VPN", err)
	}
	if err := s.nft.TestarScript(ctx, novo.Script); err != nil {
		return falha(StagePreflight, "o nftables recusou as regras novas na verificação", err)
	}

	var windowID string
	var pendingObj *storage.PendingChange
	if base.precisaJanela(novo) {
		if base.snapshot == "" {
			return falha(StageWindow, "não foi possível guardar o estado anterior para a janela de confirmação", base.falha)
		}
		id, err := s.openWindowLocked(base.snapshot, por, resumo)
		if err != nil {
			if IsWindowConflict(err) {
				return falha(StageLocked, err.Error(), err)
			}
			return falha(StageWindow, "não foi possível armar a janela de confirmação", err)
		}
		windowID = id
		pendingObj = s.pendenteDaJanela()
	}

	if err := s.nft.AplicarScript(ctx, novo.Script); err != nil {
		s.descartarJanela(windowID)
		return falha(StageReconcile, "o nftables recusou as regras novas", err)
	}

	_ = s.db.CreateAuditLog(&storage.AuditLog{
		User:     por,
		Action:   "vpn.perfil.aplicar",
		Resource: "vpn",
		Details:  resumo,
	})
	_ = s.nft.Persist(ctx)
	s.saveNftSnapshot(ctx)

	return &Applied{WindowID: windowID, Pending: pendingObj}, nil
}

// perfisVPN é o estado dos perfis dos peers que o snapshot de uma janela
// guarda. Um erro aqui nunca vira "sem perfis": a reversão devolveria todo
// mundo a "restrito, sem aliases".
func (s *Service) perfisVPN() ([]perfilVPN, error) {
	peers, err := s.db.ListWireGuardPeers()
	if err != nil {
		return nil, err
	}
	var perfis []perfilVPN
	for _, peer := range peers {
		perfis = append(perfis, perfilVPN{
			UserID:            peer.UserID,
			AccessMode:        peer.AccessMode,
			AllowedHostGroups: peer.AllowedHostGroups,
			AllowedPorts:      peer.AllowedPorts,
		})
	}
	return perfis, nil
}
