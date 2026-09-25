package firewallrules

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/giovanibalarini/linkguard-cloud/internal/fwmodel"
	"github.com/giovanibalarini/linkguard-cloud/internal/nftables"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

// Pendencias descreve a diferença entre a configuração em edição e a aplicada (§2.8).
type Pendencias struct {
	Pendente      bool               `json:"pendente"`
	Mudancas      []fwmodel.Mudanca  `json:"mudancas"`
	DiffNft       string             `json:"diff_nft"` // fwmodel.DiffLinhas(atual.Script, novo.Script)
	PrecisaJanela bool               `json:"precisa_janela"`
	Problemas     []fwmodel.Problema `json:"problemas"`
}

// EmEdicao devolve a configuração de firewall atualmente sob edição no banco.
func (s *Service) EmEdicao() (fwmodel.Config, error) {
	return s.db.CarregarConfigEmEdicao()
}

// Aplicada devolve a configuração de firewall atualmente aplicada no kernel e seu status de existência.
func (s *Service) Aplicada() (fwmodel.Config, bool, error) {
	return s.db.CarregarConfigAplicada()
}

// pessoasUserIDs devolve os IDs dos usuários cadastrados na VPN para fins de validação de regras.
func (s *Service) pessoasUserIDs() []string {
	var userIDs []string
	if s.db != nil {
		if peers, err := s.db.ListWireGuardPeers(); err == nil {
			for _, p := range peers {
				userIDs = append(userIDs, p.UserID)
			}
		}
	}
	return userIDs
}

// Pendencias inspeciona se há alterações não aplicadas entre o rascunho em edição e o que está ativo.
func (s *Service) Pendencias(ctx context.Context) (Pendencias, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out Pendencias
	emEdicao, err := s.db.CarregarConfigEmEdicao()
	if err != nil {
		return out, fmt.Errorf("carregar config em edição: %w", err)
	}

	aplicada, existe, err := s.db.CarregarConfigAplicada()
	if err != nil {
		return out, fmt.Errorf("carregar config aplicada: %w", err)
	}
	if !existe {
		aplicada = fwmodel.Config{Formato: 1, Ajustes: fwmodel.AjustesPadrao()}
	}

	out.Problemas = fwmodel.Validar(emEdicao, s.pessoasUserIDs())
	if out.Problemas == nil {
		out.Problemas = []fwmodel.Problema{}
	}

	cAtual := fwmodel.Canonico(aplicada)
	cNovo := fwmodel.Canonico(emEdicao)
	out.Pendente = !bytes.Equal(cAtual, cNovo)
	out.Mudancas = fwmodel.Mudancas(aplicada, emEdicao)
	if out.Mudancas == nil {
		out.Mudancas = []fwmodel.Mudanca{}
	}

	ins, err := s.insumos(ctx)
	if err != nil {
		return out, fmt.Errorf("ler insumos: %w", err)
	}

	atual, err := nftables.RenderZonas(aplicada, ins)
	if err != nil {
		return out, fmt.Errorf("renderizar configuração aplicada: %w", err)
	}
	novo, err := nftables.RenderZonas(emEdicao, ins)
	if err != nil {
		return out, fmt.Errorf("renderizar configuração em edição: %w", err)
	}

	out.DiffNft = fwmodel.DiffLinhas(atual.Script, novo.Script)
	out.PrecisaJanela = novo.HashEntrada != atual.HashEntrada

	return out, nil
}

// EditarConfig é o portão único para qualquer escrita na configuração em edição.
// Recusa com 409 (StageLocked) caso haja uma janela de confirmação aberta.
func (s *Service) EditarConfig(ctx context.Context, por string, f func(db *storage.DB) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.guardWindowOpen(); err != nil {
		return err
	}
	return f(s.db)
}

// Aplicar executa os 12 passos da aplicação segura do firewall por zonas (§2.8).
func (s *Service) Aplicar(ctx context.Context, por string) (appliedOut *Applied, errOut error) {
	s.mu.Lock()
	defer func() {
		if errOut != nil {
			s.ultimoErro = errOut.Error()
		} else {
			s.ultimoErro = ""
		}
		s.mu.Unlock()
	}()

	// 1 & 2. Janela aberta -> 409 (StageLocked)
	if err := s.guardWindowOpen(); err != nil {
		return nil, err
	}

	// 3. Carrega em edição e aplicada; validação
	emEdicao, err := s.db.CarregarConfigEmEdicao()
	if err != nil {
		return nil, &GuardError{
			Stage:   StageWrite,
			Message: fmt.Sprintf("carregar config em edição: %v", err),
			Err:     err,
		}
	}

	aplicada, existe, err := s.db.CarregarConfigAplicada()
	if err != nil {
		return nil, &GuardError{
			Stage:   StageWrite,
			Message: fmt.Sprintf("carregar config aplicada: %v", err),
			Err:     err,
		}
	}
	if !existe {
		aplicada = fwmodel.Config{Formato: 1, Ajustes: fwmodel.AjustesPadrao()}
	}

	// Se não há diferenças canônicas, não faz nada
	cAtual := fwmodel.Canonico(aplicada)
	cNovo := fwmodel.Canonico(emEdicao)
	if bytes.Equal(cAtual, cNovo) {
		return &Applied{}, nil
	}

	problemas := fwmodel.Validar(emEdicao, s.pessoasUserIDs())
	if fwmodel.TemErro(problemas) {
		var erros []string
		for _, p := range problemas {
			if p.Severidade == "erro" {
				erros = append(erros, fmt.Sprintf("%s: %s", p.Onde, p.Chave))
			}
		}
		msg := strings.Join(erros, "; ")
		return nil, &GuardError{
			Stage:   StageValidate,
			Message: msg,
			Err:     fmt.Errorf("%s", msg),
		}
	}

	// 4. Lê insumos
	ins, err := s.insumos(ctx)
	if err != nil {
		return nil, &GuardError{
			Stage:   StagePreflight,
			Message: fmt.Sprintf("obter insumos do firewall: %v", err),
			Err:     err,
		}
	}

	// 5. RenderZonas
	novo, err := nftables.RenderZonas(emEdicao, ins)
	if err != nil {
		return nil, &GuardError{
			Stage:   StagePreflight,
			Message: fmt.Sprintf("renderizar configuração nova: %v", err),
			Err:     err,
		}
	}
	atual, err := nftables.RenderZonas(aplicada, ins)
	if err != nil {
		return nil, &GuardError{
			Stage:   StagePreflight,
			Message: fmt.Sprintf("renderizar configuração atual: %v", err),
			Err:     err,
		}
	}

	// 6. Pré-voo nft -c -f
	if err := s.nft.TestarScript(ctx, novo.Script); err != nil {
		return nil, &GuardError{
			Stage:   StagePreflight,
			Message: fmt.Sprintf("o nftables recusou o script: %v", err),
			Err:     err,
		}
	}

	// 7. Janela de confirmação caso o acesso à caixa tenha mudado
	mudancas := fwmodel.Mudancas(aplicada, emEdicao)
	resumo := resumoMudancas(mudancas)

	var windowID string
	var pendingObj *storage.PendingChange
	if novo.HashEntrada != atual.HashEntrada {
		var perfis []perfilVPN
		if peers, err := s.db.ListWireGuardPeers(); err == nil {
			for _, peer := range peers {
				perfis = append(perfis, perfilVPN{
					UserID:            peer.UserID,
					AccessMode:        peer.AccessMode,
					AllowedHostGroups: peer.AllowedHostGroups,
					AllowedPorts:      peer.AllowedPorts,
				})
			}
		}
		snap := snapshotV2{
			Formato:   2,
			Config:    aplicada,
			PerfisVPN: perfis,
		}
		snapBytes, err := json.Marshal(snap)
		if err != nil {
			return nil, fmt.Errorf("serializar snapshot v2: %w", err)
		}

		id, err := s.openWindowLocked(string(snapBytes), por, resumo)
		if err != nil {
			if IsWindowConflict(err) {
				return nil, &GuardError{Stage: StageLocked, Message: err.Error(), Err: err}
			}
			return nil, &GuardError{
				Stage:   StageWindow,
				Message: fmt.Sprintf("abrir janela de confirmação: %v", err),
				Err:     err,
			}
		}
		windowID = id
		pendingObj, _ = s.db.GetPendingChange()
	}

	// 8. Aplica no kernel de forma atômica (nft -f)
	if err := s.nft.AplicarScript(ctx, novo.Script); err != nil {
		if windowID != "" {
			_ = s.db.ClearPendingChange()
			s.clearWindowMemory(windowID)
		}
		return nil, &GuardError{
			Stage:   StageWrite,
			Message: fmt.Sprintf("falha ao aplicar ruleset no nftables: %v", err),
			Err:     err,
		}
	}

	// 9. Numa transação: salva aplicada e histórico de revisão
	if err := s.db.SalvarAplicadaERevisao(emEdicao, por, resumo, "aplicar", s.now()); err != nil {
		// Falha na gravação: desfaz no kernel reaplicando o script anterior
		_ = s.nft.AplicarScript(ctx, atual.Script)
		if windowID != "" {
			_ = s.db.ClearPendingChange()
			s.clearWindowMemory(windowID)
		}
		return nil, &GuardError{
			Stage:   StageWrite,
			Message: fmt.Sprintf("falha ao gravar configuração aplicada no banco: %v", err),
			Err:     err,
		}
	}

	// 10. Para cada alias cujos itens mudaram, marca rotas do WireGuard como desatualizadas
	aliasMapAntes := make(map[string]fwmodel.Alias, len(aplicada.Aliases))
	for _, a := range aplicada.Aliases {
		aliasMapAntes[a.ID] = a
	}
	aliasMapDepois := make(map[string]fwmodel.Alias, len(emEdicao.Aliases))
	for _, a := range emEdicao.Aliases {
		aliasMapDepois[a.ID] = a
		ant, existe := aliasMapAntes[a.ID]
		if !existe || !equalStringSlices(ant.Itens, a.Itens) {
			_ = s.db.MarkWireGuardRoutesChangedByHostGroup(a.ID)
		}
	}
	for _, a := range aplicada.Aliases {
		if _, existe := aliasMapDepois[a.ID]; !existe {
			_ = s.db.MarkWireGuardRoutesChangedByHostGroup(a.ID)
		}
	}

	// 11. Auditoria
	_ = s.db.CreateAuditLog(&storage.AuditLog{
		User:     por,
		Action:   "fw.aplicar",
		Resource: "fw",
		Details:  resumo,
	})

	// 12. Persistência e snapshot
	_ = s.nft.Persist(ctx)
	s.saveNftSnapshot(ctx)

	return &Applied{
		WindowID: windowID,
		Pending:  pendingObj,
		Summary:  resumo,
	}, nil
}

// Descartar descarta as alterações na configuração em edição, restaurando o que está aplicado.
func (s *Service) Descartar(ctx context.Context, por string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.guardWindowOpen(); err != nil {
		return err
	}

	aplicada, existe, err := s.db.CarregarConfigAplicada()
	if err != nil {
		return &GuardError{Stage: StageWrite, Err: err, Message: err.Error()}
	}
	if !existe {
		aplicada = fwmodel.Config{Formato: 1, Ajustes: fwmodel.AjustesPadrao()}
	}

	if err := s.db.SubstituirConfigEmEdicao(aplicada); err != nil {
		return &GuardError{
			Stage:   StageWrite,
			Message: fmt.Sprintf("falha ao descartar alterações em edição: %v", err),
			Err:     err,
		}
	}

	_ = s.db.CreateAuditLog(&storage.AuditLog{
		User:     por,
		Action:   "fw.descartar",
		Resource: "fw",
		Details:  "descartou alterações em edição e restaurou a configuração aplicada",
	})
	return nil
}

// RestaurarRevisao restaura uma revisão anterior para a configuração em edição (fica pendente para aplicar).
func (s *Service) RestaurarRevisao(ctx context.Context, id, por string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.guardWindowOpen(); err != nil {
		return err
	}

	rev, err := s.db.CarregarRevisao(id)
	if err != nil {
		return fmt.Errorf("carregar revisão %s: %w", id, err)
	}

	if err := s.db.SubstituirConfigEmEdicao(rev); err != nil {
		return fmt.Errorf("substituir config em edição pela revisão %s: %w", id, err)
	}

	_ = s.db.CreateAuditLog(&storage.AuditLog{
		User:     por,
		Action:   "fw.restaurar_revisao",
		Resource: "revisao:" + id,
		Details:  fmt.Sprintf("revisão %s restaurada para edição", id),
	})
	return nil
}

// AplicarMudancaVPN aplica alterações no WireGuard (perfis, usuários) imediatamente (§2.8, decisão fixa 3).
func (s *Service) AplicarMudancaVPN(ctx context.Context, por, resumo string,
	escrever func() error, desfazer func() error) (*Applied, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.guardWindowOpen(); err != nil {
		return nil, err
	}

	aplicada, existe, err := s.db.CarregarConfigAplicada()
	if err != nil {
		return nil, &GuardError{Stage: StageWrite, Err: err, Message: err.Error()}
	}
	if !existe {
		aplicada = fwmodel.Config{Formato: 1, Ajustes: fwmodel.AjustesPadrao()}
	}

	insumosAntes, err := s.insumos(ctx)
	if err != nil {
		return nil, &GuardError{Stage: StagePreflight, Err: err, Message: err.Error()}
	}
	atual, err := nftables.RenderZonas(aplicada, insumosAntes)
	if err != nil {
		return nil, &GuardError{Stage: StagePreflight, Err: err, Message: err.Error()}
	}

	var perfisAntes []perfilVPN
	if peers, err := s.db.ListWireGuardPeers(); err == nil {
		for _, peer := range peers {
			perfisAntes = append(perfisAntes, perfilVPN{
				UserID:            peer.UserID,
				AccessMode:        peer.AccessMode,
				AllowedHostGroups: peer.AllowedHostGroups,
				AllowedPorts:      peer.AllowedPorts,
			})
		}
	}
	snap := snapshotV2{
		Formato:   2,
		Config:    aplicada,
		PerfisVPN: perfisAntes,
	}
	snapBytes, err := json.Marshal(snap)
	if err != nil {
		return nil, fmt.Errorf("serializar snapshot v2: %w", err)
	}

	// Executa a escrita solicitada (ex: persistência de novo peer ou perfil)
	if escrever != nil {
		if err := escrever(); err != nil {
			return nil, err
		}
	}

	insumosNovos, err := s.insumos(ctx)
	if err != nil {
		if desfazer != nil {
			_ = desfazer()
		}
		return nil, &GuardError{Stage: StagePreflight, Err: err, Message: err.Error()}
	}

	// Renderiza com a configuração aplicada + os insumos novos
	novo, err := nftables.RenderZonas(aplicada, insumosNovos)
	if err != nil {
		if desfazer != nil {
			_ = desfazer()
		}
		return nil, &GuardError{Stage: StagePreflight, Err: err, Message: err.Error()}
	}

	// Pré-voo com nft -c
	if err := s.nft.TestarScript(ctx, novo.Script); err != nil {
		if desfazer != nil {
			_ = desfazer()
		}
		return nil, &GuardError{
			Stage:   StagePreflight,
			Message: fmt.Sprintf("o nftables recusou o script: %v", err),
			Err:     err,
		}
	}

	var windowID string
	var pendingObj *storage.PendingChange
	if novo.HashEntrada != atual.HashEntrada {
		id, err := s.openWindowLocked(string(snapBytes), por, resumo)
		if err != nil {
			if desfazer != nil {
				_ = desfazer()
			}
			if IsWindowConflict(err) {
				return nil, &GuardError{Stage: StageLocked, Message: err.Error(), Err: err}
			}
			return nil, &GuardError{Stage: StageWindow, Message: err.Error(), Err: err}
		}
		windowID = id
		pendingObj, _ = s.db.GetPendingChange()
	}

	if err := s.nft.AplicarScript(ctx, novo.Script); err != nil {
		if desfazer != nil {
			_ = desfazer()
		}
		if windowID != "" {
			_ = s.db.ClearPendingChange()
			s.clearWindowMemory(windowID)
		}
		return nil, &GuardError{
			Stage:   StageWrite,
			Message: fmt.Sprintf("falha ao aplicar ruleset no nftables: %v", err),
			Err:     err,
		}
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

// RenderizarNoBoot renderiza e aplica o ruleset no arranque do sistema (§2.8, §4 T5).
// Se fw_aplicado estiver vazio, inicializa com o conteúdo de em edição (motivo: "conversao").
func (s *Service) RenderizarNoBoot(ctx context.Context) (errOut error) {
	s.mu.Lock()
	defer func() {
		if errOut != nil {
			s.ultimoErro = errOut.Error()
		} else {
			s.ultimoErro = ""
		}
		s.mu.Unlock()
	}()

	aplicada, existe, err := s.db.CarregarConfigAplicada()
	if err != nil {
		return fmt.Errorf("carregar config aplicada no boot: %w", err)
	}
	if !existe {
		emEdicao, err := s.db.CarregarConfigEmEdicao()
		if err != nil {
			return fmt.Errorf("carregar config em edição no boot: %w", err)
		}
		if err := s.db.SalvarAplicadaERevisao(emEdicao, "sistema", "aplicação inicial no boot", "conversao", s.now()); err != nil {
			return fmt.Errorf("salvar aplicada no boot: %w", err)
		}
		aplicada = emEdicao
	}

	ins, err := s.insumos(ctx)
	if err != nil {
		return fmt.Errorf("ler insumos no boot: %w", err)
	}

	ruleset, err := nftables.RenderZonas(aplicada, ins)
	if err != nil {
		slog.Error("falha ao renderizar script nftables no boot", "err", err)
		return err
	}
	if err := s.nft.TestarScript(ctx, ruleset.Script); err != nil {
		slog.Error("script nftables gerado no boot falhou na validação", "err", err)
		return err
	}

	if err := s.nft.AplicarScript(ctx, ruleset.Script); err != nil {
		slog.Error("falha ao aplicar script nftables no boot", "err", err)
		return err
	}

	_ = s.nft.Persist(ctx)
	s.saveNftSnapshot(ctx)
	return nil
}

// Linhas devolve as linhas compiladas da zona solicitada, com seus contadores agregados para exibição.
func (s *Service) Linhas(ctx context.Context, zona fwmodel.Zona) ([]nftables.Linha, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	emEdicao, err := s.db.CarregarConfigEmEdicao()
	if err != nil {
		return nil, fmt.Errorf("carregar config em edição: %w", err)
	}

	ins, err := s.insumos(ctx)
	if err != nil {
		return nil, fmt.Errorf("ler insumos: %w", err)
	}

	ruleset, err := nftables.RenderZonas(emEdicao, ins)
	if err != nil {
		return nil, fmt.Errorf("renderizar linhas: %w", err)
	}
	linhas := ruleset.Linhas[zona]
	if len(linhas) == 0 {
		return []nftables.Linha{}, nil
	}

	if s.nft != nil {
		contadores, err := s.nft.ContadoresPorChave(ctx)
		if err == nil && len(contadores) > 0 {
			for i := range linhas {
				if c, ok := contadores[linhas[i].Chave]; ok {
					linhas[i].Pacotes = c.Pacotes
					linhas[i].Bytes = c.Bytes
					linhas[i].Medido = c.Medido
				}
			}
		}
	}

	return linhas, nil
}

// RedesVCNExtrasAplicadas devolve as subredes adicionais da VCN configuradas na versão atualmente aplicada.
func (s *Service) RedesVCNExtrasAplicadas() []string {
	aplicada, existe, err := s.db.CarregarConfigAplicada()
	if err != nil || !existe {
		return nil
	}
	return aplicada.Ajustes.RedesVCNExtras
}

// PreviaRegra avalia a regra e devolve os problemas de validação e a representação nftables correspondente.
func (s *Service) PreviaRegra(ctx context.Context, r fwmodel.Regra) ([]nftables.LinhaNft, []fwmodel.Problema, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	emEdicao, err := s.db.CarregarConfigEmEdicao()
	if err != nil {
		return nil, nil, fmt.Errorf("carregar config em edição: %w", err)
	}

	ins, err := s.insumos(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("ler insumos: %w", err)
	}

	if r.ID == "" {
		r.ID = "previa"
	}

	// Lista de IDs de pessoas para validação
	pessoas := make([]string, 0, len(ins.Pessoas))
	for _, p := range ins.Pessoas {
		pessoas = append(pessoas, p.UserID)
	}

	// Cria uma cópia da configuração com a regra adicionada ou substituída
	testCfg := emEdicao
	substituiu := false
	for i, reg := range testCfg.Regras {
		if reg.ID == r.ID {
			testCfg.Regras[i] = r
			substituiu = true
			break
		}
	}
	if !substituiu {
		testCfg.Regras = append(testCfg.Regras, r)
	}

	todosProblemas := fwmodel.Validar(testCfg, pessoas)
	var problemas []fwmodel.Problema
	for _, p := range todosProblemas {
		if p.Onde == "regra:"+r.ID {
			problemas = append(problemas, p)
		}
	}
	if problemas == nil {
		problemas = []fwmodel.Problema{}
	}

	if fwmodel.TemErro(problemas) {
		return []nftables.LinhaNft{}, problemas, nil
	}

	// Força ativa para gerar os comandos nftables
	rAtiva := r
	rAtiva.Ativa = true
	for i, reg := range testCfg.Regras {
		if reg.ID == r.ID {
			testCfg.Regras[i] = rAtiva
			break
		}
	}

	ruleset, err := nftables.RenderZonas(testCfg, ins)
	if err != nil {
		return nil, problemas, err
	}

	var nft []nftables.LinhaNft
	for _, linha := range ruleset.Linhas[r.Zona] {
		if linha.Chave == "r:"+r.ID {
			nft = linha.Nft
			break
		}
	}
	if nft == nil {
		nft = []nftables.LinhaNft{}
	}

	return nft, problemas, nil
}

func resumoMudancas(mudancas []fwmodel.Mudanca) string {
	if len(mudancas) == 0 {
		return "nenhuma mudança"
	}
	partes := make([]string, 0, len(mudancas))
	for _, m := range mudancas {
		var desc string
		if m.Nome != "" {
			desc = fmt.Sprintf("%s %s %q", m.Objeto, m.Tipo, m.Nome)
		} else {
			desc = fmt.Sprintf("%s %s %s", m.Objeto, m.Tipo, m.ID)
		}
		partes = append(partes, desc)
	}
	return strings.Join(partes, "; ")
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
