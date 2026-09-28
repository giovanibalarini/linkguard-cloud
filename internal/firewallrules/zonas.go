package firewallrules

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
//
// Nunca falha por causa do CONTEÚDO da configuração: com um alias inválido, ou
// uma configuração que não renderiza, responde com o que dá para saber e lista
// o motivo em Problemas. É esta resposta que o painel usa para mostrar o que
// está errado e travar o Aplicar; se ela caísse, o operador perderia a tela
// justamente quando mais precisa dela.
func (s *Service) Pendencias(ctx context.Context) (Pendencias, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := Pendencias{Mudancas: []fwmodel.Mudanca{}, Problemas: []fwmodel.Problema{}}
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

	out.Problemas = append(out.Problemas, fwmodel.Validar(emEdicao, s.pessoasUserIDs())...)

	cAtual := fwmodel.Canonico(aplicada)
	cNovo := fwmodel.Canonico(emEdicao)
	out.Pendente = !bytes.Equal(cAtual, cNovo)
	out.Mudancas = fwmodel.Mudancas(aplicada, emEdicao)
	if out.Mudancas == nil {
		out.Mudancas = []fwmodel.Mudanca{}
	}
	// Sem o render não há como saber se o acesso à caixa muda; na dúvida, a janela.
	out.PrecisaJanela = out.Pendente

	ins, err := s.insumos(ctx)
	if err != nil {
		return out, fmt.Errorf("ler insumos: %w", err)
	}

	novo, err := nftables.RenderZonas(emEdicao, ins)
	if err != nil {
		if !fwmodel.TemErro(out.Problemas) {
			out.Problemas = append(out.Problemas, problemaDeRender("fwz.problema.renderFalhou", "erro", err))
		}
		return out, nil
	}
	atual, err := nftables.RenderZonas(aplicada, ins)
	if err != nil {
		slog.Warn("a configuração aplicada não renderiza mais com os insumos de hoje", "err", err)
		out.Problemas = append(out.Problemas, problemaDeRender("fwz.problema.aplicadaNaoRenderiza", "aviso", err))
		return out, nil
	}

	out.DiffNft = fwmodel.DiffLinhas(atual.Script, novo.Script)
	out.PrecisaJanela = novo.HashEntrada != atual.HashEntrada

	return out, nil
}

// problemaDeRender traduz a recusa do renderizador em um problema que o painel
// sabe mostrar. O texto vem do próprio renderizador e só cita a configuração,
// nunca caminho ou saída de comando.
func problemaDeRender(chave, severidade string, err error) fwmodel.Problema {
	return fwmodel.Problema{
		Severidade: severidade,
		Onde:       "geral",
		Chave:      chave,
		Vars:       map[string]string{"detalhe": err.Error()},
	}
}

// erroDeValidacao é o GuardError de uma configuração que não pode seguir,
// com os problemas anexados para o painel traduzir.
func erroDeValidacao(prefixo string, problemas []fwmodel.Problema) *GuardError {
	partes := make([]string, 0, len(problemas))
	for _, p := range problemas {
		partes = append(partes, fmt.Sprintf("%s: %s", p.Onde, p.Chave))
	}
	msg := strings.Join(partes, "; ")
	if prefixo != "" {
		msg = prefixo + ": " + msg
	}
	return &GuardError{Stage: StageValidate, Message: msg, Err: errors.New(msg), Problemas: problemas}
}

// erroDaEscrita classifica o que o repositório devolveu ao escrever. As recusas
// que ele sabe nomear (o objeto não existe, está em uso, o nome ou o
// identificador já é de outro, o banco não aceita o valor) são do PEDIDO e
// viram 404, 409 ou 400. Qualquer outra coisa é falha do servidor: a causa
// técnica fica em Err, para o log, e o operador lê uma frase que não cita o
// banco.
func erroDaEscrita(err error) *GuardError {
	var e *storage.ErroFW
	if !errors.As(err, &e) {
		return &GuardError{Stage: StageWrite, Message: "gravar a mudança na configuração em edição", Err: err}
	}
	switch e.Tipo {
	case storage.FWNaoEncontrado:
		return &GuardError{Stage: StageNotFound, Message: e.Msg, Err: err}
	case storage.FWEmUso:
		return &GuardError{Stage: StageInUse, Message: e.Objeto + " em uso", Err: err, Usos: e.Usos}
	case storage.FWConflito:
		if e.Campo == "nome" {
			g := erroDeValidacao("", []fwmodel.Problema{{
				Severidade: "erro",
				Onde:       e.Objeto + ":" + e.ID,
				Chave:      "fwz.problema." + e.Objeto + "NomeDuplicado",
				Vars:       map[string]string{"nome": e.Nome, "outro_id": e.Outro},
			}})
			g.Err = err
			return g
		}
		return &GuardError{Stage: StageValidate, Message: e.Msg, Err: err}
	case storage.FWEntradaInvalida:
		return &GuardError{Stage: StageValidate, Message: e.Msg, Err: err}
	}
	return &GuardError{Stage: StageWrite, Message: "gravar a mudança na configuração em edição", Err: err}
}

// EditarConfigValidando é o portão único para qualquer escrita na configuração
// em edição. Recusa com 409 (StageLocked) enquanto houver uma janela de
// confirmação aberta e, além disso, recusa — e desfaz — a escrita que deixaria
// a configuração inválida.
//
// A escrita roda, a configuração é relida e comparada com a de antes
// (fwmodel.ProblemasDaMudanca): um erro que não existia, ou um erro em algum
// dos objetos de `onde` ("regra:<id>", "alias:<id>"…), desfaz tudo e volta em
// GuardError.Problemas. Validar escrevendo e relendo, em vez de montar o
// objeto em memória, dá o mesmo veredito do Aplicar — que valida o que está no
// banco — sem uma segunda cópia das regras de "o que é um objeto válido".
//
// Um erro que já estava lá e não é dos objetos tocados não tranca a edição:
// senão a única saída de uma configuração quebrada seria o Descartar.
func (s *Service) EditarConfigValidando(ctx context.Context, por string, escrever func(db *storage.DB) error, onde ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.guardWindowOpen(); err != nil {
		return err
	}

	antes, err := s.db.CarregarConfigEmEdicao()
	if err != nil {
		return &GuardError{Stage: StageWrite, Message: "carregar a configuração em edição", Err: err}
	}
	if err := escrever(s.db); err != nil {
		return erroDaEscrita(err)
	}
	depois, err := s.db.CarregarConfigEmEdicao()
	if err != nil {
		return &GuardError{Stage: StageWrite, Message: "reler a configuração em edição", Err: err}
	}

	problemas := fwmodel.ProblemasDaMudanca(antes, depois, s.pessoasUserIDs(), onde...)
	if len(problemas) == 0 {
		return nil
	}

	if err := s.db.SubstituirConfigEmEdicao(antes); err != nil {
		slog.Error("a escrita recusada não pôde ser desfeita", "err", err)
		return &GuardError{
			Stage:     StageWrite,
			Message:   "a mudança foi recusada, mas não foi possível desfazê-la: confira a configuração em edição",
			Err:       err,
			Problemas: problemas,
		}
	}
	return erroDeValidacao("a mudança deixaria a configuração do firewall inválida", problemas)
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

	if problemas := fwmodel.Validar(emEdicao, s.pessoasUserIDs()); fwmodel.TemErro(problemas) {
		var erros []fwmodel.Problema
		for _, p := range problemas {
			if p.Severidade == "erro" {
				erros = append(erros, p)
			}
		}
		return nil, erroDeValidacao("", erros)
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
		return erroDaEscrita(fmt.Errorf("carregar revisão %s: %w", id, err))
	}

	if err := s.db.SubstituirConfigEmEdicao(rev); err != nil {
		return erroDaEscrita(fmt.Errorf("substituir config em edição pela revisão %s: %w", id, err))
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

	var linhas []nftables.Linha
	ruleset, err := nftables.RenderZonas(emEdicao, ins)
	if err != nil {
		// A lista de regras é a tela em que o operador conserta o que está
		// quebrado; se ela caísse junto com a configuração, não haveria por
		// onde consertar. Sem o render, mostra as regras do admin em ordem.
		slog.Warn("a configuração em edição não renderiza; a lista mostra só as regras do admin", "zona", zona, "err", err)
		linhas = nftables.LinhasSemRender(emEdicao, zona)
	} else {
		linhas = ruleset.Linhas[zona]
	}
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
//
// Só os problemas da própria regra contam, e o nft dela sai de um render
// mínimo (a regra, o que ela referencia e os ajustes): a prévia não pode cair
// por causa de um alias ruim que a regra nem usa.
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

	pessoas := make([]string, 0, len(ins.Pessoas))
	for _, p := range ins.Pessoas {
		pessoas = append(pessoas, p.UserID)
	}

	// A regra entra na configuração (ou toma o lugar da que tem o mesmo ID)
	// para a validação enxergar os aliases e agendamentos como o Aplicar veria.
	testCfg := emEdicao
	testCfg.Regras = make([]fwmodel.Regra, 0, len(emEdicao.Regras)+1)
	substituiu := false
	for _, reg := range emEdicao.Regras {
		if reg.ID == r.ID {
			reg = r
			substituiu = true
		}
		testCfg.Regras = append(testCfg.Regras, reg)
	}
	if !substituiu {
		testCfg.Regras = append(testCfg.Regras, r)
	}

	problemas := []fwmodel.Problema{}
	for _, p := range fwmodel.Validar(testCfg, pessoas) {
		if p.Onde == "regra:"+r.ID {
			problemas = append(problemas, p)
		}
	}
	if fwmodel.TemErro(problemas) {
		return []nftables.LinhaNft{}, problemas, nil
	}

	ruleset, err := nftables.RenderZonas(configMinimaDaRegra(emEdicao, r), ins)
	if err != nil {
		problemas = append(problemas, fwmodel.Problema{
			Severidade: "erro",
			Onde:       "regra:" + r.ID,
			Chave:      "fwz.problema.renderFalhou",
			Vars:       map[string]string{"detalhe": err.Error()},
		})
		return []nftables.LinhaNft{}, problemas, nil
	}

	nft := []nftables.LinhaNft{}
	for _, linha := range ruleset.Linhas[r.Zona] {
		if linha.Chave == "r:"+r.ID {
			nft = linha.Nft
			break
		}
	}
	return nft, problemas, nil
}

// configMinimaDaRegra é a menor configuração que renderiza a regra: ela mesma
// (ativa, senão não geraria nft), os aliases e o agendamento que referencia e
// os ajustes reais.
func configMinimaDaRegra(c fwmodel.Config, r fwmodel.Regra) fwmodel.Config {
	usados := map[string]bool{}
	if r.Origem.Tipo == fwmodel.PontaAlias {
		usados[r.Origem.Valor] = true
	}
	if r.Destino.Tipo == fwmodel.PontaAlias {
		usados[r.Destino.Valor] = true
	}
	if r.PortaDestino.Tipo == fwmodel.PortaAlias {
		usados[r.PortaDestino.Valor] = true
	}

	cfg := fwmodel.Config{Formato: c.Formato, Ajustes: c.Ajustes}
	for _, a := range c.Aliases {
		if usados[a.ID] {
			cfg.Aliases = append(cfg.Aliases, a)
		}
	}
	for _, ag := range c.Agendamentos {
		if r.AgendamentoID != "" && ag.ID == r.AgendamentoID {
			cfg.Agendamentos = append(cfg.Agendamentos, ag)
		}
	}
	r.Ativa = true
	cfg.Regras = []fwmodel.Regra{r}
	return cfg
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
