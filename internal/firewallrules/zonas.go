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
// Uma leitura que falha é erro: tratar a lista como vazia acusaria toda regra
// de pessoa de apontar para alguém que não existe.
func (s *Service) pessoasUserIDs() ([]string, error) {
	var userIDs []string
	if s.db != nil {
		peers, err := s.db.ListWireGuardPeers()
		if err != nil {
			return nil, fmt.Errorf("listar peers da VPN: %w", err)
		}
		for _, p := range peers {
			userIDs = append(userIDs, p.UserID)
		}
	}
	return userIDs, nil
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

	pessoas, err := s.pessoasUserIDs()
	if err != nil {
		return out, err
	}
	out.Problemas = append(out.Problemas, fwmodel.Validar(emEdicao, pessoas)...)

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

	// Lida antes de escrever: se a lista falhar, nada foi tocado.
	pessoas, err := s.pessoasUserIDs()
	if err != nil {
		return &GuardError{Stage: StagePreflight, Message: "não foi possível ler a lista de pessoas da VPN; nada foi alterado", Err: err}
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

	problemas := fwmodel.ProblemasDaMudanca(antes, depois, pessoas, onde...)
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
//
// Toda falha volta como GuardError cuja Message é a frase que o operador lê:
// cita a configuração, nunca o banco nem a saída do nft. A causa técnica fica
// em Err, e o handler a manda para o log.
func (s *Service) Aplicar(ctx context.Context, por string) (appliedOut *Applied, errOut error) {
	s.mu.Lock()
	defer func() {
		// Recusar por janela aberta não é falha de aplicação: nada foi tentado.
		var g *GuardError
		if !errors.As(errOut, &g) || g.Stage != StageLocked {
			s.ultimoErro = mensagemDoErro(errOut)
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
		return nil, &GuardError{Stage: StageWrite, Message: "não foi possível ler a configuração em edição", Err: err}
	}

	aplicada, existe, err := s.db.CarregarConfigAplicada()
	if err != nil {
		return nil, &GuardError{Stage: StageWrite, Message: "não foi possível ler a configuração aplicada", Err: err}
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

	pessoas, err := s.pessoasUserIDs()
	if err != nil {
		return nil, &GuardError{Stage: StagePreflight, Message: "não foi possível ler a lista de pessoas da VPN; nada foi alterado", Err: err}
	}
	if problemas := fwmodel.Validar(emEdicao, pessoas); fwmodel.TemErro(problemas) {
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
			Message: "não foi possível ler os dados da máquina para montar o firewall; nada foi alterado",
			Err:     err,
		}
	}

	// 5. RenderZonas
	novo, err := nftables.RenderZonas(emEdicao, ins)
	if err != nil {
		return nil, &GuardError{
			Stage:     StagePreflight,
			Message:   "o firewall não pôde ser montado com esta configuração; nada foi alterado",
			Err:       err,
			Problemas: []fwmodel.Problema{problemaDeRender("fwz.problema.renderFalhou", "erro", err)},
		}
	}
	// A aplicada que deixou de renderizar (a pessoa de uma regra foi revogada,
	// uma rede saiu dos insumos) não pode trancar a saída: consertá-la É aplicar
	// a que está em edição. E sem um estado anterior que renderize não há para
	// onde a janela de confirmação reverter, então essa mudança entra sem ela.
	var atual *nftables.Ruleset
	if r, err := nftables.RenderZonas(aplicada, ins); err != nil {
		slog.Warn("a configuração aplicada não renderiza com os insumos de hoje; a nova entra sem janela de confirmação", "err", err)
	} else {
		atual = &r
	}

	// 6. Pré-voo nft -c -f
	if err := s.nft.TestarScript(ctx, novo.Script); err != nil {
		return nil, &GuardError{
			Stage:   StagePreflight,
			Message: "o nftables recusou as regras novas na verificação; nada foi alterado",
			Err:     err,
		}
	}

	// 7. Janela de confirmação caso o acesso à caixa tenha mudado
	mudancas := fwmodel.Mudancas(aplicada, emEdicao)
	resumo := resumoMudancas(mudancas)

	var windowID string
	var pendingObj *storage.PendingChange
	if atual != nil && novo.HashEntrada != atual.HashEntrada {
		// Os perfis dos peers são metade do que a reversão restaura: sem eles o
		// snapshot devolveria todo mundo a "restrito, sem aliases". Se não dá
		// para lê-los, nada é tocado.
		perfis, err := s.perfisVPN()
		if err != nil {
			return nil, &GuardError{
				Stage:   StagePreflight,
				Message: "não foi possível ler os perfis da VPN para guardar o estado anterior; nada foi alterado",
				Err:     err,
			}
		}
		snapBytes, err := json.Marshal(snapshotV2{Formato: 2, Config: aplicada, PerfisVPN: perfis})
		if err != nil {
			return nil, &GuardError{
				Stage:   StageWindow,
				Message: "não foi possível guardar o estado anterior para a janela de confirmação; nada foi alterado",
				Err:     err,
			}
		}

		id, err := s.openWindowLocked(string(snapBytes), por, resumo)
		if err != nil {
			if IsWindowConflict(err) {
				return nil, &GuardError{Stage: StageLocked, Message: err.Error(), Err: err}
			}
			return nil, &GuardError{
				Stage:   StageWindow,
				Message: "não foi possível armar a janela de confirmação; nada foi alterado",
				Err:     err,
			}
		}
		windowID = id
		pendingObj = s.pendenteDaJanela()
	}

	// 8. Aplica no kernel de forma atômica (nft -f). O nft -f é tudo-ou-nada:
	// recusado, o kernel segue como estava, e não há o que reaplicar.
	if err := s.nft.AplicarScript(ctx, novo.Script); err != nil {
		s.descartarJanela(windowID)
		return nil, &GuardError{
			Stage:   StageReconcile,
			Message: "o nftables recusou as regras novas; nada foi alterado",
			Err:     err,
		}
	}

	// 9. Numa transação: salva aplicada e histórico de revisão
	if err := s.db.SalvarAplicadaERevisao(emEdicao, por, resumo, "aplicar", s.now()); err != nil {
		s.descartarJanela(windowID)
		return nil, s.voltarKernelAposFalhaDeGravacao(ctx, atual, err)
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
			s.marcarRotasDesatualizadas(a.ID)
		}
	}
	for _, a := range aplicada.Aliases {
		if _, existe := aliasMapDepois[a.ID]; !existe {
			s.marcarRotasDesatualizadas(a.ID)
		}
	}

	// 11. Auditoria
	_ = s.db.CreateAuditLog(&storage.AuditLog{
		User:     por,
		Action:   "fw.aplicar",
		Resource: "firewall",
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

// voltarKernelAposFalhaDeGravacao trata o pior meio-termo do Aplicar: o nft -f
// já pôs as regras novas no kernel e o banco não guardou que elas são as
// aplicadas — o próximo boot renderizaria as antigas e a tela as mostraria
// como as em vigor. A saída é devolver o kernel ao que a aplicada renderiza.
// Sem um ruleset anterior que renderize, ou se o nft recusar a volta, o estado
// fica pela metade e a frase diz como concluir.
func (s *Service) voltarKernelAposFalhaDeGravacao(ctx context.Context, atual *nftables.Ruleset, causa error) *GuardError {
	const pelaMetade = "as regras novas já valem no firewall, mas não foi possível gravar isso no banco nem voltar atrás; aplique de novo para concluir"
	if atual == nil {
		return &GuardError{Stage: StageStuck, Message: pelaMetade, Err: causa}
	}
	if err := s.nft.AplicarScript(ctx, atual.Script); err != nil {
		return &GuardError{Stage: StageStuck, Message: pelaMetade, Err: errors.Join(causa, err)}
	}
	return &GuardError{
		Stage:   StageWrite,
		Message: "as regras novas não puderam ser gravadas no banco; o firewall voltou ao que era e nada foi alterado",
		Err:     causa,
	}
}

func (s *Service) marcarRotasDesatualizadas(aliasID string) {
	if err := s.db.MarkWireGuardRoutesChangedByHostGroup(aliasID); err != nil {
		slog.Warn("não foi possível marcar as rotas da VPN como desatualizadas", "alias", aliasID, "err", err)
	}
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
		return &GuardError{Stage: StageWrite, Message: "não foi possível ler a configuração aplicada", Err: err}
	}
	if !existe {
		aplicada = fwmodel.Config{Formato: 1, Ajustes: fwmodel.AjustesPadrao()}
	}

	if err := s.db.SubstituirConfigEmEdicao(aplicada); err != nil {
		return &GuardError{Stage: StageWrite, Message: "não foi possível descartar as alterações em edição", Err: err}
	}

	_ = s.db.CreateAuditLog(&storage.AuditLog{
		User:     por,
		Action:   "fw.descartar",
		Resource: "firewall",
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

// RenderizarNoBoot renderiza e aplica o ruleset no arranque do sistema (§2.8, §4 T5).
// Se fw_aplicado estiver vazio, inicializa com o conteúdo de em edição (motivo: "conversao").
//
// As falhas voltam como GuardError, no mesmo padrão do Aplicar: a frase é a
// que fica em UltimoErro (e vai para a tela); a causa técnica, em Err, para o log.
func (s *Service) RenderizarNoBoot(ctx context.Context) (errOut error) {
	s.mu.Lock()
	defer func() {
		s.ultimoErro = mensagemDoErro(errOut)
		s.mu.Unlock()
	}()

	aplicada, existe, err := s.db.CarregarConfigAplicada()
	if err != nil {
		return &GuardError{Stage: StageWrite, Message: "no boot, não foi possível ler a configuração aplicada", Err: err}
	}
	if !existe {
		emEdicao, err := s.db.CarregarConfigEmEdicao()
		if err != nil {
			return &GuardError{Stage: StageWrite, Message: "no boot, não foi possível ler a configuração em edição", Err: err}
		}
		if err := s.db.SalvarAplicadaERevisao(emEdicao, "sistema", "aplicação inicial no boot", "conversao", s.now()); err != nil {
			return &GuardError{Stage: StageWrite, Message: "no boot, não foi possível gravar a configuração aplicada inicial", Err: err}
		}
		aplicada = emEdicao
	}

	ins, err := s.insumos(ctx)
	if err != nil {
		return &GuardError{Stage: StagePreflight, Message: "no boot, não foi possível ler os dados da máquina para montar o firewall", Err: err}
	}

	ruleset, err := nftables.RenderZonas(aplicada, ins)
	if err != nil {
		slog.Error("falha ao renderizar script nftables no boot", "err", err)
		return &GuardError{Stage: StagePreflight, Message: "no boot, a configuração aplicada não pôde ser montada em regras do firewall", Err: err}
	}
	if err := s.nft.TestarScript(ctx, ruleset.Script); err != nil {
		slog.Error("script nftables gerado no boot falhou na validação", "err", err)
		return &GuardError{Stage: StagePreflight, Message: "no boot, o nftables recusou as regras geradas na verificação", Err: err}
	}

	if err := s.nft.AplicarScript(ctx, ruleset.Script); err != nil {
		slog.Error("falha ao aplicar script nftables no boot", "err", err)
		return &GuardError{Stage: StageReconcile, Message: "no boot, o nftables recusou as regras geradas", Err: err}
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
			desc = fmt.Sprintf("%s %s %q", m.Objeto, participioConcordado(m), m.Nome)
		} else {
			desc = fmt.Sprintf("%s %s %s", m.Objeto, participioConcordado(m), m.ID)
		}
		partes = append(partes, desc)
	}
	return strings.Join(partes, "; ")
}

// participioConcordado concorda o tipo da mudança com o gênero do objeto:
// "regra criada", mas "alias criado" e "ajustes alterados".
func participioConcordado(m fwmodel.Mudanca) string {
	if m.Objeto == "regra" {
		return string(m.Tipo)
	}
	base := strings.TrimSuffix(string(m.Tipo), "a") + "o"
	if m.Objeto == "ajustes" {
		return base + "s"
	}
	return base
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
