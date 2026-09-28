package handlers

// Confirmar-ou-reverte pelo lado da API (Fase C2, spec §5) — a rede de
// proteção de internal/firewallrules ligada ao mundo exterior.
//
// Aqui moram as SAÍDAS da janela — confirmar e reverter — mais o GET que o
// painel lê para desenhar a faixa com a contagem regressiva, e o arme da
// janela pelas mutações de escopo input.
//
// A outra metade do mecanismo é a TRAVA (confirmWindowBlocks, em nftables.go):
// enquanto uma janela está aberta, nenhuma mutação de grupo ou regra é aceita
// (spec §5.3). As duas metades são inseparáveis, e nesta ordem: a trava só é
// aceitável porque as saídas existem — uma trava sem saída prenderia o
// operador dentro da janela, que é o oposto do objetivo.
//
// O que pode ABRIR uma janela é deliberadamente estreito: só mutação de grupo
// e de regra. O snapshot que a reversão restaura cobre `groups` e `rules` e
// mais nada (ver stateSnapshot em internal/firewallrules/confirm.go), enquanto
// as mesmas chains forward e input também são renderizadas a partir dos named
// sets de bloqueio, dos port forwards e do toggle de NTP. Uma mutação dessas
// que abrisse janela seria revertida pela METADE — o pior resultado possível
// aqui, porque o operador acredita que o estado anterior voltou inteiro.

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/giovanibalarini/linkguard-cloud/internal/firewallrules"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

// pendingView é a mudança pendente como o painel a vê. O Snapshot NÃO vem
// junto de propósito: é o estado anterior inteiro dos grupos e das regras,
// grande, sem uso na tela e desnecessariamente detalhado para quem tem apenas
// firewall.read num painel multi-admin.
//
// Reverting é o campo que separa os dois estados possíveis, e o painel PRECISA
// dos dois porque os botões disponíveis são outros em cada um:
//
//   - aguardando confirmação (Reverting=false): cabem "Confirmar" e "Reverter
//     agora";
//   - revertendo (Reverting=true): a reversão já começou, o estado anterior já
//     voltou ao banco e o que falta é o firewall vivo aceitar — não cabe
//     nenhum dos dois botões (ConfirmPending recusa), e o texto tem que dizer
//     que a reversão está em curso.
//
// SecondsLeft é a contagem regressiva medida pelo relógio que DECIDE a hora de
// reverter — firewallrules.SecondsLeft, o mesmo desempate de windowExpired
// (monotônico enquanto a janela é deste processo, expires_at depois de um
// restart). Ele existe porque ExpiresAt sozinho obriga o painel a comparar um
// instante do servidor com o Date.now() da estação do operador: um relógio
// adiantado em 40 segundos mostra "45 s" quando restam 5, e o operador usa
// exatamente esse número para decidir se ainda dá tempo de testar o SSH antes de
// confirmar.
//
// M-2 da revisão final: este campo saía de `time.Until(expires_at)`, isto é, do
// relógio de PAREDE, enquanto quem reverte olha o deadline MONOTÔNICO. Numa
// máquina que É o servidor NTP da rede, um `makestep` do chrony fazia a
// contagem da tela e a reversão de verdade discordarem — e o comentário aqui
// afirmava que era "o mesmo relógio que o watchdog usa".
//
// Ele é RECALCULADO a cada resposta e não é gravado em lugar nenhum: um
// seconds_left persistido seria a contagem de quando a linha foi escrita. E
// ExpiresAt continua no corpo — é a verdade persistida, e é dela que este campo
// sai.
type pendingView struct {
	ID          string     `json:"id"`
	Summary     string     `json:"summary"`
	AppliedBy   string     `json:"applied_by"`
	ExpiresAt   time.Time  `json:"expires_at"`
	SecondsLeft int        `json:"seconds_left"`
	CreatedAt   time.Time  `json:"created_at"`
	Reverting   bool       `json:"reverting"`
	RevertingAt *time.Time `json:"reverting_at,omitempty"`
}

// pendingView desenha a janela para o painel. É método do handler, e não uma
// função solta, por causa de um campo só: SecondsLeft tem que sair do serviço —
// é lá que mora o relógio que decide reverter (M-2).
func (h *NftablesHandler) pendingView(p *storage.PendingChange) *pendingView {
	if p == nil {
		return nil
	}
	v := &pendingView{
		ID:          p.ID,
		Summary:     p.Summary,
		AppliedBy:   p.AppliedBy,
		ExpiresAt:   p.ExpiresAt,
		SecondsLeft: h.fr.SecondsLeft(p),
		CreatedAt:   p.CreatedAt,
		Reverting:   p.Reverting(),
	}
	if p.Reverting() {
		at := p.RevertingAt
		v.RevertingAt = &at
	}
	return v
}

// pendingResponse é o corpo do GET. O campo é um ponteiro SEM omitempty: sem
// janela aberta o painel recebe `{"pending": null}`, uma resposta explícita, e
// não um objeto vazio que ele teria de adivinhar.
type pendingResponse struct {
	Pending *pendingView `json:"pending"`
}

// mutationResult é o corpo comum das mutações que já respondiam
// `{"status":"ok"}` — agora com o pendente recém-criado junto, quando a
// mutação abriu a janela. O campo é omitido quando não há janela, para que
// nenhum cliente antigo veja um campo novo onde antes não havia nada.
type mutationResult struct {
	Status  string       `json:"status"`
	Pending *pendingView `json:"pending,omitempty"`
}

func okResult(p *pendingView) mutationResult {
	return mutationResult{Status: "ok", Pending: p}
}

// createdGroupResult e createdRuleResult acrescentam o pendente à linha criada
// SEM mudar o formato que o painel já lê: o embutido é achatado pelo
// encoding/json, então todo campo do grupo/da regra continua no mesmo lugar.
type createdGroupResult struct {
	*storage.FirewallGroup
	Pending *pendingView `json:"pending,omitempty"`
}

type createdRuleResult struct {
	*storage.FirewallRule
	Pending *pendingView `json:"pending,omitempty"`
}

// PendingChange (GET /api/nftables/pending) devolve a janela em aberto, ou
// null quando não há nenhuma.
//
// Erro de leitura vira 500, e nunca "não há nada pendente": a faixa da
// contagem regressiva sumindo da tela por causa de um SELECT que falhou é o
// operador concluindo que já confirmou, no exato minuto em que confirmar é a
// única coisa que devolve o acesso dele. É a mesma razão de
// firewallrules.PendingChangeOrError não ter a forma "conveniente" que engolia
// o erro.
func (h *NftablesHandler) PendingChange(w http.ResponseWriter, r *http.Request) {
	p, err := h.fr.PendingChangeOrError()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, pendingResponse{Pending: h.pendingView(p)})
}

// ConfirmPendingChange (POST /api/nftables/pending/confirm) é o operador
// dizendo "ainda tenho acesso": a mudança passa a valer definitivamente e o
// firewall vivo não é tocado (ver firewallrules.ConfirmPending).
//
// O status do erro é escolhido pelo ESTADO, não pelo texto: não haver
// pendente, ou haver um cuja reversão já começou, é conflito do cliente com o
// estado do servidor (409) e a mensagem é nossa, escrita para o operador.
// Qualquer outra falha é do servidor (500) e vira a mensagem genérica — um
// erro de banco não pode virar 400 com SQL cru na tela.
func (h *NftablesHandler) ConfirmPendingChange(w http.ResponseWriter, r *http.Request) {
	id, ok := h.windowIDFromBody(w, r)
	if !ok {
		return
	}
	p, err := h.fr.PendingChangeOrError()
	if err != nil {
		writeInternalError(w, err)
		return
	}

	// A PROVA DE ACESSO (issue #86), antes de qualquer escrita.
	//
	// Confirmar por uma conexão que já existia quando a janela foi armada não
	// prova nada: essa conexão responderia mesmo com o acesso cortado, porque
	// uma chain que aceita `ct state established` a mantém de pé. O operador
	// testaria, veria tudo funcionando, confirmaria — e descobriria na próxima
	// reconexão, já sem janela.
	//
	// Exigir uma conexão NOVA inverte isso: conseguir chegar aqui já é a prova.
	//
	// A checagem vale para a janela que ESTÁ sendo confirmada. Se o pendente
	// lido não é o que o cliente mandou, não há com o que comparar e a decisão
	// cai em "não verificável" — o mesmo lado seguro do proxy.
	var armada time.Time
	if p != nil && p.ID == id {
		armada = p.CreatedAt
	}
	provaDeAcesso := decideFreshness(factsFromRequest(r, armada))
	if provaDeAcesso == FreshConexaoAntiga {
		// 409, e não 403: não é falta de permissão, é o estado da conexão que
		// não serve como prova. E nada foi tocado — a janela segue de pé, com o
		// prazo correndo, que é exatamente o que o operador precisa agora.
		writeError(w, http.StatusConflict, mensagemDeRecusa)
		return
	}

	if err := h.fr.ConfirmPending(r.Context(), id); err != nil {
		// A classificação sai do PRÓPRIO erro (firewallrules.IsWindowConflict),
		// nunca do `p` lido lá em cima: entre a leitura e a chamada o estado
		// pode ter mudado, e o caso em que isso acontece é o que mais dói — o
		// operador aperta "Confirmar" um segundo depois do prazo, o watchdog já
		// reverteu, e ConfirmPending tem a mensagem certa para ele ("tarde
		// demais: a mudança %q foi revertida automaticamente porque..."). Com a
		// classificação pelo estado obsoleto, aquilo virava "erro interno do
		// servidor" e o operador não ficava sabendo que a mudança tinha sido
		// desfeita, no minuto em que essa é a informação que mais importa.
		if firewallrules.IsWindowConflict(err) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeInternalError(w, err)
		return
	}
	// A auditoria registra a janela que foi CONFIRMADA — o id que o cliente
	// mandou —, e o resumo só quando ele descreve essa mesma janela. `p` foi
	// lido antes da chamada e pode já ser outro pendente (ou nenhum): usá-lo
	// sem conferir registrava, no caso que mais dói, o resumo de uma mudança
	// diferente da que acabou de passar a valer para sempre.
	summary := ""
	if p != nil && p.ID == id {
		summary = p.Summary
	}
	// A auditoria registra SE a prova foi obtida. Uma confirmação sem prova é
	// legítima (é o caminho do proxy), mas ela não vale o mesmo que uma com — e
	// quem for investigar um lockout meses depois precisa conseguir distinguir
	// as duas no histórico.
	if provaDeAcesso == FreshNaoVerificavel {
		summary = strings.TrimSpace(summary + " [confirmado sem prova de conexão nova]")
	}
	auditAction(h.db, r, "nft.pending.confirm", "pending:"+id, summary)

	resp := map[string]any{"status": "ok"}
	if provaDeAcesso == FreshNaoVerificavel {
		resp["warning"] = mensagemNaoVerificavel
	}
	writeJSON(w, http.StatusOK, resp)
}

// windowIDFromBody lê o id da janela que o cliente está resolvendo. Ele é
// OBRIGATÓRIO em confirmar e em reverter, e é a única forma de as duas saídas
// agirem sobre a janela que o operador viu na tela em vez de sobre a que
// estiver aberta no instante da chamada.
//
// Sem ele, num painel multi-admin: A aplica uma mudança de escopo input, B
// confirma a janela de A achando que confirma a dele, e a rede de proteção de
// uma alteração que B nunca viu é cancelada. O id sai da mesma faixa que
// mostra a contagem regressiva (GET /api/nftables/pending), então o painel
// sempre o tem; um cliente de linha de comando faz o GET antes.
func (h *NftablesHandler) windowIDFromBody(w http.ResponseWriter, r *http.Request) (string, bool) {
	var b struct {
		ID string `json:"id"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return "", false
	}
	id := strings.TrimSpace(b.ID)
	if id == "" {
		writeError(w, http.StatusBadRequest,
			"informe o id da mudança pendente (o mesmo que a faixa do painel mostra, em GET /api/nftables/pending): sem ele esta ação agiria sobre a janela que estiver aberta, e não sobre a que você viu")
		return "", false
	}
	return id, true
}

// RevertPendingChange (POST /api/nftables/pending/revert) é o "Reverter agora":
// desfaz a mudança sem esperar os 90 segundos acabarem.
//
// A reversão que não conclui NÃO é um caminho perdido: o pendente fica no
// banco e o watchdog retoma sozinho (ver firewallrules.revert). É isso que a
// mensagem de erro diz — o operador precisa saber que ainda há alguém tentando
// devolver o acesso dele, e não que a reversão fracassou e acabou.
func (h *NftablesHandler) RevertPendingChange(w http.ResponseWriter, r *http.Request) {
	id, ok := h.windowIDFromBody(w, r)
	if !ok {
		return
	}
	p, err := h.fr.PendingChangeOrError()
	if err != nil {
		writeInternalError(w, err)
		return
	}
	if p == nil {
		writeError(w, http.StatusConflict, "não há mudança aguardando confirmação")
		return
	}
	if err := h.fr.RevertPending(r.Context(), id); err != nil {
		// Mesma simetria do handler de confirmar: a janela que fechou entre a
		// leitura e a chamada (o watchdog reverteu primeiro, ou outro admin
		// confirmou) é conflito de estado — 409 com a mensagem escrita para o
		// operador —, não 500 "erro interno do servidor" sobre algo que já
		// aconteceu do jeito que ele queria.
		if firewallrules.IsWindowConflict(err) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		slog.Error("a reversão pedida pelo operador não pôde ser concluída", "err", err, "resumo", p.Summary)
		writeError(w, http.StatusInternalServerError,
			"não foi possível concluir a reversão agora; a mudança continua pendente e o LinkGuard vai tentar de novo sozinho")
		return
	}
	auditAction(h.db, r, "nft.pending.revert", "pending:"+id, p.Summary)
	saveNftSnapshot(r.Context(), h.db, h.svc)
	writeJSON(w, http.StatusOK, okResult(nil))
}
