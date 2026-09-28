package handlers

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/giovanibalarini/linkguard-cloud/internal/firewallrules"
)

// asGuardError isola o errors.As para que writeGuardError leia como a tabela
// de tradução que ela é.
func asGuardError(err error, target **firewallrules.GuardError) bool {
	return errors.As(err, target)
}

// writeGuardError é a tradução de etapa em status, e o único lugar onde ela
// acontece.
//
// Os status não são intercambiáveis, e cada um responde a uma pergunta
// diferente do operador:
//
//	400 — "o que você mandou não serve" (campos, ou o nft recusando o
//	      resultado). Nada foi tocado. Quando a recusa vem da validação, a
//	      resposta traz também `problemas`, para o painel mostrar cada um.
//	409 — "não é a sua vez": há uma janela aberta. É conflito de ESTADO, não
//	      erro do pedido, e a mensagem nomeia a mudança e quem a aplicou,
//	      porque é isso que ele precisa para decidir entre confirmar e reverter.
//	500 — algo do lado do servidor não deu certo. Aqui a FRASE importa mais
//	      que o número: ela é a diferença entre "nada mudou" e "pode ter
//	      ficado pela metade, o LinkGuard está tentando reverter" — e é ela
//	      que diz se ele precisa ir olhar o firewall à mão.
func writeGuardError(w http.ResponseWriter, err error) {
	var g *firewallrules.GuardError
	if !asGuardError(err, &g) {
		// Não deveria acontecer: ApplyGuarded / EditarConfigValidando devolve GuardError em todo
		// caminho de erro. Se acontecer, o genérico é o lado seguro.
		slog.Error("erro sem etapa vindo do firewall", "err", err)
		writeInternalError(w, err)
		return
	}

	switch g.Stage {
	case firewallrules.StageValidate, firewallrules.StagePreflight:
		if len(g.Problemas) > 0 {
			// Os problemas vão junto para o painel traduzi-los; o texto fica
			// como resumo para quem lê a resposta crua.
			writeJSON(w, http.StatusBadRequest, map[string]any{"erro": g.Message, "problemas": g.Problemas})
			return
		}
		writeError(w, http.StatusBadRequest, g.Message)

	case firewallrules.StageLocked:
		writeError(w, http.StatusConflict, g.Message)

	case firewallrules.StageWrite:
		// A causa técnica (erro de banco) não vai para a tela — writeInternalError
		// existe justamente para não vazar caminho de arquivo e erro de SQL para
		// quem está no painel. O log fica com tudo.
		slog.Error("a escrita da mutação falhou; a janela foi descartada e nada mudou", "err", g.Err)
		writeInternalError(w, g.Err)

	case firewallrules.StageWindow, firewallrules.StageReconcile, firewallrules.StageStuck:
		slog.Error("mutação de firewall interrompida", "etapa", g.Stage.String(), "err", g.Err)
		writeError(w, http.StatusInternalServerError, g.Message)

	default:
		writeInternalError(w, g.Err)
	}
}
