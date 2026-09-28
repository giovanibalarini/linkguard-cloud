package firewallrules

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/giovanibalarini/linkguard-cloud/internal/fwmodel"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

// Stage é a etapa em que a mutação ou aplicação do firewall parou.
type Stage int

const (
	StageValidate  Stage = iota // campos inválidos
	StageLocked                 // há uma janela aberta; a mutação nem começou
	StagePreflight              // o render, o `nft -c` ou a leitura do que eles precisam recusou o estado resultante; o firewall vivo não foi tocado
	StageWindow                 // não foi possível ler ou ARMAR a janela; o firewall vivo não foi tocado
	StageWrite                  // a leitura ou a escrita no banco falhou; a janela foi descartada (e o kernel, se já tinha as regras novas, voltou)
	StageReconcile              // o `nft -f` recusou o ruleset: o kernel ficou como estava (a aplicação é atômica)
	StageStuck                  // a mudança foi recusada E não pôde ser desfeita, ou o kernel tem regras que o banco não registra: o estado pode estar pela metade
	StageNotFound               // o objeto pedido não existe; nada foi tocado
	StageInUse                  // o objeto é usado por outros; nada foi tocado
)

func (s Stage) String() string {
	switch s {
	case StageValidate:
		return "validação"
	case StageLocked:
		return "trava do confirmar-ou-reverte"
	case StagePreflight:
		return "pré-voo nft -c"
	case StageWindow:
		return "arme da janela"
	case StageWrite:
		return "escrita no banco"
	case StageReconcile:
		return "reconciliação"
	case StageStuck:
		return "reconciliação e reversão"
	case StageNotFound:
		return "objeto não encontrado"
	case StageInUse:
		return "objeto em uso"
	}
	return "desconhecida"
}

// GuardError é a falha de uma mutação ou aplicação de firewall, com a etapa e a frase que o operador deve ler.
type GuardError struct {
	Stage     Stage
	Message   string             // para o operador: nunca cita caminho nem saída de comando
	Err       error              // a causa técnica, para o log
	Problemas []fwmodel.Problema // o que a validação achou; a interface os traduz
	Usos      []string           // StageInUse: quem usa o objeto que se tentou apagar
	// Gravada diz que o pedido FICOU no banco apesar da falha: a mudança não tem
	// volta (revogar um acesso, apagar um usuário, girar uma chave) ou a volta
	// também falhou. Quem responde ao operador precisa dizer isso, e entregar o
	// que a gravação produziu (a config de um peer que já vale).
	Gravada bool
}

func (e *GuardError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Stage, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Stage, e.Message)
}

func (e *GuardError) Unwrap() error { return e.Err }

// StageOf devolve a etapa em que err parou, e se err é mesmo um GuardError.
func StageOf(err error) (Stage, bool) {
	var g *GuardError
	if errors.As(err, &g) {
		return g.Stage, true
	}
	return 0, false
}

// Applied é o resultado de uma mutação ou aplicação que deu certo.
type Applied struct {
	WindowID string
	Pending  *storage.PendingChange
	Summary  string
}

// guardWindowOpen verifica se há uma janela de confirmação aberta e impede mutações conflitantes.
// Libera no estado "revertendo" se a reversão já concluiu no banco (RevertSettled).
func (s *Service) guardWindowOpen() error {
	p, err := s.PendingChangeOrError()
	if err != nil {
		return &GuardError{
			Stage:   StageWindow,
			Message: "não foi possível verificar se há uma mudança aguardando confirmação",
			Err:     err,
		}
	}
	if p == nil {
		return nil
	}
	if p.Reverting() {
		settled, err := s.RevertSettled(p)
		if err != nil {
			return &GuardError{
				Stage:   StageWindow,
				Message: "não foi possível confirmar o estado da reversão em andamento; tente de novo em alguns segundos",
				Err:     err,
			}
		}
		if settled {
			return nil
		}
	}
	return &GuardError{
		Stage: StageLocked,
		Message: fmt.Sprintf(
			"há uma mudança de firewall aguardando confirmação (%q, aplicada por %s): confirme ou reverta antes de aplicar outra",
			p.Summary, p.AppliedBy),
	}
}

// mensagemDoErro é a frase, para o operador, de uma falha do firewall: a do
// GuardError ou, para qualquer outro erro, uma genérica que não repete o que a
// causa técnica disse (caminho de arquivo, saída do nft, texto do SQLite).
func mensagemDoErro(err error) string {
	if err == nil {
		return ""
	}
	var g *GuardError
	if errors.As(err, &g) && g.Message != "" {
		return g.Message
	}
	return "o firewall não pôde ser aplicado; veja o registro do servidor"
}

// descartarJanela desfaz a janela que esta operação armou e não chegou a usar.
// Se o banco não deixa apagá-la, ela continua armada — então a memória do prazo
// fica, para o watchdog reverter no tempo certo em vez de esquecê-la.
func (s *Service) descartarJanela(id string) {
	if id == "" {
		return
	}
	if err := s.db.ClearPendingChange(); err != nil {
		slog.Error("não foi possível descartar a janela de confirmação de uma operação que falhou; o auto-revert a resolverá", "err", err)
		return
	}
	s.clearWindowMemory(id)
}

// pendenteDaJanela lê a janela recém-armada para a resposta. Se a leitura
// falha a janela existe do mesmo jeito, e o painel a acha em /api/firewall/estado.
func (s *Service) pendenteDaJanela() *storage.PendingChange {
	p, err := s.db.GetPendingChange()
	if err != nil {
		slog.Warn("não foi possível ler a janela recém-armada para a resposta", "err", err)
		return nil
	}
	return p
}
