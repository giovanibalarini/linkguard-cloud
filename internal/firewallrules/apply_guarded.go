package firewallrules

import (
	"errors"
	"fmt"

	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

// Stage é a etapa em que a mutação ou aplicação do firewall parou.
type Stage int

const (
	StageValidate  Stage = iota // campos inválidos
	StageLocked                 // há uma janela aberta; a mutação nem começou
	StagePreflight              // o `nft -c` recusou o estado resultante
	StageWindow                 // não foi possível ARMAR a janela; nada foi aplicado
	StageWrite                  // a escrita no banco falhou; a janela foi descartada
	StageReconcile              // o firewall vivo recusou; o estado anterior VOLTOU
	StageStuck                  // o firewall recusou E a reversão não concluiu
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
	}
	return "desconhecida"
}

// GuardError é a falha de uma mutação ou aplicação de firewall, com a etapa e a frase que o operador deve ler.
type GuardError struct {
	Stage   Stage
	Message string // para o operador
	Err     error  // a causa técnica, para o log
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
			Stage:   StageLocked,
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
				Stage:   StageLocked,
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
