package wireguard

import (
	"errors"
	"fmt"
)

// Motivo diz por que o serviço disse "não": é o que a borda HTTP lê para
// escolher o status, no lugar de olhar o texto do erro.
type Motivo int

const (
	// PedidoInvalido: o que o chamador mandou não vale (400).
	PedidoInvalido Motivo = iota
	// EstadoImpede: o pedido vale, mas o estado atual não deixa — a VPN
	// desligada, o endereço público por preencher, a chave que sumiu do cofre (409).
	EstadoImpede
	// NaoEncontrado: a pessoa ou o peer pedido não existe (404).
	NaoEncontrado
)

// Recusa é um "não" escrito para ser lido por quem pediu, e por isso a
// mensagem vai inteira para a tela. Todo outro erro do serviço é falha interna
// — banco, cofre, processo — e nunca chega ao painel com o texto original.
type Recusa struct {
	Motivo Motivo
	Msg    string
}

func (r *Recusa) Error() string { return r.Msg }

func recusa(m Motivo, format string, args ...any) error {
	return &Recusa{Motivo: m, Msg: fmt.Sprintf(format, args...)}
}

// FalhaDeReconciliacao é o erro de quem já gravou a mudança mas não conseguiu
// fazer o WireGuard do sistema segui-la. A distinção importa para quem chama: o
// que foi decidido está no banco, então o firewall tem de acompanhar essa
// decisão mesmo assim — uma revogação ou uma restrição que não chegasse ao
// ruleset só porque o `systemctl` falhou deixaria a regra antiga em vigor.
type FalhaDeReconciliacao struct{ Err error }

func (f *FalhaDeReconciliacao) Error() string { return f.Err.Error() }
func (f *FalhaDeReconciliacao) Unwrap() error { return f.Err }

// daConfigGravada reclassifica uma validação que falhou sobre dado JÁ gravado:
// o pedido de agora estava certo, é o estado que impede. Sem isto, um
// wg0.conf ou um perfil corrompido apareceria ao operador como "pedido inválido".
func daConfigGravada(err error) error {
	var r *Recusa
	if errors.As(err, &r) && r.Motivo == PedidoInvalido {
		return recusa(EstadoImpede, "a configuração gravada não é válida: %s", r.Msg)
	}
	return err
}
