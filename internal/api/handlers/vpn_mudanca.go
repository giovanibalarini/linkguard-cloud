package handlers

import (
	"context"
	"errors"
	"net/http"

	"github.com/giovanibalarini/linkguard-cloud/internal/firewallrules"
	"github.com/giovanibalarini/linkguard-cloud/internal/wireguard"
)

// aplicarMudancaVPN passa uma mudança da VPN pelo firewall.
//
// Se o WireGuard grava a mudança mas não consegue reconciliar o sistema
// (FalhaDeReconciliacao), a decisão já está no banco — e o firewall tem de
// segui-la mesmo assim: uma revogação ou uma restrição que não chegasse ao
// ruleset só porque o `systemctl` falhou deixaria a regra antiga em vigor. Por
// isso essa falha é desviada para falhaWG, a escrita conta como feita, e quem
// chama decide o que dizer ao operador depois que o firewall acompanhou.
//
// Qualquer outro erro de escrever (uma Recusa, um erro de banco) volta como
// está em err, junto com os do próprio firewall (GuardError).
func aplicarMudancaVPN(ctx context.Context, fr vpnApplier, por, resumo string,
	escrever, desfazer func() error) (falhaWG, err error) {
	seguindo := func() error {
		e := escrever()
		var f *wireguard.FalhaDeReconciliacao
		if errors.As(e, &f) {
			falhaWG = e
			return nil
		}
		return e
	}
	if fr == nil {
		err = seguindo()
		return falhaWG, err
	}
	_, err = fr.AplicarMudancaVPN(ctx, por, resumo, seguindo, desfazer)
	return falhaWG, err
}

func statusDaRecusa(m wireguard.Motivo) int {
	switch m {
	case wireguard.NaoEncontrado:
		return http.StatusNotFound
	case wireguard.EstadoImpede:
		return http.StatusConflict
	}
	return http.StatusBadRequest
}

// resumoDoErro é o que se pode gravar na auditoria e devolver à tela sobre um
// erro de mudança da VPN: a mensagem de uma recusa ou de uma etapa do
// firewall, que são escritas para serem lidas, e nunca o texto de um erro de
// sistema, que carrega caminho e saída de comando.
func resumoDoErro(err error) string {
	var r *wireguard.Recusa
	if errors.As(err, &r) {
		return r.Msg
	}
	var g *firewallrules.GuardError
	if errors.As(err, &g) {
		return g.Message
	}
	return "erro interno"
}

// writeVPNError traduz o erro de uma mudança da VPN. Uma falha do firewall que
// deixou a mudança gravada também é registrada no painel da VPN: o operador
// que abrir a tela depois tem de ver que o desejado não foi aplicado.
func (h *WireGuardHandler) writeVPNError(w http.ResponseWriter, err error) {
	var r *wireguard.Recusa
	if errors.As(err, &r) {
		writeError(w, statusDaRecusa(r.Motivo), r.Msg)
		return
	}
	var g *firewallrules.GuardError
	if errors.As(err, &g) {
		if g.Gravada {
			h.svc.RecordIntegrationError(g)
		}
		writeGuardError(w, err)
		return
	}
	writeInternalError(w, err)
}
