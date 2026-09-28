package fwmodel

import "strings"

// SemRegrasDePessoaRemovida devolve uma cópia de c sem as regras cuja origem ou
// destino é uma pessoa que já não tem VPN. Revogar o acesso remove o peer, e a
// regra que apontava para ele não pode travar o firewall inteiro: é a
// revogação que precisa alcançar as regras. A config armazenada não muda; a
// regra fica na tela, e cada uma descartada vira um aviso.
func SemRegrasDePessoaRemovida(c Config, userIDs []string) (Config, []Problema) {
	presentes := make(map[string]bool, len(userIDs))
	for _, id := range userIDs {
		presentes[id] = true
	}
	orfa := func(p Ponta) bool {
		if p.Tipo != PontaAlias || !strings.HasPrefix(p.Valor, AliasPessoaPref) {
			return false
		}
		return !presentes[strings.TrimPrefix(p.Valor, AliasPessoaPref)]
	}
	var avisos []Problema
	var mantidas []Regra
	descartou := false
	for _, r := range c.Regras {
		if orfa(r.Origem) || orfa(r.Destino) {
			descartou = true
			avisos = append(avisos, Problema{
				Severidade: "aviso",
				Onde:       "regra:" + r.ID,
				Chave:      "fwz.aviso.regraPessoaRemovida",
				Vars:       map[string]string{"regra": nomeDaRegra(r)},
			})
			continue
		}
		mantidas = append(mantidas, r)
	}
	if !descartou {
		return c, nil
	}
	c.Regras = mantidas
	return c, avisos
}

func nomeDaRegra(r Regra) string {
	if d := strings.TrimSpace(r.Descricao); d != "" {
		return d
	}
	return r.ID
}
