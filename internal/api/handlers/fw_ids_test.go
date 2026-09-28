package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// O cliente pode escolher o ID de um objeto novo; ele entra no script do nft,
// então um ID com aspas, ponto e vírgula ou quebra de linha tem de ser recusado.
func TestFirewallIDDoClienteInseguroERecusado(t *testing.T) {
	db, _, _, _, userW, router := setupFirewallTestRouter(t)
	semearConfigValida(t, db)

	ids := []string{
		`x"; flush ruleset; #`,
		"x\"\n flush ruleset\n#",
		"com espaço",
		"a:b",
		strings.Repeat("a", 65),
	}
	corpos := []struct {
		nome, caminho, chave string
		corpo                func(id string) map[string]any
	}{
		{"regra", "/api/firewall/regras", "fwz.problema.regraIdInvalido", func(id string) map[string]any {
			return map[string]any{
				"id": id, "zona": "internet", "acao": "accept", "proto": "tcp",
				"origem": map[string]any{"kind": "any"}, "destino": map[string]any{"kind": "self"},
				"porta_destino": map[string]any{"kind": "port", "value": "22"},
			}
		}},
		{"alias", "/api/firewall/aliases", "fwz.problema.aliasIdInvalido", func(id string) map[string]any {
			return map[string]any{"id": id, "nome": "Novo", "tipo": "enderecos", "itens": []string{"10.0.0.1"}}
		}},
		{"agendamento", "/api/firewall/agendamentos", "fwz.problema.agendamentoIdInvalido", func(id string) map[string]any {
			return map[string]any{"id": id, "nome": "Novo", "dias": "mon", "inicio": "08:00", "fim": "18:00"}
		}},
		{"encaminhamento", "/api/firewall/nat", "fwz.problema.encaminhamentoIdInvalido", func(id string) map[string]any {
			return map[string]any{
				"id": id, "nome": "Novo", "proto": "tcp", "porta_externa": 2222,
				"ip_destino": "10.0.0.9", "porta_destino": 22,
			}
		}},
	}

	for _, c := range corpos {
		for _, id := range ids {
			antes := configEmEdicaoJSON(t, db)
			b, err := json.Marshal(c.corpo(id))
			if err != nil {
				t.Fatalf("montar corpo: %v", err)
			}
			res := doReq(router, http.MethodPost, c.caminho, userW.ID, string(b))
			if res.Code != http.StatusBadRequest {
				t.Errorf("%s com ID %q: esperava 400, obteve %d: %s", c.nome, id, res.Code, res.Body.String())
				continue
			}
			var corpo respostaComProblemas
			if err := json.Unmarshal(res.Body.Bytes(), &corpo); err != nil {
				t.Fatalf("decodificar resposta: %v", err)
			}
			if !temProblema(corpo.Problemas, c.chave) {
				t.Errorf("%s com ID %q: faltou %s em %+v", c.nome, id, c.chave, corpo.Problemas)
			}
			if depois := configEmEdicaoJSON(t, db); depois != antes {
				t.Errorf("%s com ID %q: a recusa deixou rastro na configuração", c.nome, id)
			}
		}
	}
}

func TestFirewallIDDoClienteSeguroEPreservado(t *testing.T) {
	db, _, _, _, userW, router := setupFirewallTestRouter(t)
	semearConfigValida(t, db)

	res := doReq(router, http.MethodPost, "/api/firewall/aliases", userW.ID,
		`{"id":"meu-alias_1","nome":"Meu alias","tipo":"enderecos","itens":["10.0.0.1"]}`)
	if res.Code != http.StatusCreated {
		t.Fatalf("esperava 201, obteve %d: %s", res.Code, res.Body.String())
	}
	cfg, err := db.CarregarConfigEmEdicao()
	if err != nil {
		t.Fatalf("CarregarConfigEmEdicao: %v", err)
	}
	for _, a := range cfg.Aliases {
		if a.ID == "meu-alias_1" {
			return
		}
	}
	t.Fatalf("o alias com o ID escolhido não foi gravado: %+v", cfg.Aliases)
}
