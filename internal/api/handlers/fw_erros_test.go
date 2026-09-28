package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-cloud/internal/fwmodel"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

func ordemDaZona(t *testing.T, db *storage.DB, zona fwmodel.Zona) []string {
	t.Helper()
	cfg, err := db.CarregarConfigEmEdicao()
	if err != nil {
		t.Fatalf("CarregarConfigEmEdicao: %v", err)
	}
	var ids []string
	for _, r := range cfg.Regras {
		if r.Zona == zona {
			ids = append(ids, r.ID)
		}
	}
	return ids
}

func TestFirewallNomeRepetidoDevolve400ComProblema(t *testing.T) {
	db, _, _, _, userW, router := setupFirewallTestRouter(t)
	semearConfigValida(t, db)
	if err := db.CriarAliasFW(&fwmodel.Alias{ID: "a-outro", Nome: "Outros", Tipo: fwmodel.AliasTipoEnderecos}); err != nil {
		t.Fatal(err)
	}
	if err := db.CriarAgendamentoFW(&fwmodel.Agendamento{ID: "ag-outro", Nome: "Noite", Dias: "mon", Inicio: "20:00", Fim: "23:00"}); err != nil {
		t.Fatal(err)
	}

	cenarios := []struct {
		nome, metodo, caminho, corpo, chave, outro string
	}{
		{"criar alias com nome de outro (caixa diferente)", http.MethodPost, "/api/firewall/aliases",
			`{"nome":"servidores","tipo":"enderecos","itens":["10.0.0.1"]}`, "fwz.problema.aliasNomeDuplicado", "a-ok"},
		{"criar alias com espaços nas pontas", http.MethodPost, "/api/firewall/aliases",
			`{"nome":"  Servidores ","tipo":"enderecos","itens":["10.0.0.1"]}`, "fwz.problema.aliasNomeDuplicado", "a-ok"},
		{"renomear alias para o nome de outro", http.MethodPut, "/api/firewall/aliases/a-outro",
			`{"nome":"SERVIDORES","tipo":"enderecos","itens":[]}`, "fwz.problema.aliasNomeDuplicado", "a-ok"},
		{"criar agendamento com nome de outro", http.MethodPost, "/api/firewall/agendamentos",
			`{"nome":"comercial","dias":"mon","inicio":"08:00","fim":"18:00"}`, "fwz.problema.agendamentoNomeDuplicado", "ag-ok"},
		{"renomear agendamento para o nome de outro", http.MethodPut, "/api/firewall/agendamentos/ag-outro",
			`{"nome":" Comercial","dias":"mon","inicio":"20:00","fim":"23:00"}`, "fwz.problema.agendamentoNomeDuplicado", "ag-ok"},
	}
	for _, c := range cenarios {
		t.Run(c.nome, func(t *testing.T) {
			antes := configEmEdicaoJSON(t, db)
			res := doReq(router, c.metodo, c.caminho, userW.ID, c.corpo)
			if res.Code != http.StatusBadRequest {
				t.Fatalf("esperava 400, obteve %d: %s", res.Code, res.Body.String())
			}
			var corpo respostaComProblemas
			if err := json.Unmarshal(res.Body.Bytes(), &corpo); err != nil {
				t.Fatalf("decodificar resposta: %v", err)
			}
			var achou bool
			for _, p := range corpo.Problemas {
				if p.Chave == c.chave {
					achou = true
					if p.Vars["outro_id"] != c.outro {
						t.Errorf("outro_id = %q, esperava %q", p.Vars["outro_id"], c.outro)
					}
				}
			}
			if !achou {
				t.Errorf("faltou %s em %+v", c.chave, corpo.Problemas)
			}
			if depois := configEmEdicaoJSON(t, db); depois != antes {
				t.Errorf("a recusa deixou rastro na configuração em edição")
			}
		})
	}
}

func TestFirewallIDRepetidoDevolve400(t *testing.T) {
	db, _, _, _, userW, router := setupFirewallTestRouter(t)
	semearConfigValida(t, db)

	cenarios := []struct{ nome, caminho, corpo, id string }{
		{"regra", "/api/firewall/regras",
			`{"id":"r-ok","zona":"internet","acao":"accept","proto":"tcp","origem":{"kind":"any"},"destino":{"kind":"self"},"porta_destino":{"kind":"any"}}`, "r-ok"},
		{"alias", "/api/firewall/aliases",
			`{"id":"a-ok","nome":"Um nome livre","tipo":"enderecos","itens":["10.0.0.1"]}`, "a-ok"},
		{"agendamento", "/api/firewall/agendamentos",
			`{"id":"ag-ok","nome":"Um nome livre","dias":"mon","inicio":"08:00","fim":"18:00"}`, "ag-ok"},
		{"encaminhamento", "/api/firewall/nat",
			`{"id":"n-on","nome":"Livre","proto":"tcp","porta_externa":2222,"ip_destino":"10.0.0.9","porta_destino":22}`, "n-on"},
	}
	for _, c := range cenarios {
		t.Run(c.nome, func(t *testing.T) {
			antes := configEmEdicaoJSON(t, db)
			res := doReq(router, http.MethodPost, c.caminho, userW.ID, c.corpo)
			if res.Code != http.StatusBadRequest {
				t.Fatalf("esperava 400, obteve %d: %s", res.Code, res.Body.String())
			}
			if !strings.Contains(res.Body.String(), c.id) {
				t.Errorf("a resposta devia nomear o identificador repetido: %s", res.Body.String())
			}
			if depois := configEmEdicaoJSON(t, db); depois != antes {
				t.Errorf("a recusa deixou rastro na configuração em edição")
			}
		})
	}
}

func TestFirewallObjetoInexistenteDevolve404(t *testing.T) {
	db, _, _, _, userW, router := setupFirewallTestRouter(t)
	semearConfigValida(t, db)

	regra := `{"zona":"internet","acao":"accept","proto":"tcp","origem":{"kind":"any"},"destino":{"kind":"self"},"porta_destino":{"kind":"any"}}`
	cenarios := []struct{ nome, metodo, caminho, corpo string }{
		{"atualizar regra", http.MethodPut, "/api/firewall/regras/fantasma", regra},
		{"apagar regra", http.MethodDelete, "/api/firewall/regras/fantasma", ""},
		{"ativar regra", http.MethodPost, "/api/firewall/regras/fantasma/ativar", `{"ativa":true}`},
		{"duplicar regra", http.MethodPost, "/api/firewall/regras/fantasma/duplicar", ""},
		{"atualizar alias", http.MethodPut, "/api/firewall/aliases/fantasma", `{"nome":"Fantasma","tipo":"enderecos","itens":[]}`},
		{"apagar alias", http.MethodDelete, "/api/firewall/aliases/fantasma", ""},
		{"atualizar agendamento", http.MethodPut, "/api/firewall/agendamentos/fantasma", `{"nome":"Fantasma","dias":"mon","inicio":"08:00","fim":"18:00"}`},
		{"apagar agendamento", http.MethodDelete, "/api/firewall/agendamentos/fantasma", ""},
		{"atualizar encaminhamento", http.MethodPut, "/api/firewall/nat/fantasma", `{"nome":"Fantasma","proto":"tcp","porta_externa":2222,"ip_destino":"10.0.0.9","porta_destino":22,"ativo":true}`},
		{"apagar encaminhamento", http.MethodDelete, "/api/firewall/nat/fantasma", ""},
		{"ativar encaminhamento", http.MethodPost, "/api/firewall/nat/fantasma/ativar", `{"ativo":true}`},
		{"restaurar revisão", http.MethodPost, "/api/firewall/historico/fantasma/restaurar", ""},
	}
	for _, c := range cenarios {
		t.Run(c.nome, func(t *testing.T) {
			antes := configEmEdicaoJSON(t, db)
			res := doReq(router, c.metodo, c.caminho, userW.ID, c.corpo)
			if res.Code != http.StatusNotFound {
				t.Fatalf("esperava 404, obteve %d: %s", res.Code, res.Body.String())
			}
			if !strings.Contains(res.Body.String(), "fantasma") {
				t.Errorf("a resposta devia nomear o que faltou: %s", res.Body.String())
			}
			if depois := configEmEdicaoJSON(t, db); depois != antes {
				t.Errorf("a recusa deixou rastro na configuração em edição")
			}
		})
	}
}

func TestFirewallApagarEmUsoTrazQuemUsa(t *testing.T) {
	db, _, _, _, userW, router := setupFirewallTestRouter(t)
	semearConfigValida(t, db)
	if err := db.CriarRegraFW(&fwmodel.Regra{
		ID: "r-usa", Zona: fwmodel.ZonaVCN, Ativa: true, Acao: fwmodel.AcaoDrop, Proto: fwmodel.ProtoTCP,
		Origem:        fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
		Destino:       fwmodel.Ponta{Tipo: fwmodel.PontaAlias, Valor: "a-ok"},
		PortaDestino:  fwmodel.Porta{Tipo: fwmodel.PortaQualquer},
		AgendamentoID: "ag-ok",
		Descricao:     "usa os dois",
	}); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct{ caminho, erro string }{
		{"/api/firewall/aliases/a-ok", "alias em uso"},
		{"/api/firewall/agendamentos/ag-ok", "agendamento em uso"},
	} {
		antes := configEmEdicaoJSON(t, db)
		res := doReq(router, http.MethodDelete, c.caminho, userW.ID, "")
		if res.Code != http.StatusConflict {
			t.Fatalf("DELETE %s esperava 409, obteve %d: %s", c.caminho, res.Code, res.Body.String())
		}
		var corpo struct {
			Erro string   `json:"error"`
			Usos []string `json:"usos"`
		}
		if err := json.Unmarshal(res.Body.Bytes(), &corpo); err != nil {
			t.Fatalf("decodificar resposta: %v", err)
		}
		if corpo.Erro != c.erro {
			t.Errorf("erro = %q, esperava %q", corpo.Erro, c.erro)
		}
		if len(corpo.Usos) == 0 || !strings.Contains(strings.Join(corpo.Usos, " "), "usa os dois") {
			t.Errorf("os usos deviam citar a regra que depende do objeto: %v", corpo.Usos)
		}
		if depois := configEmEdicaoJSON(t, db); depois != antes {
			t.Errorf("a recusa deixou rastro na configuração em edição")
		}
	}
}

func TestFirewallReordenarListaInvalidaDevolve400(t *testing.T) {
	db, _, _, _, userW, router := setupFirewallTestRouter(t)
	semearConfigValida(t, db)
	for _, id := range []string{"r-2", "r-3"} {
		if err := db.CriarRegraFW(&fwmodel.Regra{
			ID: id, Zona: fwmodel.ZonaInternet, Ativa: true, Acao: fwmodel.AcaoAccept, Proto: fwmodel.ProtoTCP,
			Origem:       fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
			Destino:      fwmodel.Ponta{Tipo: fwmodel.PontaEste},
			PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaQualquer},
			Descricao:    id,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.CriarRegraFW(&fwmodel.Regra{
		ID: "r-vcn", Zona: fwmodel.ZonaVCN, Ativa: true, Acao: fwmodel.AcaoAccept, Proto: fwmodel.ProtoTCP,
		Origem:       fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
		Destino:      fwmodel.Ponta{Tipo: fwmodel.PontaEste},
		PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaQualquer},
		Descricao:    "vcn",
	}); err != nil {
		t.Fatal(err)
	}
	ordemInicial := ordemDaZona(t, db, fwmodel.ZonaInternet)

	for _, c := range []struct{ nome, corpo string }{
		{"lista incompleta", `{"zona":"internet","ids":["r-3","r-ok"]}`},
		{"id repetido", `{"zona":"internet","ids":["r-3","r-3","r-ok"]}`},
		{"id de outra zona", `{"zona":"internet","ids":["r-3","r-vcn","r-ok"]}`},
		{"id que não existe", `{"zona":"internet","ids":["r-3","fantasma","r-ok"]}`},
		{"zona que não existe", `{"zona":"dmz","ids":["r-3","r-2","r-ok"]}`},
	} {
		t.Run(c.nome, func(t *testing.T) {
			antes := configEmEdicaoJSON(t, db)
			res := doReq(router, http.MethodPost, "/api/firewall/regras/ordem", userW.ID, c.corpo)
			if res.Code != http.StatusBadRequest {
				t.Fatalf("esperava 400, obteve %d: %s", res.Code, res.Body.String())
			}
			if depois := configEmEdicaoJSON(t, db); depois != antes {
				t.Errorf("a recusa deixou rastro na configuração em edição")
			}
		})
	}
	if depois := ordemDaZona(t, db, fwmodel.ZonaInternet); strings.Join(depois, ",") != strings.Join(ordemInicial, ",") {
		t.Fatalf("a ordem mudou apesar das recusas: %v -> %v", ordemInicial, depois)
	}

	res := doReq(router, http.MethodPost, "/api/firewall/regras/ordem", userW.ID,
		`{"zona":"internet","ids":["r-3","r-2","r-ok"]}`)
	if res.Code != http.StatusOK {
		t.Fatalf("a lista completa devia passar: %d %s", res.Code, res.Body.String())
	}
	if depois := ordemDaZona(t, db, fwmodel.ZonaInternet); strings.Join(depois, ",") != "r-3,r-2,r-ok" {
		t.Errorf("ordem = %v", depois)
	}
}

func TestFirewallValorQueOBancoNaoAceitaDevolve400(t *testing.T) {
	db, _, _, _, userW, router := setupFirewallTestRouter(t)
	semearConfigValida(t, db)

	cenarios := []struct{ nome, caminho, corpo string }{
		{"zona desconhecida", "/api/firewall/regras",
			`{"zona":"dmz","acao":"accept","proto":"tcp","origem":{"kind":"any"},"destino":{"kind":"self"},"porta_destino":{"kind":"any"}}`},
		{"ação desconhecida", "/api/firewall/regras",
			`{"zona":"internet","acao":"queimar","proto":"tcp","origem":{"kind":"any"},"destino":{"kind":"self"},"porta_destino":{"kind":"any"}}`},
		{"tipo de alias desconhecido", "/api/firewall/aliases",
			`{"nome":"Redes","tipo":"redes","itens":[]}`},
		{"protocolo de encaminhamento desconhecido", "/api/firewall/nat",
			`{"nome":"Ping","proto":"icmp","porta_externa":2222,"ip_destino":"10.0.0.9","porta_destino":22}`},
	}
	for _, c := range cenarios {
		t.Run(c.nome, func(t *testing.T) {
			antes := configEmEdicaoJSON(t, db)
			res := doReq(router, http.MethodPost, c.caminho, userW.ID, c.corpo)
			if res.Code != http.StatusBadRequest {
				t.Fatalf("esperava 400, obteve %d: %s", res.Code, res.Body.String())
			}
			for _, vazou := range []string{"constraint", "CHECK", "SQLITE", "fw_"} {
				if strings.Contains(res.Body.String(), vazou) {
					t.Errorf("a resposta vazou o banco (%q): %s", vazou, res.Body.String())
				}
			}
			if depois := configEmEdicaoJSON(t, db); depois != antes {
				t.Errorf("a recusa deixou rastro na configuração em edição")
			}
		})
	}
}

func TestFirewallFalhaDoBancoContinua500SemVazarOBanco(t *testing.T) {
	db, _, _, _, userW, router := setupFirewallTestRouter(t)
	semearConfigValida(t, db)

	if _, err := db.Conn().Exec(`DROP TABLE fw_agendamentos`); err != nil {
		t.Fatal(err)
	}
	res := doReq(router, http.MethodPost, "/api/firewall/aliases", userW.ID,
		`{"nome":"Novo","tipo":"enderecos","itens":["10.0.0.1"]}`)
	if res.Code != http.StatusInternalServerError {
		t.Fatalf("falha do banco esperava 500, obteve %d: %s", res.Code, res.Body.String())
	}
	for _, vazou := range []string{"no such table", "fw_agendamentos", "sql", "SQL"} {
		if strings.Contains(res.Body.String(), vazou) {
			t.Errorf("a resposta vazou o banco (%q): %s", vazou, res.Body.String())
		}
	}
}
