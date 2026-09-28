package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-cloud/internal/fwmodel"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

type respostaComProblemas struct {
	Erro      string             `json:"erro"`
	Problemas []fwmodel.Problema `json:"problemas"`
}

func temProblema(ps []fwmodel.Problema, chave string) bool {
	for _, p := range ps {
		if p.Chave == chave {
			return true
		}
	}
	return false
}

func configEmEdicaoJSON(t *testing.T, db *storage.DB) string {
	t.Helper()
	cfg, err := db.CarregarConfigEmEdicao()
	if err != nil {
		t.Fatalf("CarregarConfigEmEdicao: %v", err)
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal da configuração: %v", err)
	}
	return string(b)
}

// semearConfigValida grava, direto no banco, uma configuração sem nenhum erro
// e os pares que os testes de escrita precisam para atualizar e conflitar.
func semearConfigValida(t *testing.T, db *storage.DB) {
	t.Helper()
	if err := db.CriarAliasFW(&fwmodel.Alias{
		ID: "a-ok", Nome: "Servidores", Tipo: fwmodel.AliasTipoEnderecos, Itens: []string{"10.0.1.10"},
	}); err != nil {
		t.Fatalf("CriarAliasFW: %v", err)
	}
	if err := db.CriarAgendamentoFW(&fwmodel.Agendamento{
		ID: "ag-ok", Nome: "Comercial", Dias: "mon,tue,wed,thu,fri", Inicio: "08:00", Fim: "18:00",
	}); err != nil {
		t.Fatalf("CriarAgendamentoFW: %v", err)
	}
	if err := db.CriarRegraFW(&fwmodel.Regra{
		ID: "r-ok", Zona: fwmodel.ZonaInternet, Ativa: true, Acao: fwmodel.AcaoAccept, Proto: fwmodel.ProtoTCP,
		Origem:       fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
		Destino:      fwmodel.Ponta{Tipo: fwmodel.PontaEste},
		PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaValor, Valor: "22"},
		Descricao:    "SSH",
	}); err != nil {
		t.Fatalf("CriarRegraFW: %v", err)
	}
	for _, e := range []fwmodel.Encaminhamento{
		{ID: "n-on", Nome: "Web", Ativo: true, Proto: "tcp", PortaExterna: 8080, IPDestino: "10.0.0.5", PortaDestino: 80},
		{ID: "n-off", Nome: "Web reserva", Ativo: false, Proto: "tcp", PortaExterna: 8080, IPDestino: "10.0.0.6", PortaDestino: 80},
	} {
		e := e
		if err := db.CriarEncaminhamentoFW(&e); err != nil {
			t.Fatalf("CriarEncaminhamentoFW: %v", err)
		}
	}
	if cfg, err := db.CarregarConfigEmEdicao(); err != nil {
		t.Fatalf("CarregarConfigEmEdicao: %v", err)
	} else if ps := fwmodel.Validar(cfg, []string{"user-alice"}); fwmodel.TemErro(ps) {
		t.Fatalf("a semente deveria ser válida: %+v", ps)
	}
}

func TestFirewallEscritaInvalidaDevolve400ComProblemasENaoGrava(t *testing.T) {
	db, _, _, _, userW, router := setupFirewallTestRouter(t)
	semearConfigValida(t, db)

	regraCompleta := func(sub string) string {
		return `{"zona":"internet","acao":"accept","proto":"tcp","descricao":"x",` + sub + `}`
	}
	cenarios := []struct {
		nome, metodo, caminho, corpo, chave string
	}{
		{"regra com porta fora da faixa", http.MethodPost, "/api/firewall/regras",
			regraCompleta(`"origem":{"kind":"any"},"destino":{"kind":"self"},"porta_destino":{"kind":"port","value":"99999"}`),
			"fwz.problema.portaValorInvalido"},
		{"regra com origem que não é endereço", http.MethodPost, "/api/firewall/regras",
			regraCompleta(`"origem":{"kind":"addr","value":"300.1.1.1"},"destino":{"kind":"self"},"porta_destino":{"kind":"any"}`),
			"fwz.problema.origemEnderecoInvalido"},
		{"regra sem origem, destino e porta", http.MethodPost, "/api/firewall/regras",
			`{"zona":"internet","acao":"accept","descricao":"incompleta"}`,
			"fwz.problema.origemTipoInvalido"},
		{"regra apontando para alias que não existe", http.MethodPut, "/api/firewall/regras/r-ok",
			regraCompleta(`"origem":{"kind":"any"},"destino":{"kind":"alias","value":"a-fantasma"},"porta_destino":{"kind":"any"}`),
			"fwz.problema.destinoAliasInexistente"},
		{"alias com endereço inválido", http.MethodPost, "/api/firewall/aliases",
			`{"nome":"Ruim","tipo":"enderecos","itens":["999.1.1.1"]}`,
			"fwz.problema.aliasItemEnderecoInvalido"},
		{"alias existente com item inválido", http.MethodPut, "/api/firewall/aliases/a-ok",
			`{"nome":"Servidores","tipo":"enderecos","itens":["nao-e-ip"]}`,
			"fwz.problema.aliasItemEnderecoInvalido"},
		{"agendamento com hora inexistente", http.MethodPost, "/api/firewall/agendamentos",
			`{"nome":"Ruim","dias":"mon","inicio":"25:00","fim":"18:00"}`,
			"fwz.problema.agendamentoHorarioInvalido"},
		{"agendamento existente com dia inválido", http.MethodPut, "/api/firewall/agendamentos/ag-ok",
			`{"nome":"Comercial","dias":"funday","inicio":"08:00","fim":"18:00"}`,
			"fwz.problema.agendamentoDiasInvalidos"},
		{"encaminhamento com porta externa fora da faixa", http.MethodPost, "/api/firewall/nat",
			`{"nome":"Ruim","proto":"tcp","porta_externa":70000,"ip_destino":"10.0.0.2","porta_destino":80}`,
			"fwz.problema.encaminhamentoPortaExternaInvalida"},
		{"encaminhamento existente com IP inválido", http.MethodPut, "/api/firewall/nat/n-on",
			`{"nome":"Web","proto":"tcp","porta_externa":8080,"ip_destino":"nao-e-ip","porta_destino":80,"ativo":true}`,
			"fwz.problema.encaminhamentoIPDestinoInvalido"},
		{"ativar encaminhamento que colide com outro ativo", http.MethodPost, "/api/firewall/nat/n-off/ativar",
			`{"ativo":true}`,
			"fwz.problema.encaminhamentoPortaExternaConflito"},
		{"ajustes com zona de anti-bloqueio inexistente", http.MethodPut, "/api/firewall/ajustes",
			`{"anti_bloqueio":{"xyz":true}}`,
			"fwz.problema.ajustesAntiBloqueioZonaInvalida"},
		{"rede extra da VCN inválida", http.MethodPut, "/api/firewall/aliases/sys:vcn/extras",
			`{"redes":["300.0.0.0/8"]}`,
			"fwz.problema.ajustesRedeVCNInvalida"},
	}

	for _, c := range cenarios {
		t.Run(c.nome, func(t *testing.T) {
			antes := configEmEdicaoJSON(t, db)

			res := doReq(router, c.metodo, c.caminho, userW.ID, c.corpo)
			if res.Code != http.StatusBadRequest {
				t.Fatalf("%s %s esperava 400, obteve %d: %s", c.metodo, c.caminho, res.Code, res.Body.String())
			}
			var corpo respostaComProblemas
			if err := json.Unmarshal(res.Body.Bytes(), &corpo); err != nil {
				t.Fatalf("decodificar resposta: %v", err)
			}
			if corpo.Erro == "" {
				t.Error("a resposta deveria trazer um resumo em 'erro'")
			}
			if !temProblema(corpo.Problemas, c.chave) {
				t.Errorf("faltou o problema %s em %+v", c.chave, corpo.Problemas)
			}
			for _, p := range corpo.Problemas {
				if p.Severidade != "erro" {
					t.Errorf("a recusa só deveria listar erros, veio %+v", p)
				}
			}

			if depois := configEmEdicaoJSON(t, db); depois != antes {
				t.Errorf("a escrita recusada deixou rastro na configuração em edição:\nantes:  %s\ndepois: %s", antes, depois)
			}
		})
	}
}

func TestFirewallEscritaValidaContinuaPassando(t *testing.T) {
	db, _, _, _, userW, router := setupFirewallTestRouter(t)
	semearConfigValida(t, db)

	cenarios := []struct {
		nome, metodo, caminho, corpo string
		status                       int
	}{
		{"regra completa", http.MethodPost, "/api/firewall/regras",
			`{"zona":"vcn","acao":"drop","proto":"tcp","origem":{"kind":"any"},"destino":{"kind":"alias","value":"a-ok"},"porta_destino":{"kind":"port","value":"3306"},"descricao":"sem banco"}`,
			http.StatusCreated},
		{"alias válido", http.MethodPost, "/api/firewall/aliases",
			`{"nome":"Portas web","tipo":"portas","itens":["80","443","8000-8100"]}`, http.StatusCreated},
		{"agendamento válido", http.MethodPost, "/api/firewall/agendamentos",
			`{"nome":"Noite","dias":"sat,sun","inicio":"20:00","fim":"23:30"}`, http.StatusCreated},
		{"encaminhamento válido", http.MethodPost, "/api/firewall/nat",
			`{"nome":"SSH alternativo","proto":"tcp","porta_externa":2222,"ip_destino":"10.0.0.9","porta_destino":22}`, http.StatusCreated},
		{"desativar encaminhamento", http.MethodPost, "/api/firewall/nat/n-on/ativar", `{"ativo":false}`, http.StatusOK},
		{"ajustes", http.MethodPut, "/api/firewall/ajustes", `{"anti_bloqueio":{"vcn":true},"registrar_bloqueados":true}`, http.StatusOK},
		{"rede extra da VCN", http.MethodPut, "/api/firewall/aliases/sys:vcn/extras", `{"redes":["172.16.0.0/12"]}`, http.StatusOK},
	}
	for _, c := range cenarios {
		res := doReq(router, c.metodo, c.caminho, userW.ID, c.corpo)
		if res.Code != c.status {
			t.Errorf("%s: %s %s esperava %d, obteve %d: %s", c.nome, c.metodo, c.caminho, c.status, res.Code, res.Body.String())
		}
	}
}

func TestFirewallLeiturasToleramConfigInvalida(t *testing.T) {
	db, _, _, userR, _, router := setupFirewallTestRouter(t)
	semearConfigValida(t, db)

	// Grava direto no banco o que o painel não deixaria gravar: é o caso de
	// uma configuração herdada, ou de um defeito que escapou.
	if err := db.CriarAliasFW(&fwmodel.Alias{
		ID: "a-ruim", Nome: "Ruim", Tipo: fwmodel.AliasTipoEnderecos, Itens: []string{"999.9.9.9"},
	}); err != nil {
		t.Fatalf("CriarAliasFW: %v", err)
	}
	if err := db.CriarRegraFW(&fwmodel.Regra{
		ID: "r-ruim", Zona: fwmodel.ZonaVCN, Ativa: true, Acao: fwmodel.AcaoDrop, Proto: fwmodel.ProtoTCP,
		Origem:       fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
		Destino:      fwmodel.Ponta{Tipo: fwmodel.PontaAlias, Valor: "a-fantasma"},
		PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaQualquer},
		Descricao:    "aponta para o nada",
	}); err != nil {
		t.Fatalf("CriarRegraFW: %v", err)
	}

	for _, caminho := range []string{
		"/api/firewall/estado",
		"/api/firewall/pendencias",
		"/api/firewall/regras?zona=flutuante",
		"/api/firewall/regras?zona=internet",
		"/api/firewall/regras?zona=vcn",
		"/api/firewall/regras?zona=vpn",
		"/api/firewall/aliases",
		"/api/firewall/agendamentos",
		"/api/firewall/nat",
		"/api/firewall/ajustes",
	} {
		res := doReq(router, http.MethodGet, caminho, userR.ID, "")
		if res.Code != http.StatusOK {
			t.Errorf("GET %s com configuração inválida esperava 200, obteve %d: %s", caminho, res.Code, res.Body.String())
		}
	}

	res := doReq(router, http.MethodGet, "/api/firewall/pendencias", userR.ID, "")
	var pend struct {
		Mudancas  []fwmodel.Mudanca  `json:"mudancas"`
		Problemas []fwmodel.Problema `json:"problemas"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &pend); err != nil {
		t.Fatalf("decodificar pendências: %v", err)
	}
	for _, chave := range []string{"fwz.problema.aliasItemEnderecoInvalido", "fwz.problema.destinoAliasInexistente"} {
		if !temProblema(pend.Problemas, chave) {
			t.Errorf("as pendências deveriam listar %s: %+v", chave, pend.Problemas)
		}
	}
	if len(pend.Mudancas) == 0 {
		t.Error("as pendências deveriam listar as mudanças mesmo com a configuração inválida")
	}

	// A tabela continua mostrando as regras do administrador, só sem o nft.
	res = doReq(router, http.MethodGet, "/api/firewall/regras?zona=vcn", userR.ID, "")
	var tabela struct {
		Linhas []LinhaView `json:"linhas"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &tabela); err != nil {
		t.Fatalf("decodificar regras: %v", err)
	}
	var achou bool
	for _, l := range tabela.Linhas {
		if l.Chave == "r:r-ruim" {
			achou = true
			if l.Nft == nil {
				t.Error("nft deveria ser lista vazia, não nulo")
			}
		}
	}
	if !achou {
		t.Errorf("a regra inválida deveria aparecer na tabela para o operador poder consertá-la: %+v", tabela.Linhas)
	}
}

func TestFirewallPendenciasSemProblemasDevolveListasVazias(t *testing.T) {
	db, _, _, userR, _, router := setupFirewallTestRouter(t)
	semearConfigValida(t, db)

	res := doReq(router, http.MethodGet, "/api/firewall/pendencias", userR.ID, "")
	if res.Code != http.StatusOK {
		t.Fatalf("GET /pendencias: %d: %s", res.Code, res.Body.String())
	}
	var bruto map[string]json.RawMessage
	if err := json.Unmarshal(res.Body.Bytes(), &bruto); err != nil {
		t.Fatalf("decodificar: %v", err)
	}
	if got := strings.TrimSpace(string(bruto["problemas"])); got != "[]" {
		t.Errorf("problemas deveria ser [] quando não há nenhum, veio %s", got)
	}
}

func TestFirewallErroAntigoNaoTrancaEdicaoDeOutroObjeto(t *testing.T) {
	db, _, _, _, userW, router := setupFirewallTestRouter(t)
	semearConfigValida(t, db)
	if err := db.CriarAliasFW(&fwmodel.Alias{
		ID: "a-ruim", Nome: "Ruim", Tipo: fwmodel.AliasTipoEnderecos, Itens: []string{"999.9.9.9"},
	}); err != nil {
		t.Fatalf("CriarAliasFW: %v", err)
	}

	res := doReq(router, http.MethodPost, "/api/firewall/agendamentos", userW.ID,
		`{"nome":"Noite","dias":"sat","inicio":"20:00","fim":"23:30"}`)
	if res.Code != http.StatusCreated {
		t.Fatalf("um defeito herdado em outro objeto não devia impedir a edição: %d: %s", res.Code, res.Body.String())
	}

	// Mexer no próprio objeto defeituoso, sem consertá-lo, continua recusado.
	res = doReq(router, http.MethodPut, "/api/firewall/aliases/a-ruim", userW.ID,
		`{"nome":"Ruim","tipo":"enderecos","descricao":"só a descrição","itens":["999.9.9.9"]}`)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("salvar o alias ainda defeituoso esperava 400, obteve %d: %s", res.Code, res.Body.String())
	}

	// E consertá-lo é o caminho que precisa funcionar.
	res = doReq(router, http.MethodPut, "/api/firewall/aliases/a-ruim", userW.ID,
		`{"nome":"Ruim","tipo":"enderecos","itens":["10.9.9.9"]}`)
	if res.Code != http.StatusOK {
		t.Fatalf("consertar o alias esperava 200, obteve %d: %s", res.Code, res.Body.String())
	}
}

func TestFirewallTrocarTipoDeAliasEmUsoERecusado(t *testing.T) {
	db, _, _, _, userW, router := setupFirewallTestRouter(t)
	semearConfigValida(t, db)
	if err := db.CriarRegraFW(&fwmodel.Regra{
		ID: "r-usa", Zona: fwmodel.ZonaVCN, Ativa: true, Acao: fwmodel.AcaoDrop, Proto: fwmodel.ProtoTCP,
		Origem:       fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
		Destino:      fwmodel.Ponta{Tipo: fwmodel.PontaAlias, Valor: "a-ok"},
		PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaQualquer},
		Descricao:    "usa o alias de endereços",
	}); err != nil {
		t.Fatalf("CriarRegraFW: %v", err)
	}
	antes := configEmEdicaoJSON(t, db)

	res := doReq(router, http.MethodPut, "/api/firewall/aliases/a-ok", userW.ID,
		`{"nome":"Servidores","tipo":"portas","itens":["443"]}`)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("trocar o tipo de um alias em uso esperava 400, obteve %d: %s", res.Code, res.Body.String())
	}
	var corpo respostaComProblemas
	_ = json.Unmarshal(res.Body.Bytes(), &corpo)
	if !temProblema(corpo.Problemas, "fwz.problema.destinoAliasTipoInvalido") {
		t.Errorf("a regra que ficaria quebrada deveria ser apontada: %+v", corpo.Problemas)
	}
	if depois := configEmEdicaoJSON(t, db); depois != antes {
		t.Error("a troca recusada não pode deixar rastro")
	}
}

func TestFirewallAtivarRegraDefeituosaERecusado(t *testing.T) {
	db, _, _, _, userW, router := setupFirewallTestRouter(t)
	semearConfigValida(t, db)
	if err := db.CriarRegraFW(&fwmodel.Regra{
		ID: "r-off", Zona: fwmodel.ZonaVCN, Ativa: false, Acao: fwmodel.AcaoDrop, Proto: fwmodel.ProtoTCP,
		Origem:       fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
		Destino:      fwmodel.Ponta{Tipo: fwmodel.PontaAlias, Valor: "a-fantasma"},
		PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaQualquer},
		Descricao:    "desligada e quebrada",
	}); err != nil {
		t.Fatalf("CriarRegraFW: %v", err)
	}

	res := doReq(router, http.MethodPost, "/api/firewall/regras/r-off/ativar", userW.ID, `{"ativa":true}`)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("ligar uma regra que não fecha esperava 400, obteve %d: %s", res.Code, res.Body.String())
	}
	cfg, _ := db.CarregarConfigEmEdicao()
	for _, r := range cfg.Regras {
		if r.ID == "r-off" && r.Ativa {
			t.Error("a regra recusada não pode ter ficado ligada")
		}
	}
}

func TestFirewallDuplicarRegraDeDescricaoNoLimite(t *testing.T) {
	db, _, _, _, userW, router := setupFirewallTestRouter(t)
	semearConfigValida(t, db)
	longa := strings.Repeat("ç", fwmodel.MaxDescricaoRegra)
	if err := db.CriarRegraFW(&fwmodel.Regra{
		ID: "r-longa", Zona: fwmodel.ZonaInternet, Ativa: true, Acao: fwmodel.AcaoAccept, Proto: fwmodel.ProtoTCP,
		Origem:       fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
		Destino:      fwmodel.Ponta{Tipo: fwmodel.PontaEste},
		PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaValor, Valor: "8443"},
		Descricao:    longa,
	}); err != nil {
		t.Fatalf("CriarRegraFW: %v", err)
	}

	res := doReq(router, http.MethodPost, "/api/firewall/regras/r-longa/duplicar", userW.ID, "")
	if res.Code != http.StatusCreated {
		t.Fatalf("duplicar uma regra com a descrição no limite esperava 201, obteve %d: %s", res.Code, res.Body.String())
	}
	var copia fwmodel.Regra
	if err := json.Unmarshal(res.Body.Bytes(), &copia); err != nil {
		t.Fatalf("decodificar cópia: %v", err)
	}
	if n := len([]rune(copia.Descricao)); n > fwmodel.MaxDescricaoRegra || n == 0 {
		t.Errorf("a descrição da cópia deveria caber em %d caracteres, tem %d", fwmodel.MaxDescricaoRegra, n)
	}
}

func TestFirewallPreviaDeRegraInvalidaDevolveProblemasSem500(t *testing.T) {
	_, _, _, userR, _, router := setupFirewallTestRouter(t)

	res := doReq(router, http.MethodPost, "/api/firewall/regras/previa", userR.ID, `{
		"zona": "vcn", "acao": "drop", "proto": "tcp",
		"origem": {"kind": "any"},
		"destino": {"kind": "alias", "value": "a-fantasma"},
		"porta_destino": {"kind": "any"}
	}`)
	if res.Code != http.StatusOK {
		t.Fatalf("prévia de regra inválida esperava 200, obteve %d: %s", res.Code, res.Body.String())
	}
	var corpo struct {
		Problemas []fwmodel.Problema `json:"problemas"`
		NFT       []json.RawMessage  `json:"nft"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &corpo); err != nil {
		t.Fatalf("decodificar: %v", err)
	}
	if !temProblema(corpo.Problemas, "fwz.problema.destinoAliasInexistente") {
		t.Errorf("faltou o problema do alias: %+v", corpo.Problemas)
	}
	if corpo.NFT == nil || len(corpo.NFT) != 0 {
		t.Errorf("sem regra válida, nft deveria ser [] (veio %v)", corpo.NFT)
	}
}

func TestGetAjustesDevolveAsRedesExtrasDaVCN(t *testing.T) {
	_, _, _, userR, userW, router := setupFirewallTestRouter(t)

	if res := doReq(router, http.MethodPut, "/api/firewall/aliases/sys:vcn/extras", userW.ID, `{"redes":["172.16.0.0/12"]}`); res.Code != http.StatusOK {
		t.Fatalf("gravar extras: %d %s", res.Code, res.Body.String())
	}
	res := doReq(router, http.MethodGet, "/api/firewall/ajustes", userR.ID, "")
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"redes_vcn_extras":["172.16.0.0/12"]`) {
		t.Fatalf("a tela precisa reler o que gravou: %d %s", res.Code, res.Body.String())
	}

	// Gravar os ajustes não pode apagar as extras nem aceitar as do corpo.
	if res := doReq(router, http.MethodPut, "/api/firewall/ajustes", userW.ID, `{"registrar_bloqueados":true,"redes_vcn_extras":["192.168.0.0/16"]}`); res.Code != http.StatusOK {
		t.Fatalf("PUT ajustes: %d %s", res.Code, res.Body.String())
	}
	res = doReq(router, http.MethodGet, "/api/firewall/ajustes", userR.ID, "")
	if !strings.Contains(res.Body.String(), `"redes_vcn_extras":["172.16.0.0/12"]`) {
		t.Fatalf("as extras mudaram pelo PUT de ajustes: %s", res.Body.String())
	}
}
