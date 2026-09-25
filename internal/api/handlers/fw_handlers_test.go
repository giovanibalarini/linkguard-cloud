package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/giovanibalarini/linkguard-cloud/internal/auth"
	"github.com/giovanibalarini/linkguard-cloud/internal/firewallrules"
	"github.com/giovanibalarini/linkguard-cloud/internal/fwmodel"
	"github.com/giovanibalarini/linkguard-cloud/internal/nftables"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

type fwTestExec struct {
	executed []string
}

func (e *fwTestExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	e.executed = append(e.executed, cmd+" "+strings.Join(args, " "))
	return "", nil
}

func (e *fwTestExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	full := cmd + " " + strings.Join(args, " ")
	if strings.Contains(full, "-j list table") {
		return `{"nftables": []}`, nil
	}
	return "table inet linkguard {\n}\n", nil
}

func (e *fwTestExec) IsDryRun() bool                              { return false }
func (_ *fwTestExec) WriteFile(string, []byte, os.FileMode) error { return nil }

func setupFirewallTestRouter(t *testing.T) (*storage.DB, *FirewallHandler, *firewallrules.Service, *storage.User, *storage.User, *chi.Mux) {
	t.Helper()
	db := newTestDB(t)
	exec := &fwTestExec{}
	nftSvc := nftables.NewService(exec)
	frSvc := firewallrules.NewService(db, nftSvc)

	frSvc.SetFonteInsumos(func(ctx context.Context) (nftables.Insumos, error) {
		return nftables.Insumos{
			RedesVCN:       []string{"10.0.0.0/16"},
			RedeVPN:        "10.7.0.0/24",
			PortaWireGuard: 51820,
			InterfaceVPN:   "linkguard",
			PortasGerencia: []int{22, 443},
			Pessoas: []nftables.PessoaVPN{
				{
					UserID:   "user-alice",
					Usuario:  "alice",
					Endereco: "10.7.0.2",
					Total:    false,
					Aliases:  []string{"sys:vcn"},
				},
			},
		}, nil
	})

	roleR := &storage.Role{Name: "Leitor FW", Permissions: []string{string(auth.PermFirewallRead)}}
	roleW := &storage.Role{Name: "Escritor FW", Permissions: []string{string(auth.PermFirewallWrite)}}
	_ = db.CreateRole(roleR)
	_ = db.CreateRole(roleW)

	userR := &storage.User{Username: "leitor"}
	userW := &storage.User{Username: "escritor"}
	_ = db.CreateUser(userR, "hash", []string{roleR.ID})
	_ = db.CreateUser(userW, "hash", []string{roleW.ID})

	authSvc := auth.NewService(db, "test-secret-key-1234567890", nil)
	fwH := NewFirewallHandler(db, frSvc, nftSvc)

	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if uid := req.Header.Get("X-User"); uid != "" {
				req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid}))
			}
			next.ServeHTTP(w, req)
		})
	})

	require := authSvc.Require
	r.With(require(auth.PermFirewallRead)).Get("/api/firewall/estado", fwH.GetEstado)
	r.With(require(auth.PermFirewallWrite)).Post("/api/firewall/conversao/entendi", fwH.EntendiConversao)
	r.With(require(auth.PermFirewallRead)).Get("/api/firewall/ajustes", fwH.GetAjustes)
	r.With(require(auth.PermFirewallWrite)).Put("/api/firewall/ajustes", fwH.PutAjustes)
	r.With(require(auth.PermFirewallRead)).Get("/api/firewall/regras", fwH.GetRegras)
	r.With(require(auth.PermFirewallWrite)).Post("/api/firewall/regras", fwH.CriarRegra)
	r.With(require(auth.PermFirewallRead)).Post("/api/firewall/regras/previa", fwH.PreviaRegra)
	r.With(require(auth.PermFirewallWrite)).Post("/api/firewall/regras/ordem", fwH.ReordenarRegras)
	r.With(require(auth.PermFirewallWrite)).Post("/api/firewall/regras/{id}/ativar", fwH.AtivarRegra)
	r.With(require(auth.PermFirewallWrite)).Post("/api/firewall/regras/{id}/duplicar", fwH.DuplicarRegra)
	r.With(require(auth.PermFirewallWrite)).Put("/api/firewall/regras/{id}", fwH.AtualizarRegra)
	r.With(require(auth.PermFirewallWrite)).Delete("/api/firewall/regras/{id}", fwH.ApagarRegra)
	r.With(require(auth.PermFirewallRead)).Get("/api/firewall/aliases", fwH.GetAliases)
	r.With(require(auth.PermFirewallWrite)).Post("/api/firewall/aliases", fwH.CriarAlias)
	r.With(require(auth.PermFirewallWrite)).Put("/api/firewall/aliases/sys:vcn/extras", fwH.PutVCNExtras)
	r.With(require(auth.PermFirewallWrite)).Put("/api/firewall/aliases/{id}", fwH.AtualizarAlias)
	r.With(require(auth.PermFirewallWrite)).Delete("/api/firewall/aliases/{id}", fwH.ApagarAlias)
	r.With(require(auth.PermFirewallRead)).Get("/api/firewall/agendamentos", fwH.GetAgendamentos)
	r.With(require(auth.PermFirewallWrite)).Post("/api/firewall/agendamentos", fwH.CriarAgendamento)
	r.With(require(auth.PermFirewallWrite)).Put("/api/firewall/agendamentos/{id}", fwH.AtualizarAgendamento)
	r.With(require(auth.PermFirewallWrite)).Delete("/api/firewall/agendamentos/{id}", fwH.ApagarAgendamento)
	r.With(require(auth.PermFirewallRead)).Get("/api/firewall/nat", fwH.GetNAT)
	r.With(require(auth.PermFirewallWrite)).Post("/api/firewall/nat", fwH.CriarNAT)
	r.With(require(auth.PermFirewallWrite)).Post("/api/firewall/nat/{id}/ativar", fwH.AtivarNAT)
	r.With(require(auth.PermFirewallWrite)).Put("/api/firewall/nat/{id}", fwH.AtualizarNAT)
	r.With(require(auth.PermFirewallWrite)).Delete("/api/firewall/nat/{id}", fwH.ApagarNAT)
	r.With(require(auth.PermFirewallRead)).Get("/api/firewall/pendencias", fwH.GetPendencias)
	r.With(require(auth.PermFirewallWrite)).Post("/api/firewall/aplicar", fwH.Aplicar)
	r.With(require(auth.PermFirewallWrite)).Post("/api/firewall/descartar", fwH.Descartar)
	r.With(require(auth.PermFirewallRead)).Get("/api/firewall/historico", fwH.GetHistorico)
	r.With(require(auth.PermFirewallWrite)).Post("/api/firewall/historico/{id}/restaurar", fwH.RestaurarRevisao)

	return db, fwH, frSvc, userR, userW, r
}

func doReq(router *chi.Mux, method, path, userID, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	if userID != "" {
		req.Header.Set("X-User", userID)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestFirewallRoutesPermissions(t *testing.T) {
	_, _, _, userR, userW, router := setupFirewallTestRouter(t)

	// Anônimo -> 401
	res := doReq(router, http.MethodGet, "/api/firewall/estado", "", "")
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("anônimo esperava 401, obteve %d", res.Code)
	}

	// Leitor pode ler estado
	res = doReq(router, http.MethodGet, "/api/firewall/estado", userR.ID, "")
	if res.Code != http.StatusOK {
		t.Fatalf("leitor esperava 200 em GET /estado, obteve %d", res.Code)
	}

	// Leitor NÃO pode criar regra -> 403
	res = doReq(router, http.MethodPost, "/api/firewall/regras", userR.ID, `{"zona":"internet","acao":"accept"}`)
	if res.Code != http.StatusForbidden {
		t.Fatalf("leitor esperava 403 em POST /regras, obteve %d", res.Code)
	}

	// Leitor NÃO pode aplicar -> 403
	res = doReq(router, http.MethodPost, "/api/firewall/aplicar", userR.ID, "")
	if res.Code != http.StatusForbidden {
		t.Fatalf("leitor esperava 403 em POST /aplicar, obteve %d", res.Code)
	}

	// Escritor pode criar regra -> 201
	res = doReq(router, http.MethodPost, "/api/firewall/regras", userW.ID, `{"zona":"internet","acao":"accept","descricao":"Liberar web"}`)
	if res.Code != http.StatusCreated {
		t.Fatalf("escritor esperava 201 em POST /regras, obteve %d: %s", res.Code, res.Body.String())
	}
}

func TestFirewallMutations409WhenWindowOpen(t *testing.T) {
	db, _, _, _, userW, router := setupFirewallTestRouter(t)

	// Abre uma janela pendente
	_ = db.SavePendingChange(storage.PendingChange{
		ID:        "window-1",
		Summary:   "Mudança teste",
		AppliedBy: "admin",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(90 * time.Second),
		Snapshot:  "{}",
	})

	mutations := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodPost, "/api/firewall/regras", `{"zona":"internet"}`},
		{http.MethodPut, "/api/firewall/ajustes", `{"registrar_bloqueados":true}`},
		{http.MethodPost, "/api/firewall/aliases", `{"nome":"teste","tipo":"enderecos","itens":["10.0.0.1"]}`},
		{http.MethodPost, "/api/firewall/agendamentos", `{"nome":"comercial","dias":"mon","inicio":"08:00","fim":"18:00"}`},
		{http.MethodPost, "/api/firewall/nat", `{"nome":"web","proto":"tcp","porta_externa":80,"ip_destino":"10.0.0.2","porta_destino":80}`},
		{http.MethodPost, "/api/firewall/descartar", ""},
		{http.MethodPost, "/api/firewall/aplicar", ""},
	}

	for _, m := range mutations {
		res := doReq(router, m.method, m.path, userW.ID, m.body)
		if res.Code != http.StatusConflict {
			t.Errorf("%s %s esperava 409 com janela aberta, obteve %d: %s", m.method, m.path, res.Code, res.Body.String())
		}
	}
}

func TestFirewallAliasEmUso409(t *testing.T) {
	db, _, _, _, userW, router := setupFirewallTestRouter(t)

	alias := fwmodel.Alias{
		ID:        "alias-srv",
		Nome:      "Servidores",
		Tipo:      fwmodel.AliasTipoEnderecos,
		Descricao: "Servidores internos",
		Itens:     []string{"10.0.1.10"},
	}
	if err := db.CriarAliasFW(&alias); err != nil {
		t.Fatalf("CriarAliasFW: %v", err)
	}

	// Adiciona regra que usa o alias
	regra := fwmodel.Regra{
		ID:           "r-1",
		Zona:         fwmodel.ZonaInternet,
		Ativa:        true,
		Acao:         fwmodel.AcaoAccept,
		Proto:        fwmodel.ProtoTCP,
		Destino:      fwmodel.Ponta{Tipo: fwmodel.PontaAlias, Valor: "alias-srv"},
		PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaValor, Valor: "443"},
		Descricao:    "HTTPS para servidores",
	}
	if err := db.CriarRegraFW(&regra); err != nil {
		t.Fatalf("CriarRegraFW: %v", err)
	}

	// Tentativa de apagar o alias em uso -> 409
	res := doReq(router, http.MethodDelete, "/api/firewall/aliases/alias-srv", userW.ID, "")
	if res.Code != http.StatusConflict {
		t.Fatalf("esperava 409 ao apagar alias em uso, obteve %d: %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), "alias em uso") {
		t.Errorf("resposta esperava conter 'alias em uso': %s", res.Body.String())
	}

	// Tentativa de apagar alias embutido sys:vcn -> 400
	res = doReq(router, http.MethodDelete, "/api/firewall/aliases/sys:vcn", userW.ID, "")
	if res.Code != http.StatusBadRequest {
		t.Fatalf("esperava 400 ao apagar sys:vcn, obteve %d", res.Code)
	}
}

func TestFirewallAgendamentoEmUso409(t *testing.T) {
	db, _, _, _, userW, router := setupFirewallTestRouter(t)

	ag := fwmodel.Agendamento{
		ID:        "ag-comercial",
		Nome:      "Horário comercial",
		Dias:      "mon,tue,wed,thu,fri",
		Inicio:    "08:00",
		Fim:       "18:00",
		Descricao: "Dias úteis",
	}
	if err := db.CriarAgendamentoFW(&ag); err != nil {
		t.Fatalf("CriarAgendamentoFW: %v", err)
	}

	regra := fwmodel.Regra{
		ID:            "r-ag",
		Zona:          fwmodel.ZonaInternet,
		Ativa:         true,
		Acao:          fwmodel.AcaoAccept,
		Proto:         fwmodel.ProtoTCP,
		AgendamentoID: "ag-comercial",
		Descricao:     "Regra agendada",
	}
	if err := db.CriarRegraFW(&regra); err != nil {
		t.Fatalf("CriarRegraFW: %v", err)
	}

	res := doReq(router, http.MethodDelete, "/api/firewall/agendamentos/ag-comercial", userW.ID, "")
	if res.Code != http.StatusConflict {
		t.Fatalf("esperava 409 ao apagar agendamento em uso, obteve %d: %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), "agendamento em uso") {
		t.Errorf("resposta esperava conter 'agendamento em uso': %s", res.Body.String())
	}
}

func TestFirewallPreviaDevolveLinhasNFT(t *testing.T) {
	_, _, _, userR, _, router := setupFirewallTestRouter(t)

	body := `{
		"zona": "internet",
		"acao": "accept",
		"proto": "tcp",
		"origem": { "kind": "any" },
		"destino": { "kind": "self" },
		"porta_destino": { "kind": "port", "value": "22" },
		"descricao": "SSH aberto"
	}`

	res := doReq(router, http.MethodPost, "/api/firewall/regras/previa", userR.ID, body)
	if res.Code != http.StatusOK {
		t.Fatalf("esperava 200 em prévia, obteve %d: %s", res.Code, res.Body.String())
	}

	var resp struct {
		NFT       []nftables.LinhaNft `json:"nft"`
		Problemas []fwmodel.Problema  `json:"problemas"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decodificar resposta: %v", err)
	}

	if len(resp.Problemas) > 0 {
		t.Errorf("não esperava problemas de validação: %+v", resp.Problemas)
	}
	if len(resp.NFT) == 0 {
		t.Fatal("esperava comandos nft na prévia")
	}

	achou := false
	for _, cmd := range resp.NFT {
		if cmd.Chain == "zona_inet_in" && strings.Contains(cmd.Texto, "tcp dport 22 counter accept") {
			achou = true
			break
		}
	}
	if !achou {
		t.Errorf("comando nft esperado não encontrado na prévia: %+v", resp.NFT)
	}
}

func TestFirewallRegrasZonaVPNTrazTravadasEPadrao(t *testing.T) {
	_, _, _, userR, _, router := setupFirewallTestRouter(t)

	res := doReq(router, http.MethodGet, "/api/firewall/regras?zona=vpn", userR.ID, "")
	if res.Code != http.StatusOK {
		t.Fatalf("GET /regras?zona=vpn esperava 200, obteve %d: %s", res.Code, res.Body.String())
	}

	var resp struct {
		Zona   string      `json:"zona"`
		Linhas []LinhaView `json:"linhas"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decodificar resposta: %v", err)
	}

	if resp.Zona != "vpn" {
		t.Errorf("zona esperada 'vpn', obteve %q", resp.Zona)
	}
	if len(resp.Linhas) == 0 {
		t.Fatal("esperava linhas na zona vpn")
	}

	// Verifica presença da linha travada de DNS
	var achouDNS, achouAlice, achouPadrao bool
	for i, l := range resp.Linhas {
		if l.Tipo == "travada" && l.Chave == "s:dns-vpn" {
			achouDNS = true
		}
		if l.Tipo == "travada" && strings.HasPrefix(l.Chave, "s:vpn:user-alice:") {
			achouAlice = true
		}
		if i == len(resp.Linhas)-1 && l.Tipo == "padrao" && l.Chave == "d:vpn:fwd" {
			achouPadrao = true
		}
	}

	if !achouDNS {
		t.Error("linha travada de DNS não encontrada na zona vpn")
	}
	if !achouAlice {
		t.Error("linha travada da pessoa alice não encontrada na zona vpn")
	}
	if !achouPadrao {
		t.Error("última linha da zona vpn deve ser a regra padrão de bloqueio (d:vpn:fwd)")
	}
}

func TestFirewallAplicarEDescartar(t *testing.T) {
	_, _, _, userR, userW, router := setupFirewallTestRouter(t)

	// Inicialmente sem regras, mas como fw_aplicado está vazio ou idêntico:
	res := doReq(router, http.MethodGet, "/api/firewall/pendencias", userR.ID, "")
	if res.Code != http.StatusOK {
		t.Fatalf("GET /pendencias: %d", res.Code)
	}

	// Adiciona regra em edição
	res = doReq(router, http.MethodPost, "/api/firewall/regras", userW.ID, `{
		"zona": "internet",
		"acao": "accept",
		"proto": "tcp",
		"origem": { "kind": "any" },
		"destino": { "kind": "self" },
		"porta_destino": { "kind": "port", "value": "80" },
		"descricao": "HTTP"
	}`)
	if res.Code != http.StatusCreated {
		t.Fatalf("criar regra: %d: %s", res.Code, res.Body.String())
	}

	// Agora há pendência
	res = doReq(router, http.MethodGet, "/api/firewall/pendencias", userR.ID, "")
	var pend firewallrules.Pendencias
	_ = json.Unmarshal(res.Body.Bytes(), &pend)
	if !pend.Pendente {
		t.Fatal("esperava pendente = true após criar regra")
	}

	// Aplica
	res = doReq(router, http.MethodPost, "/api/firewall/aplicar", userW.ID, "")
	if res.Code != http.StatusOK {
		t.Fatalf("POST /aplicar: %d: %s", res.Code, res.Body.String())
	}

	// Sem pendências agora
	res = doReq(router, http.MethodGet, "/api/firewall/pendencias", userR.ID, "")
	_ = json.Unmarshal(res.Body.Bytes(), &pend)
	if pend.Pendente {
		t.Fatal("esperava pendente = false após aplicar")
	}

	// Faz outra alteração (modifica ajustes)
	res = doReq(router, http.MethodPut, "/api/firewall/ajustes", userW.ID, `{"registrar_bloqueados": true}`)
	if res.Code != http.StatusOK {
		t.Fatalf("PUT /ajustes: %d", res.Code)
	}

	res = doReq(router, http.MethodGet, "/api/firewall/pendencias", userR.ID, "")
	_ = json.Unmarshal(res.Body.Bytes(), &pend)
	if !pend.Pendente {
		t.Fatal("esperava pendente = true após alterar ajustes")
	}

	// Descarta
	res = doReq(router, http.MethodPost, "/api/firewall/descartar", userW.ID, "")
	if res.Code != http.StatusOK {
		t.Fatalf("POST /descartar: %d: %s", res.Code, res.Body.String())
	}

	// Sem pendências após descarte
	res = doReq(router, http.MethodGet, "/api/firewall/pendencias", userR.ID, "")
	_ = json.Unmarshal(res.Body.Bytes(), &pend)
	if pend.Pendente {
		t.Fatal("esperava pendente = false após descartar")
	}
}

func TestFirewallDuplicarEReordenar(t *testing.T) {
	_, _, _, userR, userW, router := setupFirewallTestRouter(t)

	// Cria regra 1
	res := doReq(router, http.MethodPost, "/api/firewall/regras", userW.ID, `{
		"zona": "internet",
		"acao": "accept",
		"proto": "tcp",
		"origem": { "kind": "any" },
		"destino": { "kind": "self" },
		"porta_destino": { "kind": "port", "value": "8080" },
		"descricao": "Original"
	}`)
	var r1 fwmodel.Regra
	_ = json.Unmarshal(res.Body.Bytes(), &r1)

	// Duplica regra 1
	res = doReq(router, http.MethodPost, "/api/firewall/regras/"+r1.ID+"/duplicar", userW.ID, "")
	if res.Code != http.StatusCreated {
		t.Fatalf("POST duplicar: %d: %s", res.Code, res.Body.String())
	}
	var r2 fwmodel.Regra
	_ = json.Unmarshal(res.Body.Bytes(), &r2)

	if r2.ID == r1.ID {
		t.Fatalf("regra duplicada deve ter ID diferente: %q vs %q", r2.ID, r1.ID)
	}
	if !strings.HasPrefix(r2.Descricao, "Cópia de ") {
		t.Errorf("descrição deve começar com 'Cópia de ': %q", r2.Descricao)
	}
	if r2.Posicao != r1.Posicao+1 {
		t.Errorf("posição da cópia deve ser %d, obteve %d", r1.Posicao+1, r2.Posicao)
	}

	// Reordena invertendo r2 e r1
	res = doReq(router, http.MethodPost, "/api/firewall/regras/ordem", userW.ID, `{"zona":"internet","ids":["`+r2.ID+`","`+r1.ID+`"]}`)
	if res.Code != http.StatusOK {
		t.Fatalf("POST ordem: %d: %s", res.Code, res.Body.String())
	}

	// Desativa r1
	res = doReq(router, http.MethodPost, "/api/firewall/regras/"+r1.ID+"/ativar", userW.ID, `{"ativa":false}`)
	if res.Code != http.StatusOK {
		t.Fatalf("POST ativar: %d: %s", res.Code, res.Body.String())
	}

	// Consulta e confere nova ordem e status
	res = doReq(router, http.MethodGet, "/api/firewall/regras?zona=internet", userR.ID, "")
	var resp struct {
		Linhas []LinhaView `json:"linhas"`
	}
	_ = json.Unmarshal(res.Body.Bytes(), &resp)

	var foundR1, foundR2 bool
	for _, l := range resp.Linhas {
		if l.Regra.ID == r1.ID {
			foundR1 = true
			if l.Regra.Ativa {
				t.Errorf("r1 deveria estar desativada")
			}
		}
		if l.Regra.ID == r2.ID {
			foundR2 = true
		}
	}
	if !foundR1 || !foundR2 {
		t.Errorf("regras r1 e r2 devem existir na zona internet")
	}
}
