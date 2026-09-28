package firewallrules

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-cloud/internal/fwmodel"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

func TestEditarConfigValidandoClassificaARecusaDoRepositorio(t *testing.T) {
	svc, db, _ := newZonasTestService(t)
	ctx := context.Background()

	if err := db.CriarAliasFW(&fwmodel.Alias{ID: "al-web", Nome: "Web", Tipo: fwmodel.AliasTipoEnderecos, Itens: []string{"10.0.0.1"}}); err != nil {
		t.Fatal(err)
	}
	usa := regraSimples("r-usa", fwmodel.ZonaInternet, "usa o alias")
	usa.Destino = fwmodel.Ponta{Tipo: fwmodel.PontaAlias, Valor: "al-web"}
	if err := db.CriarRegraFW(&usa); err != nil {
		t.Fatal(err)
	}
	outra := regraSimples("r-outra", fwmodel.ZonaInternet, "outra")
	if err := db.CriarRegraFW(&outra); err != nil {
		t.Fatal(err)
	}
	antes, err := db.CarregarConfigEmEdicao()
	if err != nil {
		t.Fatal(err)
	}

	casos := []struct {
		nome     string
		escrever func(db *storage.DB) error
		etapa    Stage
		confere  func(t *testing.T, g *GuardError)
	}{
		{"objeto que não existe", func(db *storage.DB) error { return db.ApagarRegraFW("fantasma") }, StageNotFound,
			func(t *testing.T, g *GuardError) {
				if !strings.Contains(g.Message, "fantasma") {
					t.Errorf("a mensagem devia nomear o que faltou: %q", g.Message)
				}
			}},
		{"alias em uso", func(db *storage.DB) error { return db.ApagarAliasFW("al-web") }, StageInUse,
			func(t *testing.T, g *GuardError) {
				if len(g.Usos) == 0 {
					t.Error("a recusa devia dizer quem usa o alias")
				}
				if g.Message != "alias em uso" {
					t.Errorf("mensagem = %q", g.Message)
				}
			}},
		{"nome de alias repetido", func(db *storage.DB) error {
			return db.CriarAliasFW(&fwmodel.Alias{ID: "al-novo", Nome: " WEB", Tipo: fwmodel.AliasTipoEnderecos})
		}, StageValidate,
			func(t *testing.T, g *GuardError) {
				var p *fwmodel.Problema
				for i := range g.Problemas {
					if g.Problemas[i].Chave == "fwz.problema.aliasNomeDuplicado" {
						p = &g.Problemas[i]
					}
				}
				if p == nil {
					t.Fatalf("faltou aliasNomeDuplicado em %+v", g.Problemas)
				}
				if p.Severidade != "erro" || p.Onde != "alias:al-novo" || p.Vars["outro_id"] != "al-web" || p.Vars["nome"] != " WEB" {
					t.Errorf("problema mal montado: %+v", p)
				}
			}},
		{"ID de regra repetido", func(db *storage.DB) error {
			r := regraSimples("r-usa", fwmodel.ZonaInternet, "de novo")
			return db.CriarRegraFW(&r)
		}, StageValidate,
			func(t *testing.T, g *GuardError) {
				if !strings.Contains(g.Message, "r-usa") {
					t.Errorf("a mensagem devia nomear o identificador: %q", g.Message)
				}
			}},
		{"reordenação incompleta", func(db *storage.DB) error {
			return db.ReordenarRegrasFW(fwmodel.ZonaInternet, []string{"r-usa"})
		}, StageValidate,
			func(t *testing.T, g *GuardError) {
				if !strings.Contains(g.Message, "lista completa") {
					t.Errorf("mensagem = %q", g.Message)
				}
			}},
		{"valor que o banco não aceita", func(db *storage.DB) error {
			r := regraSimples("r-dmz", "dmz", "zona inexistente")
			return db.CriarRegraFW(&r)
		}, StageValidate, func(t *testing.T, g *GuardError) {}},
		{"falha do banco", func(db *storage.DB) error { return errors.New("disk I/O error: /var/lib/linkguard/x.db") }, StageWrite,
			func(t *testing.T, g *GuardError) {
				if g.Err == nil || !strings.Contains(g.Err.Error(), "disk I/O") {
					t.Errorf("a causa técnica devia ficar para o log: %v", g.Err)
				}
				if strings.Contains(g.Message, "/var/lib") || strings.Contains(g.Message, "disk") {
					t.Errorf("a mensagem para o operador não pode citar o banco: %q", g.Message)
				}
			}},
	}
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			err := svc.EditarConfigValidando(ctx, "admin", c.escrever)
			g := guardOf(t, err)
			if g.Stage != c.etapa {
				t.Fatalf("etapa = %s, esperava %s (%v)", g.Stage, c.etapa, err)
			}
			c.confere(t, g)
			depois, err := db.CarregarConfigEmEdicao()
			if err != nil {
				t.Fatal(err)
			}
			if string(fwmodel.Canonico(antes)) != string(fwmodel.Canonico(depois)) {
				t.Errorf("a recusa deixou rastro na configuração em edição")
			}
		})
	}
}

func TestRestaurarRevisaoInexistenteENaoEncontrada(t *testing.T) {
	svc, _, _ := newZonasTestService(t)
	err := svc.RestaurarRevisao(context.Background(), "nao-existe", "admin")
	g := guardOf(t, err)
	if g.Stage != StageNotFound {
		t.Fatalf("etapa = %s, esperava %s (%v)", g.Stage, StageNotFound, err)
	}
}
