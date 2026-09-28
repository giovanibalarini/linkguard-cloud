package firewallrules

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-cloud/internal/fwmodel"
	"github.com/giovanibalarini/linkguard-cloud/internal/nftables"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

func regraSimples(id string, zona fwmodel.Zona, desc string) fwmodel.Regra {
	return fwmodel.Regra{
		ID: id, Zona: zona, Ativa: true, Acao: fwmodel.AcaoAccept, Proto: fwmodel.ProtoTCP,
		Origem:       fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
		Destino:      fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
		PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaValor, Valor: "443"},
		Descricao:    desc,
	}
}

func semarConfig(t *testing.T, db *storage.DB, regras ...fwmodel.Regra) {
	t.Helper()
	cfg := fwmodel.Config{Formato: 1, Ajustes: fwmodel.AjustesPadrao(), Regras: regras}
	if err := db.SubstituirConfigEmEdicao(cfg); err != nil {
		t.Fatalf("SubstituirConfigEmEdicao: %v", err)
	}
}

func guardOf(t *testing.T, err error) *GuardError {
	t.Helper()
	var g *GuardError
	if !errors.As(err, &g) {
		t.Fatalf("esperava GuardError, obteve %T: %v", err, err)
	}
	return g
}

func TestEditarConfigValidandoRecusaEDesfaz(t *testing.T) {
	svc, db, _ := newZonasTestService(t)
	semarConfig(t, db, regraSimples("r-1", fwmodel.ZonaInternet, "primeira"), regraSimples("r-2", fwmodel.ZonaVCN, "segunda"))
	antes, _ := db.CarregarConfigEmEdicao()

	err := svc.EditarConfigValidando(context.Background(), "admin", func(db *storage.DB) error {
		return db.CriarAliasFW(&fwmodel.Alias{ID: "al-x", Nome: "x", Tipo: fwmodel.AliasTipoEnderecos, Itens: []string{"abc"}})
	}, "alias:al-x")
	if err == nil {
		t.Fatal("um alias com item 'abc' devia ser recusado")
	}
	g := guardOf(t, err)
	if g.Stage != StageValidate {
		t.Fatalf("etapa = %s, quero validação", g.Stage)
	}
	if len(g.Problemas) == 0 || !fwmodel.TemErro(g.Problemas) {
		t.Fatalf("o erro devia trazer os problemas, veio %+v", g.Problemas)
	}

	depois, _ := db.CarregarConfigEmEdicao()
	if string(fwmodel.Canonico(antes)) != string(fwmodel.Canonico(depois)) {
		t.Fatalf("a escrita recusada devia ser desfeita\nantes:  %s\ndepois: %s", fwmodel.Canonico(antes), fwmodel.Canonico(depois))
	}
}

func TestEditarConfigValidandoAceitaMudancaValida(t *testing.T) {
	svc, db, _ := newZonasTestService(t)

	err := svc.EditarConfigValidando(context.Background(), "admin", func(db *storage.DB) error {
		r := regraSimples("r-ok", fwmodel.ZonaInternet, "liberar https")
		return db.CriarRegraFW(&r)
	}, "regra:r-ok")
	if err != nil {
		t.Fatalf("regra válida devia passar: %v", err)
	}
	cfg, _ := db.CarregarConfigEmEdicao()
	if len(cfg.Regras) != 1 || cfg.Regras[0].ID != "r-ok" {
		t.Fatalf("a regra devia ter sido gravada: %+v", cfg.Regras)
	}
}

func TestEditarConfigValidandoNaoTrancaQuemQuerConsertar(t *testing.T) {
	svc, db, _ := newZonasTestService(t)
	ctx := context.Background()
	// Uma configuração herdada com um alias quebrado (gravado direto no banco,
	// como faria um banco antigo ou uma conversão).
	if err := db.CriarAliasFW(&fwmodel.Alias{ID: "al-velho", Nome: "velho", Tipo: fwmodel.AliasTipoPortas, Itens: []string{"99999"}}); err != nil {
		t.Fatal(err)
	}

	// Mexer em outra coisa passa.
	err := svc.EditarConfigValidando(ctx, "admin", func(db *storage.DB) error {
		r := regraSimples("r-novo", fwmodel.ZonaInternet, "nova")
		return db.CriarRegraFW(&r)
	}, "regra:r-novo")
	if err != nil {
		t.Fatalf("um erro antigo de outro objeto não pode trancar a edição: %v", err)
	}

	// Apagar o alias quebrado passa.
	err = svc.EditarConfigValidando(ctx, "admin", func(db *storage.DB) error {
		return db.ApagarAliasFW("al-velho")
	})
	if err != nil {
		t.Fatalf("apagar o alias quebrado tem que passar: %v", err)
	}
	cfg, _ := db.CarregarConfigEmEdicao()
	if len(cfg.Aliases) != 0 {
		t.Fatalf("o alias devia ter sido apagado: %+v", cfg.Aliases)
	}
}

func TestEditarConfigValidandoRespeitaAJanelaAberta(t *testing.T) {
	svc, db, _ := newZonasTestService(t)
	_ = db.SavePendingChange(storage.PendingChange{
		ID: "w-1", Summary: "mudança", AppliedBy: "admin",
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(90 * time.Second), Snapshot: "{}",
	})

	chamou := false
	err := svc.EditarConfigValidando(context.Background(), "admin", func(*storage.DB) error {
		chamou = true
		return nil
	})
	if g := guardOf(t, err); g.Stage != StageLocked {
		t.Fatalf("etapa = %s, quero a trava da janela", g.Stage)
	}
	if chamou {
		t.Fatal("com a janela aberta a escrita nem devia começar")
	}
}

func TestPendenciasComConfigInvalidaNaoFalha(t *testing.T) {
	svc, db, _ := newZonasTestService(t)
	if err := db.CriarAliasFW(&fwmodel.Alias{ID: "al-x", Nome: "x", Tipo: fwmodel.AliasTipoEnderecos, Itens: []string{"abc"}}); err != nil {
		t.Fatal(err)
	}

	p, err := svc.Pendencias(context.Background())
	if err != nil {
		t.Fatalf("a tela de pendências não pode cair por causa de um alias ruim: %v", err)
	}
	if !p.Pendente {
		t.Error("o alias novo é uma pendência")
	}
	if !fwmodel.TemErro(p.Problemas) {
		t.Errorf("os problemas devem listar o alias ruim: %+v", p.Problemas)
	}
	if p.Mudancas == nil || p.Problemas == nil {
		t.Error("listas nunca vão nulas para a interface")
	}
}

func TestPendenciasQuandoORenderFalhaSemErroDeValidacao(t *testing.T) {
	svc, db, _ := newZonasTestService(t)
	semarConfig(t, db, regraSimples("r-1", fwmodel.ZonaInternet, "x"))
	svc.SetFonteInsumos(func(ctx context.Context) (nftables.Insumos, error) {
		return nftables.Insumos{
			RedesVCN: []string{"10.0.0.0/16"}, RedeVPN: "10.7.0.0/24", PortaWireGuard: 51820,
			InterfaceVPN: "nome de interface inválido", PortasGerencia: []int{22},
		}, nil
	})

	p, err := svc.Pendencias(context.Background())
	if err != nil {
		t.Fatalf("falha de render vira problema, não erro: %v", err)
	}
	achou := false
	for _, pr := range p.Problemas {
		if pr.Chave == "fwz.problema.renderFalhou" && pr.Severidade == "erro" {
			achou = true
		}
	}
	if !achou {
		t.Fatalf("o operador precisa ver por que não dá para aplicar: %+v", p.Problemas)
	}
}

func TestLinhasComConfigInvalidaMostraAsRegrasDoAdmin(t *testing.T) {
	svc, db, _ := newZonasTestService(t)
	semarConfig(t, db, regraSimples("r-1", fwmodel.ZonaInternet, "primeira"), regraSimples("r-2", fwmodel.ZonaInternet, "segunda"))
	if err := db.CriarAliasFW(&fwmodel.Alias{ID: "al-x", Nome: "x", Tipo: fwmodel.AliasTipoEnderecos, Itens: []string{"abc"}}); err != nil {
		t.Fatal(err)
	}

	linhas, err := svc.Linhas(context.Background(), fwmodel.ZonaInternet)
	if err != nil {
		t.Fatalf("a lista de regras não pode cair por causa de um alias ruim: %v", err)
	}
	var ids []string
	for _, l := range linhas {
		if l.Tipo == "admin" {
			ids = append(ids, l.Regra.ID)
		}
	}
	if len(ids) != 2 || ids[0] != "r-1" || ids[1] != "r-2" {
		t.Fatalf("as regras do admin devem aparecer na ordem, obteve %v", ids)
	}
}

func TestPreviaRegraNaoDependeDeOutroObjetoRuim(t *testing.T) {
	svc, db, _ := newZonasTestService(t)
	if err := db.CriarAliasFW(&fwmodel.Alias{ID: "al-x", Nome: "x", Tipo: fwmodel.AliasTipoEnderecos, Itens: []string{"abc"}}); err != nil {
		t.Fatal(err)
	}

	nft, problemas, err := svc.PreviaRegra(context.Background(), regraSimples("", fwmodel.ZonaInternet, "prévia"))
	if err != nil {
		t.Fatalf("a prévia de uma regra boa não pode cair por causa de um alias ruim que ela nem usa: %v", err)
	}
	if fwmodel.TemErro(problemas) {
		t.Fatalf("a regra é válida: %+v", problemas)
	}
	if len(nft) == 0 {
		t.Fatal("a prévia devia trazer o nft da regra")
	}
}

func TestPreviaRegraContinuaApontandoOsProblemasDaPropriaRegra(t *testing.T) {
	svc, _, _ := newZonasTestService(t)
	r := regraSimples("", fwmodel.ZonaInternet, "porta ruim")
	r.PortaDestino.Valor = "99999"

	nft, problemas, err := svc.PreviaRegra(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if !fwmodel.TemErro(problemas) {
		t.Fatal("porta 99999 devia ser apontada")
	}
	if len(nft) != 0 {
		t.Fatal("regra inválida não gera nft")
	}
}
