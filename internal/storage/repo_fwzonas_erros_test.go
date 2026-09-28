package storage_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-cloud/internal/fwmodel"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

func comoErroFW(t *testing.T, err error) *storage.ErroFW {
	t.Helper()
	if err == nil {
		t.Fatal("esperava um erro, obteve nil")
	}
	var e *storage.ErroFW
	if !errors.As(err, &e) {
		t.Fatalf("esperava *storage.ErroFW, obteve %T: %v", err, err)
	}
	return e
}

func regraDeTeste(id string) fwmodel.Regra {
	return fwmodel.Regra{
		ID: id, Zona: fwmodel.ZonaInternet, Ativa: true, Acao: fwmodel.AcaoAccept, Proto: fwmodel.ProtoTCP,
		Origem:       fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
		Destino:      fwmodel.Ponta{Tipo: fwmodel.PontaEste},
		PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaValor, Valor: "22"},
	}
}

func encaminhamentoDeTeste(id string) fwmodel.Encaminhamento {
	return fwmodel.Encaminhamento{
		ID: id, Nome: "Web", Ativo: true, Proto: "tcp", PortaExterna: 8080, IPDestino: "10.0.0.5", PortaDestino: 80,
	}
}

func TestRepoFWObjetoInexistenteEErroTipado(t *testing.T) {
	db := newTestDB(t)

	casos := []struct {
		nome, objeto, msg string
		fazer             func() error
	}{
		{"apagar regra", "regra", `regra "x" não encontrada`, func() error { return db.ApagarRegraFW("x") }},
		{"ativar regra", "regra", `regra "x" não encontrada`, func() error { return db.AtivarRegraFW("x", true) }},
		{"atualizar regra", "regra", `regra "x" não encontrada`, func() error { return db.AtualizarRegraFW(regraDeTeste("x")) }},
		{"duplicar regra", "regra", `regra "x" não encontrada`, func() error { _, err := db.DuplicarRegraFW("x"); return err }},
		{"atualizar alias", "alias", `alias "x" não encontrado`, func() error {
			return db.AtualizarAliasFW(fwmodel.Alias{ID: "x", Nome: "N", Tipo: fwmodel.AliasTipoEnderecos})
		}},
		{"apagar alias", "alias", `alias "x" não encontrado`, func() error { return db.ApagarAliasFW("x") }},
		{"atualizar agendamento", "agendamento", `agendamento "x" não encontrado`, func() error {
			return db.AtualizarAgendamentoFW(fwmodel.Agendamento{ID: "x", Nome: "N", Inicio: "08:00", Fim: "18:00"})
		}},
		{"apagar agendamento", "agendamento", `agendamento "x" não encontrado`, func() error { return db.ApagarAgendamentoFW("x") }},
		{"atualizar encaminhamento", "encaminhamento", `encaminhamento "x" não encontrado`, func() error {
			return db.AtualizarEncaminhamentoFW(encaminhamentoDeTeste("x"))
		}},
		{"apagar encaminhamento", "encaminhamento", `encaminhamento "x" não encontrado`, func() error { return db.ApagarEncaminhamentoFW("x") }},
		{"ativar encaminhamento", "encaminhamento", `encaminhamento "x" não encontrado`, func() error { return db.AtivarEncaminhamentoFW("x", true) }},
		{"carregar revisão", "revisão", `revisão "x" não encontrada`, func() error { _, err := db.CarregarRevisao("x"); return err }},
	}
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			e := comoErroFW(t, c.fazer())
			if e.Tipo != storage.FWNaoEncontrado || e.Objeto != c.objeto || e.ID != "x" {
				t.Errorf("classificação errada: %+v", e)
			}
			if e.Error() != c.msg {
				t.Errorf("a mensagem mudou: %q, esperava %q", e.Error(), c.msg)
			}
		})
	}
}

func TestRepoFWApagarObjetoEmUsoDevolveOsUsos(t *testing.T) {
	db := newTestDB(t)

	al := fwmodel.Alias{ID: "a-uso", Nome: "Servidores", Tipo: fwmodel.AliasTipoEnderecos, Itens: []string{"10.0.0.1"}}
	if err := db.CriarAliasFW(&al); err != nil {
		t.Fatalf("CriarAliasFW: %v", err)
	}
	ag := fwmodel.Agendamento{ID: "ag-uso", Nome: "Comercial", Dias: "mon", Inicio: "08:00", Fim: "18:00"}
	if err := db.CriarAgendamentoFW(&ag); err != nil {
		t.Fatalf("CriarAgendamentoFW: %v", err)
	}
	r := regraDeTeste("r-uso")
	r.Origem = fwmodel.Ponta{Tipo: fwmodel.PontaAlias, Valor: "a-uso"}
	r.AgendamentoID = "ag-uso"
	if err := db.CriarRegraFW(&r); err != nil {
		t.Fatalf("CriarRegraFW: %v", err)
	}

	e := comoErroFW(t, db.ApagarAliasFW("a-uso"))
	if e.Tipo != storage.FWEmUso || e.Objeto != "alias" || e.ID != "a-uso" || len(e.Usos) == 0 {
		t.Errorf("alias em uso mal classificado: %+v", e)
	}
	e = comoErroFW(t, db.ApagarAgendamentoFW("ag-uso"))
	if e.Tipo != storage.FWEmUso || e.Objeto != "agendamento" || e.ID != "ag-uso" || len(e.Usos) == 0 {
		t.Errorf("agendamento em uso mal classificado: %+v", e)
	}

	cfg, err := db.CarregarConfigEmEdicao()
	if err != nil {
		t.Fatalf("CarregarConfigEmEdicao: %v", err)
	}
	if len(cfg.Aliases) != 1 || len(cfg.Agendamentos) != 1 {
		t.Errorf("a recusa não podia apagar nada: %+v", cfg)
	}
}

func TestRepoFWNomeEIDRepetidosSaoConflito(t *testing.T) {
	db := newTestDB(t)

	if err := db.CriarAliasFW(&fwmodel.Alias{ID: "a1", Nome: "Web", Tipo: fwmodel.AliasTipoEnderecos}); err != nil {
		t.Fatalf("CriarAliasFW: %v", err)
	}
	if err := db.CriarAliasFW(&fwmodel.Alias{ID: "a2", Nome: "Banco", Tipo: fwmodel.AliasTipoEnderecos}); err != nil {
		t.Fatalf("CriarAliasFW: %v", err)
	}
	if err := db.CriarAgendamentoFW(&fwmodel.Agendamento{ID: "g1", Nome: "Comercial", Inicio: "08:00", Fim: "18:00"}); err != nil {
		t.Fatalf("CriarAgendamentoFW: %v", err)
	}
	if err := db.CriarAgendamentoFW(&fwmodel.Agendamento{ID: "g2", Nome: "Noturno", Inicio: "22:00", Fim: "06:00"}); err != nil {
		t.Fatalf("CriarAgendamentoFW: %v", err)
	}
	r := regraDeTeste("r1")
	if err := db.CriarRegraFW(&r); err != nil {
		t.Fatalf("CriarRegraFW: %v", err)
	}
	enc := encaminhamentoDeTeste("n1")
	if err := db.CriarEncaminhamentoFW(&enc); err != nil {
		t.Fatalf("CriarEncaminhamentoFW: %v", err)
	}

	type esperado struct{ objeto, campo, nome, outro string }
	casos := []struct {
		nome   string
		fazer  func() error
		espera esperado
	}{
		{"criar alias com o nome de outro, sem olhar a caixa", func() error {
			return db.CriarAliasFW(&fwmodel.Alias{ID: "a3", Nome: " WEB ", Tipo: fwmodel.AliasTipoEnderecos})
		}, esperado{"alias", "nome", " WEB ", "a1"}},
		{"renomear alias para o nome de outro", func() error {
			return db.AtualizarAliasFW(fwmodel.Alias{ID: "a2", Nome: "web", Tipo: fwmodel.AliasTipoEnderecos})
		}, esperado{"alias", "nome", "web", "a1"}},
		{"criar alias com o ID de outro", func() error {
			return db.CriarAliasFW(&fwmodel.Alias{ID: "a1", Nome: "Outro nome", Tipo: fwmodel.AliasTipoEnderecos})
		}, esperado{"alias", "id", "", ""}},
		{"criar agendamento com o nome de outro", func() error {
			return db.CriarAgendamentoFW(&fwmodel.Agendamento{ID: "g3", Nome: "comercial", Inicio: "08:00", Fim: "18:00"})
		}, esperado{"agendamento", "nome", "comercial", "g1"}},
		{"renomear agendamento para o nome de outro", func() error {
			return db.AtualizarAgendamentoFW(fwmodel.Agendamento{ID: "g2", Nome: "COMERCIAL", Inicio: "22:00", Fim: "06:00"})
		}, esperado{"agendamento", "nome", "COMERCIAL", "g1"}},
		{"criar agendamento com o ID de outro", func() error {
			return db.CriarAgendamentoFW(&fwmodel.Agendamento{ID: "g1", Nome: "Diferente", Inicio: "08:00", Fim: "18:00"})
		}, esperado{"agendamento", "id", "", ""}},
		{"criar regra com o ID de outra", func() error {
			nova := regraDeTeste("r1")
			return db.CriarRegraFW(&nova)
		}, esperado{"regra", "id", "", ""}},
		{"criar encaminhamento com o ID de outro", func() error {
			novo := encaminhamentoDeTeste("n1")
			return db.CriarEncaminhamentoFW(&novo)
		}, esperado{"encaminhamento", "id", "", ""}},
	}
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			e := comoErroFW(t, c.fazer())
			if e.Tipo != storage.FWConflito {
				t.Fatalf("esperava conflito, obteve %+v", e)
			}
			got := esperado{e.Objeto, e.Campo, e.Nome, e.Outro}
			if got != c.espera {
				t.Errorf("conflito mal descrito: %+v, esperava %+v", got, c.espera)
			}
			if strings.Contains(e.Error(), "constraint") || strings.Contains(e.Error(), "fw_") {
				t.Errorf("a mensagem vaza o SQL: %q", e.Error())
			}
			if e.Unwrap() == nil {
				t.Error("a causa técnica se perdeu")
			}
		})
	}
}

func TestRepoFWValorForaDoDominioEEntradaInvalida(t *testing.T) {
	db := newTestDB(t)

	casos := []struct {
		nome, objeto string
		fazer        func() error
	}{
		{"regra com zona desconhecida", "regra", func() error {
			r := regraDeTeste("r1")
			r.Zona = "dmz"
			return db.CriarRegraFW(&r)
		}},
		{"regra com ação desconhecida", "regra", func() error {
			r := regraDeTeste("r1")
			r.Acao = "queimar"
			return db.CriarRegraFW(&r)
		}},
		{"alias com tipo desconhecido", "alias", func() error {
			return db.CriarAliasFW(&fwmodel.Alias{ID: "a1", Nome: "X", Tipo: "hosts"})
		}},
		{"encaminhamento com protocolo desconhecido", "encaminhamento", func() error {
			e := encaminhamentoDeTeste("n1")
			e.Proto = "sctp"
			return db.CriarEncaminhamentoFW(&e)
		}},
	}
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			e := comoErroFW(t, c.fazer())
			if e.Tipo != storage.FWEntradaInvalida || e.Objeto != c.objeto {
				t.Errorf("classificação errada: %+v", e)
			}
			if strings.Contains(e.Error(), "CHECK") || strings.Contains(e.Error(), "constraint") {
				t.Errorf("a mensagem vaza o SQL: %q", e.Error())
			}
		})
	}
}

func TestRepoFWReordenacaoInvalidaEEntradaInvalida(t *testing.T) {
	db := newTestDB(t)
	for _, id := range []string{"r1", "r2", "r3"} {
		r := regraDeTeste(id)
		if err := db.CriarRegraFW(&r); err != nil {
			t.Fatalf("CriarRegraFW: %v", err)
		}
	}

	casos := []struct {
		nome string
		ids  []string
	}{
		{"lista incompleta", []string{"r1", "r2"}},
		{"lista com id que não é da zona", []string{"r1", "r2", "r9"}},
		{"lista com id repetido", []string{"r1", "r1", "r2"}},
	}
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			e := comoErroFW(t, db.ReordenarRegrasFW(fwmodel.ZonaInternet, c.ids))
			if e.Tipo != storage.FWEntradaInvalida {
				t.Errorf("classificação errada: %+v", e)
			}
		})
	}

	if err := db.ReordenarRegrasFW(fwmodel.ZonaInternet, []string{"r3", "r1", "r2"}); err != nil {
		t.Fatalf("a reordenação válida falhou: %v", err)
	}
	cfg, err := db.CarregarConfigEmEdicao()
	if err != nil {
		t.Fatalf("CarregarConfigEmEdicao: %v", err)
	}
	var ordem []string
	for _, r := range cfg.Regras {
		ordem = append(ordem, r.ID)
	}
	if strings.Join(ordem, ",") != "r3,r1,r2" {
		t.Errorf("ordem depois da reordenação válida: %v", ordem)
	}
}

func TestRepoFWFalhaDoBancoNaoViraErroTipado(t *testing.T) {
	db := newTestDB(t)
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	for nome, err := range map[string]error{
		"apagar regra":   db.ApagarRegraFW("x"),
		"criar alias":    db.CriarAliasFW(&fwmodel.Alias{ID: "a", Nome: "A", Tipo: fwmodel.AliasTipoEnderecos}),
		"apagar alias":   db.ApagarAliasFW("a"),
		"atualizar agen": db.AtualizarAgendamentoFW(fwmodel.Agendamento{ID: "g", Nome: "G"}),
	} {
		var e *storage.ErroFW
		if err == nil || errors.As(err, &e) {
			t.Errorf("%s: falha do banco devia sair como erro comum, obteve %T: %v", nome, err, err)
		}
	}
}
