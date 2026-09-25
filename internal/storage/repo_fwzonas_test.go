package storage_test

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-cloud/internal/fwmodel"
)

func TestRepoFWZonasRoundTrip(t *testing.T) {
	db := newTestDB(t)

	cfg := fwmodel.Config{
		Formato: 1,
		Aliases: []fwmodel.Alias{
			{
				ID:        "al-web",
				Nome:      "Servidores Web",
				Tipo:      fwmodel.AliasTipoEnderecos,
				Descricao: "Backends HTTP",
				Itens:     []string{"10.0.1.10", "10.0.2.0/24"},
			},
			{
				ID:        "al-portas",
				Nome:      "Portas Web",
				Tipo:      fwmodel.AliasTipoPortas,
				Descricao: "Portas de serviço",
				Itens:     []string{"80", "443"},
			},
		},
		Agendamentos: []fwmodel.Agendamento{
			{
				ID:        "ag-comercial",
				Nome:      "Comercial",
				Descricao: "Segunda a sexta",
				Dias:      "mon,tue,wed,thu,fri",
				Inicio:    "08:00",
				Fim:       "18:00",
			},
		},
		Encaminhamentos: []fwmodel.Encaminhamento{
			{
				ID:           "nat-1",
				Nome:         "Web DNAT",
				Ativo:        true,
				Proto:        "tcp",
				PortaExterna: 8080,
				IPDestino:    "10.0.1.10",
				PortaDestino: 80,
				Posicao:      0,
			},
		},
		Ajustes: fwmodel.Ajustes{
			AntiBloqueio:        map[fwmodel.Zona]bool{fwmodel.ZonaVCN: true, fwmodel.ZonaVPN: true},
			RedesVCNExtras:      []string{"10.100.0.0/16"},
			RegistrarBloqueados: true,
			RegistrarDestinos:   false,
			RegistrarPadrao:     false,
			ContencaoBorda:      true,
		},
		Regras: []fwmodel.Regra{
			{
				ID:            "r-1",
				Zona:          fwmodel.ZonaInternet,
				Posicao:       0,
				Ativa:         true,
				Acao:          fwmodel.AcaoAccept,
				Proto:         fwmodel.ProtoTCP,
				Origem:        fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
				Destino:       fwmodel.Ponta{Tipo: fwmodel.PontaAlias, Valor: "al-web"},
				PortaDestino:  fwmodel.Porta{Tipo: fwmodel.PortaAlias, Valor: "al-portas"},
				AgendamentoID: "ag-comercial",
				Registrar:     true,
				Descricao:     "Permitir web",
			},
		},
	}

	if err := db.SubstituirConfigEmEdicao(cfg); err != nil {
		t.Fatalf("SubstituirConfigEmEdicao: %v", err)
	}

	lida, err := db.CarregarConfigEmEdicao()
	if err != nil {
		t.Fatalf("CarregarConfigEmEdicao: %v", err)
	}

	canOrig := fwmodel.Canonico(cfg)
	canLida := fwmodel.Canonico(lida)

	if !bytes.Equal(canOrig, canLida) {
		t.Fatalf("configuração lida diverge do original:\nORIG: %s\nLIDA: %s", string(canOrig), string(canLida))
	}
}

func TestRepoFWZonasAplicadaERevisoesPoda(t *testing.T) {
	db := newTestDB(t)

	cfg := fwmodel.Config{
		Formato: 1,
		Ajustes: fwmodel.AjustesPadrao(),
		Aliases: []fwmodel.Alias{
			{ID: "al-1", Nome: "A1", Tipo: fwmodel.AliasTipoPortas, Itens: []string{"22"}},
		},
	}

	baseTime := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)

	// Salva 35 revisões para testar a poda de 30
	for i := 1; i <= 35; i++ {
		resumo := fmt.Sprintf("Revisão %d", i)
		agora := baseTime.Add(time.Duration(i) * time.Minute)
		if err := db.SalvarAplicadaERevisao(cfg, "admin", resumo, "aplicar", agora); err != nil {
			t.Fatalf("SalvarAplicadaERevisao i=%d: %v", i, err)
		}
	}

	revs, err := db.ListarRevisoes(50)
	if err != nil {
		t.Fatalf("ListarRevisoes: %v", err)
	}
	if len(revs) != 30 {
		t.Fatalf("esperava 30 revisões após a poda, obteve %d", len(revs))
	}

	// A mais recente deve ser a 35
	if revs[0].Resumo != "Revisão 35" {
		t.Errorf("esperava revisão mais recente 'Revisão 35', obteve %q", revs[0].Resumo)
	}

	// Carrega a configuração aplicada
	aplicada, existe, err := db.CarregarConfigAplicada()
	if err != nil || !existe {
		t.Fatalf("CarregarConfigAplicada: existe=%v, err=%v", existe, err)
	}
	if len(aplicada.Aliases) != 1 || aplicada.Aliases[0].ID != "al-1" {
		t.Errorf("config aplicada inesperada: %+v", aplicada)
	}

	// CarregarRevisao por ID
	recuperada, err := db.CarregarRevisao(revs[0].ID)
	if err != nil {
		t.Fatalf("CarregarRevisao: %v", err)
	}
	if !bytes.Equal(fwmodel.Canonico(cfg), fwmodel.Canonico(recuperada)) {
		t.Fatal("revisão recuperada diverge do canônico esperado")
	}
}

func TestRepoFWZonasCRUDFino(t *testing.T) {
	db := newTestDB(t)

	// 1. Criar Regras e verificar posicionamento
	r1 := fwmodel.Regra{
		Zona:      fwmodel.ZonaVCN,
		Ativa:     true,
		Acao:      fwmodel.AcaoAccept,
		Proto:     fwmodel.ProtoTCP,
		Descricao: "VCN TCP",
	}
	if err := db.CriarRegraFW(&r1); err != nil {
		t.Fatalf("CriarRegraFW r1: %v", err)
	}
	if r1.Posicao != 0 {
		t.Errorf("primeira regra na zona VCN deveria ter pos 0, teve %d", r1.Posicao)
	}

	r2 := fwmodel.Regra{
		Zona:      fwmodel.ZonaVCN,
		Ativa:     true,
		Acao:      fwmodel.AcaoDrop,
		Proto:     fwmodel.ProtoUDP,
		Descricao: "VCN UDP",
	}
	if err := db.CriarRegraFW(&r2); err != nil {
		t.Fatalf("CriarRegraFW r2: %v", err)
	}
	if r2.Posicao != 1 {
		t.Errorf("segunda regra na zona VCN deveria ter pos 1, teve %d", r2.Posicao)
	}

	// 2. Reordenar regras
	if err := db.ReordenarRegrasFW(fwmodel.ZonaVCN, []string{r1.ID}); err == nil {
		t.Fatal("esperava erro ao tentar reordenar com lista incompleta")
	}
	if err := db.ReordenarRegrasFW(fwmodel.ZonaVCN, []string{r2.ID, r1.ID}); err != nil {
		t.Fatalf("ReordenarRegrasFW: %v", err)
	}

	// 3. Atualizar regra mudando de zona
	r1.Zona = fwmodel.ZonaInternet
	if err := db.AtualizarRegraFW(r1); err != nil {
		t.Fatalf("AtualizarRegraFW mudando zona: %v", err)
	}

	// 4. Ativar / Desativar regra
	if err := db.AtivarRegraFW(r2.ID, false); err != nil {
		t.Fatalf("AtivarRegraFW: %v", err)
	}

	// 5. Apagar regra
	if err := db.ApagarRegraFW(r1.ID); err != nil {
		t.Fatalf("ApagarRegraFW: %v", err)
	}

	// 6. Aliases e UsosDoAlias
	al := fwmodel.Alias{
		Nome:      "Alvo 1",
		Tipo:      fwmodel.AliasTipoEnderecos,
		Descricao: "Desc",
		Itens:     []string{"10.0.0.1"},
	}
	if err := db.CriarAliasFW(&al); err != nil {
		t.Fatalf("CriarAliasFW: %v", err)
	}

	// Cria regra usando o alias
	rUso := fwmodel.Regra{
		Zona:      fwmodel.ZonaVPN,
		Ativa:     true,
		Acao:      fwmodel.AcaoAccept,
		Proto:     fwmodel.ProtoTCP,
		Destino:   fwmodel.Ponta{Tipo: fwmodel.PontaAlias, Valor: al.ID},
		Descricao: "Regra que usa alias",
	}
	if err := db.CriarRegraFW(&rUso); err != nil {
		t.Fatalf("CriarRegraFW rUso: %v", err)
	}

	usos, err := db.UsosDoAlias(al.ID)
	if err != nil {
		t.Fatalf("UsosDoAlias: %v", err)
	}
	if len(usos) == 0 {
		t.Fatal("esperava encontrar uso do alias na regra")
	}

	// Tentar apagar alias em uso
	if err := db.ApagarAliasFW(al.ID); err == nil {
		t.Fatal("esperava erro ao tentar apagar alias em uso")
	}

	// Remove a regra que usa e apaga o alias
	if err := db.ApagarRegraFW(rUso.ID); err != nil {
		t.Fatalf("ApagarRegraFW: %v", err)
	}
	if err := db.ApagarAliasFW(al.ID); err != nil {
		t.Fatalf("ApagarAliasFW após remover uso: %v", err)
	}

	// 7. Agendamento e UsosDoAgendamento
	ag := fwmodel.Agendamento{
		Nome:   "Noturno",
		Inicio: "22:00",
		Fim:    "06:00",
	}
	if err := db.CriarAgendamentoFW(&ag); err != nil {
		t.Fatalf("CriarAgendamentoFW: %v", err)
	}
	rAg := fwmodel.Regra{
		Zona:          fwmodel.ZonaInternet,
		Ativa:         true,
		Acao:          fwmodel.AcaoDrop,
		Proto:         fwmodel.ProtoQualquer,
		AgendamentoID: ag.ID,
		Descricao:     "Bloqueio noturno",
	}
	if err := db.CriarRegraFW(&rAg); err != nil {
		t.Fatalf("CriarRegraFW rAg: %v", err)
	}
	usosAg, err := db.UsosDoAgendamento(ag.ID)
	if err != nil || len(usosAg) == 0 {
		t.Fatalf("UsosDoAgendamento: len=%d, err=%v", len(usosAg), err)
	}
	if err := db.ApagarAgendamentoFW(ag.ID); err == nil {
		t.Fatal("esperava erro ao apagar agendamento em uso")
	}

	// 8. Encaminhamentos
	enc := fwmodel.Encaminhamento{
		Nome:         "SSH ext",
		Ativo:        true,
		Proto:        "tcp",
		PortaExterna: 2222,
		IPDestino:    "10.0.1.5",
		PortaDestino: 22,
	}
	if err := db.CriarEncaminhamentoFW(&enc); err != nil {
		t.Fatalf("CriarEncaminhamentoFW: %v", err)
	}
	enc.PortaExterna = 2223
	if err := db.AtualizarEncaminhamentoFW(enc); err != nil {
		t.Fatalf("AtualizarEncaminhamentoFW: %v", err)
	}
	if err := db.ApagarEncaminhamentoFW(enc.ID); err != nil {
		t.Fatalf("ApagarEncaminhamentoFW: %v", err)
	}

	// 9. SalvarAjustesFW
	aj := fwmodel.AjustesPadrao()
	aj.ContencaoBorda = true
	if err := db.SalvarAjustesFW(aj); err != nil {
		t.Fatalf("SalvarAjustesFW: %v", err)
	}
}
