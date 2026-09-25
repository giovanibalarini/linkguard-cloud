package fwmodel

import (
	"reflect"
	"testing"
)

func TestMudancasCriadaRemovidaAlteradaMovida(t *testing.T) {
	antes := Config{
		Formato: 1,
		Aliases: []Alias{
			{ID: "al-1", Nome: "Alias 1", Tipo: AliasTipoEnderecos, Itens: []string{"10.0.0.1"}},
			{ID: "al-2", Nome: "Alias 2", Tipo: AliasTipoPortas, Itens: []string{"80"}},
		},
		Agendamentos: []Agendamento{
			{ID: "ag-1", Nome: "Agenda 1", Dias: "mon", Inicio: "08:00", Fim: "12:00"},
		},
		Encaminhamentos: []Encaminhamento{
			{ID: "nat-1", Nome: "NAT 1", Ativo: true, Proto: "tcp", PortaExterna: 80, IPDestino: "10.0.0.1", PortaDestino: 80},
		},
		Ajustes: AjustesPadrao(),
		Regras: []Regra{
			{ID: "r-1", Zona: ZonaInternet, Posicao: 0, Ativa: true, Acao: AcaoAccept, Proto: ProtoTCP, Descricao: "R1"},
			{ID: "r-2", Zona: ZonaInternet, Posicao: 1, Ativa: true, Acao: AcaoDrop, Proto: ProtoUDP, Descricao: "R2"},
			{ID: "r-3", Zona: ZonaInternet, Posicao: 2, Ativa: true, Acao: AcaoAccept, Proto: ProtoICMP, Descricao: "R3"},
		},
	}

	depois := Config{
		Formato: 1,
		Aliases: []Alias{
			// al-1 removido
			// al-2 alterado (itens)
			{ID: "al-2", Nome: "Alias 2", Tipo: AliasTipoPortas, Itens: []string{"80", "443"}},
			// al-3 criado
			{ID: "al-3", Nome: "Alias 3", Tipo: AliasTipoEnderecos, Itens: []string{"192.168.1.1"}},
		},
		Agendamentos: []Agendamento{
			// ag-1 alterado (fim)
			{ID: "ag-1", Nome: "Agenda 1", Dias: "mon", Inicio: "08:00", Fim: "13:00"},
		},
		Encaminhamentos: []Encaminhamento{
			// nat-1 alterado (porta externa)
			{ID: "nat-1", Nome: "NAT 1", Ativo: true, Proto: "tcp", PortaExterna: 8080, IPDestino: "10.0.0.1", PortaDestino: 80},
		},
		Ajustes: Ajustes{
			AntiBloqueio:        map[Zona]bool{ZonaVCN: true, ZonaVPN: true}, // mudou VPN
			RedesVCNExtras:      []string{"10.50.0.0/16"},                    // criado
			RegistrarBloqueados: true,                                        // mudou
			RegistrarDestinos:   false,
			RegistrarPadrao:     false,
			ContencaoBorda:      false,
		},
		Regras: []Regra{
			// r-1 movida (foi para posicao 1)
			// r-2 alterada (mudou ação para accept)
			{ID: "r-2", Zona: ZonaInternet, Posicao: 0, Ativa: true, Acao: AcaoAccept, Proto: ProtoUDP, Descricao: "R2"},
			{ID: "r-1", Zona: ZonaInternet, Posicao: 1, Ativa: true, Acao: AcaoAccept, Proto: ProtoTCP, Descricao: "R1"},
			// r-3 removida
			// r-4 criada na VCN
			{ID: "r-4", Zona: ZonaVCN, Posicao: 0, Ativa: true, Acao: AcaoAccept, Proto: ProtoQualquer, Descricao: "R4"},
		},
	}

	muds := Mudancas(antes, depois)

	// Mapa para conferir resultados facilmente
	mapMuds := make(map[string]Mudanca)
	for _, m := range muds {
		mapMuds[m.Objeto+":"+m.ID+":"+string(m.Tipo)] = m
	}

	// 1. Regras
	if _, ok := mapMuds["regra:r-4:criada"]; !ok {
		t.Error("esperava regra:r-4:criada")
	}
	if _, ok := mapMuds["regra:r-3:removida"]; !ok {
		t.Error("esperava regra:r-3:removida")
	}
	if m, ok := mapMuds["regra:r-2:alterada"]; !ok {
		t.Error("esperava regra:r-2:alterada")
	} else {
		if !contemString(m.Campos, "acao") {
			t.Errorf("r-2 alterada deveria listar acao em campos: %v", m.Campos)
		}
	}
	// r-1 teve só posição invertida com r-2 -> movida
	if _, ok := mapMuds["regra:r-1:movida"]; !ok {
		t.Errorf("esperava regra:r-1:movida, obteve: %+v", mapMuds)
	}

	// 2. Aliases
	if _, ok := mapMuds["alias:al-3:criada"]; !ok {
		t.Error("esperava alias:al-3:criada")
	}
	if _, ok := mapMuds["alias:al-1:removida"]; !ok {
		t.Error("esperava alias:al-1:removida")
	}
	if m, ok := mapMuds["alias:al-2:alterada"]; !ok {
		t.Error("esperava alias:al-2:alterada")
	} else if !contemString(m.Campos, "itens") {
		t.Errorf("al-2 deveria listar itens nos campos alterados: %v", m.Campos)
	}

	// 3. Agendamento
	if m, ok := mapMuds["agendamento:ag-1:alterada"]; !ok {
		t.Error("esperava agendamento:ag-1:alterada")
	} else if !contemString(m.Campos, "fim") {
		t.Errorf("ag-1 deveria listar fim nos campos alterados: %v", m.Campos)
	}

	// 4. Encaminhamento
	if m, ok := mapMuds["encaminhamento:nat-1:alterada"]; !ok {
		t.Error("esperava encaminhamento:nat-1:alterada")
	} else if !contemString(m.Campos, "porta_externa") {
		t.Errorf("nat-1 deveria listar porta_externa nos campos alterados: %v", m.Campos)
	}

	// 5. Ajustes
	if m, ok := mapMuds["ajustes:ajustes:alterada"]; !ok {
		t.Error("esperava ajustes:ajustes:alterada")
	} else {
		if !contemString(m.Campos, "anti_bloqueio") || !contemString(m.Campos, "redes_vcn_extras") || !contemString(m.Campos, "registrar_bloqueados") {
			t.Errorf("ajustes deveria listar campos alterados, obteve %v", m.Campos)
		}
	}
}

func contemString(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}

func TestMudancasOrdemEstavel(t *testing.T) {
	c1 := configBaseValida()
	c2 := configBaseValida()
	c2.Regras = append(c2.Regras, Regra{ID: "r-nova", Zona: ZonaFlutuante, Posicao: 99, Descricao: "Nova"})
	c2.Aliases = append(c2.Aliases, Alias{ID: "al-novo", Nome: "Novo", Tipo: AliasTipoPortas})

	m1 := Mudancas(c1, c2)
	m2 := Mudancas(c1, c2)

	if !reflect.DeepEqual(m1, m2) {
		t.Fatal("saída de Mudancas não é determinística")
	}
}
