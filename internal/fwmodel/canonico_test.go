package fwmodel

import (
	"bytes"
	"testing"
)

func TestCanonicoEstavel(t *testing.T) {
	c1 := Config{
		Formato: 1,
		Aliases: []Alias{
			{ID: "al-2", Nome: "B", Tipo: AliasTipoEnderecos, Itens: []string{"10.0.1.7/24", "10.0.2.1/32"}},
			{ID: "al-1", Nome: "A", Tipo: AliasTipoPortas, Itens: []string{"443", "80"}},
		},
		Agendamentos: []Agendamento{
			{ID: "ag-2", Nome: "B", Dias: "sun,mon", Inicio: "08:00", Fim: "17:00"},
			{ID: "ag-1", Nome: "A", Dias: "fri,tue", Inicio: "09:00", Fim: "18:00"},
		},
		Encaminhamentos: []Encaminhamento{
			{ID: "nat-2", Nome: "N2", Ativo: true, Proto: "TCP", PortaExterna: 443, IPDestino: "10.0.1.5/32", PortaDestino: 8443},
			{ID: "nat-1", Nome: "N1", Ativo: false, Proto: "udp", PortaExterna: 53, IPDestino: "10.0.1.2", PortaDestino: 53},
		},
		Ajustes: Ajustes{
			AntiBloqueio:   map[Zona]bool{ZonaVCN: true, ZonaVPN: false},
			RedesVCNExtras: []string{"192.168.1.5/24", "10.200.0.0/16"},
		},
		Regras: []Regra{
			{ID: "r-vpn-1", Zona: ZonaVPN, Posicao: 5, Descricao: "VPN 1", Origem: Ponta{Tipo: PontaEndereco, Valor: "10.7.0.2/32"}},
			{ID: "r-inet-2", Zona: ZonaInternet, Posicao: 10, Descricao: "Inet 2", Origem: Ponta{Tipo: PontaQualquer}},
			{ID: "r-inet-1", Zona: ZonaInternet, Posicao: 2, Descricao: "Inet 1", Origem: Ponta{Tipo: PontaQualquer}},
			{ID: "r-flut-1", Zona: ZonaFlutuante, Posicao: 0, Descricao: "Flut 1", Origem: Ponta{Tipo: PontaQualquer}},
		},
	}

	// c2 tem os mesmos dados mas em ordem diferente, sem ordenação prévia, com dias desordenados e /32
	c2 := Config{
		Formato: 1,
		Aliases: []Alias{
			{ID: "al-1", Nome: "A", Tipo: AliasTipoPortas, Itens: []string{"80", "443"}},
			{ID: "al-2", Nome: "B", Tipo: AliasTipoEnderecos, Itens: []string{"10.0.2.1", "10.0.1.0/24"}},
		},
		Agendamentos: []Agendamento{
			{ID: "ag-1", Nome: "A", Dias: "tue,fri", Inicio: "09:00", Fim: "18:00"},
			{ID: "ag-2", Nome: "B", Dias: "mon,sun", Inicio: "08:00", Fim: "17:00"},
		},
		Encaminhamentos: []Encaminhamento{
			{ID: "nat-1", Nome: "N1", Ativo: false, Proto: "udp", PortaExterna: 53, IPDestino: "10.0.1.2", PortaDestino: 53},
			{ID: "nat-2", Nome: "N2", Ativo: true, Proto: "tcp", PortaExterna: 443, IPDestino: "10.0.1.5", PortaDestino: 8443},
		},
		Ajustes: Ajustes{
			AntiBloqueio:   map[Zona]bool{ZonaVPN: false, ZonaVCN: true},
			RedesVCNExtras: []string{"10.200.0.0/16", "192.168.1.0/24"},
		},
		Regras: []Regra{
			{ID: "r-flut-1", Zona: ZonaFlutuante, Posicao: 99, Descricao: "Flut 1", Origem: Ponta{Tipo: PontaQualquer}},
			{ID: "r-inet-1", Zona: ZonaInternet, Posicao: 0, Descricao: "Inet 1", Origem: Ponta{Tipo: PontaQualquer}},
			{ID: "r-inet-2", Zona: ZonaInternet, Posicao: 1, Descricao: "Inet 2", Origem: Ponta{Tipo: PontaQualquer}},
			{ID: "r-vpn-1", Zona: ZonaVPN, Posicao: 0, Descricao: "VPN 1", Origem: Ponta{Tipo: PontaEndereco, Valor: "10.7.0.2"}},
		},
	}

	can1 := Canonico(c1)
	can2 := Canonico(c2)

	if !bytes.Equal(can1, can2) {
		t.Fatalf("Canonico diverge para configs semanticamente iguais:\nC1: %s\nC2: %s", string(can1), string(can2))
	}
}

func TestNormalizarRegrasRenumeraPorZona(t *testing.T) {
	c := Config{
		Regras: []Regra{
			{ID: "r3", Zona: ZonaInternet, Posicao: 40},
			{ID: "r1", Zona: ZonaInternet, Posicao: 10},
			{ID: "r2", Zona: ZonaInternet, Posicao: 20},
			{ID: "rf1", Zona: ZonaFlutuante, Posicao: 5},
			{ID: "rv1", Zona: ZonaVPN, Posicao: 2},
		},
	}

	norm := Normalizar(c)
	if len(norm.Regras) != 5 {
		t.Fatalf("esperava 5 regras, obteve %d", len(norm.Regras))
	}

	// Ordem esperada: rf1 (flutuante pos 0), r1 (internet pos 0), r2 (internet pos 1), r3 (internet pos 2), rv1 (vpn pos 0)
	esperados := []struct {
		id      string
		zona    Zona
		posicao int
	}{
		{"rf1", ZonaFlutuante, 0},
		{"r1", ZonaInternet, 0},
		{"r2", ZonaInternet, 1},
		{"r3", ZonaInternet, 2},
		{"rv1", ZonaVPN, 0},
	}

	for i, esp := range esperados {
		r := norm.Regras[i]
		if r.ID != esp.id || r.Zona != esp.zona || r.Posicao != esp.posicao {
			t.Errorf("regra[%d] = (ID:%s, Zona:%s, Pos:%d), queria (ID:%s, Zona:%s, Pos:%d)",
				i, r.ID, r.Zona, r.Posicao, esp.id, esp.zona, esp.posicao)
		}
	}
}

func TestNormalizarSlicesNil(t *testing.T) {
	c := Config{}
	norm := Normalizar(c)
	if norm.Regras == nil || norm.Aliases == nil || norm.Agendamentos == nil || norm.Encaminhamentos == nil || norm.Ajustes.RedesVCNExtras == nil {
		t.Fatal("normalização não converteu slices nil em vazias")
	}
}
