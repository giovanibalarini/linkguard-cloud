package fwmodel

import (
	"strings"
	"testing"
)

func configBaseValida() Config {
	return Config{
		Formato: 1,
		Aliases: []Alias{
			{
				ID:        "al-web",
				Nome:      "servidores-web",
				Tipo:      AliasTipoEnderecos,
				Descricao: "Web servers",
				Itens:     []string{"10.0.1.10", "10.0.1.0/24"},
			},
			{
				ID:        "al-portas",
				Nome:      "portas-web",
				Tipo:      AliasTipoPortas,
				Descricao: "HTTP e HTTPS",
				Itens:     []string{"80", "443", "8000-8080"},
			},
		},
		Agendamentos: []Agendamento{
			{
				ID:        "ag-comercial",
				Nome:      "Horário comercial",
				Descricao: "Segunda a sexta das 8h às 18h",
				Dias:      "mon,tue,wed,thu,fri",
				Inicio:    "08:00",
				Fim:       "18:00",
			},
		},
		Encaminhamentos: []Encaminhamento{
			{
				ID:           "nat-1",
				Nome:         "Web server",
				Ativo:        true,
				Proto:        "tcp",
				PortaExterna: 8080,
				IPDestino:    "10.0.1.10",
				PortaDestino: 80,
				Posicao:      0,
			},
		},
		Ajustes: AjustesPadrao(),
		Regras: []Regra{
			{
				ID:            "r-1",
				Zona:          ZonaInternet,
				Posicao:       0,
				Ativa:         true,
				Acao:          AcaoAccept,
				Proto:         ProtoTCP,
				Origem:        Ponta{Tipo: PontaQualquer},
				Destino:       Ponta{Tipo: PontaAlias, Valor: "al-web"},
				PortaDestino:  Porta{Tipo: PortaAlias, Valor: "al-portas"},
				AgendamentoID: "ag-comercial",
				Registrar:     true,
				Descricao:     "Liberar web comercial",
			},
			{
				ID:           "r-2",
				Zona:         ZonaVCN,
				Posicao:      0,
				Ativa:        true,
				Acao:         AcaoAccept,
				Proto:        ProtoQualquer,
				Origem:       Ponta{Tipo: PontaAlias, Valor: AliasVCN},
				Destino:      Ponta{Tipo: PontaEste},
				PortaDestino: Porta{Tipo: PortaQualquer},
				Descricao:    "Liberar tudo da VCN para o firewall",
			},
		},
	}
}

func TestValidarConfigValida(t *testing.T) {
	cfg := configBaseValida()
	pessoas := []string{"u1", "u2"}
	prob := Validar(cfg, pessoas)
	if TemErro(prob) {
		t.Fatalf("configuração válida retornou erros: %+v", prob)
	}
}

func TestValidarRegras(t *testing.T) {
	pessoas := []string{"usr-maria"}

	t.Run("zona desconhecida", func(t *testing.T) {
		cfg := configBaseValida()
		cfg.Regras[0].Zona = "desconhecida"
		ps := Validar(cfg, pessoas)
		if !TemErro(ps) {
			t.Fatal("esperava erro para zona inválida")
		}
	})

	t.Run("acao desconhecida", func(t *testing.T) {
		cfg := configBaseValida()
		cfg.Regras[0].Acao = "bloquear"
		ps := Validar(cfg, pessoas)
		if !TemErro(ps) {
			t.Fatal("esperava erro para acao inválida")
		}
	})

	t.Run("proto desconhecido", func(t *testing.T) {
		cfg := configBaseValida()
		cfg.Regras[0].Proto = "sctp"
		ps := Validar(cfg, pessoas)
		if !TemErro(ps) {
			t.Fatal("esperava erro para proto inválido")
		}
	})

	t.Run("origem self é recusada", func(t *testing.T) {
		cfg := configBaseValida()
		cfg.Regras[0].Origem = Ponta{Tipo: PontaEste}
		ps := Validar(cfg, pessoas)
		if !TemErro(ps) {
			t.Fatal("esperava erro para origem self")
		}
	})

	t.Run("origem addr IPv4 válido e inválido", func(t *testing.T) {
		cfg := configBaseValida()
		cfg.Regras[0].Origem = Ponta{Tipo: PontaEndereco, Valor: "192.168.1.5"}
		if TemErro(Validar(cfg, pessoas)) {
			t.Fatal("não esperava erro com IP válido")
		}
		cfg.Regras[0].Origem = Ponta{Tipo: PontaEndereco, Valor: "192.168.1.0/24"}
		if TemErro(Validar(cfg, pessoas)) {
			t.Fatal("não esperava erro com CIDR válido")
		}
		cfg.Regras[0].Origem = Ponta{Tipo: PontaEndereco, Valor: "invalido"}
		if !TemErro(Validar(cfg, pessoas)) {
			t.Fatal("esperava erro com endereço inválido")
		}
	})

	t.Run("origem alias embutido e pessoa", func(t *testing.T) {
		cfg := configBaseValida()
		cfg.Regras[0].Origem = Ponta{Tipo: PontaAlias, Valor: AliasVCN}
		if TemErro(Validar(cfg, pessoas)) {
			t.Fatal("não esperava erro com sys:vcn")
		}
		cfg.Regras[0].Origem = Ponta{Tipo: PontaAlias, Valor: AliasVPN}
		if TemErro(Validar(cfg, pessoas)) {
			t.Fatal("não esperava erro com sys:vpn")
		}
		cfg.Regras[0].Origem = Ponta{Tipo: PontaAlias, Valor: AliasPessoaPref + "usr-maria"}
		if TemErro(Validar(cfg, pessoas)) {
			t.Fatal("não esperava erro com pessoa existente")
		}
		cfg.Regras[0].Origem = Ponta{Tipo: PontaAlias, Valor: AliasPessoaPref + "usr-inexistente"}
		if !TemErro(Validar(cfg, pessoas)) {
			t.Fatal("esperava erro com pessoa inexistente")
		}
		cfg.Regras[0].Origem = Ponta{Tipo: PontaAlias, Valor: "al-portas"} // alias de portas em origem!
		if !TemErro(Validar(cfg, pessoas)) {
			t.Fatal("esperava erro ao usar alias de portas em origem de endereço")
		}
	})

	t.Run("destino self é válido", func(t *testing.T) {
		cfg := configBaseValida()
		cfg.Regras[0].Destino = Ponta{Tipo: PontaEste}
		if TemErro(Validar(cfg, pessoas)) {
			t.Fatal("não esperava erro com destino self")
		}
	})

	t.Run("porta só permitida com tcp ou udp", func(t *testing.T) {
		cfg := configBaseValida()
		cfg.Regras[0].Proto = ProtoICMP
		cfg.Regras[0].PortaDestino = Porta{Tipo: PortaValor, Valor: "80"}
		if !TemErro(Validar(cfg, pessoas)) {
			t.Fatal("esperava erro para porta com protocolo icmp")
		}
		cfg.Regras[0].Proto = ProtoQualquer
		if !TemErro(Validar(cfg, pessoas)) {
			t.Fatal("esperava erro para porta com protocolo vazio")
		}
		cfg.Regras[0].Proto = ProtoTCP
		if TemErro(Validar(cfg, pessoas)) {
			t.Fatal("não esperava erro para porta com tcp")
		}
		cfg.Regras[0].Proto = ProtoUDP
		if TemErro(Validar(cfg, pessoas)) {
			t.Fatal("não esperava erro para porta com udp")
		}
		cfg.Regras[0].Proto = ProtoTCPUDP
		if TemErro(Validar(cfg, pessoas)) {
			t.Fatal("não esperava erro para porta com tcp/udp")
		}
	})

	t.Run("porta valor faixa válida e inválida", func(t *testing.T) {
		cfg := configBaseValida()
		cfg.Regras[0].Proto = ProtoTCP
		cfg.Regras[0].PortaDestino = Porta{Tipo: PortaValor, Valor: "8000-8100"}
		if TemErro(Validar(cfg, pessoas)) {
			t.Fatal("não esperava erro para faixa válida")
		}
		cfg.Regras[0].PortaDestino = Porta{Tipo: PortaValor, Valor: "8100-8000"}
		if !TemErro(Validar(cfg, pessoas)) {
			t.Fatal("esperava erro para faixa invertida a > b")
		}
		cfg.Regras[0].PortaDestino = Porta{Tipo: PortaValor, Valor: "70000"}
		if !TemErro(Validar(cfg, pessoas)) {
			t.Fatal("esperava erro para porta > 65535")
		}
		cfg.Regras[0].PortaDestino = Porta{Tipo: PortaValor, Valor: "0"}
		if !TemErro(Validar(cfg, pessoas)) {
			t.Fatal("esperava erro para porta 0")
		}
	})

	t.Run("porta alias sys:gerencia e tipos", func(t *testing.T) {
		cfg := configBaseValida()
		cfg.Regras[0].Proto = ProtoTCP
		cfg.Regras[0].PortaDestino = Porta{Tipo: PortaAlias, Valor: AliasGerencia}
		if TemErro(Validar(cfg, pessoas)) {
			t.Fatal("não esperava erro para sys:gerencia em porta")
		}
		cfg.Regras[0].PortaDestino = Porta{Tipo: PortaAlias, Valor: "al-web"} // alias de endereços
		if !TemErro(Validar(cfg, pessoas)) {
			t.Fatal("esperava erro para alias de endereços em porta_destino")
		}
	})

	t.Run("agendamento inexistente", func(t *testing.T) {
		cfg := configBaseValida()
		cfg.Regras[0].AgendamentoID = "ag-fantasma"
		if !TemErro(Validar(cfg, pessoas)) {
			t.Fatal("esperava erro para agendamento inexistente")
		}
	})

	t.Run("descricao muito longa", func(t *testing.T) {
		cfg := configBaseValida()
		cfg.Regras[0].Descricao = strings.Repeat("x", 201)
		if !TemErro(Validar(cfg, pessoas)) {
			t.Fatal("esperava erro para descrição > 200 caracteres")
		}
	})

	t.Run("posicao repetida na mesma zona", func(t *testing.T) {
		cfg := configBaseValida()
		rDup := cfg.Regras[0]
		rDup.ID = "r-dup"
		rDup.Posicao = cfg.Regras[0].Posicao
		cfg.Regras = append(cfg.Regras, rDup)
		if !TemErro(Validar(cfg, pessoas)) {
			t.Fatal("esperava erro para posições repetidas na mesma zona")
		}
	})

	t.Run("avisos de incompatibilidade e regra idêntica", func(t *testing.T) {
		cfg := configBaseValida()
		// sys:vcn na VPN gera aviso
		rAviso := cfg.Regras[0]
		rAviso.ID = "r-aviso-1"
		rAviso.Zona = ZonaVPN
		rAviso.Posicao = 10
		rAviso.Origem = Ponta{Tipo: PontaAlias, Valor: AliasVCN}
		cfg.Regras = append(cfg.Regras, rAviso)

		// sys:vpn na VCN gera aviso
		rAviso2 := cfg.Regras[0]
		rAviso2.ID = "r-aviso-2"
		rAviso2.Zona = ZonaVCN
		rAviso2.Posicao = 10
		rAviso2.Origem = Ponta{Tipo: PontaAlias, Valor: AliasVPN}
		cfg.Regras = append(cfg.Regras, rAviso2)

		// regra idêntica ativa gera aviso
		rIdentica := cfg.Regras[0]
		rIdentica.ID = "r-identica"
		rIdentica.Posicao = 99
		cfg.Regras = append(cfg.Regras, rIdentica)

		ps := Validar(cfg, pessoas)
		if TemErro(ps) {
			t.Fatalf("avisos não deveriam gerar erro: %+v", ps)
		}
		var achouVCN, achouVPN, achouIdentica bool
		for _, p := range ps {
			if p.Severidade == "aviso" {
				if p.Chave == "fwz.problema.origemVCNEmVPN" {
					achouVCN = true
				}
				if p.Chave == "fwz.problema.origemVPNEmVCN" {
					achouVPN = true
				}
				if p.Chave == "fwz.problema.regraIdentica" {
					achouIdentica = true
				}
			}
		}
		if !achouVCN || !achouVPN || !achouIdentica {
			t.Errorf("esperava avisos, achou: vcn=%v, vpn=%v, identica=%v", achouVCN, achouVPN, achouIdentica)
		}
	})
}

func TestValidarAliases(t *testing.T) {
	pessoas := []string{}

	t.Run("nomes reservados", func(t *testing.T) {
		reservados := []string{"VCN", "vpn", "Gerência", "gerencia", "Este firewall", "este FIREWALL", "sys:custom"}
		for _, nome := range reservados {
			cfg := configBaseValida()
			cfg.Aliases = append(cfg.Aliases, Alias{
				ID:   "al-res",
				Nome: nome,
				Tipo: AliasTipoEnderecos,
			})
			if !TemErro(Validar(cfg, pessoas)) {
				t.Errorf("esperava erro para alias com nome reservado %q", nome)
			}
		}
	})

	t.Run("nome duplicado sem diferenciar maiusculas", func(t *testing.T) {
		cfg := configBaseValida()
		cfg.Aliases = append(cfg.Aliases, Alias{
			ID:   "al-dup",
			Nome: "SERVIDORES-WEB",
			Tipo: AliasTipoEnderecos,
		})
		if !TemErro(Validar(cfg, pessoas)) {
			t.Fatal("esperava erro para nome de alias duplicado em caixa alta")
		}
	})

	t.Run("limite de 4096 itens", func(t *testing.T) {
		cfg := configBaseValida()
		muitos := make([]string, 4097)
		for i := range muitos {
			muitos[i] = "10.0.0.1"
		}
		cfg.Aliases[0].Itens = muitos
		if !TemErro(Validar(cfg, pessoas)) {
			t.Fatal("esperava erro para alias com > 4096 itens")
		}
	})
}

func TestValidarEncaminhamentos(t *testing.T) {
	pessoas := []string{}

	t.Run("conflito de porta e proto entre ativos", func(t *testing.T) {
		cfg := configBaseValida()
		cfg.Encaminhamentos = append(cfg.Encaminhamentos, Encaminhamento{
			ID:           "nat-dup",
			Nome:         "Outro",
			Ativo:        true,
			Proto:        "tcp",
			PortaExterna: 8080,
			IPDestino:    "10.0.1.20",
			PortaDestino: 8080,
		})
		if !TemErro(Validar(cfg, pessoas)) {
			t.Fatal("esperava erro para dois encaminhamentos ativos na mesma porta externa tcp 8080")
		}
	})

	t.Run("mesma porta externa com proto diferente é permitido", func(t *testing.T) {
		cfg := configBaseValida()
		cfg.Encaminhamentos = append(cfg.Encaminhamentos, Encaminhamento{
			ID:           "nat-udp",
			Nome:         "UDP DNS",
			Ativo:        true,
			Proto:        "udp",
			PortaExterna: 8080,
			IPDestino:    "10.0.1.20",
			PortaDestino: 53,
		})
		if TemErro(Validar(cfg, pessoas)) {
			t.Fatal("não esperava erro com protos diferentes")
		}
	})

	t.Run("mesma porta externa com um inativo é permitido", func(t *testing.T) {
		cfg := configBaseValida()
		cfg.Encaminhamentos = append(cfg.Encaminhamentos, Encaminhamento{
			ID:           "nat-inativo",
			Nome:         "Inativo",
			Ativo:        false,
			Proto:        "tcp",
			PortaExterna: 8080,
			IPDestino:    "10.0.1.20",
			PortaDestino: 8080,
		})
		if TemErro(Validar(cfg, pessoas)) {
			t.Fatal("não esperava erro se o segundo encaminhamento estiver inativo")
		}
	})
}

func TestValidarAjustes(t *testing.T) {
	pessoas := []string{}

	t.Run("zona inválida em AntiBloqueio", func(t *testing.T) {
		cfg := configBaseValida()
		cfg.Ajustes.AntiBloqueio[ZonaInternet] = true
		if !TemErro(Validar(cfg, pessoas)) {
			t.Fatal("esperava erro com zona internet em AntiBloqueio")
		}
	})

	t.Run("rede vcn extra não CIDR", func(t *testing.T) {
		cfg := configBaseValida()
		cfg.Ajustes.RedesVCNExtras = []string{"192.168.1.1"} // sem /24
		if !TemErro(Validar(cfg, pessoas)) {
			t.Fatal("esperava erro com IP solto em RedesVCNExtras")
		}
	})
}
