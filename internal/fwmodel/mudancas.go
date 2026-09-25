package fwmodel

import (
	"reflect"
	"sort"
)

// MudancaTipo indica a operação realizada sobre o elemento.
type MudancaTipo string

const (
	MudancaCriada   MudancaTipo = "criada"
	MudancaRemovida MudancaTipo = "removida"
	MudancaAlterada MudancaTipo = "alterada"
	MudancaMovida   MudancaTipo = "movida"
)

// Mudanca descreve uma diferença estrutural entre duas configurações do firewall.
type Mudanca struct {
	Objeto string      `json:"objeto"` // "regra" | "alias" | "agendamento" | "encaminhamento" | "ajustes"
	Tipo   MudancaTipo `json:"tipo"`   // "criada" | "removida" | "alterada" | "movida"
	ID     string      `json:"id"`
	Nome   string      `json:"nome,omitempty"`
	Zona   Zona        `json:"zona,omitempty"`
	Campos []string    `json:"campos,omitempty"`
}

// Mudancas calcula as diferenças semânticas entre a configuração antes e depois, com ordem de saída estável.
func Mudancas(antes, depois Config) []Mudanca {
	var out []Mudanca

	a := Normalizar(antes)
	d := Normalizar(depois)

	// 1. Regras
	regrasAntesMap := make(map[string]Regra, len(a.Regras))
	for _, r := range a.Regras {
		regrasAntesMap[r.ID] = r
	}
	regrasDepoisMap := make(map[string]Regra, len(d.Regras))
	for _, r := range d.Regras {
		regrasDepoisMap[r.ID] = r
	}

	var mudancasRegras []Mudanca
	for _, r := range d.Regras {
		rA, existe := regrasAntesMap[r.ID]
		if !existe {
			mudancasRegras = append(mudancasRegras, Mudanca{
				Objeto: "regra",
				Tipo:   MudancaCriada,
				ID:     r.ID,
				Nome:   r.Descricao,
				Zona:   r.Zona,
			})
			continue
		}

		var campos []string
		if rA.Ativa != r.Ativa {
			campos = append(campos, "ativa")
		}
		if rA.Acao != r.Acao {
			campos = append(campos, "acao")
		}
		if rA.Proto != r.Proto {
			campos = append(campos, "proto")
		}
		if rA.Origem != r.Origem {
			campos = append(campos, "origem")
		}
		if rA.Destino != r.Destino {
			campos = append(campos, "destino")
		}
		if rA.PortaDestino != r.PortaDestino {
			campos = append(campos, "porta_destino")
		}
		if rA.AgendamentoID != r.AgendamentoID {
			campos = append(campos, "agendamento_id")
		}
		if rA.Registrar != r.Registrar {
			campos = append(campos, "registrar")
		}
		if rA.Descricao != r.Descricao {
			campos = append(campos, "descricao")
		}

		posOuZonaMudou := rA.Posicao != r.Posicao || rA.Zona != r.Zona
		if len(campos) > 0 {
			if rA.Posicao != r.Posicao {
				campos = append(campos, "posicao")
			}
			if rA.Zona != r.Zona {
				campos = append(campos, "zona")
			}
			mudancasRegras = append(mudancasRegras, Mudanca{
				Objeto: "regra",
				Tipo:   MudancaAlterada,
				ID:     r.ID,
				Nome:   r.Descricao,
				Zona:   r.Zona,
				Campos: campos,
			})
		} else if posOuZonaMudou {
			mudancasRegras = append(mudancasRegras, Mudanca{
				Objeto: "regra",
				Tipo:   MudancaMovida,
				ID:     r.ID,
				Nome:   r.Descricao,
				Zona:   r.Zona,
			})
		}
	}

	for _, r := range a.Regras {
		if _, existe := regrasDepoisMap[r.ID]; !existe {
			mudancasRegras = append(mudancasRegras, Mudanca{
				Objeto: "regra",
				Tipo:   MudancaRemovida,
				ID:     r.ID,
				Nome:   r.Descricao,
				Zona:   r.Zona,
			})
		}
	}
	out = append(out, mudancasRegras...)

	// 2. Aliases
	aliasesAntesMap := make(map[string]Alias, len(a.Aliases))
	for _, al := range a.Aliases {
		aliasesAntesMap[al.ID] = al
	}
	aliasesDepoisMap := make(map[string]Alias, len(d.Aliases))
	for _, al := range d.Aliases {
		aliasesDepoisMap[al.ID] = al
	}

	var mudancasAliases []Mudanca
	for _, al := range d.Aliases {
		alA, existe := aliasesAntesMap[al.ID]
		if !existe {
			mudancasAliases = append(mudancasAliases, Mudanca{
				Objeto: "alias",
				Tipo:   MudancaCriada,
				ID:     al.ID,
				Nome:   al.Nome,
			})
			continue
		}

		var campos []string
		if alA.Nome != al.Nome {
			campos = append(campos, "nome")
		}
		if alA.Tipo != al.Tipo {
			campos = append(campos, "tipo")
		}
		if alA.Descricao != al.Descricao {
			campos = append(campos, "descricao")
		}
		if !reflect.DeepEqual(alA.Itens, al.Itens) {
			campos = append(campos, "itens")
		}
		if len(campos) > 0 {
			mudancasAliases = append(mudancasAliases, Mudanca{
				Objeto: "alias",
				Tipo:   MudancaAlterada,
				ID:     al.ID,
				Nome:   al.Nome,
				Campos: campos,
			})
		}
	}
	for _, al := range a.Aliases {
		if _, existe := aliasesDepoisMap[al.ID]; !existe {
			mudancasAliases = append(mudancasAliases, Mudanca{
				Objeto: "alias",
				Tipo:   MudancaRemovida,
				ID:     al.ID,
				Nome:   al.Nome,
			})
		}
	}
	sort.Slice(mudancasAliases, func(i, j int) bool {
		return mudancasAliases[i].ID < mudancasAliases[j].ID
	})
	out = append(out, mudancasAliases...)

	// 3. Agendamentos
	agendsAntesMap := make(map[string]Agendamento, len(a.Agendamentos))
	for _, ag := range a.Agendamentos {
		agendsAntesMap[ag.ID] = ag
	}
	agendsDepoisMap := make(map[string]Agendamento, len(d.Agendamentos))
	for _, ag := range d.Agendamentos {
		agendsDepoisMap[ag.ID] = ag
	}

	var mudancasAgends []Mudanca
	for _, ag := range d.Agendamentos {
		agA, existe := agendsAntesMap[ag.ID]
		if !existe {
			mudancasAgends = append(mudancasAgends, Mudanca{
				Objeto: "agendamento",
				Tipo:   MudancaCriada,
				ID:     ag.ID,
				Nome:   ag.Nome,
			})
			continue
		}

		var campos []string
		if agA.Nome != ag.Nome {
			campos = append(campos, "nome")
		}
		if agA.Descricao != ag.Descricao {
			campos = append(campos, "descricao")
		}
		if agA.Dias != ag.Dias {
			campos = append(campos, "dias")
		}
		if agA.Inicio != ag.Inicio {
			campos = append(campos, "inicio")
		}
		if agA.Fim != ag.Fim {
			campos = append(campos, "fim")
		}
		if len(campos) > 0 {
			mudancasAgends = append(mudancasAgends, Mudanca{
				Objeto: "agendamento",
				Tipo:   MudancaAlterada,
				ID:     ag.ID,
				Nome:   ag.Nome,
				Campos: campos,
			})
		}
	}
	for _, ag := range a.Agendamentos {
		if _, existe := agendsDepoisMap[ag.ID]; !existe {
			mudancasAgends = append(mudancasAgends, Mudanca{
				Objeto: "agendamento",
				Tipo:   MudancaRemovida,
				ID:     ag.ID,
				Nome:   ag.Nome,
			})
		}
	}
	sort.Slice(mudancasAgends, func(i, j int) bool {
		return mudancasAgends[i].ID < mudancasAgends[j].ID
	})
	out = append(out, mudancasAgends...)

	// 4. Encaminhamentos
	encsAntesMap := make(map[string]Encaminhamento, len(a.Encaminhamentos))
	for _, enc := range a.Encaminhamentos {
		encsAntesMap[enc.ID] = enc
	}
	encsDepoisMap := make(map[string]Encaminhamento, len(d.Encaminhamentos))
	for _, enc := range d.Encaminhamentos {
		encsDepoisMap[enc.ID] = enc
	}

	var mudancasEncs []Mudanca
	for _, enc := range d.Encaminhamentos {
		encA, existe := encsAntesMap[enc.ID]
		if !existe {
			mudancasEncs = append(mudancasEncs, Mudanca{
				Objeto: "encaminhamento",
				Tipo:   MudancaCriada,
				ID:     enc.ID,
				Nome:   enc.Nome,
			})
			continue
		}

		var campos []string
		if encA.Nome != enc.Nome {
			campos = append(campos, "nome")
		}
		if encA.Ativo != enc.Ativo {
			campos = append(campos, "ativo")
		}
		if encA.Proto != enc.Proto {
			campos = append(campos, "proto")
		}
		if encA.PortaExterna != enc.PortaExterna {
			campos = append(campos, "porta_externa")
		}
		if encA.IPDestino != enc.IPDestino {
			campos = append(campos, "ip_destino")
		}
		if encA.PortaDestino != enc.PortaDestino {
			campos = append(campos, "porta_destino")
		}
		if encA.Posicao != enc.Posicao {
			campos = append(campos, "posicao")
		}
		if len(campos) > 0 {
			mudancasEncs = append(mudancasEncs, Mudanca{
				Objeto: "encaminhamento",
				Tipo:   MudancaAlterada,
				ID:     enc.ID,
				Nome:   enc.Nome,
				Campos: campos,
			})
		}
	}
	for _, enc := range a.Encaminhamentos {
		if _, existe := encsDepoisMap[enc.ID]; !existe {
			mudancasEncs = append(mudancasEncs, Mudanca{
				Objeto: "encaminhamento",
				Tipo:   MudancaRemovida,
				ID:     enc.ID,
				Nome:   enc.Nome,
			})
		}
	}
	sort.Slice(mudancasEncs, func(i, j int) bool {
		return mudancasEncs[i].ID < mudancasEncs[j].ID
	})
	out = append(out, mudancasEncs...)

	// 5. Ajustes
	var camposAjustes []string
	if !reflect.DeepEqual(a.Ajustes.AntiBloqueio, d.Ajustes.AntiBloqueio) {
		camposAjustes = append(camposAjustes, "anti_bloqueio")
	}
	if !reflect.DeepEqual(a.Ajustes.RedesVCNExtras, d.Ajustes.RedesVCNExtras) {
		camposAjustes = append(camposAjustes, "redes_vcn_extras")
	}
	if a.Ajustes.RegistrarBloqueados != d.Ajustes.RegistrarBloqueados {
		camposAjustes = append(camposAjustes, "registrar_bloqueados")
	}
	if a.Ajustes.RegistrarDestinos != d.Ajustes.RegistrarDestinos {
		camposAjustes = append(camposAjustes, "registrar_destinos")
	}
	if a.Ajustes.RegistrarPadrao != d.Ajustes.RegistrarPadrao {
		camposAjustes = append(camposAjustes, "registrar_padrao")
	}
	if a.Ajustes.ContencaoBorda != d.Ajustes.ContencaoBorda {
		camposAjustes = append(camposAjustes, "contencao_borda")
	}

	if len(camposAjustes) > 0 {
		out = append(out, Mudanca{
			Objeto: "ajustes",
			Tipo:   MudancaAlterada,
			ID:     "ajustes",
			Nome:   "Ajustes do firewall",
			Campos: camposAjustes,
		})
	}

	return out
}
