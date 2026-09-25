package main

import (
	"context"
	"log/slog"
	"strings"

	"github.com/giovanibalarini/linkguard-cloud/internal/platform"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

// detectPlatformOnBoot descobre em que máquina o produto está e NUNCA derruba
// o boot: uma falha aqui devolve o instantâneo permissivo, que é exatamente o
// comportamento de hoje.
//
// Roda DEPOIS de openStore, porque o resultado é gravado na tabela settings, e
// ANTES de buildServices, porque é dali para baixo que todo o resto vai
// derivar. Não pode descer para provisionSystem: aquela função só é chamada
// depois de bootstrapdeps.Ensure, que num link ruim leva meia hora — nada que
// os outros serviços consultem pode nascer ali.
//
// Na caixa on-prem isto custa quatro leituras de arquivo e nenhum socket: sem
// sinal local de nuvem aceso, a detecção nem chega a tentar a rede. Ver
// internal/platform.
func detectPlatformOnBoot(db *storage.DB) platform.Snapshot {
	ctx, cancel := context.WithTimeout(context.Background(), platform.DetectBudget)
	defer cancel()

	snap, err := platform.NewDetector(db).Detect(ctx)
	if err != nil {
		slog.Warn("não foi possível detectar a plataforma; seguindo como máquina genérica", "err", err)
		return platform.UnknownSnapshot()
	}

	slog.Info("plataforma detectada",
		"plataforma", string(snap.Facts.Kind),
		"confianca", string(snap.Facts.Confidence),
		"sinais", strings.Join(snap.Facts.Signals, ","),
		"multi_wan", snap.Capabilities.MultiWAN,
		"origem", snap.Source)

	return snap
}

// redesLocais são os CIDRs que contam como "dentro" numa máquina em que entra e
// sai pela mesma interface. Só têm efeito ali: fora do hairpin o eixo das
// regras é a interface, e a lista é ignorada.
//
// DUAS FONTES, NESTA ORDEM, E NENHUMA TABELA NOVA:
//
//  1. netsvc.Config.SubnetCIDR — a sub-rede que o admin configurou pela tela.
//     É lida exatamente assim em buildServices para montar AdminAccess, e em
//     internal/netif para o roleSets. Quando existe, é a resposta certa.
//
//  2. platform.Facts.OCI.VNICs[].SubnetCIDR — de graça, já dentro do
//     instantâneo que o boot carregou. É o que faz o produto FUNCIONAR DE
//     PRIMEIRA numa VM recém-criada: ali netsvc_config está vazio, ninguém
//     abriu tela nenhuma, e o CIDR da sub-rede da VCN já está no banco antes
//     do primeiro pacote. Sem isto, a caixa nova subiria sem saber o que é
//     "dentro" e as chains nasceriam vazias esperando alguém configurar.
//
// As duas entram: numa VM com a LAN configurada por cima da sub-rede da nuvem,
// as duas respostas são verdadeiras ao mesmo tempo. sanitizeNetworks, do lado
// do nftables, descarta duplicata, CIDR inválido, curinga e IPv6.
func redesLocais(db *storage.DB, plat platform.Snapshot) []string {
	// Quem responde é a plataforma. Até 25/09/2026 entrava aqui também a LAN
	// configurada na tela de DHCP; o DHCP saiu da versão de nuvem, e a rede
	// privada é a da VCN, que a fabric informa.
	redes := redesDasPlacas(plat)

	// NUM GATEWAY DE TRÂNSITO, "DENTRO" É O ESPAÇO PRIVADO INTEIRO — não a
	// sub-rede desta placa.
	//
	// Aprendido num deploy que quebrou. A fabric só informa o CIDR da VNIC
	// desta máquina (10.0.0.0/24), mas quem passa por um gateway está, por
	// definição, ATRÁS dele, noutra sub-rede: os nós k3s em 10.0.1.0/24. Com
	// "dentro" limitado à própria sub-rede, a contabilidade por host não via
	// ninguém e a proteção de entrada tratava o vizinho da nuvem como Internet.
	//
	// Descobrir a lista exata de redes atrás é impossível, e chutar seria pior.
	// Mas a pergunta certa é outra: quem chega com endereço PRIVADO não veio da
	// Internet. Isso é verdade em qualquer nuvem e em qualquer topologia, e é o
	// mesmo raciocínio que faz o masquerade qualificar pelo destino.
	//
	// Só em hairpin: numa caixa com placas separadas o eixo é a interface e
	// esta lista não é consultada para decidir o que é de fora.
	if !plat.Capable().RoutedTransit {
		redes = append(redes, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
	}
	return redes
}

// redesDasPlacas são as sub-redes das placas desta máquina, como a fabric da
// nuvem as informa. Fora da nuvem, nenhuma.
func redesDasPlacas(plat platform.Snapshot) []string {
	var redes []string
	if plat.Facts.OCI != nil {
		for _, v := range plat.Facts.OCI.VNICs {
			if v.SubnetCIDR != "" {
				redes = append(redes, v.SubnetCIDR)
			}
		}
	}
	return redes
}
