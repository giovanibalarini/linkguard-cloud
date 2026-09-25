package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/giovanibalarini/linkguard-cloud/internal/api/handlers"
	"github.com/giovanibalarini/linkguard-cloud/internal/firewall"
	"github.com/giovanibalarini/linkguard-cloud/internal/platform"
)

// O UPLINK — por onde esta máquina sai para a Internet.
//
// ─── NÃO HÁ CADASTRO ─────────────────────────────────────────────────────────
//
// A versão on-prem tinha a tabela `links`: o admin cadastrava cada WAN, e o
// cadastro vencia qualquer dedução. Na nuvem a saída é UMA e é da VCN, e a
// versão cloud não tem mais links (nem failover, nem balanceamento). A pergunta
// "quais são as WANs" passa a ter só duas fontes, nesta ordem:
//
//  1. A PLATAFORMA, quando o IMDS do provedor confirmou: a placa da VNIC
//     primária e a MTU do caminho externo (que numa VM da OCI não é a da placa:
//     a placa anuncia 9000 e o caminho aceita 1500).
//  2. O KERNEL: a placa da rota default. É a fonte de reserva para o boot em
//     que o IMDS não respondeu (cache invalidado, metadata fora do ar) — sem
//     ela, uma falha passageira do IMDS esvaziaria a lista de WANs, e com a
//     lista vazia a mss_clamp e a proteção de entrada da WAN nasceriam vazias
//     e seriam persistidas assim.
//
// A ROTA DEFAULT APONTA PARA FORA, POR DEFINIÇÃO. O medo que a versão on-prem
// tinha de deduzir uplink ("a placa eleita pode ser a da LAN") vinha da eleição
// por "primeira placa que não é de sistema". A rota default não é eleição: é o
// próprio kernel dizendo por onde sai o que não é local.
//
// ─── A GUARDA NÃO SAIU ───────────────────────────────────────────────────────
//
// Se nenhuma das duas responder, a lista é VAZIA, e lista vazia é o que mantém
// ReconcileMasquerade se recusando a tocar na chain de NAT.

// Uplink é por onde esta máquina sai para a Internet, e o que o caminho de
// saída suporta. Zero-value == "não sei".
type Uplink struct {
	// Interface é a placa de saída. "" = desconhecido.
	Interface string
	// PathMTU é o que o CAMINHO até a Internet suporta, não o que a interface
	// anuncia. 0 = desconhecido. Só a plataforma sabe responder isto.
	PathMTU int
	// Origem é de onde a resposta veio: handlers.UplinkOrigem*.
	Origem string
}

// uplinkDaPlataforma devolve o uplink que a plataforma AFIRMA, ou o zero-value.
//
// Kind.IsCloud() && Confidence == ConfidenceAuthoritative: só quando o IMDS do
// provedor CONFIRMOU. "Achei que era nuvem por um sinal local" não é autoridade
// para escolher a placa — para isso existe a rota default, logo abaixo.
//
// Com mais de uma VNIC a resposta continua sendo a PRIMÁRIA: é nela que a VCN
// põe a rota default da instância, e a versão cloud não tem cadastro de WAN que
// pudesse escolher outra.
func uplinkDaPlataforma(plat platform.Snapshot) Uplink {
	if !plat.Facts.Kind.IsCloud() || plat.Facts.Confidence != platform.ConfidenceAuthoritative {
		return Uplink{}
	}
	if plat.Facts.Net.PrimaryInterface == "" {
		return Uplink{}
	}
	return Uplink{
		Interface: plat.Facts.Net.PrimaryInterface,
		// PathMTU e NÃO LinkMTU. Copiar a MTU da placa para cá seria o bug que
		// mssclamp.go descreve: um ajuste de MSS para 8960 num caminho de 1500
		// é pior do que nenhum, porque parece feito.
		PathMTU: plat.Facts.Net.PathMTU,
		Origem:  handlers.UplinkOrigemPlataforma,
	}
}

// uplinkEfetivo resolve a precedência: plataforma, depois kernel.
//
// ERRO DE LEITURA PROPAGA. Obedecer a uma lista vazia que na verdade é um `ip
// route` que falhou apagaria a proteção de entrada de uma caixa que a tem, e o
// painel continuaria dizendo que ela está protegida. É o contrato que
// internal/nftables/policy.go declara para a fonte de WANs.
func uplinkEfetivo(ctx context.Context, exec firewall.Executor, plat platform.Snapshot) (Uplink, error) {
	if u := uplinkDaPlataforma(plat); u.Interface != "" {
		return u, nil
	}
	dev, err := placaDaRotaDefault(ctx, exec)
	if err != nil {
		return Uplink{}, err
	}
	if dev == "" {
		return Uplink{}, nil
	}
	// Sem a plataforma, a MTU do caminho é desconhecida: o ajuste de MSS fica
	// de fora em vez de chutar.
	return Uplink{Interface: dev, Origem: handlers.UplinkOrigemKernel}, nil
}

// wansEfetivas é A LISTA — a única derivação de "quais são as WANs desta
// máquina" que o produto tem. Na versão cloud é o uplink, ou nada.
func wansEfetivas(ctx context.Context, exec firewall.Executor, plat platform.Snapshot) ([]string, error) {
	u, err := uplinkEfetivo(ctx, exec, plat)
	if err != nil {
		return nil, fmt.Errorf("descobrir por onde esta máquina sai para a Internet: %w", err)
	}
	if u.Interface == "" {
		return nil, nil
	}
	return []string{u.Interface}, nil
}

// rotaDefault é o pedaço de `ip -j route show default` que interessa.
type rotaDefault struct {
	Dev    string `json:"dev"`
	Metric int    `json:"metric"`
}

// placaDaRotaDefault devolve a placa da rota default de menor métrica, ou ""
// quando não há rota default.
func placaDaRotaDefault(ctx context.Context, exec firewall.Executor) (string, error) {
	out, err := exec.ExecuteRead(ctx, "ip", "-j", "route", "show", "default")
	if err != nil {
		return "", fmt.Errorf("ip route show default: %w", err)
	}
	var rotas []rotaDefault
	if err := json.Unmarshal([]byte(out), &rotas); err != nil {
		return "", fmt.Errorf("ler a rota default: %w", err)
	}
	melhor := -1
	for i, r := range rotas {
		if r.Dev == "" {
			continue
		}
		if melhor < 0 || r.Metric < rotas[melhor].Metric {
			melhor = i
		}
	}
	if melhor < 0 {
		return "", nil
	}
	return rotas[melhor].Dev, nil
}

// uplinkParaTela traduz o uplink efetivo no que o painel mostra.
//
// TRADUZ AQUI, e não no handler: quem sabe casar o instantâneo da plataforma
// com o kernel é este arquivo, e a camada HTTP não pode importar
// internal/platform só para nomear a plataforma numa frase de tela.
func uplinkParaTela(ctx context.Context, exec firewall.Executor, plat platform.Snapshot) handlers.UplinkView {
	nome := string(plat.Facts.Kind)
	if nome == "" {
		nome = string(platform.KindUnknown)
	}
	v := handlers.UplinkView{Origem: handlers.UplinkOrigemNenhuma, Plataforma: nome}
	u, err := uplinkEfetivo(ctx, exec, plat)
	if err != nil {
		// Erro de leitura NÃO vira "não há uplink" na tela sem aviso: a origem
		// fica em "none" com interface vazia, que é o honesto "não sei
		// responder agora", e o log diz por quê.
		slog.Warn("não foi possível derivar o uplink para a tela", "err", err)
		return v
	}
	if u.Interface == "" {
		return v
	}
	v.Interface = u.Interface
	v.PathMTU = u.PathMTU
	v.Origem = u.Origem
	return v
}
