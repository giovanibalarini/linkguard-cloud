package nftables

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
)

// masqueradeChain is the chain whose sole content is the WAN masquerade
// rule (verified against the live production ruleset: nothing else is ever
// written there — port forwards live in prerouting_dnat, filtering in
// forward/user_rules). That is what makes flush-then-rewrite safe here.
const masqueradeChain = "postrouting"

// ReconcileMasquerade re-derives the WAN masquerade (NAT) rule from the
// currently configured WAN interfaces, on every boot and on every link
// mutation — not just once at bootstrap.
//
// Why this exists: EnsureTable only creates `table inet linkguard` when it
// is missing, so on an already-provisioned box it is a no-op and the
// masquerade rule keeps whatever interface names it was born with. In
// production on 2026-08-10 a NIC was renamed by a PCI reshuffle
// (enp4s0 -> enp5s0) and the stale rule silently stopped matching, taking
// WAN1's NAT down until an operator added an iptables rule by hand.
//
// It flushes the chain before writing because `nft -f` (and `nft add`)
// ACCUMULATE rules rather than replacing them — the same production ruleset
// ended up with two masquerade lines, one of them referencing an interface
// that no longer existed. Flushing only this chain (never the table or the
// ruleset) keeps host_wan / blocklist / blocked_hosts / user_rules /
// prerouting_dnat untouched.
//
// Idempotent by construction: the same WAN set always yields the same two
// commands and the same final chain contents. A no-op in dry-run mode, same
// convention as the rest of the package.
//
// A FORMA DA REGRA DEPENDE DA PLATAFORMA, e o conteúdo dela vem inteiro de
// masqueradeRules — nunca daqui. Numa caixa de várias interfaces sai a regra
// de sempre, byte a byte; numa VM em que entra e sai pela mesma placa ela
// qualifica a origem pelas redes locais e carrega `counter`, porque ali
// `oifname` sozinho mascararia também o trânsito interno da nuvem e apagaria a
// identidade de origem que este produto existe para medir.
//
// A RECUSA COM LISTA VAZIA CONTINUA SENDO A PRIMEIRA COISA QUE ESTA FUNÇÃO FAZ,
// e continua certa. Numa VM de nuvem recém-instalada a lista deixou de chegar
// vazia — quem a preenche é o uplink derivado da plataforma, em
// cmd/linkguard-cloud/uplink.go —, e foi isso que mudou, não a guarda.
func (s *Service) ReconcileMasquerade(ctx context.Context, wanInterfaces []string) error {
	if s.exec.IsDryRun() {
		return nil
	}
	ifaces := sanitizeInterfaces(wanInterfaces)

	if len(ifaces) == 0 {
		// No configured WANs (all disabled, last one deleted, or a box using
		// LinkGuard for firewall/hosts but no links): refuse to touch the
		// chain at all. Flushing here would take down whatever masquerade
		// rule is currently live and working, and since Persist is skipped
		// in this branch too, /etc/nftables.conf would silently diverge
		// from the (now empty) live chain. Acting on an empty source of
		// truth is strictly less safe than doing nothing, so we do nothing.
		slog.Warn("nenhuma interface WAN válida configurada; regra de NAT existente foi mantida intacta", "requested", wanInterfaces)
		return nil
	}

	// A MESMA LEITURA DE PLATAFORMA QUE OS OUTROS Ensure* FAZEM. Em caixa de
	// várias interfaces a zona renderiza por interface e a regra sai byte a
	// byte a de sempre; em hairpin ela qualifica a origem. Ver masqueradeRules.
	z, err := s.zone(ifaces)
	if err != nil {
		return err
	}
	regras := masqueradeRules(z)
	if z.Hairpin() && !z.Discriminates() {
		slog.Warn("NAT aplicado SEM qualificar a origem; o tráfego interno da nuvem sai mascarado "+
			"e a medição por host perde a identidade de origem",
			"motivo", motivoDeChainVazia(z), "uplink", ifaces)
	}

	if _, err := s.exec.Execute(ctx, "nft", "flush", "chain", Family, Table, masqueradeChain); err != nil {
		return fmt.Errorf("limpar chain %s: %w", masqueradeChain, err)
	}

	// À MÃO, E NÃO POR rebuildChain, de propósito: rebuildChainIn ENGOLE a
	// falha de uma regra e segue adiante, enquanto esta função DEVOLVE o erro.
	// Numa chain de NAT a diferença é entre "o produto avisou que não há saída"
	// e "o produto disse que estava tudo bem com a rede fora do ar".
	for _, regra := range regras {
		args := append([]string{"add", "rule", Family, Table, masqueradeChain}, regra...)
		if _, err := s.exec.Execute(ctx, "nft", args...); err != nil {
			return fmt.Errorf("aplicar regra de masquerade: %w", err)
		}
	}

	slog.Info("regra de NAT reconciliada a partir das WANs configuradas", "interfaces", ifaces)

	if err := s.Persist(ctx); err != nil {
		slog.Warn("regra de NAT reconciliada, mas não foi possível persistir para o próximo boot", "err", err)
	}
	return nil
}

// masqueradeRules é a definição canônica da chain postrouting — a única fonte
// do que ela contém, como acctChainRules é para a acct e markHostsChainRules
// para a mark_hosts.
//
// EXISTE PORQUE HAVIA DUAS. ReconcileMasquerade montava o set à mão e
// buildBootstrapRuleset montava outro, com literal próprio. Duas cópias da
// mesma regra numa chain de NAT é a instalação nova divergindo da caixa
// atualizada no primeiro boot — a invariante que bootstrap.go repete em cada
// bloco.
//
// Devolve nil com lista vazia, e QUEM CHAMA é que decide o que fazer com isso:
// ReconcileMasquerade se recusa a tocar na chain (ver a guarda lá em cima) e o
// bootstrap escreve uma chain sem regra.
func masqueradeRules(z Zone) [][]string {
	if len(z.WANIfaces()) == 0 {
		return nil
	}
	if !z.Hairpin() {
		// VÁRIAS INTERFACES: INTOCADO. Sem `counter`, sem qualificação de
		// origem. Acrescentar `counter` aqui reescreveria a chain postrouting
		// da caixa de produção, e é o golden de onprem_2wan que diz não.
		//
		// A qualificação também não faria falta: com placas separadas, o que
		// sai pela WAN veio de dentro por definição — o trânsito leste-oeste
		// que o ramo de hairpin precisa excluir não existe aqui.
		return [][]string{zoneRule(z.ToExternal(), "masquerade")}
	}
	// HAIRPIN. Entra e sai pela MESMA placa, então `oifname` sozinho casa
	// TAMBÉM o tráfego leste-oeste da nuvem: o nó de uma sub-rede falando com o
	// de outra sai mascarado como se fosse esta máquina, e a identidade de
	// origem — que é o que o produto promete medir — evapora. Em Kubernetes
	// isso não é só medição: é o IP de origem que a política de rede do cluster
	// lê.
	if !z.Discriminates() {
		// Sem CIDR de dentro não dá para qualificar, e `ip saddr { }` é um set
		// anônimo vazio que o nft recusa. NAT SOLTO MESMO ASSIM: a promessa de
		// primeira ordem deste produto é "a máquina nova sai para a Internet".
		// Uma chain vazia aqui quebra a rede; uma regra larga demais degrada a
		// medição. Quem chama registra o motivo.
		return [][]string{zoneRule(z.ToExternal(), "counter", "masquerade")}
	}
	// QUALIFICA PELO DESTINO, NÃO PELA ORIGEM. Trocado depois de um incidente
	// medido: qualificar por `ip saddr { locais }` mascarava só quem estivesse
	// na sub-rede DESTA máquina, e num gateway de trânsito quem precisa de NAT
	// é justamente quem está ATRÁS dele, noutra sub-rede. Num bastion real, com
	// dois nós k3s em 10.0.1.0/24 mandando o default route para cá, a regra
	// qualificada por origem simplesmente não casava: o tráfego saía sem SNAT,
	// com endereço privado, e a resposta não tinha como voltar.
	//
	// Descobrir "quais redes estão atrás de mim" não é possível: a fabric não
	// diz o CIDR da nuvem, só o da sub-rede desta VNIC. Mas a pergunta certa
	// nunca foi essa — é "isto vai para a Internet?". O que vai para endereço
	// privado é trânsito interno e continua SEM máscara, que é como a
	// identidade de origem sobrevive para a contabilidade e para a política de
	// rede do cluster. O que vai para endereço público é mascarado, venha de
	// onde vier.
	return [][]string{zoneRule(z.ToExternal(),
		"ip", "daddr", "!=", redesPrivadasSet,
		"counter", "masquerade",
	)}
}

// redesPrivadasSet é o espaço RFC 1918 como set anônimo de nft.
//
// É o complemento de "a Internet" para efeito de NAT numa nuvem privada. Não
// inclui link-local (169.254.0.0/16) de propósito: o serviço de metadados da
// fabric vive lá, é alcançado pela própria máquina e nunca é trânsito.
const redesPrivadasSet = "{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }"

// sanitizeNetworks validates admin-supplied CIDRs before they reach an nft
// argv, mirroring sanitizeInterfaces' treatment of interface names — an
// admin-controlled string is exactly as dangerous here as an interface name
// is elsewhere in this package. An entry is dropped (not fatal to the whole
// reconcile) when it fails net.ParseCIDR, is a duplicate, is the open
// wildcard (0.0.0.0/0 or ::/0, checked by mask size so any equivalent
// spelling is caught), or is IPv6.
//
// IPv6 is rejected here too, independent of the handler-level
// timesync.ValidateAllowedNetworks that is the primary gate: the rule this
// function builds is `ip saddr { … }`, which in the `inet` family only ever
// matches IPv4 — nft errors out on an IPv6 prefix there. Before this guard
// existed, an IPv6 entry reaching ReconcileNTPInput made the accept-rule nft
// command itself fail, which returned an error *after* the chain had
// already been flushed and *before* the drop rule was added — an empty,
// unprotected input chain, silently. Dropping the bad entry here instead
// keeps the reconcile succeeding and every valid IPv4 entry still
// protected, the same "one bad entry doesn't sink the good ones" contract
// already applied to the wildcard and to plain garbage.
//
// A survivor is rewritten to ipnet.String() — its canonical network form —
// rather than passed through as typed, so a non-canonical prefix like
// "192.168.3.5/24" (host bits set, which net.ParseCIDR accepts and masks)
// ends up in the nft saddr set as exactly the same bytes as everywhere else
// this value is used (persisted config, chrony's `allow` line). This is
// defense in depth: the API handler already normalizes on save (see
// timesync.NormalizeAllowedNetworks), but this function must hold the same
// property on its own for any value that reached it another way (an old DB
// row saved before normalization existed, for instance).
func sanitizeNetworks(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, cidr := range in {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" || seen[cidr] {
			continue
		}
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ones, _ := ipnet.Mask.Size(); ones == 0 {
			continue
		}
		if ipnet.IP.To4() == nil {
			slog.Warn("rede IPv6 ignorada na chain de proteção do NTP (ainda não suportada; ip saddr só casa IPv4 na família inet)", "network", cidr)
			continue
		}
		seen[cidr] = true
		out = append(out, ipnet.String())
	}
	return out
}

// rebuildChain flushes exactly the named chain and re-adds each rule from
// the given canonical token lists, in order. Shared by every chain rebuilt
// from a canonical definition so the flush-then-rewrite sequence can't drift
// between them.
//
// C-1 (fix): a flush failure still aborts immediately — nothing can safely
// proceed without knowing the chain is actually empty first. But a failure
// adding one specific rule no longer aborts the rest: before this fix, the
// very first `nft add rule` error returned immediately, leaving the chain
// flushed but only partially rebuilt — every rule after the failing one
// silently disappeared from the live firewall, on this call and (since the
// same bad row keeps being re-rendered) on every subsequent boot too. A
// rule nft rejects for a reason field-level validation cannot catch (nft's
// own semantic checks go further than buildRuleTokens' regexes) must not be
// able to take the rest of the chain down with it: skip it, log it loudly,
// keep going, and report every failure back to the caller as one aggregate
// error so it can be surfaced (400 with nft's message, an alert, a boot-log
// warning) — a partial firewall with the other rules intact is strictly
// safer than an empty one.
func (s *Service) rebuildChain(ctx context.Context, chain string, rules [][]string) error {
	return s.rebuildChainIn(ctx, Table, chain, rules)
}

// rebuildChainIn é o mesmo flush-e-reescreve, numa tabela nomeada.
//
// Existe porque o registro de conversa da #115 vive numa TABELA PRÓPRIA
// (nftables.FlowsTable) — ver o topo de flows.go para a razão, que é o Persist
// não poder despejar aquele set no /etc/nftables.conf. Sem este parâmetro a
// feature nova teria de duplicar a sequência aqui, e é exatamente a duplicação
// que o comentário acima existe para impedir: as duas cópias divergiriam, e a
// que divergisse deixaria uma chain vazia num hook por onde passa todo o
// tráfego da LAN.
func (s *Service) rebuildChainIn(ctx context.Context, table, chain string, rules [][]string) error {
	if _, err := s.exec.Execute(ctx, "nft", "flush", "chain", Family, table, chain); err != nil {
		return fmt.Errorf("limpar chain %s: %w", chain, err)
	}
	var failures []string
	for _, tokens := range rules {
		args := append([]string{"add", "rule", Family, table, chain}, tokens...)
		if _, err := s.exec.Execute(ctx, "nft", args...); err != nil {
			expr := strings.Join(tokens, " ")
			slog.Error("nft rejeitou uma regra ao reconciliar a chain; as demais continuam sendo aplicadas",
				"chain", chain, "regra", expr, "err", err)
			failures = append(failures, fmt.Sprintf("%q: %v", expr, err))
			continue
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("%d regra(s) rejeitada(s) pelo nft em %s (as demais foram aplicadas normalmente): %s",
			len(failures), chain, strings.Join(failures, "; "))
	}
	return nil
}
