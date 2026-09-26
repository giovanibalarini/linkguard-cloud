package nftables

import (
	"context"
	"os"
	"strings"
	"testing"
)

// fakeReconcileExec records every command so the test can assert the exact
// nft invocations. Dedicated to this file: the package's other fakes answer
// different command shapes, and reusing a generic one would hide which nft
// subcommand actually ran — the whole point of these assertions.
type fakeReconcileExec struct {
	dryRun   bool
	executed []string
	execErr  error
	// failOn, when set, overrides execErr per command: it receives the full
	// joined command string and decides whether that specific invocation
	// fails, letting a test simulate nft rejecting exactly one rule (C-1)
	// while every other command in the same reconcile still succeeds.
	failOn func(cmd string) error

	reads   []string
	readErr error
	// readFailOn mirrors failOn for ExecuteRead (used by the `nft -c`
	// pre-flight, which never mutates anything but must still be able to
	// fail in a test).
	readFailOn func(cmd string) error
	// readOut lets a test answer a specific read with canned nft output,
	// keyed by command prefix (the longest matching prefix wins, so the
	// answer is deterministic no matter how Go orders the map). Anything
	// not listed keeps the default behavior — empty output and readErr.
	// Needed by reconciles that first LOOK at the live ruleset before
	// deciding what to change (listGroupChains).
	readOut map[string]string
	// checkScripts holds the body of every temp file handed to `nft -c -f`,
	// captured at call time (CheckChain deletes it on return). Without this
	// a test can only see the file's path, which says nothing about what
	// was actually validated.
	checkScripts []string
	// applyScripts é o mesmo para `nft -f` SEM o -c: o caminho atômico da
	// chain forward com política restritiva (issue #92). Sem isto o teste só
	// enxerga o caminho do arquivo temporário, que é apagado no retorno e não
	// diz nada sobre o que foi aplicado.
	applyScripts []string
}

func (e *fakeReconcileExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	full := strings.Join(append([]string{cmd}, args...), " ")
	e.executed = append(e.executed, full)
	if len(args) >= 2 && args[0] == "-f" {
		if body, err := os.ReadFile(args[1]); err == nil {
			e.applyScripts = append(e.applyScripts, string(body))
		}
	}
	if e.failOn != nil {
		return "", e.failOn(full)
	}
	return "", e.execErr
}
func (e *fakeReconcileExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	full := strings.Join(append([]string{cmd}, args...), " ")
	e.reads = append(e.reads, full)
	if len(args) >= 3 && args[0] == "-c" && args[1] == "-f" {
		if body, err := os.ReadFile(args[2]); err == nil {
			e.checkScripts = append(e.checkScripts, string(body))
		}
	}
	if e.readFailOn != nil {
		return "", e.readFailOn(full)
	}
	best := ""
	for prefix := range e.readOut {
		if strings.HasPrefix(full, prefix) && len(prefix) > len(best) {
			best = prefix
		}
	}
	if best != "" {
		return e.readOut[best], nil
	}
	return "", e.readErr
}
func (e *fakeReconcileExec) IsDryRun() bool                              { return e.dryRun }
func (_ *fakeReconcileExec) WriteFile(string, []byte, os.FileMode) error { return nil }

func ranCommand(executed []string, want string) bool {
	for _, c := range executed {
		if c == want {
			return true
		}
	}
	return false
}

// TestReconcileMasqueradeFlushesBeforeAdding is the regression test for the
// real production bug this feature exists to fix: `nft -f` on the persisted
// ruleset ADDS rules instead of replacing them, so a stale masquerade line
// referencing a renamed interface (enp4s0 after the NIC became enp5s0)
// survived alongside the new one. Reconciliation must flush the chain first
// so the result is exactly one masquerade rule matching current reality.
func TestReconcileMasqueradeFlushesBeforeAdding(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileMasquerade(context.Background(), []string{"enp2s0", "enp5s0"}); err != nil {
		t.Fatalf("ReconcileMasquerade: %v", err)
	}

	wantFlush := "nft flush chain inet linkguard postrouting"
	if !ranCommand(exec.executed, wantFlush) {
		t.Errorf("missing %q; ran: %v", wantFlush, exec.executed)
	}
	wantAdd := `nft add rule inet linkguard postrouting oifname { "enp2s0", "enp5s0" } masquerade`
	if !ranCommand(exec.executed, wantAdd) {
		t.Errorf("missing %q; ran: %v", wantAdd, exec.executed)
	}
	// Order matters: flushing after adding would wipe the new rule.
	flushIdx, addIdx := -1, -1
	for i, c := range exec.executed {
		if c == wantFlush {
			flushIdx = i
		}
		if c == wantAdd {
			addIdx = i
		}
	}
	if flushIdx > addIdx {
		t.Errorf("flush ran after add (would erase the new rule); ran: %v", exec.executed)
	}
}

// TestReconcileMasqueradeNeverFlushesTheWholeTable guards the elements that
// live in the same table but must survive: host_wan, blocklist,
// blocked_hosts, user_rules and prerouting_dnat.
func TestReconcileMasqueradeNeverFlushesTheWholeTable(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileMasquerade(context.Background(), []string{"enp2s0"}); err != nil {
		t.Fatalf("ReconcileMasquerade: %v", err)
	}
	for _, c := range exec.executed {
		if strings.Contains(c, "flush table") || strings.Contains(c, "flush ruleset") {
			t.Errorf("must never flush the table/ruleset (would drop host_wan/blocklist/user_rules), ran: %q", c)
		}
	}
}

func TestReconcileMasqueradeIsIdempotent(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileMasquerade(context.Background(), []string{"enp2s0"}); err != nil {
		t.Fatalf("first: %v", err)
	}
	first := append([]string(nil), exec.executed...)
	exec.executed = nil
	if err := s.ReconcileMasquerade(context.Background(), []string{"enp2s0"}); err != nil {
		t.Fatalf("second: %v", err)
	}
	if len(first) != len(exec.executed) {
		t.Errorf("second run issued a different command set:\nfirst=%v\nsecond=%v", first, exec.executed)
	}
}

// TestReconcileMasqueradeSanitizesInterfaces: an invalid name must never be
// interpolated into text handed to `nft` (command injection guard, same
// rule the bootstrap path already applies).
func TestReconcileMasqueradeSanitizesInterfaces(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileMasquerade(context.Background(), []string{"enp2s0", "evil; rm -rf /"}); err != nil {
		t.Fatalf("ReconcileMasquerade: %v", err)
	}
	for _, c := range exec.executed {
		if strings.Contains(c, "evil") || strings.Contains(c, "rm -rf") {
			t.Errorf("invalid interface reached the nft command: %q", c)
		}
	}
}

// TestReconcileMasqueradeWithNoWANsLeavesTheChainAlone: with zero configured
// WANs (all disabled, last one deleted, or a box using LinkGuard for
// firewall/hosts but no links) there is nothing legitimate to masquerade on
// — but there may well be a live, working NAT rule already in the chain
// (e.g. written by a previous reconcile, or the DB read racing a link
// delete). Flushing on an empty source of truth would take a healthy box's
// NAT down and, since Persist is also skipped in this branch, leave
// /etc/nftables.conf out of sync with whatever the live chain ends up as.
// Refusing to act — no flush, no add — is strictly safer than acting on
// nothing, and it stays idempotent.
func TestReconcileMasqueradeWithNoWANsLeavesTheChainAlone(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}

	if err := s.ReconcileMasquerade(context.Background(), nil); err != nil {
		t.Fatalf("ReconcileMasquerade: %v", err)
	}
	if len(exec.executed) != 0 {
		t.Errorf("expected no commands at all with zero WANs (chain must be left alone), ran: %v", exec.executed)
	}
}

func TestReconcileMasqueradeNoopInDryRun(t *testing.T) {
	exec := &fakeReconcileExec{dryRun: true}
	s := &Service{exec: exec}

	if err := s.ReconcileMasquerade(context.Background(), []string{"enp2s0"}); err != nil {
		t.Fatalf("ReconcileMasquerade in dry-run: %v", err)
	}
	if len(exec.executed) != 0 {
		t.Errorf("expected no commands in dry-run, ran: %v", exec.executed)
	}
}

// ─── O masquerade qualificado (o incremento do uplink) ───────────────────────

// TestEmHairpinOMasqueradeQualificaPeloDestinoENaoPelaOrigem é a segunda metade
// do incremento, e a que o produto PROMETE MEDIR.
//
// Numa VM de VNIC única entra e sai pela MESMA placa, então `oifname` sozinho
// casa também o tráfego leste-oeste da nuvem: o nó de uma sub-rede falando com
// o de outra sai mascarado como se fosse esta máquina, e a identidade de origem
// evapora. Em Kubernetes isso não é só medição — é o IP de origem que a política
// de rede do cluster lê.
//
// A PRIMEIRA TENTATIVA QUALIFICOU PELA ORIGEM E QUEBROU EM PRODUÇÃO. Num
// gateway de trânsito quem precisa de NAT é quem está ATRÁS, noutra sub-rede:
// dois nós k3s em 10.0.1.0/24 com o default route apontado para o bastion
// saíram sem SNAT, com endereço privado, e a resposta não tinha como voltar.
// Descobrir "quais redes estão atrás de mim" é impossível — a fabric só informa
// o CIDR desta VNIC. A pergunta certa é "isto vai para a Internet?".
func TestEmHairpinOMasqueradeQualificaPeloDestinoENaoPelaOrigem(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}
	s.SetZoneFactsSource(func() (ZoneFacts, error) {
		return ZoneFacts{Hairpin: true, LocalNets: []string{"10.0.0.0/24"}, PathMTU: 1500}, nil
	})

	if err := s.ReconcileMasquerade(context.Background(), []string{"ens3"}); err != nil {
		t.Fatalf("ReconcileMasquerade: %v", err)
	}

	var regra string
	for _, c := range exec.executed {
		if strings.Contains(c, "add rule") {
			regra = c
		}
	}
	want := `nft add rule inet linkguard postrouting oifname { "ens3" } ip daddr != { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } counter masquerade`
	if regra != want {
		t.Errorf("regra de NAT:\n  %q\nqueria:\n  %q", regra, want)
	}
	// `counter` NÃO É DECORAÇÃO: é o que permite ao operador ver que a regra
	// está sendo usada numa chain que ele não pode listar por host.
	if !strings.Contains(regra, "counter") {
		t.Error("a regra de NAT da nuvem saiu sem contador")
	}
}

// TestEmVariasWANsOMasqueradeContinuaSemContadorESemQualificacao trava a chain
// postrouting da caixa de produção.
//
// Alimentar a zona com CIDRs e com MTU de caminho não pode mudar um byte aqui:
// com placas separadas, o que sai pela WAN veio de dentro por definição, e
// acrescentar `counter` reescreveria a chain de uma máquina que está
// funcionando 24/7 para resolver um problema que ela não tem.
func TestEmVariasWANsOMasqueradeContinuaSemContadorESemQualificacao(t *testing.T) {
	rodar := func(fonte func() (ZoneFacts, error)) string {
		exec := &fakeReconcileExec{}
		s := &Service{exec: exec}
		if fonte != nil {
			s.SetZoneFactsSource(fonte)
		}
		if err := s.ReconcileMasquerade(context.Background(), []string{"ppp0", "enp2s0"}); err != nil {
			t.Fatalf("ReconcileMasquerade: %v", err)
		}
		for _, c := range exec.executed {
			if strings.Contains(c, "add rule") {
				return c
			}
		}
		t.Fatal("nenhuma regra foi emitida numa caixa com duas WANs")
		return ""
	}

	semFonte := rodar(nil)
	comFonte := rodar(func() (ZoneFacts, error) {
		return ZoneFacts{Hairpin: false, LocalNets: []string{"192.168.3.0/24"}, PathMTU: 1500}, nil
	})

	want := `nft add rule inet linkguard postrouting oifname { "ppp0", "enp2s0" } masquerade`
	if semFonte != want {
		t.Errorf("sem a fonte da plataforma a regra mudou:\n  %q\nqueria:\n  %q", semFonte, want)
	}
	if comFonte != want {
		t.Errorf("alimentar a plataforma mudou a chain de NAT da produção:\n  %q\nqueria:\n  %q", comFonte, want)
	}
	// A ORDEM DE CADASTRO É CONTRATO: ppp0 primeiro, não em ordem alfabética.
	if strings.Index(comFonte, "ppp0") > strings.Index(comFonte, "enp2s0") {
		t.Errorf("a ordem das WANs foi trocada: %q", comFonte)
	}
}

// TestEmHairpinSemRedeLocalONATSaiLargoEmVezDeAChainFicarVazia prende o ramo
// degradado.
//
// Sem CIDR de dentro não dá para qualificar, e `ip saddr { }` — o set anônimo
// vazio — é recusado pelo nft. A escolha é entre uma regra larga demais, que
// degrada a MEDIÇÃO, e uma chain vazia, que tira a máquina da Internet. A
// promessa de primeira ordem deste produto é que a máquina nova saia para a
// Internet, então a regra sai larga, com contador e com aviso.
func TestEmHairpinSemRedeLocalONATSaiLargoEmVezDeAChainFicarVazia(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}
	s.SetZoneFactsSource(func() (ZoneFacts, error) {
		return ZoneFacts{Hairpin: true, PathMTU: 1500}, nil
	})

	if err := s.ReconcileMasquerade(context.Background(), []string{"ens3"}); err != nil {
		t.Fatalf("ReconcileMasquerade: %v", err)
	}

	var regra string
	for _, c := range exec.executed {
		if strings.Contains(c, "add rule") {
			regra = c
		}
		if strings.Contains(c, "saddr { }") {
			t.Fatalf("emitiu um set anônimo vazio, que o nft recusa: %q", c)
		}
	}
	want := `nft add rule inet linkguard postrouting oifname { "ens3" } counter masquerade`
	if regra != want {
		t.Errorf("regra de NAT degradada:\n  %q\nqueria:\n  %q", regra, want)
	}
}

// TestAGuardaDeFonteVaziaDoMasqueradeContinuaIntacta é a afirmação que este
// incremento NÃO podia quebrar, e por isso é reafirmada do lado de cá.
//
// A guarda está certa: agir sobre uma fonte de verdade vazia é estritamente
// menos seguro do que não fazer nada, porque derrubaria a regra de NAT que
// estiver viva por causa de um SELECT que falhou ou de um link recém-apagado.
// O que o uplink implícito mudou não foi a guarda — foi a lista deixar de
// chegar vazia numa máquina em que a plataforma sabe responder.
func TestAGuardaDeFonteVaziaDoMasqueradeContinuaIntacta(t *testing.T) {
	casos := map[string]func() (ZoneFacts, error){
		"sem fonte de plataforma": nil,
		"numa máquina de nuvem com rede local conhecida": func() (ZoneFacts, error) {
			return ZoneFacts{Hairpin: true, LocalNets: []string{"10.0.0.0/24"}, PathMTU: 1500}, nil
		},
	}
	for nome, fonte := range casos {
		t.Run(nome, func(t *testing.T) {
			exec := &fakeReconcileExec{}
			s := &Service{exec: exec}
			if fonte != nil {
				s.SetZoneFactsSource(fonte)
			}
			if err := s.ReconcileMasquerade(context.Background(), nil); err != nil {
				t.Fatalf("ReconcileMasquerade: %v", err)
			}
			if len(exec.executed) != 0 {
				t.Errorf("com a fonte de verdade VAZIA a chain tinha de ficar intocada; rodou: %v", exec.executed)
			}
		})
	}
}

// TestOMasqueradeDoBootstrapEODaReconciliacaoSaoAMesmaRegra: instalação nova ==
// caixa atualizada.
//
// Duas cópias da mesma regra numa chain de NAT é a instalação nova divergindo
// no primeiro boot — e numa chain de NAT isso é a identidade de origem
// aparecendo e sumindo conforme quem escreveu por último.
func TestOMasqueradeDoBootstrapEODaReconciliacaoSaoAMesmaRegra(t *testing.T) {
	casos := []struct {
		nome  string
		wans  []string
		fatos ZoneFacts
	}{
		{"produção de duas WANs", []string{"ppp0", "enp2s0"}, ZoneFacts{LocalNets: []string{"192.168.3.0/24"}}},
		{"VM de nuvem com uplink implícito", []string{"ens3"}, ZoneFacts{Hairpin: true, LocalNets: []string{"10.0.0.0/24"}, PathMTU: 1500}},
		{"VM de nuvem sem rede local", []string{"ens3"}, ZoneFacts{Hairpin: true, PathMTU: 1500}},
	}
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			exec := &fakeReconcileExec{}
			s := &Service{exec: exec}
			s.SetZoneFactsSource(func() (ZoneFacts, error) { return c.fatos, nil })
			if err := s.ReconcileMasquerade(context.Background(), c.wans); err != nil {
				t.Fatalf("ReconcileMasquerade: %v", err)
			}
			var daReconciliacao string
			for _, cmd := range exec.executed {
				if i := strings.Index(cmd, "postrouting "); strings.Contains(cmd, "add rule") && i >= 0 {
					daReconciliacao = cmd[i+len("postrouting "):]
				}
			}
			if daReconciliacao == "" {
				t.Fatal("a reconciliação não emitiu regra nenhuma")
			}
			if doBootstrap := buildBootstrapRuleset(c.wans, c.fatos); !strings.Contains(doBootstrap, "\t\t"+daReconciliacao+"\n") {
				t.Errorf("o ruleset de instalação nova não contém a MESMA regra que a reconciliação escreve.\nreconciliação: %q\nbootstrap:\n%s",
					daReconciliacao, doBootstrap)
			}
		})
	}
}
