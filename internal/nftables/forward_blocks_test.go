package nftables

import (
	"context"
	"strings"
	"testing"
)

// Era TestReconcileStructuralChainsForwardRuleOrder, que assertava a ordem
// ANTIGA: `jump user_rules` primeiro e os bloqueios depois. A intenção
// continua a mesma — o nft avalia de cima para baixo, então a ordem desta
// chain é comportamento observável e precisa de teste —, mas a expectativa
// está invertida de propósito (design spec §3): bloqueio administrativo é
// avaliado antes dos grupos e sempre vence, porque "bloquear host em 1
// clique" que perde para uma regra criada meses antes é um bloqueio que
// mente. E a forward deixou de alcançar user_rules: as regras do admin
// passaram a morar dentro de grupos.
//
// ATUALIZADO (a forward virou uma lista ordenada só): os quatro bloqueios
// deixaram de ser literais em código e passaram a ser dois itens da lista,
// então a lista deste teste é a que a produção tem depois da migração — os
// dois grupos do sistema nas posições 0 e 1, o grupo do admin depois. A
// asserção não mudou: bloqueio antes do jump.
func TestForwardChainNoLongerLetsUserRulesShadowTheBlocks(t *testing.T) {
	exec := &fakeReconcileExec{}
	s := &Service{exec: exec}
	wireNoInputExtras(s)
	groups := []StoredGroup{
		{ID: "h", Name: "Hosts bloqueados", ChainName: SystemChainBlockedHosts,
			Kind: GroupKindBlockedHosts, Enabled: true, Position: 0, Fallthrough: FallthroughContinue},
		{ID: "l", Name: "Destinos bloqueados", ChainName: SystemChainBlocklist,
			Kind: GroupKindBlocklist, Enabled: true, Position: 1, Fallthrough: FallthroughContinue},
		{ID: "a", Name: "Minhas regras", ChainName: "grp_aaa", Kind: GroupKindAdmin,
			Enabled: true, Position: 2, Fallthrough: FallthroughContinue}}

	if err := s.ReconcileGroups(context.Background(), groups); err != nil {
		t.Fatalf("ReconcileGroups: %v", err)
	}
	var adds []string
	for _, c := range exec.executed {
		if strings.HasPrefix(c, "nft add rule inet linkguard forward") {
			adds = append(adds, c)
		}
	}
	if len(adds) != 8 {
		t.Fatalf("expected 8 rules added to forward (7 blocks + 1 group jump), got %d: %v", len(adds), adds)
	}
	for i, want := range []string{"@blocked_hosts", "@blocked_hosts", "@blocked_macs", "@blocklist", "@blocklist", "@dom_blocked", "@dom_blocked6"} {
		if !strings.Contains(adds[i], want) {
			t.Errorf("forward rule %d = %q, want it to contain %q", i, adds[i], want)
		}
	}
	if !strings.Contains(adds[7], "jump grp_aaa") {
		t.Errorf("last forward rule must be the group jump, got %q", adds[7])
	}
	for _, c := range adds {
		if strings.Contains(c, "jump "+UserChain) {
			t.Errorf("a forward não pode mais pular para %s: %q", UserChain, c)
		}
	}
}
