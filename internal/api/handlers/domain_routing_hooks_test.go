package handlers_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/giovanibalarini/linkguard-cloud/internal/nftables"
)

type domainReconcileSpy struct {
	calls int
	err   error
}

func (s *domainReconcileSpy) Reconcile(context.Context) error {
	s.calls++
	return s.err
}

func TestBlocklistGroupToggleReconcilesDomainRouting(t *testing.T) {
	h, db := newGroupTestHandler(t)
	spy := &domainReconcileSpy{}
	h.SetDomainRouting(spy)

	groups, err := db.ListFirewallGroups()
	if err != nil {
		t.Fatal(err)
	}
	var blocklistID string
	for _, group := range groups {
		if group.Kind == nftables.GroupKindBlocklist {
			blocklistID = group.ID
			break
		}
	}
	if blocklistID == "" {
		t.Fatal("fixture sem grupo blocklist")
	}

	w := doJSON(t, h.ToggleGroup, http.MethodPost, "/api/nftables/groups/toggle",
		`{"id":"`+blocklistID+`","enabled":false}`)
	if w.Code != http.StatusOK {
		t.Fatalf("desligar blocklist = %d: %s", w.Code, w.Body.String())
	}
	if spy.calls != 1 {
		t.Fatalf("toggle do blocklist deveria reconciliar domínio uma vez, chamadas=%d", spy.calls)
	}
}
