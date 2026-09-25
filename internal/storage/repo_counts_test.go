package storage_test

import (
	"testing"

	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

// Rede de segurança para o recorte da issue #26: CountLinks e CountAlerts
// estavam encalhados a ~900 linhas dos seus domínios e não tinham teste, embora
// alimentem o /health (CountLinks) e o coletor de monitoramento (CountAlerts).

func TestCountAlertsCountsOnlyTheUnresolvedOnes(t *testing.T) {
	db := newTestDB(t)

	n, err := db.CountAlerts()
	if err != nil {
		t.Fatalf("CountAlerts: %v", err)
	}
	if n != 0 {
		t.Fatalf("esperava 0 alertas, veio %d", n)
	}

	aberto := &storage.Alert{Type: "link_down", Severity: "critical", Title: "WAN1 caiu", Message: "sem resposta"}
	if err := db.CreateAlert(aberto); err != nil {
		t.Fatalf("CreateAlert: %v", err)
	}
	jaFechado := &storage.Alert{Type: "link_up", Severity: "info", Title: "WAN1 voltou", Message: "ok", Resolved: true}
	if err := db.CreateAlert(jaFechado); err != nil {
		t.Fatalf("CreateAlert: %v", err)
	}

	n, err = db.CountAlerts()
	if err != nil {
		t.Fatalf("CountAlerts: %v", err)
	}
	if n != 1 {
		t.Fatalf("esperava 1 alerta em aberto, veio %d", n)
	}

	if err := db.ResolveAlert(aberto.ID); err != nil {
		t.Fatalf("ResolveAlert: %v", err)
	}
	n, err = db.CountAlerts()
	if err != nil {
		t.Fatalf("CountAlerts: %v", err)
	}
	if n != 0 {
		t.Fatalf("esperava 0 alertas depois de resolver, veio %d", n)
	}
}
