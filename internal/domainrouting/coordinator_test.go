package domainrouting_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/giovanibalarini/linkguard-cloud/internal/domainrouting"
	"github.com/giovanibalarini/linkguard-cloud/internal/domtargets"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
	_ "modernc.org/sqlite"
)

type fakeRuntime struct {
	mu    sync.Mutex
	last  []domtargets.Alvo
	state domtargets.Estado
}

func (f *fakeRuntime) DefinirAlvos(alvos []domtargets.Alvo) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.last = append([]domtargets.Alvo(nil), alvos...)
}

func (f *fakeRuntime) Estado(context.Context) domtargets.Estado {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state
}

func (f *fakeRuntime) alvo(domain string) (domtargets.Alvo, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, target := range f.last {
		if target.Dominio == domain {
			return target, true
		}
	}
	return domtargets.Alvo{}, false
}

func newDB(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "domain-routing.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func addBlockGroup(t *testing.T, db *storage.DB, enabled bool) {
	t.Helper()
	if err := db.CreateFirewallGroup(&storage.FirewallGroup{
		ID: "system-blocklist", Name: "Destinos bloqueados", Kind: "blocklist", Enabled: enabled,
	}); err != nil {
		t.Fatal(err)
	}
}

func addActiveBlock(t *testing.T, db *storage.DB) *storage.DomainTarget {
	t.Helper()
	target := &storage.DomainTarget{Domain: "video.example.com", Capability: storage.DomainCapBarrar}
	if err := db.CreateDomainTarget(target); err != nil {
		t.Fatal(err)
	}
	if err := db.SetDomainTargetStage(target.ID, storage.DomainStageAtivo); err != nil {
		t.Fatal(err)
	}
	return target
}

func targetView(t *testing.T, state domainrouting.State, domain string) domainrouting.TargetView {
	t.Helper()
	for _, row := range state.Targets {
		if row.Domain == domain {
			return row
		}
	}
	t.Fatalf("target %s não apareceu em %+v", domain, state.Targets)
	return domainrouting.TargetView{}
}

func TestBootGateKeepsActiveIntentSuspendedUntilPrepare(t *testing.T) {
	db := newDB(t)
	addBlockGroup(t, db, true)
	addActiveBlock(t, db)
	runtime := &fakeRuntime{}
	coordinator := domainrouting.New(db, runtime)

	if err := coordinator.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := targetView(t, coordinator.State(context.Background()), "video.example.com")
	if before.Stage != storage.DomainStageAtivo || before.EffectiveStage != storage.DomainStageEnsaio ||
		!before.Suspended || before.SuspensionReason != domainrouting.ReasonBootPending {
		t.Fatalf("gate de boot não suspendeu a intenção ativa: %+v", before)
	}
	if got, _ := runtime.alvo(before.Domain); got.Estagio != domtargets.Ensaio {
		t.Fatalf("runtime recebeu estágio %q antes de Prepare", got.Estagio)
	}

	if err := coordinator.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	afterState := coordinator.State(context.Background())
	after := targetView(t, afterState, "video.example.com")
	if !afterState.Ready || after.EffectiveStage != storage.DomainStageAtivo || after.Suspended {
		t.Fatalf("Prepare não ativou: state=%+v target=%+v", afterState, after)
	}
	if got, _ := runtime.alvo(after.Domain); got.Estagio != domtargets.Ativo || got.Capacidade != domtargets.Barrar {
		t.Fatalf("runtime não recebeu o bloqueio ativo: %+v", got)
	}
}

func TestHoldClosesAnAlreadyOpenBootGate(t *testing.T) {
	db := newDB(t)
	addBlockGroup(t, db, true)
	addActiveBlock(t, db)
	runtime := &fakeRuntime{}
	coordinator := domainrouting.New(db, runtime)
	if err := coordinator.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}

	if err := coordinator.Hold(context.Background()); err != nil {
		t.Fatal(err)
	}
	state := coordinator.State(context.Background())
	row := targetView(t, state, "video.example.com")
	if state.Ready || !row.Suspended || row.SuspensionReason != domainrouting.ReasonBootPending || row.EffectiveStage != storage.DomainStageEnsaio {
		t.Fatalf("Hold não fechou o gate: state=%+v target=%+v", state, row)
	}
	if got, _ := runtime.alvo(row.Domain); got.Estagio != domtargets.Ensaio {
		t.Fatalf("runtime continuou ativo após Hold: %+v", got)
	}
}

// Uma linha de "direcionar" vinda do linkguard-fw (escolher a WAN por
// domínio, que saiu com o multi-WAN) aparece suspensa para ser vista e
// apagada, e nunca chega ao runtime.
func TestOldSteeringRowIsShownSuspendedAndNeverPublished(t *testing.T) {
	path := filepath.Join(t.TempDir(), "domain-routing.db")
	db, err := storage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	addBlockGroup(t, db, true)
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`INSERT INTO domain_targets (id, domain, capability, stage, link_id, mark)
		VALUES ('velho', 'video.example.com', 'direcionar', 'ativo', 'wan-2', 200)`); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	runtime := &fakeRuntime{}
	coordinator := domainrouting.New(db, runtime)
	if err := coordinator.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	row := targetView(t, coordinator.State(context.Background()), "video.example.com")
	if !row.Suspended || row.SuspensionReason != domainrouting.ReasonInvalidIntent || row.EffectiveStage != storage.DomainStageEnsaio {
		t.Fatalf("a linha de direcionamento antiga não ficou suspensa: %+v", row)
	}
	if _, ok := runtime.alvo("video.example.com"); ok {
		t.Fatal("a linha de direcionamento antiga chegou ao runtime")
	}
	if _, err := coordinator.Delete(context.Background(), row.ID); err != nil {
		t.Fatalf("a linha antiga tem de poder ser apagada: %v", err)
	}
}

func TestDisabledBlockGroupSuspendsBlockTargetsAndReenableRestoresIntent(t *testing.T) {
	db := newDB(t)
	addBlockGroup(t, db, false)
	target := &storage.DomainTarget{Domain: "ads.example.com", Capability: storage.DomainCapBarrar}
	if err := db.CreateDomainTarget(target); err != nil {
		t.Fatal(err)
	}
	if err := db.SetDomainTargetStage(target.ID, storage.DomainStageAtivo); err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRuntime{}
	coordinator := domainrouting.New(db, runtime)
	if err := coordinator.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	disabled := targetView(t, coordinator.State(context.Background()), target.Domain)
	if !disabled.Suspended || disabled.SuspensionReason != domainrouting.ReasonBlockingGroupDisabled {
		t.Fatalf("grupo desligado não suspendeu bloqueio: %+v", disabled)
	}

	if err := db.SetFirewallGroupEnabled("system-blocklist", true); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	enabled := targetView(t, coordinator.State(context.Background()), target.Domain)
	if enabled.Suspended || enabled.EffectiveStage != storage.DomainStageAtivo {
		t.Fatalf("grupo reativado não reabilitou intenção: %+v", enabled)
	}
}

func TestCRUDRequiresExplicitStageAndReturnsKernelObservability(t *testing.T) {
	db := newDB(t)
	addBlockGroup(t, db, true)
	runtime := &fakeRuntime{state: domtargets.Estado{
		Vivo: true, KernelLido: true,
		Dominios: []domtargets.EstadoDominio{{
			Dominio: "video.example.com", NoIndice: 2, NoKernel: intPtr(1),
			Rotatividade: 7,
		}},
	}}
	coordinator := domainrouting.New(db, runtime)
	if err := coordinator.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}

	created, err := coordinator.Create(context.Background(), domainrouting.Input{
		Domain: "video.example.com", Capability: storage.DomainCapBarrar, Note: "vídeo",
	})
	if err != nil {
		t.Fatal(err)
	}
	row := targetView(t, created, "video.example.com")
	if row.Stage != storage.DomainStageEnsaio || row.EffectiveStage != storage.DomainStageEnsaio {
		t.Fatalf("criação promoveu por acidente: %+v", row)
	}

	promoted, err := coordinator.SetStage(context.Background(), row.ID, storage.DomainStageAtivo)
	if err != nil {
		t.Fatal(err)
	}
	row = targetView(t, promoted, "video.example.com")
	if row.Stage != storage.DomainStageAtivo || row.EffectiveStage != storage.DomainStageAtivo ||
		row.NoKernel == nil || *row.NoKernel != 1 || row.NoIndex != 2 || row.Rotation != 7 {
		t.Fatalf("promoção/observabilidade incompleta: %+v", row)
	}

	updated, err := coordinator.Update(context.Background(), row.ID, domainrouting.Input{
		Domain: "media.example.com", Capability: storage.DomainCapBarrar, Note: "editado",
	})
	if err != nil {
		t.Fatal(err)
	}
	row = targetView(t, updated, "media.example.com")
	if row.Stage != storage.DomainStageAtivo || row.Note != "editado" {
		t.Fatalf("edição alterou estágio: %+v", row)
	}

	if _, err := coordinator.Create(context.Background(), domainrouting.Input{
		Domain: "other.example.com", Capability: "direcionar",
	}); !errors.Is(err, domainrouting.ErrInvalid) {
		t.Fatalf("direcionar (saiu com o multi-WAN) não virou ErrInvalid: %v", err)
	}
	if _, err := coordinator.SetStage(context.Background(), row.ID, "talvez"); !errors.Is(err, domainrouting.ErrInvalid) {
		t.Fatalf("stage desconhecido não virou ErrInvalid: %v", err)
	}
	if _, err := coordinator.Delete(context.Background(), row.ID); err != nil {
		t.Fatal(err)
	}
	if len(coordinator.State(context.Background()).Targets) != 0 {
		t.Fatal("delete não retirou alvo da visão/runtime")
	}
}

func intPtr(v int) *int { return &v }
