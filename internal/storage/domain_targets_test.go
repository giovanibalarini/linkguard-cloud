package storage_test

import (
	"context"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

// Alvo de regra por domínio (#123): a lista que o admin mantém.

// TestUmDominioNasceEmEnsaioMesmoQuandoAChamadaPedeAtivo prende a proteção mais
// importante desta tabela.
//
// Sair do ensaio é a ÚNICA coisa nesta capacidade que muda o que passa na rede.
// Se uma gravação de rotina — editar a observação, trocar o link, importar um
// backup — pudesse promover de carona, o produto ligaria um bloqueio que
// ninguém pediu, e o admin descobriria pelo telefone tocando.
func TestUmDominioNasceEmEnsaioMesmoQuandoAChamadaPedeAtivo(t *testing.T) {
	db := newTestDB(t)
	err := db.SaveDomainTarget(storage.DomainTarget{
		Domain: "netflix.com", Capability: storage.DomainCapBarrar,
		Stage: storage.DomainStageAtivo, // a chamada pede ativo…
	})
	if err != nil {
		t.Fatalf("SaveDomainTarget: %v", err)
	}
	lista, err := db.ListDomainTargets()
	if err != nil {
		t.Fatalf("ListDomainTargets: %v", err)
	}
	if len(lista) != 1 {
		t.Fatalf("esperava um domínio, vieram %d", len(lista))
	}
	if lista[0].Stage != storage.DomainStageEnsaio {
		t.Fatalf("…e ele nasceu %q em vez de ensaio", lista[0].Stage)
	}
}

// TestPromoverEhAUnicaPortaDeSaidaDoEnsaio.
func TestPromoverEhAUnicaPortaDeSaidaDoEnsaio(t *testing.T) {
	db := newTestDB(t)
	if err := db.SaveDomainTarget(storage.DomainTarget{Domain: "netflix.com"}); err != nil {
		t.Fatalf("SaveDomainTarget: %v", err)
	}
	if err := db.PromoteDomainTarget("netflix.com", storage.DomainStageAtivo); err != nil {
		t.Fatalf("PromoteDomainTarget: %v", err)
	}
	lista, _ := db.ListDomainTargets()
	if lista[0].Stage != storage.DomainStageAtivo {
		t.Fatalf("a promoção não valeu: %q", lista[0].Stage)
	}

	// E uma gravação depois disso NÃO pode rebaixar nem manter por acidente: o
	// Save não toca no estágio de quem já existe.
	if err := db.SaveDomainTarget(storage.DomainTarget{Domain: "netflix.com", Note: "editado"}); err != nil {
		t.Fatalf("SaveDomainTarget: %v", err)
	}
	lista, _ = db.ListDomainTargets()
	if lista[0].Stage != storage.DomainStageAtivo || lista[0].Note != "editado" {
		t.Fatalf("a edição mexeu no estágio: %+v", lista[0])
	}
}

// TestODominioEhUnicoNaTabela.
//
// Duas linhas para o mesmo nome deixariam "qual capacidade vale" sem resposta —
// a resposta seria a ordem do SELECT, quer dizer: um domínio que barra ou
// direciona conforme o dia.
func TestODominioEhUnicoNaTabela(t *testing.T) {
	db := newTestDB(t)
	if err := db.SaveDomainTarget(storage.DomainTarget{Domain: "netflix.com", Capability: storage.DomainCapBarrar}); err != nil {
		t.Fatalf("primeira gravação: %v", err)
	}
	if err := db.SaveDomainTarget(storage.DomainTarget{
		Domain: "NETFLIX.COM.", Capability: storage.DomainCapBarrar, Note: "segunda",
	}); err != nil {
		t.Fatalf("segunda gravação: %v", err)
	}
	lista, _ := db.ListDomainTargets()
	if len(lista) != 1 {
		t.Fatalf("o mesmo nome virou %d linhas", len(lista))
	}
	if lista[0].Note != "segunda" {
		t.Fatalf("a segunda gravação não corrigiu a primeira: %+v", lista[0])
	}
}

// TestDominioSemPontoEhRecusado — ver NormalizarDominio no domtargets: um nome
// de um rótulo só casaria com um TLD inteiro.
func TestDominioSemPontoEhRecusado(t *testing.T) {
	db := newTestDB(t)
	if err := db.SaveDomainTarget(storage.DomainTarget{Domain: "com"}); err == nil {
		t.Fatal("um domínio de um rótulo só foi aceito")
	}
	if err := db.SaveDomainTarget(storage.DomainTarget{Domain: "   "}); err == nil {
		t.Fatal("um domínio vazio foi aceito")
	}
}

// TestApagarTiraDaLista.
func TestApagarTiraDaLista(t *testing.T) {
	db := newTestDB(t)
	if err := db.SaveDomainTarget(storage.DomainTarget{Domain: "netflix.com"}); err != nil {
		t.Fatalf("SaveDomainTarget: %v", err)
	}
	if err := db.DeleteDomainTarget("netflix.com"); err != nil {
		t.Fatalf("DeleteDomainTarget: %v", err)
	}
	lista, _ := db.ListDomainTargets()
	if len(lista) != 0 {
		t.Fatalf("sobrou %d depois de apagar", len(lista))
	}
	if err := db.PromoteDomainTarget("netflix.com", storage.DomainStageAtivo); err == nil {
		t.Fatal("promover um domínio que não existe passou em silêncio")
	}
}

func TestDomainTargetCRUDByIDPreservesStage(t *testing.T) {
	db := newTestDB(t)
	target := &storage.DomainTarget{
		Domain: "  VIDEO.Example.COM. ", Capability: storage.DomainCapBarrar,
		Stage: storage.DomainStageAtivo, Note: "streaming",
	}
	if err := db.CreateDomainTarget(target); err != nil {
		t.Fatalf("CreateDomainTarget: %v", err)
	}
	if target.ID == "" {
		t.Fatal("CreateDomainTarget não atribuiu id estável")
	}
	got, err := db.GetDomainTarget(target.ID)
	if err != nil || got == nil {
		t.Fatalf("GetDomainTarget: %+v, %v", got, err)
	}
	if got.Domain != "video.example.com" || got.Stage != storage.DomainStageEnsaio {
		t.Fatalf("alvo criado com intenção errada: %+v", got)
	}

	if err := db.SetDomainTargetStage(target.ID, storage.DomainStageAtivo); err != nil {
		t.Fatalf("SetDomainTargetStage: %v", err)
	}
	if err := db.UpdateDomainTarget(target.ID, storage.DomainTarget{
		Domain: "media.example.com", Capability: storage.DomainCapBarrar, Note: "editado",
	}); err != nil {
		t.Fatalf("UpdateDomainTarget: %v", err)
	}
	got, _ = db.GetDomainTarget(target.ID)
	if got.Stage != storage.DomainStageAtivo || got.Domain != "media.example.com" || got.Note != "editado" {
		t.Fatalf("edição mudou o estágio ou não gravou campos: %+v", got)
	}

	if err := db.DeleteDomainTargetByID(target.ID); err != nil {
		t.Fatalf("DeleteDomainTargetByID: %v", err)
	}
	got, err = db.GetDomainTarget(target.ID)
	if err != nil || got != nil {
		t.Fatalf("alvo apagado ainda existe: %+v, %v", got, err)
	}
}

func TestDomainTargetStorageRejectsInvalidIntent(t *testing.T) {
	db := newTestDB(t)
	longNote := strings.Repeat("x", 501)
	for _, target := range []storage.DomainTarget{
		{Domain: "-api.example.com", Capability: storage.DomainCapBarrar},
		{Domain: "api.example.com", Capability: "permitir"},
		// A escolha de WAN por domínio saiu com o multi-WAN.
		{Domain: "api.example.com", Capability: "direcionar"},
		{Domain: "api.example.com", Capability: storage.DomainCapBarrar, Note: longNote},
		{Domain: "api.example.com", Capability: storage.DomainCapBarrar, Note: "linha\nnova"},
	} {
		target := target
		if err := db.CreateDomainTarget(&target); err == nil {
			t.Errorf("intenção inválida foi gravada: %+v", target)
		}
	}
	if err := db.SetDomainTargetStage("ausente", "talvez"); err == nil {
		t.Fatal("estágio fora da enum foi aceito")
	}
}

func TestDomainRoutingSnapshotReadsTargetsAndBlockGroupTogether(t *testing.T) {
	db := newTestDB(t)
	target := &storage.DomainTarget{Domain: "example.com", Capability: storage.DomainCapBarrar}
	if err := db.CreateDomainTarget(target); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateFirewallGroup(&storage.FirewallGroup{
		ID: "system-blocklist", Name: "Destinos bloqueados", Kind: "blocklist", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}

	snap, err := db.DomainRoutingSnapshot(context.Background())
	if err != nil {
		t.Fatalf("DomainRoutingSnapshot: %v", err)
	}
	if len(snap.Targets) != 1 || !snap.BlocklistPresent || !snap.BlocklistEnabled {
		t.Fatalf("snapshot incompleto: %+v", snap)
	}
}
