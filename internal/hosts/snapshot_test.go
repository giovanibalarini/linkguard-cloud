package hosts_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-cloud/internal/hosts"
	"github.com/giovanibalarini/linkguard-cloud/internal/nftables"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

// fakeExec responde o ruleset da tabela e os sets de contagem; guarda o que
// foi escrito.
type fakeExec struct {
	ruleset  string
	acctUp   string
	comandos []string
}

func (f *fakeExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	f.comandos = append(f.comandos, cmd+" "+strings.Join(args, " "))
	return "", nil
}
func (f *fakeExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	if cmd == "nft" && len(args) >= 4 && args[0] == "list" && args[1] == "table" {
		return f.ruleset, nil
	}
	if cmd == "nft" && len(args) >= 5 && args[0] == "list" && args[1] == "set" && args[4] == nftables.AcctUpSet {
		return f.acctUp, nil
	}
	return "", nil
}
func (f *fakeExec) IsDryRun() bool                              { return false }
func (_ *fakeExec) WriteFile(string, []byte, os.FileMode) error { return nil }

func (f *fakeExec) escreveu(sub string) bool {
	for _, c := range f.comandos {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

func abrir(t *testing.T) *storage.DB {
	t.Helper()
	origConfPath := nftables.ConfPath
	nftables.ConfPath = filepath.Join(t.TempDir(), "nftables.conf")
	t.Cleanup(func() { nftables.ConfPath = origConfPath })
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// Bloquear grava a flag, põe o IP no set e salva o snapshot do ruleset, para
// uma reinstalação do zero restaurar o bloqueio junto.
func TestSetBlockedAplicaNoSetEPersisteOSnapshot(t *testing.T) {
	db := abrir(t)
	const ruleset = "table inet linkguard {\n\tset blocked_hosts {\n\t\telements = { 10.0.1.20 }\n\t}\n}\n"
	e := &fakeExec{ruleset: ruleset}
	svc := hosts.NewService(db, nftables.NewService(e), nil)

	if err := svc.SetBlocked(context.Background(), "10.0.1.20", true); err != nil {
		t.Fatalf("SetBlocked: %v", err)
	}
	if !e.escreveu("add element inet linkguard blocked_hosts { 10.0.1.20 }") {
		t.Errorf("o IP não foi para o set: %v", e.comandos)
	}
	got, _ := db.GetSetting(nftables.LiveSnapshotSettingKey)
	if got != ruleset {
		t.Errorf("snapshot não gravado:\n%q", got)
	}
	infos, _ := db.ListHostInfo()
	if len(infos) != 1 || !infos[0].Blocked {
		t.Errorf("flag não gravada: %+v", infos)
	}
}

func TestSetBlockedNaoPersisteOCacheDeDominios(t *testing.T) {
	db := abrir(t)
	const live = "table inet linkguard {\n\tset blocked_hosts {\n\t\telements = { 10.0.1.20 }\n\t}\n\tset dom_blocked {\n\t\ttype ipv4_addr\n\t\tflags timeout\n\t\telements = { 9.9.9.9 timeout 1h }\n\t}\n}\n"
	e := &fakeExec{ruleset: live}
	svc := hosts.NewService(db, nftables.NewService(e), nil)
	if err := svc.SetBlocked(context.Background(), "10.0.1.20", true); err != nil {
		t.Fatalf("SetBlocked: %v", err)
	}
	got, _ := db.GetSetting(nftables.LiveSnapshotSettingKey)
	if strings.Contains(got, "9.9.9.9") {
		t.Fatalf("snapshot persistiu cache DNS transitório:\n%s", got)
	}
}

// A máquina de outra sub-rede — o nó do k3s que chega pelo roteador da VCN —
// não está na vizinhança desta caixa, mas está no contador de tráfego. É por
// ele que ela entra no inventário.
func TestAMaquinaDeOutraSubRedeEntraPeloContador(t *testing.T) {
	db := abrir(t)
	e := &fakeExec{acctUp: "table inet linkguard {\n\tset acct_up {\n\t\telements = { 10.0.1.20 counter packets 10 bytes 1000, 10.7.0.5 counter packets 2 bytes 100 }\n\t}\n}\n"}
	u := &storage.User{ID: "u-diego", Username: "diego"}
	if err := db.CreateUser(u, "x", nil); err != nil {
		t.Fatalf("usuário: %v", err)
	}
	if _, err := db.UpsertWireGuardPeer(
		&storage.WireGuardPeer{UserID: "u-diego", PublicKey: "chave", Address: "10.7.0.5/32", SecretName: "wg-diego"},
	); err != nil {
		t.Fatalf("peer: %v", err)
	}
	svc := hosts.NewService(db, nftables.NewService(e), nil)

	lista, err := svc.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	porIP := map[string]hosts.Host{}
	for _, h := range lista {
		porIP[h.IP] = h
	}
	k3s, ok := porIP["10.0.1.20"]
	if !ok || k3s.Kind != hosts.KindVCN {
		t.Fatalf("o nó do k3s não entrou como máquina da VCN: %+v", lista)
	}
	diego, ok := porIP["10.7.0.5"]
	if !ok || diego.Kind != hosts.KindVPN || diego.Hostname != "diego" {
		t.Fatalf("o peer da VPN tinha de aparecer com o nome do usuário: %+v", lista)
	}
}
