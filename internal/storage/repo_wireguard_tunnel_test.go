package storage_test

import (
	"testing"

	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

func novoPeerDeTeste(t *testing.T, db *storage.DB, username string) *storage.WireGuardPeer {
	t.Helper()
	user := &storage.User{Username: username}
	if err := db.CreateUser(user, "hash", nil); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	peer := &storage.WireGuardPeer{
		UserID:          user.ID,
		PublicKey:       "pub_" + username,
		Address:         "10.7.0.9/32",
		SecretName:      "secret_" + username,
		FirewallGroupID: "fg_" + username,
	}
	group := &storage.FirewallGroup{
		ID: "fg_" + username, Name: "VPN — " + username, ChainName: "grp_" + username,
	}
	if _, err := db.UpsertWireGuardPeer(peer, group); err != nil {
		t.Fatalf("UpsertWireGuardPeer: %v", err)
	}
	return peer
}

func TestPeerNasceFullTunnelEEnrolarNaoDeixaConfigVelha(t *testing.T) {
	db := newTestDB(t)
	peer := novoPeerDeTeste(t, db, "tunneldefault")

	got, err := db.GetWireGuardPeer(peer.UserID)
	if err != nil {
		t.Fatalf("GetWireGuardPeer: %v", err)
	}
	if got.TunnelMode != "full" {
		t.Errorf("modo de túnel padrão = %q, queria full", got.TunnelMode)
	}
	if got.MTU != 0 || len(got.ExtraRoutes) != 0 {
		t.Errorf("peer novo veio com rotas/MTU: %+v", got)
	}
	if got.ConfigStale {
		t.Error("quem acabou de receber a config não pode estar desatualizado")
	}
}

func TestMudarOTunelDesatualizaAConfigEReemitirLimpa(t *testing.T) {
	db := newTestDB(t)
	peer := novoPeerDeTeste(t, db, "tunnelstale")

	if err := db.UpdateWireGuardPeerAccess(peer.UserID, storage.WireGuardPeerAccess{
		AccessMode: "full",
		TunnelMode: "split",
		MTU:        1440,
	}); err != nil {
		t.Fatalf("UpdateWireGuardPeerAccess: %v", err)
	}
	got, err := db.GetWireGuardPeer(peer.UserID)
	if err != nil {
		t.Fatalf("GetWireGuardPeer: %v", err)
	}
	if !got.ConfigStale {
		t.Fatal("trocar para split tem que marcar a config do cliente como velha")
	}
	if got.TunnelMode != "split" || got.MTU != 1440 {
		t.Fatalf("perfil não gravou: %+v", got)
	}

	if err := db.MarkWireGuardConfigIssued(peer.UserID); err != nil {
		t.Fatalf("MarkWireGuardConfigIssued: %v", err)
	}
	got, err = db.GetWireGuardPeer(peer.UserID)
	if err != nil {
		t.Fatalf("GetWireGuardPeer: %v", err)
	}
	if got.ConfigStale {
		t.Fatal("depois de reemitir a config não pode seguir desatualizada")
	}
}

func TestMexerSoNoZTNADeFullTunnelNaoDesatualizaNada(t *testing.T) {
	db := newTestDB(t)
	peer := novoPeerDeTeste(t, db, "tunnelztna")

	// Em full tunnel o AllowedIPs é 0.0.0.0/0 aconteça o que acontecer com os
	// grupos: o arquivo do cliente não muda, e avisar que mudou ensinaria o
	// admin a ignorar o aviso.
	if err := db.UpdateWireGuardPeerAccess(peer.UserID, storage.WireGuardPeerAccess{
		AccessMode:        "restricted",
		AllowedHostGroups: []string{"hg_k3s"},
		AllowedPorts:      "22",
		TunnelMode:        "full",
	}); err != nil {
		t.Fatalf("UpdateWireGuardPeerAccess: %v", err)
	}
	got, err := db.GetWireGuardPeer(peer.UserID)
	if err != nil {
		t.Fatalf("GetWireGuardPeer: %v", err)
	}
	if got.ConfigStale {
		t.Fatal("ZTNA em full tunnel não altera a config do cliente")
	}
}

func TestEditarUmHostGroupDesatualizaQuemOUsaEmSplit(t *testing.T) {
	db := newTestDB(t)
	grupo := &storage.HostGroup{Name: "Cluster", Hosts: []string{"10.0.1.20"}}
	if err := db.CreateHostGroup(grupo); err != nil {
		t.Fatalf("CreateHostGroup: %v", err)
	}
	split := novoPeerDeTeste(t, db, "splituser")
	if err := db.UpdateWireGuardPeerAccess(split.UserID, storage.WireGuardPeerAccess{
		AccessMode:        "restricted",
		AllowedHostGroups: []string{grupo.ID},
		TunnelMode:        "split",
	}); err != nil {
		t.Fatalf("UpdateWireGuardPeerAccess: %v", err)
	}
	if err := db.MarkWireGuardConfigIssued(split.UserID); err != nil {
		t.Fatalf("MarkWireGuardConfigIssued: %v", err)
	}

	// Acrescentar um host ao grupo muda a regra do firewall na hora, mas não o
	// arquivo que o usuário baixou: sem a rota, o acesso liberado não funciona.
	grupo.Hosts = append(grupo.Hosts, "10.0.1.21")
	if err := db.UpdateHostGroup(grupo); err != nil {
		t.Fatalf("UpdateHostGroup: %v", err)
	}
	if err := db.MarkWireGuardRoutesChangedByHostGroup(grupo.ID); err != nil {
		t.Fatalf("MarkWireGuardRoutesChangedByHostGroup: %v", err)
	}
	got, err := db.GetWireGuardPeer(split.UserID)
	if err != nil {
		t.Fatalf("GetWireGuardPeer: %v", err)
	}
	if !got.ConfigStale {
		t.Fatal("quem libera o grupo em split ficou com rota faltando e sem aviso")
	}
}
