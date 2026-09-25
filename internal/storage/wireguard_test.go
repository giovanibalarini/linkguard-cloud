package storage_test

import (
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

func TestWireGuardPeerPersistsWithStableFirewallGroup(t *testing.T) {
	db := newTestDB(t)
	u := &storage.User{Username: "ana"}
	if err := db.CreateUser(u, "hash", nil); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	peer := storage.WireGuardPeer{
		UserID: u.ID, PublicKey: "public-one", Address: "10.7.0.2/32",
		SecretName: "wireguard_peer_secret_one", FirewallGroupID: "550e8400-e29b-41d4-a716-446655440001",
	}
	old, err := db.UpsertWireGuardPeer(&peer)
	if err != nil {
		t.Fatalf("UpsertWireGuardPeer(create): %v", err)
	}
	if old != nil {
		t.Fatalf("first upsert returned old peer: %+v", old)
	}

	peer.PublicKey = "public-two"
	peer.SecretName = "wireguard_peer_secret_two"
	old, err = db.UpsertWireGuardPeer(&peer)
	if err != nil {
		t.Fatalf("UpsertWireGuardPeer(rotate): %v", err)
	}
	if old == nil || old.SecretName != "wireguard_peer_secret_one" {
		t.Fatalf("rotation old peer = %+v", old)
	}
	got, err := db.GetWireGuardPeer(u.ID)
	if err != nil || got == nil {
		t.Fatalf("GetWireGuardPeer = %+v, %v", got, err)
	}
	if got.FirewallGroupID != "550e8400-e29b-41d4-a716-446655440001" || got.Address != "10.7.0.2/32" || got.Username != "ana" {
		t.Fatalf("peer association changed: %+v", got)
	}
}

func TestDeleteUserCleansWireGuardOwnershipAndEncryptedSecret(t *testing.T) {
	db := newTestDB(t)
	u := &storage.User{Username: "carla"}
	if err := db.CreateUser(u, "hash", nil); err != nil {
		t.Fatal(err)
	}
	peer := storage.WireGuardPeer{UserID: u.ID, PublicKey: "pub-carla", Address: "10.7.0.2/32", SecretName: "secret-carla", FirewallGroupID: "g-user"}
	if _, err := db.UpsertWireGuardPeer(&peer); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Conn().Exec(`INSERT INTO secrets (name, nonce, ciphertext, updated_at) VALUES (?, ?, ?, ?)`, peer.SecretName, []byte("nonce"), []byte("ciphertext"), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteUser(u.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if got, _ := db.GetWireGuardPeer(u.ID); got != nil {
		t.Fatalf("peer survived user deletion: %+v", got)
	}
	var secrets int
	if err := db.Conn().QueryRow(`SELECT COUNT(*) FROM secrets WHERE name = ?`, peer.SecretName).Scan(&secrets); err != nil {
		t.Fatal(err)
	}
	if secrets != 0 {
		t.Fatal("encrypted peer secret survived user deletion")
	}
}

func TestDeleteWireGuardPeerDeletesItsGroupAndRules(t *testing.T) {
	db := newTestDB(t)
	u := &storage.User{Username: "bia"}
	if err := db.CreateUser(u, "hash", nil); err != nil {
		t.Fatal(err)
	}
	peer := storage.WireGuardPeer{UserID: u.ID, PublicKey: "pub", Address: "10.7.0.2/32", SecretName: "sec", FirewallGroupID: "g-peer"}
	if _, err := db.UpsertWireGuardPeer(&peer); err != nil {
		t.Fatal(err)
	}
	removed, err := db.DeleteWireGuardPeer(u.ID)
	if err != nil || removed == nil || removed.SecretName != "sec" {
		t.Fatalf("DeleteWireGuardPeer = %+v, %v", removed, err)
	}
	if got, _ := db.GetWireGuardPeer(u.ID); got != nil {
		t.Fatalf("peer still exists: %+v", got)
	}
}

func mustGroups(t *testing.T, db *storage.DB) []storage.FirewallGroup {
	t.Helper()
	v, err := db.ListFirewallGroups()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func mustRules(t *testing.T, db *storage.DB) []storage.FirewallRule {
	t.Helper()
	v, err := db.ListFirewallRules()
	if err != nil {
		t.Fatal(err)
	}
	return v
}
