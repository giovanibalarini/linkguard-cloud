package wireguard

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-cloud/internal/nftables"
)

func TestGenerateKeypairProducesWireGuardKeys(t *testing.T) {
	priv, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	for name, key := range map[string]string{"private": priv, "public": pub} {
		decoded, err := base64.StdEncoding.DecodeString(key)
		if err != nil || len(decoded) != 32 {
			t.Fatalf("%s key = %q, decoded=%d err=%v", name, key, len(decoded), err)
		}
	}
	if priv == pub {
		t.Fatal("private and public key must differ")
	}
}

func TestValidateConfigRejectsEveryRenderedInjectionSlot(t *testing.T) {
	valid := DefaultConfig()
	cases := []struct {
		name string
		edit func(*Config)
	}{
		{"address newline", func(c *Config) { c.Address = "10.7.0.1/24\nPostUp = touch /tmp/pwn" }},
		{"invalid port", func(c *Config) { c.ListenPort = 70000 }},
		{"endpoint newline", func(c *Config) { c.EndpointHost = "vpn.example\nAllowedIPs = 0.0.0.0/0" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := valid
			tc.edit(&c)
			if err := ValidateConfig(c); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestRenderServerConfigRevalidatesPersistedValuesAtSink(t *testing.T) {
	c := DefaultConfig()
	c.Enabled = true
	c.Address = "10.7.0.1/24\nPostUp = touch /tmp/pwn"
	_, err := RenderServerConfig(c, strings.Repeat("A", 43)+"=", nil, 0)
	if err == nil {
		t.Fatal("sink accepted an injected address")
	}
}

func TestRenderServerAndClientConfigsKeepPrivateKeysSeparated(t *testing.T) {
	c := DefaultConfig()
	c.Enabled = true
	c.EndpointHost = "vpn.example.net"
	serverPriv, serverPub, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	clientPriv, clientPub, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	peer := Peer{UserID: "550e8400-e29b-41d4-a716-446655440000", Username: "ana", PublicKey: clientPub, Address: "10.7.0.2/32"}
	server, err := RenderServerConfig(c, serverPriv, []Peer{peer}, 0)
	if err != nil {
		t.Fatalf("RenderServerConfig: %v", err)
	}
	if strings.Contains(server, clientPriv) || !strings.Contains(server, clientPub) {
		t.Fatal("server config must contain only the client's public key")
	}
	client, err := RenderClientConfig(c, serverPub, peer, clientPriv, "vpn.example.net", nil)
	if err != nil {
		t.Fatalf("RenderClientConfig: %v", err)
	}
	if !strings.Contains(client, clientPriv) || strings.Contains(client, serverPriv) {
		t.Fatal("client config did not keep private keys separated")
	}
	if !strings.Contains(client, "DNS = 10.7.0.1") || !strings.Contains(client, "Endpoint = vpn.example.net:51820") {
		t.Fatalf("client config lacks tunnel DNS/endpoint:\n%s", client)
	}
	// Peer sem modo declarado continua full tunnel: é o que a config que os
	// peers já enrolados têm na mão diz.
	if !strings.Contains(client, "AllowedIPs = 0.0.0.0/0") {
		t.Fatalf("peer sem modo deveria seguir full tunnel:\n%s", client)
	}
}

func TestNextAddressKeepsExistingPeerAndAllocatesNextFreeHost(t *testing.T) {
	c := DefaultConfig()
	got, err := NextAddress(c, []Peer{{Address: "10.7.0.2/32"}, {Address: "10.7.0.4/32"}})
	if err != nil {
		t.Fatalf("NextAddress: %v", err)
	}
	if got != "10.7.0.3/32" {
		t.Fatalf("NextAddress = %q, want 10.7.0.3/32", got)
	}
}

func TestServerMTUDescontaOTunelDaMTUDoCaminho(t *testing.T) {
	for _, c := range []struct{ caminho, quer int }{
		{0, 0},       // desconhecido: o wg-quick decide pela placa
		{1500, 1420}, // a nuvem: 9000 na placa, 1500 no caminho
		{1492, 1412}, // PPPoE
		{1300, MTUMin},
		{65535, MTUMax},
	} {
		if got := ServerMTU(c.caminho); got != c.quer {
			t.Errorf("ServerMTU(%d) = %d, quer %d", c.caminho, got, c.quer)
		}
	}
}

func TestVPNInterfaceDoNftablesEAInterfaceDoTunel(t *testing.T) {
	if nftables.VPNInterface != InterfaceName {
		t.Fatalf("a mss_clamp ajusta %q, mas o túnel é %q", nftables.VPNInterface, InterfaceName)
	}
}

func TestRenderServerConfigEscreveAMTUEARotaDoPeerQuePedeMenos(t *testing.T) {
	c := DefaultConfig()
	serverPriv, _, _ := GenerateKeypair()
	peer := func(addr string, mtu int) Peer {
		_, pub, _ := GenerateKeypair()
		return Peer{UserID: "550e8400-e29b-41d4-a716-446655440000", Username: "ana", PublicKey: pub, Address: addr, MTU: mtu}
	}
	peers := []Peer{
		peer("10.7.0.2/32", 0),    // sem MTU: segue a da interface
		peer("10.7.0.3/32", 1350), // celular: ganha rota própria
		peer("10.7.0.4/32", 1420), // igual à interface: nada a fazer
		peer("10.7.0.5/32", 9000), // maior que a interface: não amplia
		peer("10.7.0.6/32", 100),  // lixo vindo do banco: ignora, não derruba
	}
	got, err := RenderServerConfig(c, serverPriv, peers, 1420)
	if err != nil {
		t.Fatalf("RenderServerConfig: %v", err)
	}
	if !strings.Contains(got, "\nMTU = 1420\n") {
		t.Errorf("faltou a MTU da interface:\n%s", got)
	}
	rotas := strings.Count(got, "PostUp = ")
	if rotas != 1 || !strings.Contains(got, "PostUp = ip route replace 10.7.0.3/32 dev %i mtu 1350\n") {
		t.Errorf("esperava só a rota do peer de 1350, vieram %d:\n%s", rotas, got)
	}
	if strings.Index(got, "PostUp") > strings.Index(got, "[Peer]") {
		t.Errorf("PostUp tem de ficar na seção [Interface]:\n%s", got)
	}
	if strings.Count(got, "[Peer]") != len(peers) {
		t.Errorf("algum peer sumiu:\n%s", got)
	}
}

func TestRenderServerConfigSemMTUNaoEscreveMTUNemRota(t *testing.T) {
	c := DefaultConfig()
	serverPriv, _, _ := GenerateKeypair()
	_, pub, _ := GenerateKeypair()
	p := Peer{UserID: "550e8400-e29b-41d4-a716-446655440000", Username: "ana", PublicKey: pub, Address: "10.7.0.2/32", MTU: 1350}
	got, err := RenderServerConfig(c, serverPriv, []Peer{p}, 0)
	if err != nil {
		t.Fatalf("RenderServerConfig: %v", err)
	}
	// Sem a MTU da interface não há como saber se 1350 é menor que ela.
	if strings.Contains(got, "MTU") || strings.Contains(got, "PostUp") {
		t.Errorf("caminho desconhecido não pode escrever MTU nem rota:\n%s", got)
	}
}
