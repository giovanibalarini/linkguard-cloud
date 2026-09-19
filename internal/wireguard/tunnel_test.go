package wireguard

import (
	"strings"
	"testing"
)

func TestClientAllowedIPsFullIgnoresRoutes(t *testing.T) {
	c := DefaultConfig()
	got, err := ClientAllowedIPs(c, TunnelFull, []string{"10.0.1.20", "192.168.9.0/24"})
	if err != nil {
		t.Fatalf("ClientAllowedIPs: %v", err)
	}
	if got != "0.0.0.0/0" {
		t.Fatalf("full tunnel deveria mandar tudo, veio %q", got)
	}
}

func TestClientAllowedIPsSplitSempreCarregaARedeDoTunelPrimeiro(t *testing.T) {
	c := DefaultConfig() // 10.7.0.1/24
	got, err := ClientAllowedIPs(c, TunnelSplit, nil)
	if err != nil {
		t.Fatalf("ClientAllowedIPs: %v", err)
	}
	// Sem a rede do túnel o cliente não alcança nem o servidor, e o "DNS ="
	// que a própria config aponta para 10.7.0.1 deixaria de resolver.
	if got != "10.7.0.0/24" {
		t.Fatalf("split sem rotas deveria render a rede do túnel, veio %q", got)
	}

	comRotas, err := ClientAllowedIPs(c, TunnelSplit, []string{"192.168.9.5", "10.0.1.0/24", "10.7.0.0/24"})
	if err != nil {
		t.Fatalf("ClientAllowedIPs: %v", err)
	}
	if !strings.HasPrefix(comRotas, "10.7.0.0/24") {
		t.Fatalf("a rede do túnel tem que vir primeiro, veio %q", comRotas)
	}
	if strings.Count(comRotas, "10.7.0.0/24") != 1 {
		t.Fatalf("a rede do túnel repetiu: %q", comRotas)
	}
	if !strings.Contains(comRotas, "192.168.9.5/32") {
		t.Fatalf("host solto deveria virar /32, veio %q", comRotas)
	}
}

func TestNormalizeRoutesRejeitaInjecaoENormalizaOQueAceita(t *testing.T) {
	// O .conf é texto: uma rota com quebra de linha acrescentaria uma diretiva
	// ao arquivo do cliente. Nenhum destes pode passar.
	for _, ruim := range []string{
		"10.0.0.0/8\nPostUp = touch /tmp/pwn",
		"0.0.0.0/0, 10.0.0.0/8",
		"10.0.0.300/24",
		"nao-e-um-ip",
		"2001:db8::/32",
	} {
		if _, err := NormalizeRoutes([]string{ruim}); err == nil {
			t.Fatalf("NormalizeRoutes aceitou %q", ruim)
		}
	}

	// E o que é aceito volta reimpresso pelo netip, nunca como veio.
	got, err := NormalizeRoutes([]string{" 10.0.1.20 ", "192.168.9.7/24", "10.0.1.20"})
	if err != nil {
		t.Fatalf("NormalizeRoutes: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("esperava 2 rotas sem repetição, veio %v", got)
	}
	if got[0] != "10.0.1.20/32" || got[1] != "192.168.9.0/24" {
		t.Fatalf("rotas não normalizadas/ordenadas: %v", got)
	}
}

func TestRenderClientConfigEscreveSplitEMTU(t *testing.T) {
	c := DefaultConfig()
	c.Enabled = true
	c.EndpointHost = "vpn.example.net"
	_, serverPub, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	clientPriv, clientPub, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	peer := Peer{
		UserID: "550e8400-e29b-41d4-a716-446655440000", Username: "ana",
		PublicKey: clientPub, Address: "10.7.0.2/32",
		TunnelMode: TunnelSplit, MTU: 1440,
	}
	got, err := RenderClientConfig(c, serverPub, peer, clientPriv, "vpn.example.net", []string{"10.0.1.0/24"})
	if err != nil {
		t.Fatalf("RenderClientConfig: %v", err)
	}
	if !strings.Contains(got, "AllowedIPs = 10.7.0.0/24, 10.0.1.0/24") {
		t.Fatalf("split não chegou ao arquivo:\n%s", got)
	}
	if !strings.Contains(got, "MTU = 1440") {
		t.Fatalf("MTU não foi escrito:\n%s", got)
	}

	// MTU 0 não escreve a linha: vale o padrão do cliente.
	peer.MTU = 0
	got, err = RenderClientConfig(c, serverPub, peer, clientPriv, "vpn.example.net", nil)
	if err != nil {
		t.Fatalf("RenderClientConfig: %v", err)
	}
	if strings.Contains(got, "MTU") {
		t.Fatalf("MTU 0 não deveria escrever linha:\n%s", got)
	}

	// E um MTU fora da faixa é recusado no sink, não só no formulário.
	peer.MTU = 42
	if _, err := RenderClientConfig(c, serverPub, peer, clientPriv, "vpn.example.net", nil); err == nil {
		t.Fatal("o render aceitou um MTU impraticável")
	}
}

func TestRenderClientConfigRecusaRotaInjetadaNoSink(t *testing.T) {
	c := DefaultConfig()
	c.Enabled = true
	_, serverPub, _ := GenerateKeypair()
	clientPriv, clientPub, _ := GenerateKeypair()
	peer := Peer{
		UserID: "550e8400-e29b-41d4-a716-446655440000", Username: "ana",
		PublicKey: clientPub, Address: "10.7.0.2/32", TunnelMode: TunnelSplit,
	}
	_, err := RenderClientConfig(c, serverPub, peer, clientPriv, "vpn.example.net",
		[]string{"10.0.0.0/8\nPostUp = touch /tmp/pwn"})
	if err == nil {
		t.Fatal("o sink aceitou uma rota com quebra de linha")
	}
}
