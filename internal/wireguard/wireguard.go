// Package wireguard manages the LinkGuard-owned road-warrior VPN.
package wireguard

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/crypto/curve25519"
)

const (
	InterfaceName = "linkguard"
	ConfigPath    = "/etc/wireguard/linkguard.conf"
	ServiceName   = "wg-quick@linkguard.service"
	ServerSecret  = "wireguard_server_private_v1"
)

// TunnelMode decide o AllowedIPs que vai na config DO CLIENTE, ou seja, o que a
// máquina dele sequer manda para dentro do túnel. É roteamento, não controle de
// acesso: quem garante o que o peer alcança é o grupo nftables criado por peer
// (AccessMode/AllowedHostGroups). Os dois são deliberadamente independentes —
// há quem queira acesso restrito a dois servidores E toda a navegação passando
// pelo firewall, para ganhar blocklist, dnstap e QoS no road-warrior.
//
// Vazio conta como TunnelFull: é o valor de todo peer enrolado antes desta
// coluna existir, e é o que a config que eles já têm na mão diz.
const (
	TunnelFull  = "full"  // AllowedIPs = 0.0.0.0/0 — tudo pelo túnel
	TunnelSplit = "split" // só a rede do túnel e os destinos liberados
)

// Limites do MTU do cliente. 0 significa "não escreve a linha", deixando o
// padrão do cliente valer. O piso é o mínimo que o IPv6 exige; o teto cobre
// jumbo frames de nuvem.
const (
	MTUMin = 1280
	MTUMax = 9000
)

type Config struct {
	Enabled      bool   `json:"enabled"`
	ListenPort   int    `json:"listen_port"`
	Address      string `json:"address"`
	EndpointHost string `json:"endpoint_host"`
}

type Peer struct {
	UserID            string   `json:"user_id"`
	Username          string   `json:"username"`
	PublicKey         string   `json:"public_key"`
	Address           string   `json:"address"`
	FirewallGroupID   string   `json:"firewall_group_id"`
	AccessMode        string   `json:"access_mode,omitempty"`
	AllowedHostGroups []string `json:"allowed_host_groups,omitempty"`
	AllowedPorts      string   `json:"allowed_ports,omitempty"`
	TunnelMode        string   `json:"tunnel_mode,omitempty"`
	ExtraRoutes       []string `json:"extra_routes,omitempty"`
	MTU               int      `json:"mtu,omitempty"`
	ConfigStale       bool     `json:"config_stale,omitempty"`
	CreatedAt         int64    `json:"created_at,omitempty"`
	RotatedAt         int64    `json:"rotated_at,omitempty"`
	Online            bool     `json:"online"`
	Endpoint          string   `json:"endpoint,omitempty"`
	LatestHandshake   int64    `json:"latest_handshake,omitempty"`
	TransferRx        int64    `json:"transfer_rx"`
	TransferTx        int64    `json:"transfer_tx"`
	LatencyMs         float64  `json:"latency_ms,omitempty"`
}

func DefaultConfig() Config {
	return Config{ListenPort: 51820, Address: "10.7.0.1/24"}
}

func GenerateKeypair() (priv, pub string, err error) {
	var key [32]byte
	if _, err = rand.Read(key[:]); err != nil {
		return "", "", err
	}
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64
	public, err := curve25519.X25519(key[:], curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(key[:]), base64.StdEncoding.EncodeToString(public), nil
}

func PublicKey(private string) (string, error) {
	key, err := decodeKey(private)
	if err != nil {
		return "", err
	}
	public, err := curve25519.X25519(key, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(public), nil
}

func decodeKey(v string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("chave WireGuard inválida")
	}
	return b, nil
}

var (
	hostnameRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
	userIDRE   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)
)

func ValidateConfig(c Config) error {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(c.Address))
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() < 16 || prefix.Bits() > 30 || prefix != prefix.Masked() && prefix.Addr() == prefix.Masked().Addr() {
		return fmt.Errorf("endereço do túnel inválido: use IPv4 CIDR com prefixo /16 a /30")
	}
	if prefix.Addr() == prefix.Masked().Addr() || prefix.Addr() == lastAddr(prefix.Masked()) {
		return fmt.Errorf("o endereço do servidor não pode ser o endereço de rede ou broadcast")
	}
	if c.ListenPort < 1 || c.ListenPort > 65535 {
		return fmt.Errorf("porta WireGuard inválida")
	}
	if c.EndpointHost != "" && !validEndpointHost(c.EndpointHost) {
		return fmt.Errorf("endpoint inválido: use um endereço IP ou hostname")
	}
	return nil
}

func validEndpointHost(host string) bool {
	if strings.TrimSpace(host) != host || strings.ContainsAny(host, "\r\n\t :/[]") {
		return false
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.IsValid()
	}
	return len(host) <= 253 && hostnameRE.MatchString(host) && !strings.Contains(host, "..")
}

func validatePeer(c Config, p Peer) error {
	if !userIDRE.MatchString(p.UserID) {
		return fmt.Errorf("id de usuário inválido")
	}
	if _, err := decodeKey(p.PublicKey); err != nil {
		return fmt.Errorf("peer %s: %w", p.UserID, err)
	}
	addr, err := netip.ParsePrefix(p.Address)
	if err != nil || !addr.Addr().Is4() || addr.Bits() != 32 {
		return fmt.Errorf("peer %s: endereço /32 inválido", p.UserID)
	}
	server, _ := netip.ParsePrefix(c.Address)
	if !server.Masked().Contains(addr.Addr()) || server.Addr() == addr.Addr() {
		return fmt.Errorf("peer %s: endereço fora do túnel", p.UserID)
	}
	return nil
}

func RenderServerConfig(c Config, private string, peers []Peer) (string, error) {
	if err := ValidateConfig(c); err != nil {
		return "", err
	}
	if _, err := decodeKey(private); err != nil {
		return "", err
	}
	ordered := append([]Peer(nil), peers...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Address < ordered[j].Address })
	var b strings.Builder
	b.WriteString("# Managed by LinkGuard Cloud — do not edit by hand.\n[Interface]\n")
	fmt.Fprintf(&b, "Address = %s\nListenPort = %d\nPrivateKey = %s\n", c.Address, c.ListenPort, private)
	for _, p := range ordered {
		if err := validatePeer(c, p); err != nil {
			return "", err
		}
		b.WriteString("\n[Peer]\n")
		fmt.Fprintf(&b, "PublicKey = %s\nAllowedIPs = %s\n", p.PublicKey, p.Address)
	}
	return b.String(), nil
}

// ValidateMTU aceita 0 (não escreve a linha, vale o padrão do cliente) ou um
// valor dentro dos limites praticáveis.
func ValidateMTU(mtu int) error {
	if mtu == 0 {
		return nil
	}
	if mtu < MTUMin || mtu > MTUMax {
		return fmt.Errorf("MTU inválido: use 0 para o padrão do cliente ou um valor entre %d e %d", MTUMin, MTUMax)
	}
	return nil
}

// NormalizeRoutes valida cada destino e devolve a forma canônica, ordenada e
// sem repetição.
//
// O valor devolvido NUNCA é o texto que entrou: cada item volta reimpresso por
// netip. É isso que torna impossível injetar uma linha no .conf por um host
// group ou por uma rota extra — um "10.0.0.0/8\nPostUp = ..." não sobrevive ao
// ParsePrefix, e o que é aceito sai reescrito pelo netip, sem os caracteres
// originais.
func NormalizeRoutes(routes []string) ([]string, error) {
	seen := make(map[string]bool, len(routes))
	out := make([]string, 0, len(routes))
	for _, raw := range routes {
		route := strings.TrimSpace(raw)
		if route == "" {
			continue
		}
		var canonical string
		if prefix, err := netip.ParsePrefix(route); err == nil && prefix.Addr().Is4() {
			canonical = prefix.Masked().String()
		} else if addr, err := netip.ParseAddr(route); err == nil && addr.Is4() {
			canonical = netip.PrefixFrom(addr, 32).String()
		} else {
			return nil, fmt.Errorf("destino inválido para a rota do túnel: %q", raw)
		}
		if seen[canonical] {
			continue
		}
		seen[canonical] = true
		out = append(out, canonical)
	}
	sort.Strings(out)
	return out, nil
}

// ClientAllowedIPs monta o AllowedIPs do cliente.
//
// No modo split a rede do túnel entra SEMPRE e em primeiro lugar: sem ela o
// cliente não alcança nem o próprio servidor, e o "DNS =" que esta mesma config
// aponta para o endereço do túnel deixaria de resolver.
func ClientAllowedIPs(c Config, mode string, routes []string) (string, error) {
	if mode != TunnelSplit {
		return "0.0.0.0/0", nil
	}
	server, err := netip.ParsePrefix(strings.TrimSpace(c.Address))
	if err != nil {
		return "", fmt.Errorf("endereço do túnel inválido")
	}
	tunnel := server.Masked().String()
	normalized, err := NormalizeRoutes(routes)
	if err != nil {
		return "", err
	}
	out := []string{tunnel}
	for _, route := range normalized {
		if route != tunnel {
			out = append(out, route)
		}
	}
	return strings.Join(out, ", "), nil
}

// RenderClientConfig emite a config do cliente. As rotas chegam já resolvidas
// pelo serviço (host groups liberados + rotas extras do peer) porque só ele
// alcança o banco; aqui elas são revalidadas antes de virar texto.
func RenderClientConfig(c Config, serverPublic string, p Peer, private, endpoint string, routes []string) (string, error) {
	if err := ValidateConfig(c); err != nil {
		return "", err
	}
	if _, err := decodeKey(serverPublic); err != nil {
		return "", err
	}
	if _, err := decodeKey(private); err != nil {
		return "", err
	}
	if err := validatePeer(c, p); err != nil {
		return "", err
	}
	if !validEndpointHost(endpoint) {
		return "", fmt.Errorf("endpoint inválido")
	}
	if err := ValidateMTU(p.MTU); err != nil {
		return "", err
	}
	allowed, err := ClientAllowedIPs(c, p.TunnelMode, routes)
	if err != nil {
		return "", err
	}
	server, _ := netip.ParsePrefix(c.Address)
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\nAddress = %s\nDNS = %s\n", private, p.Address, server.Addr())
	if p.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", p.MTU)
	}
	fmt.Fprintf(&b, "\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = %s\nPersistentKeepalive = 25\n",
		serverPublic, net.JoinHostPort(endpoint, fmt.Sprint(c.ListenPort)), allowed)
	return b.String(), nil
}

func NextAddress(c Config, peers []Peer) (string, error) {
	if err := ValidateConfig(c); err != nil {
		return "", err
	}
	server, _ := netip.ParsePrefix(c.Address)
	network := server.Masked()
	used := map[netip.Addr]bool{server.Addr(): true, network.Addr(): true, lastAddr(network): true}
	for _, p := range peers {
		if a, err := netip.ParsePrefix(p.Address); err == nil {
			used[a.Addr()] = true
		}
	}
	for addr := network.Addr().Next(); addr.IsValid() && network.Contains(addr); addr = addr.Next() {
		if !used[addr] {
			return addr.String() + "/32", nil
		}
	}
	return "", fmt.Errorf("sem endereços livres no túnel %s", network)
}

func lastAddr(prefix netip.Prefix) netip.Addr {
	b := prefix.Addr().As4()
	hostBits := 32 - prefix.Bits()
	mask := uint32(1<<hostBits) - 1
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v |= mask
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}
