package firewallrules

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-cloud/internal/nftables"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

// TestMain tira do caminho, para TODO teste deste binário (os dois pacotes de
// teste, firewallrules e firewallrules_test), o único efeito colateral em
// disco que o executor falso não intercepta: o nftables.Persist, que grava o
// ruleset de BOOT da máquina.
//
// Quase todo teste daqui reconcilia, e reconciliar termina em Persist. Sem
// isto, a suíte tentava escrever no /etc/nftables.conf DE VERDADE o dump do
// executor falso (`table inet linkguard {}`): numa estação de trabalho falha
// por permissão e vira só uma linha de WARN no log da suíte; rodada como root
// na própria appliance — o mesmo binário, a mesma máquina —, sobrescreve o
// firewall com que ela volta no próximo boot. Este projeto já perdeu um boot
// de produção por configuração corrompida (2026-07-24).
//
// Os construtores de serviço destes testes já apontam o Service para o próprio
// t.TempDir() (SetConfPath, o caminho de verdade); isto aqui é a rede embaixo,
// para um teste futuro que monte o nftables.Service por conta própria.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "linkguard-fr-conf")
	if err != nil {
		fmt.Fprintf(os.Stderr, "não foi possível criar o diretório temporário do ConfPath: %v\n", err)
		os.Exit(1)
	}
	nftables.ConfPath = filepath.Join(dir, "nftables.conf")
	code := m.Run()
	os.RemoveAll(dir) //nolint:errcheck // limpeza de melhor esforço
	os.Exit(code)
}

func newTestDB(t *testing.T) *storage.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := storage.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

type fakeClock struct {
	wall time.Time
	mono time.Time
}

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{wall: t, mono: t} }

func (c *fakeClock) wire(s *Service) {
	s.now = func() time.Time { return c.wall }
	s.monoNow = func() time.Time { return c.mono }
}

func (c *fakeClock) advance(d time.Duration) {
	c.wall = c.wall.Add(d)
	c.mono = c.mono.Add(d)
}

func (c *fakeClock) jumpWall(d time.Duration) { c.wall = c.wall.Add(d) }
