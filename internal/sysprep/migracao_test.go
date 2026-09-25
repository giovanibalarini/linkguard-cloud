package sysprep

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// Migração do linkguard-fw para o linkguard-cloud.
//
// Como os testes do postinst acima, estes RODAM os scripts do pacote com um
// systemctl de mentira. O que está em jogo é a caixa da OCI que já roda o
// linkguard-fw: um preinst que perde o banco, ou um postinst que não religa o
// serviço, deixa a conta sem ninguém reconciliando o NAT.
// ─────────────────────────────────────────────────────────────────────────────

type migracao struct {
	oldData, oldConf, newData, newConf, bin, log string
}

func novaMigracao(t *testing.T) migracao {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("scripts de pacote Debian")
	}
	base := t.TempDir()
	m := migracao{
		oldData: filepath.Join(base, "var-lib-linkguard-fw"),
		oldConf: filepath.Join(base, "etc-linkguard-fw"),
		newData: filepath.Join(base, "var-lib-linkguard-cloud"),
		newConf: filepath.Join(base, "etc-linkguard-cloud"),
		bin:     filepath.Join(base, "bin"),
		log:     filepath.Join(base, "systemctl.log"),
	}
	if err := os.MkdirAll(m.bin, 0o755); err != nil {
		t.Fatal(err)
	}
	// O dublê anota cada chamada; `enable` liga um estado que o `is-enabled`
	// passa a responder, como o systemctl de verdade.
	stub := "#!/bin/sh\necho \"$*\" >> " + m.log + "\ncase \"$1\" in\n" +
		"  enable) : > " + m.log + ".enabled ;;\n" +
		"  is-enabled) [ -f " + m.log + ".enabled ] && exit 0 || exit 1 ;;\n" +
		"esac\nexit 0\n"
	if err := os.WriteFile(filepath.Join(m.bin, "systemctl"), []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	return m
}

func (m migracao) run(t *testing.T, script string, args ...string) string {
	t.Helper()
	cmd := exec.Command("sh", append([]string{filepath.Join(repoRoot(t), "deploy/deb", script)}, args...)...)
	cmd.Env = append(os.Environ(),
		"PATH="+m.bin+":"+os.Getenv("PATH"),
		"LINKGUARD_OLD_DATA_DIR="+m.oldData,
		"LINKGUARD_OLD_CONFIG_DIR="+m.oldConf,
		"LINKGUARD_DATA_DIR="+m.newData,
		"LINKGUARD_CONFIG_DIR="+m.newConf,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s falhou: %v\n%s", script, err, out)
	}
	return string(out)
}

func (m migracao) chamadas(t *testing.T) string {
	t.Helper()
	b, _ := os.ReadFile(m.log)
	return string(b)
}

func escreve(t *testing.T, path, conteudo string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(conteudo), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestOPreinstCopiaOEstadoDoLinkguardFw(t *testing.T) {
	m := novaMigracao(t)
	escreve(t, filepath.Join(m.oldData, "linkguard.db"), "banco")
	escreve(t, filepath.Join(m.oldData, "secret.key"), "chave")
	escreve(t, filepath.Join(m.oldConf, "config.json"),
		`{"db_path": "`+m.oldData+`/linkguard.db", "port": 9997}`)

	m.run(t, "preinst", "install")

	for _, f := range []string{"linkguard.db", "secret.key", ".migrado-do-linkguard-fw"} {
		if _, err := os.Stat(filepath.Join(m.newData, f)); err != nil {
			t.Errorf("%s não chegou ao diretório novo: %v", f, err)
		}
	}
	cfg, err := os.ReadFile(filepath.Join(m.newConf, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cfg), m.newData+"/linkguard.db") || strings.Contains(string(cfg), m.oldData) {
		t.Errorf("db_path não foi apontado para o diretório novo: %s", cfg)
	}
	// Copia, não move: o linkguard-fw reinstalado tem que achar tudo.
	if _, err := os.Stat(filepath.Join(m.oldData, "linkguard.db")); err != nil {
		t.Errorf("o banco original sumiu: %v", err)
	}
	if !strings.Contains(m.chamadas(t), "stop linkguard-fw") {
		t.Errorf("o serviço antigo não foi parado antes da cópia; chamadas: %q", m.chamadas(t))
	}
}

func TestOPreinstNuncaSobrescreveOEstadoDoCloud(t *testing.T) {
	m := novaMigracao(t)
	escreve(t, filepath.Join(m.oldData, "linkguard.db"), "banco antigo")
	escreve(t, filepath.Join(m.newData, "linkguard.db"), "banco do cloud")

	m.run(t, "preinst", "upgrade", "1.0.0")

	b, _ := os.ReadFile(filepath.Join(m.newData, "linkguard.db"))
	if string(b) != "banco do cloud" {
		t.Errorf("o banco do cloud foi sobrescrito: %q", b)
	}
	if _, err := os.Stat(filepath.Join(m.newData, ".migrado-do-linkguard-fw")); err == nil {
		t.Error("marcou migração numa caixa que já era linkguard-cloud")
	}
}

func TestOPreinstSemLinkguardFwNaoFazNada(t *testing.T) {
	m := novaMigracao(t)
	m.run(t, "preinst", "install")
	if _, err := os.Stat(m.newData); err == nil {
		t.Error("criou o diretório de dados numa instalação nova; isso é trabalho do --prepare-system")
	}
	if m.chamadas(t) != "" {
		t.Errorf("chamou o systemctl sem haver o que migrar: %q", m.chamadas(t))
	}
}

func TestOPostinstLigaOServicoMigrado(t *testing.T) {
	m := novaMigracao(t)
	escreve(t, filepath.Join(m.newData, ".migrado-do-linkguard-fw"), "")
	escreve(t, filepath.Join(m.newConf, "config.json"), "{}")

	out := m.run(t, "postinst", "configure")

	c := m.chamadas(t)
	if !strings.Contains(c, "enable linkguard-cloud") || !strings.Contains(c, "restart linkguard-cloud") {
		t.Errorf("o serviço migrado não foi habilitado e iniciado; chamadas: %q\n%s", c, out)
	}
	if _, err := os.Stat(filepath.Join(m.newData, ".migrado-do-linkguard-fw")); err == nil {
		t.Error("o marcador de migração ficou para trás")
	}
}

// O linkguard-fw servia DHCP pelo kea, e a caixa de produção da OCI tem o
// kea-dhcp4-server ativo. A versão cloud não serve DHCP: o que sobrasse de pé
// seria um servidor DHCP sem dono na VCN.
func TestOPostinstDesligaOKeaDaCaixaMigrada(t *testing.T) {
	m := novaMigracao(t)
	escreve(t, filepath.Join(m.newData, ".migrado-do-linkguard-fw"), "")
	escreve(t, filepath.Join(m.newConf, "config.json"), "{}")

	out := m.run(t, "postinst", "configure")

	if c := m.chamadas(t); !strings.Contains(c, "disable --now kea-dhcp4-server") {
		t.Errorf("o kea da caixa migrada ficou de pé; chamadas: %q\n%s", c, out)
	}
}

// Numa instalação que não veio do linkguard-fw o pacote não tem por que mexer
// em serviço alheio.
func TestOPostinstNaoMexeNoKeaSemMigracao(t *testing.T) {
	m := novaMigracao(t)
	escreve(t, filepath.Join(m.newConf, "config.json"), "{}")

	m.run(t, "postinst", "configure")

	if c := m.chamadas(t); strings.Contains(c, "kea") {
		t.Errorf("mexeu no kea sem haver migração; chamadas: %q", c)
	}
}

func TestOPacoteSubstituiOLinkguardFw(t *testing.T) {
	mk, err := os.ReadFile(filepath.Join(repoRoot(t), "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	for _, campo := range []string{`Conflicts: linkguard-fw\n`, `Replaces: linkguard-fw\n`, "DEBIAN/preinst"} {
		if !strings.Contains(string(mk), campo) {
			t.Errorf("o pacote não declara %q; sem isso o dpkg não troca o linkguard-fw pelo cloud", campo)
		}
	}
}
