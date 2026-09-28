package handlers

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Toda chave i18n que o servidor escreve como literal (fwz.*, fw.*) precisa ter
// texto nos YAMLs do painel; senão o operador vê a chave crua.
func TestChavesI18nDoServidorTemTextoNoPainel(t *testing.T) {
	raiz := filepath.Join("..", "..", "..")

	definidas := map[string]bool{}
	yamls, err := filepath.Glob(filepath.Join(raiz, "web", "src", "i18n", "strings", "*.yaml"))
	if err != nil || len(yamls) == 0 {
		t.Fatalf("YAMLs do painel não encontrados: %v", err)
	}
	reChave := regexp.MustCompile(`^([A-Za-z0-9_.]+):\s*$`)
	for _, y := range yamls {
		b, err := os.ReadFile(y)
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range strings.Split(string(b), "\n") {
			if m := reChave.FindStringSubmatch(l); m != nil {
				definidas[m[1]] = true
			}
		}
	}

	reLiteral := regexp.MustCompile(`"((?:fwz|fw\.(?:aviso|travada|padrao))\.[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*)"`)
	faltando := map[string]string{}
	err = filepath.Walk(filepath.Join(raiz, "internal"), func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, m := range reLiteral.FindAllStringSubmatch(string(b), -1) {
			if !definidas[m[1]] {
				faltando[m[1]] = p
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for k, p := range faltando {
		t.Errorf("chave %q (em %s) não tem texto nos YAMLs do painel", k, p)
	}
}
