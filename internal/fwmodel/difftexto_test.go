package fwmodel

import (
	"strings"
	"testing"
)

func TestDiffLinhas(t *testing.T) {
	t.Run("textos iguais devolvem string vazia", func(t *testing.T) {
		a := "linha 1\nlinha 2\nlinha 3\n"
		got := DiffLinhas(a, a)
		if got != "" {
			t.Fatalf("esperava vazio para textos iguais, obteve: %q", got)
		}
	})

	t.Run("insercao simples", func(t *testing.T) {
		a := "linha 1\nlinha 2\nlinha 3\n"
		b := "linha 1\nlinha 2\nlinha 2.5\nlinha 3\n"
		got := DiffLinhas(a, b)
		if !strings.Contains(got, "+linha 2.5") {
			t.Fatalf("esperava conter '+linha 2.5', obteve:\n%s", got)
		}
		if !strings.Contains(got, "@@") {
			t.Fatalf("esperava cabeçalho de hunk com @@, obteve:\n%s", got)
		}
	})

	t.Run("remocao simples", func(t *testing.T) {
		a := "linha 1\nlinha 2\nlinha 3\n"
		b := "linha 1\nlinha 3\n"
		got := DiffLinhas(a, b)
		if !strings.Contains(got, "-linha 2") {
			t.Fatalf("esperava conter '-linha 2', obteve:\n%s", got)
		}
	})

	t.Run("modificacao com contexto de 3 linhas", func(t *testing.T) {
		a := "c1\nc2\nc3\nvelha\nc4\nc5\nc6\n"
		b := "c1\nc2\nc3\nnova\nc4\nc5\nc6\n"
		got := DiffLinhas(a, b)
		if !strings.Contains(got, "-velha") || !strings.Contains(got, "+nova") {
			t.Fatalf("esperava conter -velha e +nova, obteve:\n%s", got)
		}
		// Deve conter as 3 linhas de contexto antes e depois
		for _, ctx := range []string{" c1", " c2", " c3", " c4", " c5", " c6"} {
			if !strings.Contains(got, ctx) {
				t.Errorf("esperava contexto %q no diff, obteve:\n%s", ctx, got)
			}
		}
	})

	t.Run("um texto vazio e outro preenchido", func(t *testing.T) {
		a := ""
		b := "linha 1\nlinha 2\n"
		got := DiffLinhas(a, b)
		if !strings.Contains(got, "+linha 1") || !strings.Contains(got, "+linha 2") {
			t.Fatalf("esperava adicoes completas, obteve:\n%s", got)
		}
	})
}
