package fwmodel

import (
	"sort"
	"strings"
)

// ProblemasDaMudanca devolve os erros que uma escrita deixaria na configuração,
// comparando o que havia (antes) com o que ficaria (depois). Avisos nunca
// bloqueiam.
//
// Bloqueiam dois tipos de erro: os dos objetos que o operador acabou de mexer
// (onde), mesmo que já estivessem ruins — o que ele salva tem que sair certo —
// e qualquer erro que não existia antes, esteja no objeto mexido ou em outro
// que dependia dele (trocar o tipo de um alias que uma regra usa quebra a
// regra, não o alias).
//
// Um erro que já estava lá e não é do que ele mexeu não tranca a edição; senão
// uma configuração herdada com um defeito impediria até de consertá-la.
func ProblemasDaMudanca(antes, depois Config, pessoas []string, onde ...string) []Problema {
	restantes := make(map[string]int)
	for _, p := range Validar(antes, pessoas) {
		if p.Severidade == "erro" {
			restantes[chaveDoProblema(p)]++
		}
	}
	alvo := make(map[string]bool, len(onde))
	for _, o := range onde {
		alvo[o] = true
	}

	var out []Problema
	for _, p := range Validar(depois, pessoas) {
		if p.Severidade != "erro" {
			continue
		}
		novo := true
		if k := chaveDoProblema(p); restantes[k] > 0 {
			restantes[k]--
			novo = false
		}
		if novo || alvo[p.Onde] {
			out = append(out, p)
		}
	}
	return out
}

func chaveDoProblema(p Problema) string {
	var b strings.Builder
	b.WriteString(p.Onde)
	b.WriteByte(0)
	b.WriteString(p.Chave)
	nomes := make([]string, 0, len(p.Vars))
	for k := range p.Vars {
		nomes = append(nomes, k)
	}
	sort.Strings(nomes)
	for _, k := range nomes {
		b.WriteByte(0)
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(p.Vars[k])
	}
	return b.String()
}
