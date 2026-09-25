package fwmodel

import (
	"fmt"
	"strings"
)

type diffOp struct {
	op    rune // ' ', '-', '+'
	text  string
	lineA int
	lineB int
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	lines := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// DiffLinhas produz um diff unificado simples entre os textos a e b por LCS de linhas,
// com 3 linhas de contexto e prefixos ' ', '-' e '+'.
// Se a e b forem iguais, devolve string vazia.
func DiffLinhas(a, b string) string {
	if a == b {
		return ""
	}

	linesA := splitLines(a)
	linesB := splitLines(b)
	m := len(linesA)
	n := len(linesB)

	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}

	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if linesA[i-1] == linesB[j-1] {
				dp[i][j] = dp[i-1][j-1] + 1
			} else if dp[i-1][j] >= dp[i][j-1] {
				dp[i][j] = dp[i-1][j]
			} else {
				dp[i][j] = dp[i][j-1]
			}
		}
	}

	var ops []diffOp
	i, j := m, n
	for i > 0 || j > 0 {
		if i > 0 && j > 0 && linesA[i-1] == linesB[j-1] {
			ops = append(ops, diffOp{op: ' ', text: linesA[i-1], lineA: i, lineB: j})
			i--
			j--
		} else if j > 0 && (i == 0 || dp[i][j-1] >= dp[i-1][j]) {
			ops = append(ops, diffOp{op: '+', text: linesB[j-1], lineA: 0, lineB: j})
			j--
		} else if i > 0 && (j == 0 || dp[i-1][j] >= dp[i][j-1]) {
			ops = append(ops, diffOp{op: '-', text: linesA[i-1], lineA: i, lineB: 0})
			i--
		}
	}

	for l, r := 0, len(ops)-1; l < r; l, r = l+1, r-1 {
		ops[l], ops[r] = ops[r], ops[l]
	}

	var hasChange bool
	for _, op := range ops {
		if op.op != ' ' {
			hasChange = true
			break
		}
	}
	if !hasChange {
		return ""
	}

	const contextLines = 3
	type rangeSpan struct {
		start int
		end   int
	}

	var spans []rangeSpan
	for idx, op := range ops {
		if op.op != ' ' {
			st := idx - contextLines
			if st < 0 {
				st = 0
			}
			en := idx + contextLines
			if en >= len(ops) {
				en = len(ops) - 1
			}
			if len(spans) > 0 && st <= spans[len(spans)-1].end+1 {
				spans[len(spans)-1].end = en
			} else {
				spans = append(spans, rangeSpan{start: st, end: en})
			}
		}
	}

	var buf strings.Builder
	for _, sp := range spans {
		lastA := 0
		lastB := 0
		for k := 0; k < sp.start; k++ {
			if ops[k].lineA > 0 {
				lastA = ops[k].lineA
			}
			if ops[k].lineB > 0 {
				lastB = ops[k].lineB
			}
		}

		startA, countA := 0, 0
		startB, countB := 0, 0
		for k := sp.start; k <= sp.end; k++ {
			if ops[k].op == ' ' || ops[k].op == '-' {
				if countA == 0 {
					startA = ops[k].lineA
				}
				countA++
			}
			if ops[k].op == ' ' || ops[k].op == '+' {
				if countB == 0 {
					startB = ops[k].lineB
				}
				countB++
			}
		}
		if countA == 0 {
			startA = lastA
		}
		if countB == 0 {
			startB = lastB
		}

		fmt.Fprintf(&buf, "@@ -%d,%d +%d,%d @@\n", startA, countA, startB, countB)
		for k := sp.start; k <= sp.end; k++ {
			fmt.Fprintf(&buf, "%c%s\n", ops[k].op, ops[k].text)
		}
	}

	return buf.String()
}
