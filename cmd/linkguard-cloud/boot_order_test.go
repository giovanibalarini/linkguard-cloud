package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"testing"
)

// TestConverterLegadoUmaVezRunsBeforeRenderizarNoBoot é um guarda de
// deriva sobre a ordem de execução do boot: a conversão das regras legadas
// precisa rodar antes da primeira renderização por zonas.
func TestConverterLegadoUmaVezRunsBeforeRenderizarNoBoot(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("não foi possível localizar o arquivo de teste")
	}
	srcPath := filepath.Join(filepath.Dir(thisFile), "main.go")

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, srcPath, nil, 0)
	if err != nil {
		t.Fatalf("parsear main.go: %v", err)
	}

	pos := map[string]int{}
	ast.Inspect(file, func(n ast.Node) bool {
		call, isCall := n.(*ast.CallExpr)
		if !isCall {
			return true
		}
		sel, isSel := call.Fun.(*ast.SelectorExpr)
		if !isSel {
			return true
		}
		recv, isIdent := sel.X.(*ast.Ident)
		if !isIdent || recv.Name != "frSvc" {
			return true
		}
		if _, already := pos[sel.Sel.Name]; !already {
			pos[sel.Sel.Name] = int(call.Pos())
		}
		return true
	})

	for _, name := range []string{"ConverterLegadoUmaVez", "RenderizarNoBoot"} {
		if _, found := pos[name]; !found {
			t.Fatalf("o boot não chama mais frSvc.%s -- se a sequência mudou de forma, este guarda precisa mudar junto", name)
		}
	}
	if pos["ConverterLegadoUmaVez"] > pos["RenderizarNoBoot"] {
		t.Errorf("frSvc.ConverterLegadoUmaVez tem que vir ANTES de frSvc.RenderizarNoBoot: a conversão precisa preparar as regras antes da primeira renderização")
	}
}

// TestMainWiresFonteInsumos guarda a ligação de que a renderização por zonas depende.
func TestMainWiresFonteInsumos(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("não foi possível localizar o arquivo de teste")
	}
	srcPath := filepath.Join(filepath.Dir(thisFile), "main.go")

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, srcPath, nil, 0)
	if err != nil {
		t.Fatalf("parsear main.go: %v", err)
	}

	wired := -1
	firstReconcile := -1
	ast.Inspect(file, func(n ast.Node) bool {
		call, isCall := n.(*ast.CallExpr)
		if !isCall {
			return true
		}
		sel, isSel := call.Fun.(*ast.SelectorExpr)
		if !isSel {
			return true
		}
		recv, isIdent := sel.X.(*ast.Ident)
		if !isIdent {
			return true
		}
		switch {
		case recv.Name == "frSvc" && sel.Sel.Name == "SetFonteInsumos":
			if wired == -1 {
				wired = int(call.Pos())
			}
		case recv.Name == "frSvc" && sel.Sel.Name == "RenderizarNoBoot":
			if firstReconcile == -1 || int(call.Pos()) < firstReconcile {
				firstReconcile = int(call.Pos())
			}
		}
		return true
	})

	if wired == -1 {
		t.Fatal("o boot não liga mais frSvc.SetFonteInsumos")
	}
	if firstReconcile == -1 {
		t.Fatal("o boot não chama mais frSvc.RenderizarNoBoot")
	}
	if wired > firstReconcile {
		t.Errorf("frSvc.SetFonteInsumos tem que ser ligado ANTES da primeira renderização do boot")
	}
}

// ─── Confirmar-ou-reverte: a verificação de boot (Fase C2) ────────────────

// TestPendingChangeIsRevertedBeforeAnyReconcileOnBoot guarda a ordem de que
// depende a única proteção que existe contra o pior caso desta fase.
//
// Uma regra de escopo input mal escrita tira o SSH e o painel do próprio
// operador, numa máquina remota. A rede de proteção é a janela de 90 s; a
// rede EMBAIXO dela é esta verificação de boot, para quando a máquina cai
// dentro da janela — que é o caso comum quando a mudança foi a causa da
// queda.
//
// A posição é a proteção, não organização: reverter DEPOIS de já ter
// reconciliado é aplicar mais uma vez, na máquina que acabou de voltar,
// exatamente a regra que pode tê-la derrubado. Por isso
// frSvc.RevertPendingOnBoot tem que vir antes de TUDO que aplica firewall no
// boot — as reconciliações do nftSvc e as do frSvc, incluindo o
// nftSvc.Restore que repõe os elementos salvos depois de um bootstrap.
//
// Guarda de deriva sobre a árvore sintática, como os demais deste arquivo:
// nenhum teste de pacote enxerga a sequência de main.go.
func TestPendingChangeIsRevertedBeforeAnyReconcileOnBoot(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("não foi possível localizar o arquivo de teste")
	}
	srcPath := filepath.Join(filepath.Dir(thisFile), "main.go")

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, srcPath, nil, 0)
	if err != nil {
		t.Fatalf("parsear main.go: %v", err)
	}

	// m-6: a comparação é feita DENTRO do corpo de provisionSystem, não no
	// arquivo inteiro. Comparar posições no arquivo aprovava um
	// RevertPendingOnBoot que estivesse numa função anterior qualquer — até
	// numa função morta —, e o guarda existe justamente para dizer que ele vem
	// antes das reconciliações NA SEQUÊNCIA QUE O BOOT EXECUTA.
	body := provisionSystemBody(t, file)

	// Só o que APLICA firewall entra na lista. frSvc.WatchPending não entra:
	// é a goroutine do timer, e ela não aplica nada por si.
	applies := map[string]bool{
		"frSvc.ConverterLegadoUmaVez":        true,
		"frSvc.RenderizarNoBoot":             true,
		"nftSvc.Restore":                     true,
		"nftSvc.ReconcileMasquerade":         true,
		"nftSvc.ReconcileStructuralChains":   true,
	}

	revert := -1
	firstApply, firstApplyName := -1, ""
	ast.Inspect(body, func(n ast.Node) bool {
		call, isCall := n.(*ast.CallExpr)
		if !isCall {
			return true
		}
		sel, isSel := call.Fun.(*ast.SelectorExpr)
		if !isSel {
			return true
		}
		recv, isIdent := sel.X.(*ast.Ident)
		if !isIdent {
			return true
		}
		name := recv.Name + "." + sel.Sel.Name
		if recv.Name == "frSvc" && sel.Sel.Name == "RevertPendingOnBoot" && revert == -1 {
			revert = int(call.Pos())
		}
		if applies[name] && (firstApply == -1 || int(call.Pos()) < firstApply) {
			firstApply, firstApplyName = int(call.Pos()), name
		}
		return true
	})

	if revert == -1 {
		t.Fatal("provisionSystem não verifica mais a mudança de firewall pendente: um reboot dentro da janela de confirmação passaria a deixar valendo para sempre uma regra não confirmada que pode ter trancado o operador fora da máquina")
	}
	if firstApply == -1 {
		t.Fatal("provisionSystem não aplica mais firewall por nenhum caminho conhecido -- se a sequência mudou de forma, este guarda precisa mudar junto")
	}
	if revert > firstApply {
		t.Errorf("frSvc.RevertPendingOnBoot tem que vir ANTES de %s: reverter depois de já ter aplicado é aplicar mais uma vez, na máquina que acabou de voltar, a regra que pode tê-la derrubado", firstApplyName)
	}
}

// provisionSystemBody devolve o corpo do FuncLit atribuído a
// `provisionSystem := func() { … }` em main.go — a sequência que o boot de
// fato executa. Os guardas deste arquivo comparam posições DENTRO dele: no
// arquivo inteiro, uma chamada perdida numa função anterior (ou morta)
// aprovaria uma sequência de boot errada (m-6).
func provisionSystemBody(t *testing.T, file *ast.File) *ast.FuncLit {
	t.Helper()
	var body *ast.FuncLit
	ast.Inspect(file, func(n ast.Node) bool {
		assign, isAssign := n.(*ast.AssignStmt)
		if !isAssign || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		name, isIdent := assign.Lhs[0].(*ast.Ident)
		if !isIdent || name.Name != "provisionSystem" {
			return true
		}
		if lit, isLit := assign.Rhs[0].(*ast.FuncLit); isLit && body == nil {
			body = lit
		}
		return true
	})
	if body == nil {
		t.Fatal("não encontrei `provisionSystem := func() { … }` em main.go -- se a sequência de boot mudou de forma, os guardas deste arquivo precisam mudar junto")
	}
	return body
}

// A verificação de boot roda uma vez por processo — e a trava que garante isso
// só pode ser marcada quando ela CONCLUI.
//
// São duas propriedades opostas, e o guarda cobra as duas porque cada uma
// sozinha reabre um buraco diferente:
//
//   - sem trava nenhuma: provisionSystem é reexecutado quando uma tentativa
//     posterior de instalar a base finalmente dá certo, o que pode ser meia
//     hora depois da subida, com o operador já no painel. A segunda passada
//     reverteria uma janela de confirmação recém-aberta como se a máquina
//     tivesse reiniciado. "No boot" tem que querer dizer no boot;
//   - com uma trava que queima cedo demais (era um sync.Once, N-4): a PRIMEIRA
//     passada roda mesmo com o bootstrap falhado (`if done || attempt == 0`),
//     isto é, possivelmente numa máquina onde o `nft` ainda nem existe e a
//     reversão de boot não tem como se completar. O Once queimava ali e a
//     passada que finalmente dava certo não repetia a verificação.
//
// Então: a chamada mora dentro de um `if !<trava>` em provisionSystem; a trava
// é declarada FORA do corpo de provisionSystem (declarada dentro, é recriada a
// cada passada e não guarda nada); e ela só é marcada no ramo em que
// RevertPendingOnBoot devolveu erro nil.
//
// Guarda de deriva sobre a árvore sintática — I-5 continua valendo: a versão
// antiga deste teste procurava só a chamada e passava verde com a trava movida
// para dentro do FuncLit.
func TestTheBootPendingCheckRunsOnlyOnceAndOnlyWhenItCompletes(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("não foi possível localizar o arquivo de teste")
	}
	srcPath := filepath.Join(filepath.Dir(thisFile), "main.go")

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, srcPath, nil, 0)
	if err != nil {
		t.Fatalf("parsear main.go: %v", err)
	}
	body := provisionSystemBody(t, file)

	// 1. o `if !<trava> { … RevertPendingOnBoot … }` dentro de provisionSystem.
	guardName := ""
	var guardStmt *ast.IfStmt
	ast.Inspect(body, func(n ast.Node) bool {
		ifStmt, isIf := n.(*ast.IfStmt)
		if !isIf || guardStmt != nil {
			return true
		}
		unary, isUnary := ifStmt.Cond.(*ast.UnaryExpr)
		if !isUnary || unary.Op != token.NOT {
			return true
		}
		ident, isIdent := unary.X.(*ast.Ident)
		if !isIdent {
			return true
		}
		if !callsRevertPendingOnBoot(ifStmt.Body) {
			return true
		}
		guardName, guardStmt = ident.Name, ifStmt
		return true
	})
	if guardStmt == nil {
		t.Fatal("frSvc.RevertPendingOnBoot tem que estar dentro de um `if !<trava> { … }` em provisionSystem: provisionSystem roda de novo quando a base termina de instalar, e uma segunda passada reverteria uma janela de confirmação aberta minutos antes pelo operador")
	}

	// 2. a trava é declarada FORA do corpo de provisionSystem — senão é
	//    recriada a cada passada e não guarda coisa nenhuma.
	declaredOutside := false
	ast.Inspect(file, func(n ast.Node) bool {
		assign, isAssign := n.(*ast.AssignStmt)
		if !isAssign || assign.Tok != token.DEFINE {
			return true
		}
		for _, lhs := range assign.Lhs {
			ident, isIdent := lhs.(*ast.Ident)
			if !isIdent || ident.Name != guardName {
				continue
			}
			if int(assign.Pos()) < int(body.Pos()) || int(assign.Pos()) > int(body.End()) {
				declaredOutside = true
			}
		}
		return true
	})
	if !declaredOutside {
		t.Errorf("a trava %q tem que ser declarada FORA do corpo de provisionSystem: declarada dentro, ela é recriada a cada passada e a segunda execução (quando a base termina de instalar) volta a reverter a janela de confirmação que o operador acabou de abrir", guardName)
	}

	// 3. a trava só é marcada no ramo de SUCESSO. O que se procura é
	//    `if err := frSvc.RevertPendingOnBoot(ctx); err != nil { … } else {
	//    <trava> = true }`: a atribuição tem que estar no Else, e não solta no
	//    corpo do if externo (aí ela marcaria mesmo com a reversão falhando).
	markedOnSuccess, markedAnywhere := false, false
	ast.Inspect(guardStmt.Body, func(n ast.Node) bool {
		assign, isAssign := n.(*ast.AssignStmt)
		if !isAssign || assign.Tok != token.ASSIGN || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}
		ident, isIdent := assign.Lhs[0].(*ast.Ident)
		if !isIdent || ident.Name != guardName {
			return true
		}
		lit, isLit := assign.Rhs[0].(*ast.Ident)
		if !isLit || lit.Name != "true" {
			return true
		}
		markedAnywhere = true
		// Dentro de qual `else` de um if cujo Init chama RevertPendingOnBoot?
		ast.Inspect(guardStmt.Body, func(m ast.Node) bool {
			inner, isIf := m.(*ast.IfStmt)
			if !isIf || inner.Else == nil || inner.Init == nil {
				return true
			}
			if !callsRevertPendingOnBoot(inner.Init) {
				return true
			}
			if int(inner.Else.Pos()) <= int(assign.Pos()) && int(assign.End()) <= int(inner.Else.End()) {
				markedOnSuccess = true
			}
			return true
		})
		return true
	})

	if !markedAnywhere {
		t.Fatalf("nada marca a trava %q dentro do `if`: sem marcar, a verificação de boot roda de novo em CADA passada de provisionSystem e reverteria a janela de confirmação que o operador acabou de abrir", guardName)
	}
	if !markedOnSuccess {
		t.Errorf("a trava %q só pode ser marcada no ramo em que frSvc.RevertPendingOnBoot devolveu nil (N-4): a primeira passada de provisionSystem roda mesmo com o bootstrap falhado — possivelmente sem o `nft` na máquina —, e marcar ali gasta a única chance de \"no boot\" numa passada que não conseguiu concluir a verificação", guardName)
	}
}

// callsRevertPendingOnBoot diz se `frSvc.RevertPendingOnBoot(…)` aparece em
// algum lugar da subárvore.
func callsRevertPendingOnBoot(n ast.Node) bool {
	found := false
	ast.Inspect(n, func(node ast.Node) bool {
		call, isCall := node.(*ast.CallExpr)
		if !isCall {
			return true
		}
		sel, isSel := call.Fun.(*ast.SelectorExpr)
		if !isSel || sel.Sel.Name != "RevertPendingOnBoot" {
			return true
		}
		if recv, isIdent := sel.X.(*ast.Ident); isIdent && recv.Name == "frSvc" {
			found = true
		}
		return true
	})
	return found
}

// TestMainWiresThePersistGuard guarda a ligação que faz o /etc/nftables.conf
// deixar de receber uma regra ainda não confirmada (I-1 da revisão final da
// Fase C2).
//
// Sem esta linha o binário compila, a suíte inteira passa e o comportamento
// volta a ser o antigo em silêncio: o arquivo que o nftables.service carrega
// ANTES de o LinkGuard subir passa a conter a regra de escopo input não
// confirmada, e uma queda de energia dentro dos 90 segundos faz a máquina voltar
// com ela valendo — sem SSH e sem painel numa máquina remota, e sem o LinkGuard
// de pé para reverter.
//
// O guarda também exige que a guarda seja ligada ANTES da primeira
// reconciliação do boot, pela mesma razão de SetInputChainSources: uma passada
// que rode antes disso persistiria sem consultar ninguém.
func TestMainWiresThePersistGuard(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("não foi possível localizar o arquivo de teste")
	}
	srcPath := filepath.Join(filepath.Dir(thisFile), "main.go")

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, srcPath, nil, 0)
	if err != nil {
		t.Fatalf("parsear main.go: %v", err)
	}

	wired, firstReconcile := -1, -1
	ast.Inspect(file, func(n ast.Node) bool {
		call, isCall := n.(*ast.CallExpr)
		if !isCall {
			return true
		}
		sel, isSel := call.Fun.(*ast.SelectorExpr)
		if !isSel {
			return true
		}
		recv, isIdent := sel.X.(*ast.Ident)
		if !isIdent || recv.Name != "nftSvc" && recv.Name != "frSvc" {
			return true
		}
		switch {
		case recv.Name == "nftSvc" && sel.Sel.Name == "SetPersistGuard":
			if wired == -1 {
				wired = int(call.Pos())
			}
		case recv.Name == "frSvc" && sel.Sel.Name == "RenderizarNoBoot",
			recv.Name == "nftSvc" && sel.Sel.Name == "ReconcileMasquerade":
			if firstReconcile == -1 || int(call.Pos()) < firstReconcile {
				firstReconcile = int(call.Pos())
			}
		}
		return true
	})

	if wired == -1 {
		t.Fatal("o boot não liga mais nftSvc.SetPersistGuard: o /etc/nftables.conf volta a receber a regra de escopo input NÃO confirmada, e uma queda de energia dentro dos 90 segundos faz a máquina voltar com ela valendo, antes de o LinkGuard subir para reverter")
	}
	if firstReconcile == -1 {
		t.Fatal("o boot não reconcilia mais por nenhum caminho -- se a sequência mudou de forma, este guarda precisa mudar junto")
	}
	if wired > firstReconcile {
		t.Errorf("nftSvc.SetPersistGuard tem que ser ligado ANTES da primeira reconciliação do boot: até lá, persistir não consulta ninguém")
	}
}

// TestMainWiresTheBootPersistSource guarda a ligação do vigia ao serviço de
// nftables. Sem ela o Collector não tem como saber nada sobre o
// /etc/nftables.conf, o item "Regras no próximo boot" da Saúde do sistema
// simplesmente não existe, e a falha do Persist volta a ser o que a validação
// em VM mediu no §10: um WARN no journal, com o painel dizendo `ok: true`
// enquanto as regras não sobreviveriam ao reboot.
//
// Guarda de deriva na AST, como TestMainWiresTheInputChainSources e
// TestMainWiresThePersistGuard: o modo de falha é uma linha REMOVIDA num
// refactor, que compila igual e não quebra teste nenhum de comportamento.
func TestMainWiresTheBootPersistSource(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("não foi possível localizar o arquivo de teste")
	}
	srcPath := filepath.Join(filepath.Dir(thisFile), "main.go")

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, srcPath, nil, 0)
	if err != nil {
		t.Fatalf("parsear main.go: %v", err)
	}

	wired := false
	ast.Inspect(file, func(n ast.Node) bool {
		call, isCall := n.(*ast.CallExpr)
		if !isCall {
			return true
		}
		sel, isSel := call.Fun.(*ast.SelectorExpr)
		if !isSel || sel.Sel.Name != "SetBootPersistSource" {
			return true
		}
		recv, isIdent := sel.X.(*ast.Ident)
		if !isIdent || recv.Name != "metricsCollector" {
			return true
		}
		// A fonte tem que ser o MESMO nftSvc que persiste de verdade: um
		// segundo Service teria um PersistState próprio, sempre "nunca
		// tentou", e o item nunca apareceria.
		if len(call.Args) == 1 {
			if arg, isIdent := call.Args[0].(*ast.Ident); isIdent && arg.Name == "nftSvc" {
				wired = true
			}
		}
		return true
	})

	if !wired {
		t.Fatal("o boot não liga mais metricsCollector.SetBootPersistSource(nftSvc): o item \"Regras no próximo boot\" some da Saúde do sistema e a falha do Persist volta a ser muda na tela (§10 da validação em VM)")
	}
}

// TestMainReconciliaOResolvConf guarda a chamada que reescreve o resolv.conf
// para o resolver local no boot.
//
// O guarda antigo aqui vigiava unboundSvc.SetAlerter: o veredito sobre o CAMINHO de
// resolução (issue #195) nascia dentro do EnsureResolvConf, uma vez por
// processo. Ele mudou de lugar — quem mede agora é o vigia por tique
// monitoring.Collector.checkCaminhoNSS, e quem o guarda contra deriva é
// TestCollectRodaOCheckCaminhoNSS, em internal/monitoring, que roda de verdade
// (os testes deste pacote não compilam sem web/dist construído). O que sobra
// aqui é a outra metade: sem esta chamada ninguém reconcilia o resolv.conf, e
// o dhclient devolve o DNS do provedor na renovação do lease.
func TestMainReconciliaOResolvConf(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("não foi possível localizar o arquivo de teste")
	}
	srcPath := filepath.Join(filepath.Dir(thisFile), "main.go")

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, srcPath, nil, 0)
	if err != nil {
		t.Fatalf("parsear main.go: %v", err)
	}

	chamado := false
	ast.Inspect(file, func(n ast.Node) bool {
		call, isCall := n.(*ast.CallExpr)
		if !isCall {
			return true
		}
		sel, isSel := call.Fun.(*ast.SelectorExpr)
		if !isSel {
			return true
		}
		recv, isIdent := sel.X.(*ast.Ident)
		if !isIdent || recv.Name != "unboundSvc" {
			return true
		}
		if sel.Sel.Name == "EnsureResolvConf" {
			chamado = true
		}
		return true
	})

	if !chamado {
		t.Fatal("o boot não chama mais unboundSvc.EnsureResolvConf: ninguém aponta o resolv.conf para o resolver local, e o dhclient devolve o DNS do provedor na renovação do lease")
	}
}
