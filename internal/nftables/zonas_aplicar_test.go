package nftables

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestService_ObjetosExistentes(t *testing.T) {
	ctx := context.Background()
	jsonContent, err := os.ReadFile("testdata/zonas_v2/list_table.json")
	if err != nil {
		t.Fatalf("ler testdata/zonas_v2/list_table.json: %v", err)
	}

	t.Run("sucesso lendo tabela populada", func(t *testing.T) {
		exec := &fakeReconcileExec{
			readOut: map[string]string{
				"nft -j list table inet linkguard": string(jsonContent),
			},
		}
		s := NewService(exec)

		obj, err := s.ObjetosExistentes(ctx)
		if err != nil {
			t.Fatalf("ObjetosExistentes falhou: %v", err)
		}

		esperaChains := []string{"forward", "grp_0a1b2c3d4e5f", "input", "zona_flut_in"}
		if len(obj.Chains) != len(esperaChains) {
			t.Fatalf("esperava %d chains, vieram %d: %v", len(esperaChains), len(obj.Chains), obj.Chains)
		}
		for i, ch := range esperaChains {
			if obj.Chains[i] != ch {
				t.Errorf("chain[%d] = %q; esperava %q", i, obj.Chains[i], ch)
			}
		}

		esperaSets := []string{"blocked_hosts", "blocked_macs", "blocklist"}
		if len(obj.Sets) != len(esperaSets) {
			t.Fatalf("esperava %d sets, vieram %d: %v", len(esperaSets), len(obj.Sets), obj.Sets)
		}
		for i, st := range esperaSets {
			if obj.Sets[i] != st {
				t.Errorf("set[%d] = %q; esperava %q", i, obj.Sets[i], st)
			}
		}
	})

	t.Run("tabela inexistente devolve Existentes vazio sem erro", func(t *testing.T) {
		exec := &fakeReconcileExec{
			readErr: errors.New("Error: No such file or directory"),
		}
		s := NewService(exec)

		obj, err := s.ObjetosExistentes(ctx)
		if err != nil {
			t.Fatalf("esperava nil para tabela inexistente, veio: %v", err)
		}
		if len(obj.Chains) != 0 || len(obj.Sets) != 0 {
			t.Fatalf("esperava Existentes vazio, veio: %+v", obj)
		}
	})

	t.Run("dry-run devolve Existentes vazio sem executar", func(t *testing.T) {
		exec := &fakeReconcileExec{
			dryRun: true,
		}
		s := NewService(exec)

		obj, err := s.ObjetosExistentes(ctx)
		if err != nil {
			t.Fatalf("esperava nil no dry-run, veio: %v", err)
		}
		if len(exec.reads) != 0 {
			t.Fatalf("dry-run não devia executar leitura, executou: %v", exec.reads)
		}
		if len(obj.Chains) != 0 || len(obj.Sets) != 0 {
			t.Fatalf("esperava Existentes vazio, veio: %+v", obj)
		}
	})
}

func TestService_TestarScript(t *testing.T) {
	ctx := context.Background()
	scriptExemplo := "add table inet linkguard\nadd chain inet linkguard input { type filter hook input priority 0; policy accept; }\n"

	t.Run("sucesso envia script completo para nft -c -f", func(t *testing.T) {
		exec := &fakeReconcileExec{}
		s := NewService(exec)

		err := s.TestarScript(ctx, scriptExemplo)
		if err != nil {
			t.Fatalf("TestarScript falhou: %v", err)
		}

		if len(exec.reads) != 1 {
			t.Fatalf("esperava 1 leitura, vieram %d: %v", len(exec.reads), exec.reads)
		}
		if !strings.HasPrefix(exec.reads[0], "nft -c -f ") {
			t.Errorf("comando lido inesperado: %q", exec.reads[0])
		}
		if len(exec.checkScripts) != 1 {
			t.Fatalf("esperava 1 script capturado em checkScripts, vieram %d", len(exec.checkScripts))
		}
		if exec.checkScripts[0] != scriptExemplo {
			t.Errorf("script entregue ao nft -c diverge do original:\nObtido:\n%s\nEsperado:\n%s", exec.checkScripts[0], scriptExemplo)
		}
	})

	t.Run("falha no preflight nft -c propaga erro", func(t *testing.T) {
		exec := &fakeReconcileExec{
			readFailOn: func(cmd string) error {
				return errors.New("syntax error, unexpected invalid token")
			},
		}
		s := NewService(exec)

		err := s.TestarScript(ctx, scriptExemplo)
		if err == nil || !strings.Contains(err.Error(), "syntax error") {
			t.Fatalf("esperava erro de sintaxe, veio: %v", err)
		}
	})

	t.Run("dry-run não executa", func(t *testing.T) {
		exec := &fakeReconcileExec{dryRun: true}
		s := NewService(exec)

		err := s.TestarScript(ctx, scriptExemplo)
		if err != nil {
			t.Fatalf("dry-run falhou: %v", err)
		}
		if len(exec.reads) != 0 {
			t.Fatalf("dry-run não devia executar leitura: %v", exec.reads)
		}
	})
}

func TestService_AplicarScript(t *testing.T) {
	ctx := context.Background()
	scriptExemplo := "add table inet linkguard\nadd chain inet linkguard input { type filter hook input priority 0; policy accept; }\n"

	t.Run("sucesso aplica atômico e persiste em disco", func(t *testing.T) {
		exec := &fakeReconcileExec{
			readOut: map[string]string{
				"nft list table inet linkguard": "table inet linkguard {\n\tchain input {\n\t}\n}\n",
			},
		}
		s := NewService(exec)
		confFile := filepath.Join(t.TempDir(), "nftables.conf")
		s.SetConfPath(confFile)

		err := s.AplicarScript(ctx, scriptExemplo)
		if err != nil {
			t.Fatalf("AplicarScript falhou: %v", err)
		}

		if len(exec.executed) != 1 {
			t.Fatalf("esperava 1 execução, vieram %d: %v", len(exec.executed), exec.executed)
		}
		if !strings.HasPrefix(exec.executed[0], "nft -f ") {
			t.Errorf("comando executado inesperado: %q", exec.executed[0])
		}
		if len(exec.applyScripts) != 1 {
			t.Fatalf("esperava 1 script capturado em applyScripts, vieram %d", len(exec.applyScripts))
		}
		if exec.applyScripts[0] != scriptExemplo {
			t.Errorf("script entregue ao nft -f diverge do original:\nObtido:\n%s\nEsperado:\n%s", exec.applyScripts[0], scriptExemplo)
		}

		// Valida que o Persist gravou o arquivo em disco
		body, err := os.ReadFile(confFile)
		if err != nil {
			t.Fatalf("ler arquivo persistido %s: %v", confFile, err)
		}
		if !strings.Contains(string(body), "table inet linkguard") {
			t.Errorf("arquivo persistido não contém a tabela esperada: %s", string(body))
		}
	})

	t.Run("falha no nft -f aborta e não persiste", func(t *testing.T) {
		exec := &fakeReconcileExec{
			failOn: func(cmd string) error {
				return errors.New("kernel rejection")
			},
		}
		s := NewService(exec)
		confFile := filepath.Join(t.TempDir(), "nftables.conf")
		s.SetConfPath(confFile)

		err := s.AplicarScript(ctx, scriptExemplo)
		if err == nil || !strings.Contains(err.Error(), "kernel rejection") {
			t.Fatalf("esperava erro do kernel, veio: %v", err)
		}

		if _, err := os.Stat(confFile); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("arquivo persistido não devia existir após falha no nft -f: %v", err)
		}
	})

	t.Run("falha ao gravar o arquivo de boot não é falha da aplicação", func(t *testing.T) {
		exec := &fakeReconcileExec{
			readOut: map[string]string{
				"nft list table inet linkguard": "table inet linkguard {\n\tchain input {\n\t}\n}\n",
			},
		}
		s := NewService(exec)
		// o diretório-pai não existe: o nft -f passa e o os.WriteFile falha
		s.SetConfPath(filepath.Join(t.TempDir(), "nao-existe", "nftables.conf"))

		if err := s.AplicarScript(ctx, scriptExemplo); err != nil {
			t.Fatalf("o ruleset entrou no kernel: AplicarScript não podia devolver erro, veio: %v", err)
		}
		if len(exec.executed) != 1 || !strings.HasPrefix(exec.executed[0], "nft -f ") {
			t.Fatalf("esperava exatamente um nft -f, vieram: %v", exec.executed)
		}
		st := s.PersistState()
		if !st.Attempted || st.OK || st.Err == "" {
			t.Fatalf("a falha do arquivo de boot devia ficar registrada em PersistState, veio: %+v", st)
		}
	})

	t.Run("dry-run não executa nada", func(t *testing.T) {
		exec := &fakeReconcileExec{dryRun: true}
		s := NewService(exec)
		confFile := filepath.Join(t.TempDir(), "nftables.conf")
		s.SetConfPath(confFile)

		err := s.AplicarScript(ctx, scriptExemplo)
		if err != nil {
			t.Fatalf("dry-run falhou: %v", err)
		}
		if len(exec.executed) != 0 {
			t.Fatalf("dry-run não devia executar nada: %v", exec.executed)
		}
	})
}

func TestService_ContadoresPorChave(t *testing.T) {
	ctx := context.Background()
	jsonContent, err := os.ReadFile("testdata/zonas_v2/list_table.json")
	if err != nil {
		t.Fatalf("ler testdata/zonas_v2/list_table.json: %v", err)
	}

	t.Run("sucesso agrega contadores pelo comment", func(t *testing.T) {
		exec := &fakeReconcileExec{
			readOut: map[string]string{
				"nft -j list table inet linkguard": string(jsonContent),
			},
		}
		s := NewService(exec)

		ctrs, err := s.ContadoresPorChave(ctx)
		if err != nil {
			t.Fatalf("ContadoresPorChave falhou: %v", err)
		}

		// s:ping: 1 regra com 15 pacotes, 1260 bytes
		cPing, ok := ctrs["s:ping"]
		if !ok {
			t.Fatalf("chave 's:ping' não encontrada nos contadores: %v", ctrs)
		}
		if !cPing.Medido || cPing.Pacotes != 15 || cPing.Bytes != 1260 {
			t.Errorf("s:ping: obtido %+v, esperava Medido=true, Pacotes=15, Bytes=1260", cPing)
		}

		// s:hosts-bloqueados: 2 regras somadas (10+5 = 15 pacotes, 600+300 = 900 bytes)
		cHosts, ok := ctrs["s:hosts-bloqueados"]
		if !ok {
			t.Fatalf("chave 's:hosts-bloqueados' não encontrada: %v", ctrs)
		}
		if !cHosts.Medido || cHosts.Pacotes != 15 || cHosts.Bytes != 900 {
			t.Errorf("s:hosts-bloqueados: obtido %+v, esperava Medido=true, Pacotes=15, Bytes=900", cHosts)
		}

		// r:uuid-casa: 1 regra com 100 pacotes, 8000 bytes
		cCasa, ok := ctrs["r:uuid-casa"]
		if !ok {
			t.Fatalf("chave 'r:uuid-casa' não encontrada: %v", ctrs)
		}
		if !cCasa.Medido || cCasa.Pacotes != 100 || cCasa.Bytes != 8000 {
			t.Errorf("r:uuid-casa: obtido %+v, esperava Medido=true, Pacotes=100, Bytes=8000", cCasa)
		}

		// regra-sem-contador: regra sem cláusula counter => Medido=false (a tela mostra "—")
		cSemCtr, ok := ctrs["regra-sem-contador"]
		if !ok {
			t.Fatalf("chave 'regra-sem-contador' não encontrada: %v", ctrs)
		}
		if cSemCtr.Medido {
			t.Errorf("regra-sem-contador: esperava Medido=false, obtido %+v", cSemCtr)
		}
	})

	t.Run("tabela inexistente devolve mapa vazio sem erro", func(t *testing.T) {
		exec := &fakeReconcileExec{
			readErr: errors.New("Error: No such file or directory"),
		}
		s := NewService(exec)

		ctrs, err := s.ContadoresPorChave(ctx)
		if err != nil {
			t.Fatalf("esperava nil para tabela inexistente, veio: %v", err)
		}
		if len(ctrs) != 0 {
			t.Fatalf("esperava mapa vazio, vieram %d entradas: %v", len(ctrs), ctrs)
		}
	})

	t.Run("dry-run devolve mapa vazio sem leituras", func(t *testing.T) {
		exec := &fakeReconcileExec{dryRun: true}
		s := NewService(exec)

		ctrs, err := s.ContadoresPorChave(ctx)
		if err != nil {
			t.Fatalf("dry-run falhou: %v", err)
		}
		if len(exec.reads) != 0 {
			t.Fatalf("dry-run não devia executar leituras: %v", exec.reads)
		}
		if len(ctrs) != 0 {
			t.Fatalf("esperava mapa vazio no dry-run, vieram %d entradas: %v", len(ctrs), ctrs)
		}
	})
}
