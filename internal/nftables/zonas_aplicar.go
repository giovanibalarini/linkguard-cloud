package nftables

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
)

// Contador representa as estatísticas de pacotes e bytes de regras com o mesmo comentário.
type Contador struct {
	Pacotes uint64 `json:"pacotes"`
	Bytes   uint64 `json:"bytes"`
	Medido  bool   `json:"medido"`
}

type nftablesJSON struct {
	Nftables []json.RawMessage `json:"nftables"`
}

type nftChainElement struct {
	Chain *struct {
		Family string `json:"family"`
		Table  string `json:"table"`
		Name   string `json:"name"`
	} `json:"chain"`
}

type nftSetElement struct {
	Set *struct {
		Family string `json:"family"`
		Table  string `json:"table"`
		Name   string `json:"name"`
	} `json:"set"`
}

type nftRuleElement struct {
	Rule *struct {
		Family  string            `json:"family"`
		Table   string            `json:"table"`
		Chain   string            `json:"chain"`
		Comment string            `json:"comment"`
		Expr    []json.RawMessage `json:"expr"`
	} `json:"rule"`
}

type nftExprCounterElement struct {
	Counter *struct {
		Packets uint64 `json:"packets"`
		Bytes   uint64 `json:"bytes"`
	} `json:"counter"`
}

// ObjetosExistentes lê o estado atual do kernel via `nft -j list table inet linkguard`
// e devolve as chains e sets existentes (usados na limpeza do legado após a troca atômica).
// Caso a tabela não exista, devolve Existentes{} sem erro.
func (s *Service) ObjetosExistentes(ctx context.Context) (Existentes, error) {
	if s.exec.IsDryRun() {
		return Existentes{}, nil
	}

	out, err := s.exec.ExecuteRead(ctx, "nft", "-j", "list", "table", Family, Table)
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "No such file or directory") ||
			strings.Contains(errStr, "does not exist") ||
			strings.Contains(errStr, "not found") {
			return Existentes{}, nil
		}
		return Existentes{}, fmt.Errorf("listar objetos existentes no nftables: %w", err)
	}

	return parseObjetosExistentesJSON([]byte(out))
}

func parseObjetosExistentesJSON(data []byte) (Existentes, error) {
	if len(strings.TrimSpace(string(data))) == 0 {
		return Existentes{}, nil
	}

	var root nftablesJSON
	if err := json.Unmarshal(data, &root); err != nil {
		return Existentes{}, fmt.Errorf("decodificar JSON do nftables: %w", err)
	}

	seenChains := make(map[string]bool)
	seenSets := make(map[string]bool)

	for _, item := range root.Nftables {
		var ch nftChainElement
		if err := json.Unmarshal(item, &ch); err == nil && ch.Chain != nil {
			if (ch.Chain.Table == "" || ch.Chain.Table == Table) && ch.Chain.Name != "" {
				seenChains[ch.Chain.Name] = true
			}
		}

		var st nftSetElement
		if err := json.Unmarshal(item, &st); err == nil && st.Set != nil {
			if (st.Set.Table == "" || st.Set.Table == Table) && st.Set.Name != "" {
				seenSets[st.Set.Name] = true
			}
		}
	}

	var chains []string
	for c := range seenChains {
		chains = append(chains, c)
	}
	sort.Strings(chains)

	var sets []string
	for st := range seenSets {
		sets = append(sets, st)
	}
	sort.Strings(sets)

	return Existentes{
		Chains: chains,
		Sets:   sets,
	}, nil
}

// TestarScript valida a sintaxe e semântica do script nftables completo através de `nft -c -f <arquivo>`.
// O script não é aplicado no kernel. Dry-run devolve nil.
func (s *Service) TestarScript(ctx context.Context, script string) error {
	if s.exec.IsDryRun() {
		return nil
	}

	f, err := os.CreateTemp("", "linkguard-nft-check-*.conf")
	if err != nil {
		return fmt.Errorf("criar arquivo temporário para validação: %w", err)
	}
	defer os.Remove(f.Name())

	if _, err := f.WriteString(script); err != nil {
		f.Close()
		return fmt.Errorf("escrever script de validação: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("fechar arquivo temporário de validação: %w", err)
	}

	if _, err := s.exec.ExecuteRead(ctx, "nft", "-c", "-f", f.Name()); err != nil {
		return err
	}
	return nil
}

// AplicarScript escreve o script atômico no kernel via `nft -f <arquivo>` e tenta persistir as regras
// em disco (s.Persist). Só o `nft -f` conta como falha: se ele passou, o ruleset já vale e um erro
// ao gravar o arquivo de boot fica em PersistState e no log. Adquire reconcileMu durante toda a
// operação. Dry-run devolve nil.
func (s *Service) AplicarScript(ctx context.Context, script string) error {
	s.reconcileMu.Lock()
	defer s.reconcileMu.Unlock()

	if s.exec.IsDryRun() {
		return nil
	}

	f, err := os.CreateTemp("", "linkguard-nft-apply-*.conf")
	if err != nil {
		return fmt.Errorf("criar arquivo temporário para aplicação: %w", err)
	}
	defer os.Remove(f.Name())

	if _, err := f.WriteString(script); err != nil {
		f.Close()
		return fmt.Errorf("escrever script de aplicação: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("fechar arquivo temporário de aplicação: %w", err)
	}

	if _, err := s.exec.Execute(ctx, "nft", "-f", f.Name()); err != nil {
		return err
	}

	if err := s.Persist(ctx); err != nil {
		slog.Warn("o ruleset entrou no kernel, mas o arquivo de boot não foi gravado", "err", err)
	}
	return nil
}

// ContadoresPorChave lê a tabela via `nft -j list table inet linkguard` e agrega pacotes e bytes
// de cada regra pelo seu comentário estável (`comment`). Se uma regra não tiver cláusula counter,
// Medido fica como false para que a interface mostre "—" em vez de 0.
func (s *Service) ContadoresPorChave(ctx context.Context) (map[string]Contador, error) {
	if s.exec.IsDryRun() {
		return make(map[string]Contador), nil
	}

	out, err := s.exec.ExecuteRead(ctx, "nft", "-j", "list", "table", Family, Table)
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "No such file or directory") ||
			strings.Contains(errStr, "does not exist") ||
			strings.Contains(errStr, "not found") {
			return make(map[string]Contador), nil
		}
		return nil, fmt.Errorf("ler contadores do nftables: %w", err)
	}

	return parseContadoresJSON([]byte(out))
}

func parseContadoresJSON(data []byte) (map[string]Contador, error) {
	contadores := make(map[string]Contador)
	if len(strings.TrimSpace(string(data))) == 0 {
		return contadores, nil
	}

	var root nftablesJSON
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("decodificar JSON do nftables: %w", err)
	}

	for _, item := range root.Nftables {
		var rElem nftRuleElement
		if err := json.Unmarshal(item, &rElem); err != nil || rElem.Rule == nil {
			continue
		}
		rule := rElem.Rule
		if rule.Comment == "" {
			continue
		}

		temCounter := false
		var pkt, bts uint64

		for _, exprRaw := range rule.Expr {
			var cElem nftExprCounterElement
			if err := json.Unmarshal(exprRaw, &cElem); err == nil && cElem.Counter != nil {
				temCounter = true
				pkt += cElem.Counter.Packets
				bts += cElem.Counter.Bytes
			}
		}

		atual, existe := contadores[rule.Comment]
		if !existe {
			atual = Contador{
				Pacotes: pkt,
				Bytes:   bts,
				Medido:  temCounter,
			}
		} else {
			atual.Pacotes += pkt
			atual.Bytes += bts
			if temCounter {
				atual.Medido = true
			}
		}
		contadores[rule.Comment] = atual
	}

	return contadores, nil
}
