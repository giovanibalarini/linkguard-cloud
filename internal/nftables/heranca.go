package nftables

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
)

// O que o multi-WAN deixou na tabela.
//
// A versão cloud não tem mais links, balanceamento nem direcionamento por
// host, e o código que escrevia estas estruturas saiu. Mas apagar código não
// apaga o kernel: numa caixa migrada do linkguard-fw as chains e o map
// continuam na tabela viva e no /etc/nftables.conf, e o nftables.service os
// recarrega a cada boot, antes de o LinkGuard subir. Ninguém mais os
// reconcilia, então eles ficariam para sempre marcando pacote por uma regra
// que ninguém lê.
//
// A ORDEM IMPORTA: mark_hosts consulta @host_wan, e o nft recusa apagar um map
// que uma regra ainda usa. As chains saem antes do map.
var herancaMultiWAN = []struct{ tipo, nome string }{
	{"chain", "mark_hosts"},
	{"chain", "conn_mark"},
	{"chain", "conn_mark_out"},
	{"chain", "output_mark"},
	{"map", "host_wan"},
}

// RemoverHerancaMultiWAN apaga da tabela as estruturas do multi-WAN que ainda
// estiverem lá, e devolve quantas apagou. Idempotente: numa caixa limpa não
// faz nada.
//
// O que não dá para ler é tratado como ausente, e não como erro: a pergunta é
// "existe?", e um `nft list` que falhou não é prova de que exista. Erro ao
// APAGAR algo que existe, esse sim volta — é uma estrutura velha que vai
// continuar valendo.
func (s *Service) RemoverHerancaMultiWAN(ctx context.Context) (int, error) {
	if s.exec.IsDryRun() {
		return 0, nil
	}
	removidos := 0
	for _, o := range herancaMultiWAN {
		if _, err := s.exec.ExecuteRead(ctx, "nft", "list", o.tipo, Family, Table, o.nome); err != nil {
			continue
		}
		if out, err := s.exec.Execute(ctx, "nft", "delete", o.tipo, Family, Table, o.nome); err != nil {
			return removidos, fmt.Errorf("apagar %s %s: %w (%s)", o.tipo, o.nome, err, strings.TrimSpace(out))
		}
		removidos++
	}
	if removidos > 0 {
		slog.Info("estruturas do multi-WAN removidas da tabela", "quantas", removidos)
		if err := s.Persist(ctx); err != nil {
			slog.Warn("estruturas do multi-WAN removidas, mas não foi possível persistir para o próximo boot", "err", err)
		}
	}
	return removidos, nil
}
