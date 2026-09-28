package storage_test

import (
	"testing"

	"github.com/giovanibalarini/linkguard-cloud/internal/fwmodel"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

func posicaoGravada(t *testing.T, db *storage.DB, tabela, id string) int {
	t.Helper()
	var pos int
	if err := db.Conn().QueryRow(`SELECT posicao FROM `+tabela+` WHERE id = ?`, id).Scan(&pos); err != nil {
		t.Fatalf("ler posição de %s em %s: %v", id, tabela, err)
	}
	return pos
}

// A posição de uma regra só muda por Reordenar (ou ao mudar de zona). Um PUT
// que traz `posicao` — ou que não a traz, o que em JSON vira 0 — não pode mexer
// na ordem: a ordem é o que decide qual regra vale primeiro.
func TestRepoFWAtualizarRegraNaoTomaAPosicaoDoCliente(t *testing.T) {
	db := newTestDB(t)
	for _, id := range []string{"a", "b", "c"} {
		r := regraDeTeste(id)
		if err := db.CriarRegraFW(&r); err != nil {
			t.Fatal(err)
		}
	}

	for _, doCliente := range []int{0, -1, 99, 2} {
		r := regraDeTeste("b")
		r.Descricao = "editada"
		r.Posicao = doCliente
		if err := db.AtualizarRegraFW(r); err != nil {
			t.Fatalf("AtualizarRegraFW com posicao=%d: %v", doCliente, err)
		}
		if got := posicaoGravada(t, db, "fw_regras", "b"); got != 1 {
			t.Errorf("posicao do cliente %d: a regra foi para a posição %d, devia continuar na 1", doCliente, got)
		}
	}

	if err := db.CriarRegraFW(&fwmodel.Regra{
		ID: "v", Zona: fwmodel.ZonaVCN, Ativa: true, Acao: fwmodel.AcaoAccept, Proto: fwmodel.ProtoTCP,
	}); err != nil {
		t.Fatal(err)
	}
	r := regraDeTeste("b")
	r.Zona = fwmodel.ZonaVCN
	r.Posicao = 0
	if err := db.AtualizarRegraFW(r); err != nil {
		t.Fatal(err)
	}
	if got := posicaoGravada(t, db, "fw_regras", "b"); got != 1 {
		t.Errorf("ao mudar de zona a regra vai para o fim da nova (posição 1), ficou na %d", got)
	}
}

func TestRepoFWAtualizarEncaminhamentoNaoTomaAPosicaoDoCliente(t *testing.T) {
	db := newTestDB(t)
	for _, id := range []string{"n1", "n2", "n3"} {
		e := encaminhamentoDeTeste(id)
		e.Nome = id
		e.PortaExterna = 8000 + len(id) + int(id[1])
		if err := db.CriarEncaminhamentoFW(&e); err != nil {
			t.Fatal(err)
		}
	}
	for _, doCliente := range []int{0, -1, 99} {
		e := encaminhamentoDeTeste("n2")
		e.Nome = "editado"
		e.PortaExterna = 9000
		e.Posicao = doCliente
		if err := db.AtualizarEncaminhamentoFW(e); err != nil {
			t.Fatalf("AtualizarEncaminhamentoFW com posicao=%d: %v", doCliente, err)
		}
		if got := posicaoGravada(t, db, "fw_encaminhamentos", "n2"); got != 1 {
			t.Errorf("posicao do cliente %d: o encaminhamento foi para a posição %d, devia continuar na 1", doCliente, got)
		}
	}
}
