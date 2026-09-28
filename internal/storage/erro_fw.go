package storage

import (
	"errors"
	"fmt"
	"strings"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// TipoErroFW separa o que o pedido do operador provoca do que é falha do banco.
type TipoErroFW int

const (
	FWNaoEncontrado   TipoErroFW = iota + 1 // o objeto pedido não existe
	FWEmUso                                 // outros objetos ainda dependem dele
	FWConflito                              // o nome ou o identificador já pertence a outro objeto
	FWEntradaInvalida                       // o valor enviado não cabe no que a configuração aceita
)

// ErroFW é uma recusa esperada do repositório do firewall. A mensagem é a de
// sempre; o tipo é o que deixa a borda responder 404, 409 ou 400 em vez de
// tratar o pedido do operador como falha do servidor.
type ErroFW struct {
	Tipo   TipoErroFW
	Objeto string   // "regra", "alias", "agendamento", "encaminhamento", "revisão"
	ID     string   // do objeto a que a recusa se refere
	Campo  string   // em FWConflito: "nome" ou "id"
	Nome   string   // em FWConflito por nome: o nome recusado
	Outro  string   // em FWConflito por nome: o ID de quem já o ocupa
	Usos   []string // em FWEmUso: quem ainda depende do objeto
	Msg    string
	Err    error // a causa técnica, quando veio do banco
}

func (e *ErroFW) Error() string { return e.Msg }
func (e *ErroFW) Unwrap() error { return e.Err }

func fwNaoEncontrada(objeto, id string) error {
	return &ErroFW{Tipo: FWNaoEncontrado, Objeto: objeto, ID: id, Msg: fmt.Sprintf("%s %q não encontrada", objeto, id)}
}

func fwNaoEncontrado(objeto, id string) error {
	return &ErroFW{Tipo: FWNaoEncontrado, Objeto: objeto, ID: id, Msg: fmt.Sprintf("%s %q não encontrado", objeto, id)}
}

func fwEmUso(objeto, id string, usos []string) error {
	return &ErroFW{Tipo: FWEmUso, Objeto: objeto, ID: id, Usos: usos, Msg: fmt.Sprintf("%s %q em uso: %v", objeto, id, usos)}
}

func fwEntradaInvalida(objeto, id, msg string) error {
	return &ErroFW{Tipo: FWEntradaInvalida, Objeto: objeto, ID: id, Msg: msg}
}

// restricaoFW traduz a violação de restrição do SQLite numa recusa tipada;
// qualquer outro erro sai como entrou. tabelaNome é a tabela cujo nome_chave
// é UNIQUE ("" quando o objeto não tem nome único), e nome, o que se gravava.
func (db *DB) restricaoFW(err error, objeto, id, nome, tabelaNome string) error {
	var se *sqlite.Error
	if !errors.As(err, &se) {
		return err
	}
	switch se.Code() {
	case sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY:
		return &ErroFW{
			Tipo: FWConflito, Objeto: objeto, ID: id, Campo: "id", Err: err,
			Msg: fmt.Sprintf("já existe %s com o identificador %q", objeto, id),
		}
	case sqlite3.SQLITE_CONSTRAINT_UNIQUE:
		if tabelaNome == "" {
			return err
		}
		return &ErroFW{
			Tipo: FWConflito, Objeto: objeto, ID: id, Campo: "nome", Nome: nome,
			Outro: db.donoDoNomeFW(tabelaNome, nomeChaveFW(nome)), Err: err,
			Msg: fmt.Sprintf("já existe %s com o nome %q", objeto, nome),
		}
	case sqlite3.SQLITE_CONSTRAINT_CHECK:
		return &ErroFW{
			Tipo: FWEntradaInvalida, Objeto: objeto, ID: id, Err: err,
			Msg: fmt.Sprintf("%s %q tem um valor que o firewall não aceita (zona, ação, tipo ou protocolo desconhecido)", objeto, id),
		}
	}
	return err
}

// donoDoNomeFW devolve o ID de quem ocupa o nome; vazio se ninguém (ou se a consulta falhar).
// tabela vem sempre de uma constante do código, nunca do pedido.
func (db *DB) donoDoNomeFW(tabela, nomeChave string) string {
	var id string
	if err := db.conn.QueryRow(`SELECT id FROM `+tabela+` WHERE nome_chave = ?`, nomeChave).Scan(&id); err != nil {
		return ""
	}
	return id
}

// nomeChaveFW é a chave de unicidade do nome de alias e de agendamento: sem
// espaço nas pontas e sem diferença de caixa.
func nomeChaveFW(nome string) string { return strings.ToLower(strings.TrimSpace(nome)) }
