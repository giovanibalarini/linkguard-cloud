package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/giovanibalarini/linkguard-cloud/internal/fwmodel"
)

// RevisaoFW representa o cabeçalho de uma revisão gravada do firewall (sem o JSON completo da configuração).
type RevisaoFW struct {
	ID          string `json:"id"`
	Resumo      string `json:"resumo"`
	Motivo      string `json:"motivo"`
	AplicadoEm  int64  `json:"aplicado_em"`
	AplicadoPor string `json:"aplicado_por"`
}

// CarregarConfigEmEdicao carrega a configuração em edição a partir das tabelas fw_*.
// Se fw_ajustes estiver ausente, inicializa com fwmodel.AjustesPadrao().
func (db *DB) CarregarConfigEmEdicao() (fwmodel.Config, error) {
	c := fwmodel.Config{
		Formato: 1,
	}

	// 1. Regras
	rowsR, err := db.conn.Query(`
		SELECT id, zona, posicao, ativa, acao, proto,
		       origem_tipo, origem_valor, destino_tipo, destino_valor,
		       porta_tipo, porta_valor, agendamento_id, registrar, descricao
		FROM fw_regras
		ORDER BY CASE zona
		             WHEN 'flutuante' THEN 1
		             WHEN 'internet' THEN 2
		             WHEN 'vcn' THEN 3
		             WHEN 'vpn' THEN 4
		             ELSE 5
		         END, posicao ASC, id ASC`)
	if err != nil {
		return c, fmt.Errorf("carregar fw_regras: %w", err)
	}
	defer rowsR.Close()

	for rowsR.Next() {
		var r fwmodel.Regra
		var ativaInt, regInt int
		if err := rowsR.Scan(
			&r.ID, &r.Zona, &r.Posicao, &ativaInt, &r.Acao, &r.Proto,
			&r.Origem.Tipo, &r.Origem.Valor, &r.Destino.Tipo, &r.Destino.Valor,
			&r.PortaDestino.Tipo, &r.PortaDestino.Valor, &r.AgendamentoID, &regInt, &r.Descricao,
		); err != nil {
			return c, fmt.Errorf("ler linha fw_regras: %w", err)
		}
		r.Ativa = ativaInt == 1
		r.Registrar = regInt == 1
		c.Regras = append(c.Regras, r)
	}

	// 2. Aliases
	rowsA, err := db.conn.Query(`
		SELECT id, nome, tipo, descricao, itens
		FROM fw_aliases
		ORDER BY id ASC`)
	if err != nil {
		return c, fmt.Errorf("carregar fw_aliases: %w", err)
	}
	defer rowsA.Close()

	for rowsA.Next() {
		var a fwmodel.Alias
		var itensRaw string
		if err := rowsA.Scan(&a.ID, &a.Nome, &a.Tipo, &a.Descricao, &itensRaw); err != nil {
			return c, fmt.Errorf("ler linha fw_aliases: %w", err)
		}
		if itensRaw != "" {
			_ = json.Unmarshal([]byte(itensRaw), &a.Itens)
		}
		if a.Itens == nil {
			a.Itens = []string{}
		}
		c.Aliases = append(c.Aliases, a)
	}

	// 3. Agendamentos
	rowsAg, err := db.conn.Query(`
		SELECT id, nome, descricao, dias, inicio, fim
		FROM fw_agendamentos
		ORDER BY id ASC`)
	if err != nil {
		return c, fmt.Errorf("carregar fw_agendamentos: %w", err)
	}
	defer rowsAg.Close()

	for rowsAg.Next() {
		var ag fwmodel.Agendamento
		if err := rowsAg.Scan(&ag.ID, &ag.Nome, &ag.Descricao, &ag.Dias, &ag.Inicio, &ag.Fim); err != nil {
			return c, fmt.Errorf("ler linha fw_agendamentos: %w", err)
		}
		c.Agendamentos = append(c.Agendamentos, ag)
	}

	// 4. Encaminhamentos
	rowsEnc, err := db.conn.Query(`
		SELECT id, nome, ativo, proto, porta_externa, ip_destino, porta_destino, posicao
		FROM fw_encaminhamentos
		ORDER BY posicao ASC, id ASC`)
	if err != nil {
		return c, fmt.Errorf("carregar fw_encaminhamentos: %w", err)
	}
	defer rowsEnc.Close()

	for rowsEnc.Next() {
		var enc fwmodel.Encaminhamento
		var ativoInt int
		if err := rowsEnc.Scan(
			&enc.ID, &enc.Nome, &ativoInt, &enc.Proto,
			&enc.PortaExterna, &enc.IPDestino, &enc.PortaDestino, &enc.Posicao,
		); err != nil {
			return c, fmt.Errorf("ler linha fw_encaminhamentos: %w", err)
		}
		enc.Ativo = ativoInt == 1
		c.Encaminhamentos = append(c.Encaminhamentos, enc)
	}

	// 5. Ajustes
	var ajustesRaw string
	err = db.conn.QueryRow(`SELECT ajustes FROM fw_ajustes WHERE only_row = 1`).Scan(&ajustesRaw)
	if err != nil {
		if err == sql.ErrNoRows {
			c.Ajustes = fwmodel.AjustesPadrao()
		} else {
			return c, fmt.Errorf("carregar fw_ajustes: %w", err)
		}
	} else {
		if err := json.Unmarshal([]byte(ajustesRaw), &c.Ajustes); err != nil {
			c.Ajustes = fwmodel.AjustesPadrao()
		}
	}

	return fwmodel.Normalizar(c), nil
}

// SubstituirConfigEmEdicao substitui em transação todas as 5 partes da configuração em edição.
func (db *DB) SubstituirConfigEmEdicao(c fwmodel.Config) error {
	tx, err := db.conn.Begin()
	if err != nil {
		return fmt.Errorf("iniciar transação SubstituirConfigEmEdicao: %w", err)
	}
	defer tx.Rollback()

	if err := db.substituirConfigEmEdicaoTx(tx, c); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *DB) substituirConfigEmEdicaoTx(tx *sql.Tx, c fwmodel.Config) error {
	norm := fwmodel.Normalizar(c)

	if _, err := tx.Exec(`DELETE FROM fw_regras`); err != nil {
		return fmt.Errorf("limpar fw_regras: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM fw_aliases`); err != nil {
		return fmt.Errorf("limpar fw_aliases: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM fw_agendamentos`); err != nil {
		return fmt.Errorf("limpar fw_agendamentos: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM fw_encaminhamentos`); err != nil {
		return fmt.Errorf("limpar fw_encaminhamentos: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM fw_ajustes`); err != nil {
		return fmt.Errorf("limpar fw_ajustes: %w", err)
	}

	// Grava Ajustes
	ajustesJSON, err := json.Marshal(norm.Ajustes)
	if err != nil {
		return fmt.Errorf("serializar ajustes: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO fw_ajustes (only_row, ajustes) VALUES (1, ?)`, string(ajustesJSON)); err != nil {
		return fmt.Errorf("gravar fw_ajustes: %w", err)
	}

	// Grava Aliases
	stmtAl, err := tx.Prepare(`
		INSERT INTO fw_aliases (id, nome, nome_chave, tipo, descricao, itens)
		VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("preparar insert fw_aliases: %w", err)
	}
	defer stmtAl.Close()

	for _, a := range norm.Aliases {
		nomeChave := nomeChaveFW(a.Nome)
		itensJSON, _ := json.Marshal(a.Itens)
		if _, err := stmtAl.Exec(a.ID, a.Nome, nomeChave, string(a.Tipo), a.Descricao, string(itensJSON)); err != nil {
			return fmt.Errorf("gravar alias %q: %w", a.ID, err)
		}
	}

	// Grava Agendamentos
	stmtAg, err := tx.Prepare(`
		INSERT INTO fw_agendamentos (id, nome, nome_chave, descricao, dias, inicio, fim)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("preparar insert fw_agendamentos: %w", err)
	}
	defer stmtAg.Close()

	for _, ag := range norm.Agendamentos {
		nomeChave := nomeChaveFW(ag.Nome)
		if _, err := stmtAg.Exec(ag.ID, ag.Nome, nomeChave, ag.Descricao, ag.Dias, ag.Inicio, ag.Fim); err != nil {
			return fmt.Errorf("gravar agendamento %q: %w", ag.ID, err)
		}
	}

	// Grava Encaminhamentos
	stmtEnc, err := tx.Prepare(`
		INSERT INTO fw_encaminhamentos (id, nome, ativo, proto, porta_externa, ip_destino, porta_destino, posicao)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("preparar insert fw_encaminhamentos: %w", err)
	}
	defer stmtEnc.Close()

	for _, enc := range norm.Encaminhamentos {
		ativoInt := 0
		if enc.Ativo {
			ativoInt = 1
		}
		if _, err := stmtEnc.Exec(
			enc.ID, enc.Nome, ativoInt, enc.Proto,
			enc.PortaExterna, enc.IPDestino, enc.PortaDestino, enc.Posicao,
		); err != nil {
			return fmt.Errorf("gravar encaminhamento %q: %w", enc.ID, err)
		}
	}

	// Grava Regras
	stmtR, err := tx.Prepare(`
		INSERT INTO fw_regras (
			id, zona, posicao, ativa, acao, proto,
			origem_tipo, origem_valor, destino_tipo, destino_valor,
			porta_tipo, porta_valor, agendamento_id, registrar, descricao
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("preparar insert fw_regras: %w", err)
	}
	defer stmtR.Close()

	for _, r := range norm.Regras {
		ativaInt := 0
		if r.Ativa {
			ativaInt = 1
		}
		regInt := 0
		if r.Registrar {
			regInt = 1
		}
		if _, err := stmtR.Exec(
			r.ID, string(r.Zona), r.Posicao, ativaInt, string(r.Acao), string(r.Proto),
			string(r.Origem.Tipo), r.Origem.Valor, string(r.Destino.Tipo), r.Destino.Valor,
			string(r.PortaDestino.Tipo), r.PortaDestino.Valor, r.AgendamentoID, regInt, r.Descricao,
		); err != nil {
			return fmt.Errorf("gravar regra %q: %w", r.ID, err)
		}
	}

	return nil
}

// CarregarConfigAplicada carrega a última configuração aplicada registrada em fw_aplicado.
func (db *DB) CarregarConfigAplicada() (c fwmodel.Config, existe bool, err error) {
	var rawConfig string
	err = db.conn.QueryRow(`SELECT config FROM fw_aplicado WHERE only_row = 1`).Scan(&rawConfig)
	if err != nil {
		if err == sql.ErrNoRows {
			return fwmodel.Config{}, false, nil
		}
		return fwmodel.Config{}, false, fmt.Errorf("carregar fw_aplicado: %w", err)
	}

	if err := json.Unmarshal([]byte(rawConfig), &c); err != nil {
		return fwmodel.Config{}, false, fmt.Errorf("decodificar fw_aplicado config: %w", err)
	}

	return fwmodel.Normalizar(c), true, nil
}

// CarregarMetadadosAplicada devolve a data/hora (unix timestamp) e o usuário que aplicou a configuração.
func (db *DB) CarregarMetadadosAplicada() (aplicadoEm int64, aplicadoPor string, existe bool, err error) {
	err = db.conn.QueryRow(`SELECT aplicado_em, aplicado_por FROM fw_aplicado WHERE only_row = 1`).Scan(&aplicadoEm, &aplicadoPor)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, "", false, nil
		}
		return 0, "", false, fmt.Errorf("carregar metadados fw_aplicado: %w", err)
	}
	return aplicadoEm, aplicadoPor, true, nil
}

// SalvarAplicadaERevisao grava em transação a configuração aplicada, gera uma revisão no histórico
// e poda o histórico de revisões para manter no máximo 30 registros.
func (db *DB) SalvarAplicadaERevisao(c fwmodel.Config, por, resumo, motivo string, agora time.Time) error {
	norm := fwmodel.Normalizar(c)
	canonico := string(fwmodel.Canonico(norm))
	unixSec := agora.Unix()

	tx, err := db.conn.Begin()
	if err != nil {
		return fmt.Errorf("iniciar transação SalvarAplicadaERevisao: %w", err)
	}
	defer tx.Rollback()

	// 1. Atualiza fw_aplicado
	if _, err := tx.Exec(`
		INSERT INTO fw_aplicado (only_row, config, aplicado_em, aplicado_por)
		VALUES (1, ?, ?, ?)
		ON CONFLICT(only_row) DO UPDATE SET
			config = excluded.config,
			aplicado_em = excluded.aplicado_em,
			aplicado_por = excluded.aplicado_por`,
		canonico, unixSec, por,
	); err != nil {
		return fmt.Errorf("gravar fw_aplicado: %w", err)
	}

	// 2. Insere revisão
	revisaoID := uuid.NewString()
	if _, err := tx.Exec(`
		INSERT INTO fw_revisoes (id, config, resumo, motivo, aplicado_em, aplicado_por)
		VALUES (?, ?, ?, ?, ?, ?)`,
		revisaoID, canonico, resumo, motivo, unixSec, por,
	); err != nil {
		return fmt.Errorf("gravar fw_revisoes: %w", err)
	}

	// 3. Poda revisões antigas mantendo no máximo 30
	if _, err := tx.Exec(`
		DELETE FROM fw_revisoes
		WHERE id NOT IN (
			SELECT id FROM fw_revisoes
			ORDER BY aplicado_em DESC, rowid DESC
			LIMIT 30
		)`); err != nil {
		return fmt.Errorf("podar fw_revisoes para 30: %w", err)
	}

	return tx.Commit()
}

// ListarRevisoes lista os metadados das revisões no histórico (sem o corpo da configuração).
func (db *DB) ListarRevisoes(limite int) ([]RevisaoFW, error) {
	if limite <= 0 {
		limite = 30
	}

	rows, err := db.conn.Query(`
		SELECT id, resumo, motivo, aplicado_em, aplicado_por
		FROM fw_revisoes
		ORDER BY aplicado_em DESC, rowid DESC
		LIMIT ?`, limite)
	if err != nil {
		return nil, fmt.Errorf("listar revisões: %w", err)
	}
	defer rows.Close()

	var revs []RevisaoFW
	for rows.Next() {
		var r RevisaoFW
		if err := rows.Scan(&r.ID, &r.Resumo, &r.Motivo, &r.AplicadoEm, &r.AplicadoPor); err != nil {
			return nil, fmt.Errorf("ler linha revisão: %w", err)
		}
		revs = append(revs, r)
	}
	if revs == nil {
		revs = []RevisaoFW{}
	}
	return revs, nil
}

// CarregarRevisao recupera a configuração completa guardada numa revisão específica.
func (db *DB) CarregarRevisao(id string) (fwmodel.Config, error) {
	var rawConfig string
	err := db.conn.QueryRow(`SELECT config FROM fw_revisoes WHERE id = ?`, id).Scan(&rawConfig)
	if err != nil {
		if err == sql.ErrNoRows {
			return fwmodel.Config{}, fwNaoEncontrada("revisão", id)
		}
		return fwmodel.Config{}, fmt.Errorf("carregar revisão %q: %w", id, err)
	}

	var c fwmodel.Config
	if err := json.Unmarshal([]byte(rawConfig), &c); err != nil {
		return fwmodel.Config{}, fmt.Errorf("decodificar config da revisão: %w", err)
	}

	return fwmodel.Normalizar(c), nil
}

// CriarRegraFW adiciona uma regra na configuração em edição no fim da zona (posicao = MAX(posicao)+1).
func (db *DB) CriarRegraFW(r *fwmodel.Regra) error {
	if r.ID == "" {
		r.ID = uuid.NewString()
	}

	var maxPos int
	err := db.conn.QueryRow(`
		SELECT COALESCE(MAX(posicao), -1)
		FROM fw_regras
		WHERE zona = ?`, string(r.Zona)).Scan(&maxPos)
	if err != nil {
		return fmt.Errorf("calcular posição da nova regra: %w", err)
	}
	r.Posicao = maxPos + 1

	ativaInt := 0
	if r.Ativa {
		ativaInt = 1
	}
	regInt := 0
	if r.Registrar {
		regInt = 1
	}

	_, err = db.conn.Exec(`
		INSERT INTO fw_regras (
			id, zona, posicao, ativa, acao, proto,
			origem_tipo, origem_valor, destino_tipo, destino_valor,
			porta_tipo, porta_valor, agendamento_id, registrar, descricao
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, string(r.Zona), r.Posicao, ativaInt, string(r.Acao), string(r.Proto),
		string(r.Origem.Tipo), r.Origem.Valor, string(r.Destino.Tipo), r.Destino.Valor,
		string(r.PortaDestino.Tipo), r.PortaDestino.Valor, r.AgendamentoID, regInt, r.Descricao,
	)
	if err != nil {
		return db.restricaoFW(fmt.Errorf("inserir fw_regras: %w", err), "regra", r.ID, "", "")
	}
	return nil
}

// AtualizarRegraFW atualiza os campos de uma regra existente. A posição não é
// dela (só ReordenarRegrasFW a muda): se a zona mudou, a regra vai para o fim da nova.
func (db *DB) AtualizarRegraFW(r fwmodel.Regra) error {
	var zonaAtual string
	var posAtual int
	err := db.conn.QueryRow(`SELECT zona, posicao FROM fw_regras WHERE id = ?`, r.ID).Scan(&zonaAtual, &posAtual)
	if err != nil {
		if err == sql.ErrNoRows {
			return fwNaoEncontrada("regra", r.ID)
		}
		return fmt.Errorf("consultar regra %q: %w", r.ID, err)
	}

	posicao := posAtual
	if zonaAtual != string(r.Zona) {
		var maxPos int
		err := db.conn.QueryRow(`
			SELECT COALESCE(MAX(posicao), -1)
			FROM fw_regras
			WHERE zona = ?`, string(r.Zona)).Scan(&maxPos)
		if err != nil {
			return fmt.Errorf("calcular nova posição na zona %q: %w", r.Zona, err)
		}
		posicao = maxPos + 1
	}

	ativaInt := 0
	if r.Ativa {
		ativaInt = 1
	}
	regInt := 0
	if r.Registrar {
		regInt = 1
	}

	_, err = db.conn.Exec(`
		UPDATE fw_regras SET
			zona = ?, posicao = ?, ativa = ?, acao = ?, proto = ?,
			origem_tipo = ?, origem_valor = ?, destino_tipo = ?, destino_valor = ?,
			porta_tipo = ?, porta_valor = ?, agendamento_id = ?, registrar = ?,
			descricao = ?, atualizada_em = CURRENT_TIMESTAMP
		WHERE id = ?`,
		string(r.Zona), posicao, ativaInt, string(r.Acao), string(r.Proto),
		string(r.Origem.Tipo), r.Origem.Valor, string(r.Destino.Tipo), r.Destino.Valor,
		string(r.PortaDestino.Tipo), r.PortaDestino.Valor, r.AgendamentoID, regInt,
		r.Descricao, r.ID,
	)
	if err != nil {
		return db.restricaoFW(fmt.Errorf("atualizar fw_regras: %w", err), "regra", r.ID, "", "")
	}
	return nil
}

// ApagarRegraFW remove uma regra da configuração em edição.
func (db *DB) ApagarRegraFW(id string) error {
	res, err := db.conn.Exec(`DELETE FROM fw_regras WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("apagar fw_regras: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fwNaoEncontrada("regra", id)
	}
	return nil
}

// AtivarRegraFW liga ou desliga uma regra na configuração em edição.
func (db *DB) AtivarRegraFW(id string, ativa bool) error {
	ativaInt := 0
	if ativa {
		ativaInt = 1
	}
	res, err := db.conn.Exec(`
		UPDATE fw_regras
		SET ativa = ?, atualizada_em = CURRENT_TIMESTAMP
		WHERE id = ?`, ativaInt, id)
	if err != nil {
		return fmt.Errorf("ativar/desativar regra: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fwNaoEncontrada("regra", id)
	}
	return nil
}

// DuplicarRegraFW duplica uma regra existente, posicionando a nova regra logo abaixo da original.
func (db *DB) DuplicarRegraFW(id string) (*fwmodel.Regra, error) {
	tx, err := db.conn.Begin()
	if err != nil {
		return nil, fmt.Errorf("iniciar transação DuplicarRegraFW: %w", err)
	}
	defer tx.Rollback()

	var r fwmodel.Regra
	var ativaInt, regInt int
	var origTipo, origVal, destTipo, destVal, portaTipo, portaVal, agID sql.NullString
	err = tx.QueryRow(`
		SELECT id, zona, posicao, ativa, acao, proto,
		       origem_tipo, origem_valor, destino_tipo, destino_valor,
		       porta_tipo, porta_valor, agendamento_id, registrar, descricao
		FROM fw_regras
		WHERE id = ?`, id,
	).Scan(
		&r.ID, &r.Zona, &r.Posicao, &ativaInt, &r.Acao, &r.Proto,
		&origTipo, &origVal, &destTipo, &destVal,
		&portaTipo, &portaVal, &agID, &regInt, &r.Descricao,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fwNaoEncontrada("regra", id)
		}
		return nil, fmt.Errorf("consultar regra para duplicar: %w", err)
	}

	r.Ativa = ativaInt == 1
	r.Registrar = regInt == 1
	r.Origem = fwmodel.Ponta{Tipo: fwmodel.PontaTipo(origTipo.String), Valor: origVal.String}
	r.Destino = fwmodel.Ponta{Tipo: fwmodel.PontaTipo(destTipo.String), Valor: destVal.String}
	r.PortaDestino = fwmodel.Porta{Tipo: fwmodel.PortaTipo(portaTipo.String), Valor: portaVal.String}
	r.AgendamentoID = agID.String

	novaPosicao := r.Posicao + 1
	_, err = tx.Exec(`
		UPDATE fw_regras
		SET posicao = posicao + 1
		WHERE zona = ? AND posicao >= ?`,
		string(r.Zona), novaPosicao,
	)
	if err != nil {
		return nil, fmt.Errorf("deslocar posições para duplicar regra: %w", err)
	}

	r.ID = uuid.NewString()
	r.Posicao = novaPosicao
	if r.Descricao != "" {
		// A cópia de uma regra de descrição longa não pode nascer inválida.
		desc := []rune("Cópia de " + r.Descricao)
		if len(desc) > fwmodel.MaxDescricaoRegra {
			desc = desc[:fwmodel.MaxDescricaoRegra]
		}
		r.Descricao = string(desc)
	} else {
		r.Descricao = "Cópia"
	}

	rAtivaInt := 0
	if r.Ativa {
		rAtivaInt = 1
	}
	rRegInt := 0
	if r.Registrar {
		rRegInt = 1
	}

	_, err = tx.Exec(`
		INSERT INTO fw_regras (
			id, zona, posicao, ativa, acao, proto,
			origem_tipo, origem_valor, destino_tipo, destino_valor,
			porta_tipo, porta_valor, agendamento_id, registrar, descricao
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.ID, string(r.Zona), r.Posicao, rAtivaInt, string(r.Acao), string(r.Proto),
		string(r.Origem.Tipo), r.Origem.Valor, string(r.Destino.Tipo), r.Destino.Valor,
		string(r.PortaDestino.Tipo), r.PortaDestino.Valor, r.AgendamentoID, rRegInt, r.Descricao,
	)
	if err != nil {
		return nil, fmt.Errorf("inserir cópia da regra: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("comitar transação DuplicarRegraFW: %w", err)
	}

	return &r, nil
}

// ReordenarRegrasFW altera as posições das regras de uma zona, exigindo a lista completa de IDs da zona.
func (db *DB) ReordenarRegrasFW(zona fwmodel.Zona, ids []string) error {
	rows, err := db.conn.Query(`SELECT id FROM fw_regras WHERE zona = ?`, string(zona))
	if err != nil {
		return fmt.Errorf("consultar regras da zona %q: %w", zona, err)
	}
	defer rows.Close()

	existentes := make(map[string]bool)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return fmt.Errorf("ler id da regra: %w", err)
		}
		existentes[id] = true
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("ler as regras da zona %q: %w", zona, err)
	}

	if len(existentes) != len(ids) {
		return fwEntradaInvalida("regra", "", fmt.Sprintf("a reordenação exige a lista completa das regras da zona (%d esperadas, %d fornecidas)", len(existentes), len(ids)))
	}
	vistos := make(map[string]bool, len(ids))
	for _, id := range ids {
		if !existentes[id] {
			return fwEntradaInvalida("regra", id, fmt.Sprintf("id %q não pertence à zona %q", id, zona))
		}
		if vistos[id] {
			return fwEntradaInvalida("regra", id, fmt.Sprintf("id %q repetido na lista da zona %q", id, zona))
		}
		vistos[id] = true
	}

	tx, err := db.conn.Begin()
	if err != nil {
		return fmt.Errorf("iniciar transação de reordenação: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`UPDATE fw_regras SET posicao = ?, atualizada_em = CURRENT_TIMESTAMP WHERE id = ?`)
	if err != nil {
		return fmt.Errorf("preparar update de posição: %w", err)
	}
	defer stmt.Close()

	for pos, id := range ids {
		if _, err := stmt.Exec(pos, id); err != nil {
			return fmt.Errorf("reordenar regra %q: %w", id, err)
		}
	}

	return tx.Commit()
}

// CriarAliasFW adiciona um alias à configuração em edição.
func (db *DB) CriarAliasFW(a *fwmodel.Alias) error {
	if a.ID == "" {
		a.ID = uuid.NewString()
	}
	nomeChave := nomeChaveFW(a.Nome)
	itensJSON, err := json.Marshal(a.Itens)
	if err != nil {
		return fmt.Errorf("serializar itens do alias: %w", err)
	}

	_, err = db.conn.Exec(`
		INSERT INTO fw_aliases (id, nome, nome_chave, tipo, descricao, itens)
		VALUES (?, ?, ?, ?, ?, ?)`,
		a.ID, a.Nome, nomeChave, string(a.Tipo), a.Descricao, string(itensJSON),
	)
	if err != nil {
		return db.restricaoFW(fmt.Errorf("inserir fw_aliases: %w", err), "alias", a.ID, a.Nome, "fw_aliases")
	}
	return nil
}

// AtualizarAliasFW atualiza um alias existente na configuração em edição.
func (db *DB) AtualizarAliasFW(a fwmodel.Alias) error {
	nomeChave := nomeChaveFW(a.Nome)
	itensJSON, err := json.Marshal(a.Itens)
	if err != nil {
		return fmt.Errorf("serializar itens do alias: %w", err)
	}

	res, err := db.conn.Exec(`
		UPDATE fw_aliases SET
			nome = ?, nome_chave = ?, tipo = ?, descricao = ?, itens = ?, atualizado_em = CURRENT_TIMESTAMP
		WHERE id = ?`,
		a.Nome, nomeChave, string(a.Tipo), a.Descricao, string(itensJSON), a.ID,
	)
	if err != nil {
		return db.restricaoFW(fmt.Errorf("atualizar fw_aliases: %w", err), "alias", a.ID, a.Nome, "fw_aliases")
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fwNaoEncontrado("alias", a.ID)
	}
	return nil
}

// ApagarAliasFW remove um alias da configuração em edição, recusando se estiver em uso.
func (db *DB) ApagarAliasFW(id string) error {
	usos, err := db.UsosDoAlias(id)
	if err != nil {
		return fmt.Errorf("verificar usos do alias %q: %w", id, err)
	}
	if len(usos) > 0 {
		return fwEmUso("alias", id, usos)
	}

	res, err := db.conn.Exec(`DELETE FROM fw_aliases WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("apagar fw_aliases: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fwNaoEncontrado("alias", id)
	}
	return nil
}

// CriarAgendamentoFW adiciona um agendamento à configuração em edição.
func (db *DB) CriarAgendamentoFW(ag *fwmodel.Agendamento) error {
	if ag.ID == "" {
		ag.ID = uuid.NewString()
	}
	nomeChave := nomeChaveFW(ag.Nome)

	_, err := db.conn.Exec(`
		INSERT INTO fw_agendamentos (id, nome, nome_chave, descricao, dias, inicio, fim)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ag.ID, ag.Nome, nomeChave, ag.Descricao, ag.Dias, ag.Inicio, ag.Fim,
	)
	if err != nil {
		return db.restricaoFW(fmt.Errorf("inserir fw_agendamentos: %w", err), "agendamento", ag.ID, ag.Nome, "fw_agendamentos")
	}
	return nil
}

// AtualizarAgendamentoFW atualiza um agendamento existente na configuração em edição.
func (db *DB) AtualizarAgendamentoFW(ag fwmodel.Agendamento) error {
	nomeChave := nomeChaveFW(ag.Nome)

	res, err := db.conn.Exec(`
		UPDATE fw_agendamentos SET
			nome = ?, nome_chave = ?, descricao = ?, dias = ?, inicio = ?, fim = ?, atualizado_em = CURRENT_TIMESTAMP
		WHERE id = ?`,
		ag.Nome, nomeChave, ag.Descricao, ag.Dias, ag.Inicio, ag.Fim, ag.ID,
	)
	if err != nil {
		return db.restricaoFW(fmt.Errorf("atualizar fw_agendamentos: %w", err), "agendamento", ag.ID, ag.Nome, "fw_agendamentos")
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fwNaoEncontrado("agendamento", ag.ID)
	}
	return nil
}

// ApagarAgendamentoFW remove um agendamento da configuração em edição, recusando se estiver em uso.
func (db *DB) ApagarAgendamentoFW(id string) error {
	usos, err := db.UsosDoAgendamento(id)
	if err != nil {
		return fmt.Errorf("verificar usos do agendamento %q: %w", id, err)
	}
	if len(usos) > 0 {
		return fwEmUso("agendamento", id, usos)
	}

	res, err := db.conn.Exec(`DELETE FROM fw_agendamentos WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("apagar fw_agendamentos: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fwNaoEncontrado("agendamento", id)
	}
	return nil
}

// CriarEncaminhamentoFW adiciona um encaminhamento DNAT à configuração em edição.
func (db *DB) CriarEncaminhamentoFW(enc *fwmodel.Encaminhamento) error {
	if enc.ID == "" {
		enc.ID = uuid.NewString()
	}

	var maxPos int
	err := db.conn.QueryRow(`SELECT COALESCE(MAX(posicao), -1) FROM fw_encaminhamentos`).Scan(&maxPos)
	if err != nil {
		return fmt.Errorf("calcular posição do encaminhamento: %w", err)
	}
	enc.Posicao = maxPos + 1

	ativoInt := 0
	if enc.Ativo {
		ativoInt = 1
	}

	_, err = db.conn.Exec(`
		INSERT INTO fw_encaminhamentos (id, nome, ativo, proto, porta_externa, ip_destino, porta_destino, posicao)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		enc.ID, enc.Nome, ativoInt, enc.Proto, enc.PortaExterna, enc.IPDestino, enc.PortaDestino, enc.Posicao,
	)
	if err != nil {
		return db.restricaoFW(fmt.Errorf("inserir fw_encaminhamentos: %w", err), "encaminhamento", enc.ID, "", "")
	}
	return nil
}

// AtualizarEncaminhamentoFW atualiza um encaminhamento DNAT existente na configuração em edição.
func (db *DB) AtualizarEncaminhamentoFW(enc fwmodel.Encaminhamento) error {
	ativoInt := 0
	if enc.Ativo {
		ativoInt = 1
	}

	res, err := db.conn.Exec(`
		UPDATE fw_encaminhamentos SET
			nome = ?, ativo = ?, proto = ?, porta_externa = ?, ip_destino = ?, porta_destino = ?,
			atualizado_em = CURRENT_TIMESTAMP
		WHERE id = ?`,
		enc.Nome, ativoInt, enc.Proto, enc.PortaExterna, enc.IPDestino, enc.PortaDestino, enc.ID,
	)
	if err != nil {
		return db.restricaoFW(fmt.Errorf("atualizar fw_encaminhamentos: %w", err), "encaminhamento", enc.ID, "", "")
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fwNaoEncontrado("encaminhamento", enc.ID)
	}
	return nil
}

// ApagarEncaminhamentoFW remove um encaminhamento DNAT da configuração em edição.
func (db *DB) ApagarEncaminhamentoFW(id string) error {
	res, err := db.conn.Exec(`DELETE FROM fw_encaminhamentos WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("apagar fw_encaminhamentos: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fwNaoEncontrado("encaminhamento", id)
	}
	return nil
}

// AtivarEncaminhamentoFW ativa ou desativa um encaminhamento DNAT existente.
func (db *DB) AtivarEncaminhamentoFW(id string, ativo bool) error {
	ativoInt := 0
	if ativo {
		ativoInt = 1
	}
	res, err := db.conn.Exec(`UPDATE fw_encaminhamentos SET ativo = ?, atualizado_em = CURRENT_TIMESTAMP WHERE id = ?`, ativoInt, id)
	if err != nil {
		return fmt.Errorf("ativar/desativar encaminhamento %q: %w", id, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fwNaoEncontrado("encaminhamento", id)
	}
	return nil
}

// SalvarAjustesFW atualiza os ajustes globais do firewall na configuração em edição.
func (db *DB) SalvarAjustesFW(a fwmodel.Ajustes) error {
	ajustesJSON, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("serializar ajustes: %w", err)
	}

	_, err = db.conn.Exec(`
		INSERT INTO fw_ajustes (only_row, ajustes)
		VALUES (1, ?)
		ON CONFLICT(only_row) DO UPDATE SET ajustes = excluded.ajustes`,
		string(ajustesJSON),
	)
	if err != nil {
		return fmt.Errorf("salvar fw_ajustes: %w", err)
	}
	return nil
}

// UsosDoAlias pesquisa referências a um determinado alias em regras do firewall e em perfis de acesso da VPN.
func (db *DB) UsosDoAlias(id string) ([]string, error) {
	var usos []string

	// 1. Uso em regras do firewall
	rowsR, err := db.conn.Query(`
		SELECT id, descricao, zona
		FROM fw_regras
		WHERE (origem_tipo = 'alias' AND origem_valor = ?)
		   OR (destino_tipo = 'alias' AND destino_valor = ?)
		   OR (porta_tipo = 'alias' AND porta_valor = ?)`,
		id, id, id,
	)
	if err != nil {
		return nil, fmt.Errorf("buscar uso do alias em fw_regras: %w", err)
	}
	defer rowsR.Close()

	for rowsR.Next() {
		var rID, desc, zona string
		if err := rowsR.Scan(&rID, &desc, &zona); err == nil {
			if desc != "" {
				usos = append(usos, fmt.Sprintf("Regra %q (%s)", desc, zona))
			} else {
				usos = append(usos, fmt.Sprintf("Regra %s (%s)", rID, zona))
			}
		}
	}

	// 2. Uso em perfis de acesso da VPN (wireguard_peers.allowed_host_groups)
	var wgTableExists bool
	_ = db.conn.QueryRow(`SELECT 1 FROM sqlite_master WHERE type='table' AND name='wireguard_peers'`).Scan(&wgTableExists)
	if wgTableExists {
		rowsWG, err := db.conn.Query(`SELECT user_id, allowed_host_groups FROM wireguard_peers WHERE allowed_host_groups LIKE ?`, "%"+id+"%")
		if err == nil {
			defer rowsWG.Close()
			for rowsWG.Next() {
				var uid, groupsJSON string
				if err := rowsWG.Scan(&uid, &groupsJSON); err == nil {
					var gids []string
					if err := json.Unmarshal([]byte(groupsJSON), &gids); err == nil {
						for _, gid := range gids {
							if gid == id {
								usos = append(usos, fmt.Sprintf("Perfil VPN do usuário %q", uid))
								break
							}
						}
					}
				}
			}
		}
	}

	return usos, nil
}

// UsosDoAgendamento pesquisa regras do firewall que referenciam o agendamento fornecido.
func (db *DB) UsosDoAgendamento(id string) ([]string, error) {
	var usos []string

	rows, err := db.conn.Query(`
		SELECT id, descricao, zona
		FROM fw_regras
		WHERE agendamento_id = ?`, id)
	if err != nil {
		return nil, fmt.Errorf("buscar uso do agendamento em fw_regras: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var rID, desc, zona string
		if err := rows.Scan(&rID, &desc, &zona); err == nil {
			if desc != "" {
				usos = append(usos, fmt.Sprintf("Regra %q (%s)", desc, zona))
			} else {
				usos = append(usos, fmt.Sprintf("Regra %s (%s)", rID, zona))
			}
		}
	}

	return usos, nil
}
