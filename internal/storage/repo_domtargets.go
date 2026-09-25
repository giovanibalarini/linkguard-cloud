package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/giovanibalarini/linkguard-cloud/internal/validate"
)

// Alvo de regra por domínio (#123): a lista que o admin mantém.
//
// O que este arquivo guarda é INTENÇÃO, e não estado do firewall. Os endereços
// que cada domínio ensinou vivem no índice em memória do alimentador e nas
// estruturas do kernel, e nenhum dos dois é gravado aqui — cache de DNS que
// sobrevive ao reboot afirma sobre endereços o que ninguém mais confirmou, que
// é a mesma razão pela qual o mapa da #116 também não é gravado.

// Estágios de um domínio. Ver a coluna stage em createDomainTargetsTable.
const (
	// DomainStageEnsaio aprende e não escreve no firewall.
	DomainStageEnsaio = "ensaio"
	// DomainStageAtivo escreve. Só por ação explícita.
	DomainStageAtivo = "ativo"
)

// DomainCapBarrar é a capacidade de um domínio listado. Havia uma segunda,
// "direcionar" (escolher a WAN por domínio), que saiu com o multi-WAN.
const DomainCapBarrar = "barrar"

// DomainTarget é um domínio listado.
type DomainTarget struct {
	ID     string `json:"id"`
	Domain string `json:"domain"`
	// Capability é "barrar". Linhas antigas podem trazer "direcionar" (a
	// escolha de WAN por domínio, que saiu com o multi-WAN): elas continuam
	// legíveis para a tela poder mostrar e apagar, e nunca são publicadas.
	Capability string `json:"capability"`
	// Stage é "ensaio" ou "ativo".
	Stage     string    `json:"stage"`
	Note      string    `json:"note"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ListDomainTargets devolve a lista inteira, em ordem de domínio.
func (db *DB) ListDomainTargets() ([]DomainTarget, error) {
	rows, err := db.conn.Query(`
		SELECT id, domain, capability, stage, note, created_at, updated_at
		FROM domain_targets ORDER BY domain`)
	if err != nil {
		return nil, fmt.Errorf("listar os alvos por domínio: %w", err)
	}
	defer rows.Close()
	out := []DomainTarget{}
	for rows.Next() {
		var t DomainTarget
		if err := rows.Scan(&t.ID, &t.Domain, &t.Capability, &t.Stage, &t.Note, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, fmt.Errorf("ler um alvo por domínio: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// SaveDomainTarget grava um domínio, criando ou atualizando pelo NOME.
//
// O conflito é resolvido por domain e não por id de propósito: quem digita o
// mesmo nome duas vezes está corrigindo a mesma entrada, e deixar as duas
// entrarem geraria a ambiguidade que o UNIQUE da coluna existe para impedir.
//
// O ESTÁGIO NÃO É GRAVADO AQUI. Editar a capacidade, o link ou a observação de
// um domínio não pode promovê-lo por tabela — promover é PromoteDomainTarget, e
// a separação é o que impede que uma tela de edição, um import de backup ou um
// campo em branco liguem um bloqueio que ninguém pediu.
func (db *DB) SaveDomainTarget(t DomainTarget) error {
	if t.Capability == "" {
		t.Capability = DomainCapBarrar
	}
	if err := normalizeDomainTarget(&t); err != nil {
		return err
	}
	if t.ID == "" {
		t.ID = t.Domain
	}
	_, err := db.conn.Exec(`
		INSERT INTO domain_targets (id, domain, capability, stage, note, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(domain) DO UPDATE SET
			capability = excluded.capability,
			link_id    = '',
			link_name  = '',
			mark       = 0,
			note       = excluded.note,
			updated_at = excluded.updated_at`,
		t.ID, t.Domain, t.Capability, DomainStageEnsaio, t.Note, time.Now())
	if err != nil {
		return fmt.Errorf("gravar o alvo por domínio %s: %w", t.Domain, err)
	}
	return nil
}

const MaxDomainTargetNoteRunes = 500

var ErrDomainTargetNotFound = errors.New("alvo por domínio não encontrado")

func normalizeDomainTarget(t *DomainTarget) error {
	dom, ok := validate.NormalizeDomainTarget(t.Domain)
	if !ok {
		return fmt.Errorf("domínio inválido: %q", t.Domain)
	}
	t.Domain = dom
	if t.Capability != DomainCapBarrar {
		return fmt.Errorf("capacidade inválida: %q (a versão cloud só bloqueia por domínio)", t.Capability)
	}
	t.Note = strings.TrimSpace(t.Note)
	if utf8.RuneCountInString(t.Note) > MaxDomainTargetNoteRunes || strings.ContainsFunc(t.Note, unicode.IsControl) {
		return fmt.Errorf("observação inválida: use até %d caracteres sem controles", MaxDomainTargetNoteRunes)
	}
	return nil
}

// CreateDomainTarget cria intenção nova sempre em ensaio.
func (db *DB) CreateDomainTarget(t *DomainTarget) error {
	if t == nil {
		return fmt.Errorf("alvo por domínio ausente")
	}
	if err := normalizeDomainTarget(t); err != nil {
		return err
	}
	if t.ID == "" {
		t.ID = uuid.NewString()
	}
	now := time.Now()
	t.Stage, t.CreatedAt, t.UpdatedAt = DomainStageEnsaio, now, now
	_, err := db.conn.Exec(`
		INSERT INTO domain_targets
			(id, domain, capability, stage, note, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.Domain, t.Capability, t.Stage, t.Note, now, now)
	if err != nil {
		return fmt.Errorf("criar o alvo por domínio %s: %w", t.Domain, err)
	}
	return nil
}

// GetDomainTarget devolve uma intenção por id.
func (db *DB) GetDomainTarget(id string) (*DomainTarget, error) {
	var t DomainTarget
	err := db.conn.QueryRow(`
		SELECT id, domain, capability, stage, note, created_at, updated_at
		  FROM domain_targets WHERE id = ?`, strings.TrimSpace(id)).Scan(
		&t.ID, &t.Domain, &t.Capability, &t.Stage, &t.Note, &t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ler alvo por domínio: %w", err)
	}
	return &t, nil
}

// UpdateDomainTarget edita a intenção sem tocar no estágio.
func (db *DB) UpdateDomainTarget(id string, t DomainTarget) error {
	if err := normalizeDomainTarget(&t); err != nil {
		return err
	}
	res, err := db.conn.Exec(`
		UPDATE domain_targets
		   SET domain = ?, capability = ?, link_id = '', link_name = '', mark = 0, note = ?, updated_at = ?
		 WHERE id = ?`,
		t.Domain, t.Capability, t.Note, time.Now(), strings.TrimSpace(id))
	if err != nil {
		return fmt.Errorf("editar o alvo por domínio %s: %w", t.Domain, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrDomainTargetNotFound
	}
	return nil
}

// SetDomainTargetStage é a única escrita por id que muda ensaio/ativo.
func (db *DB) SetDomainTargetStage(id, stage string) error {
	if stage != DomainStageEnsaio && stage != DomainStageAtivo {
		return fmt.Errorf("estágio inválido: %q", stage)
	}
	res, err := db.conn.Exec(`UPDATE domain_targets SET stage = ?, updated_at = ? WHERE id = ?`,
		stage, time.Now(), strings.TrimSpace(id))
	if err != nil {
		return fmt.Errorf("mudar estágio do alvo por domínio: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrDomainTargetNotFound
	}
	return nil
}

func (db *DB) DeleteDomainTargetByID(id string) error {
	res, err := db.conn.Exec(`DELETE FROM domain_targets WHERE id = ?`, strings.TrimSpace(id))
	if err != nil {
		return fmt.Errorf("apagar alvo por domínio: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrDomainTargetNotFound
	}
	return nil
}

// PromoteDomainTarget move o domínio entre ensaio e ativo.
//
// É a ÚNICA porta de saída do ensaio, e existe separada de SaveDomainTarget
// pela razão dita lá: sair do ensaio é a única coisa nesta capacidade que muda
// o que passa na rede, e uma mudança dessas não pode acontecer de carona numa
// gravação de rotina.
func (db *DB) PromoteDomainTarget(domain, stage string) error {
	if stage != DomainStageAtivo && stage != DomainStageEnsaio {
		return fmt.Errorf("estágio inválido: %q", stage)
	}
	dom := strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))
	res, err := db.conn.Exec(
		`UPDATE domain_targets SET stage = ?, updated_at = ? WHERE domain = ?`,
		stage, time.Now(), dom)
	if err != nil {
		return fmt.Errorf("mudar o estágio de %s: %w", dom, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("domínio não listado: %s", dom)
	}
	return nil
}

type DomainRoutingDBSnapshot struct {
	Targets          []DomainTarget
	BlocklistPresent bool
	BlocklistEnabled bool
}

// DomainRoutingSnapshot lê toda a entrada da reconciliação numa transação
// read-only: os alvos e o estado do grupo de bloqueio têm de ser da mesma
// rodada.
func (db *DB) DomainRoutingSnapshot(ctx context.Context) (DomainRoutingDBSnapshot, error) {
	var snap DomainRoutingDBSnapshot
	tx, err := db.conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return snap, fmt.Errorf("abrir snapshot de domínio: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op depois do commit

	rows, err := tx.QueryContext(ctx, `
		SELECT id, domain, capability, stage, note, created_at, updated_at
		  FROM domain_targets ORDER BY domain`)
	if err != nil {
		return snap, fmt.Errorf("listar alvos no snapshot: %w", err)
	}
	for rows.Next() {
		var t DomainTarget
		if err := rows.Scan(&t.ID, &t.Domain, &t.Capability, &t.Stage, &t.Note, &t.CreatedAt, &t.UpdatedAt); err != nil {
			rows.Close()
			return snap, fmt.Errorf("ler alvo no snapshot: %w", err)
		}
		snap.Targets = append(snap.Targets, t)
	}
	if err := rows.Close(); err != nil {
		return snap, err
	}
	if err := rows.Err(); err != nil {
		return snap, err
	}

	var enabled int
	err = tx.QueryRowContext(ctx,
		`SELECT enabled FROM firewall_groups WHERE kind = 'blocklist' LIMIT 1`).Scan(&enabled)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return snap, fmt.Errorf("ler grupo de bloqueio no snapshot: %w", err)
	default:
		snap.BlocklistPresent = true
		snap.BlocklistEnabled = enabled != 0
	}
	if err := tx.Commit(); err != nil {
		return snap, fmt.Errorf("fechar snapshot de domínio: %w", err)
	}
	if snap.Targets == nil {
		snap.Targets = []DomainTarget{}
	}
	return snap, nil
}

// DeleteDomainTarget tira o domínio da lista.
func (db *DB) DeleteDomainTarget(domain string) error {
	dom := strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))
	_, err := db.conn.Exec(`DELETE FROM domain_targets WHERE domain = ?`, dom)
	if err != nil {
		return fmt.Errorf("apagar o alvo por domínio %s: %w", dom, err)
	}
	return nil
}
