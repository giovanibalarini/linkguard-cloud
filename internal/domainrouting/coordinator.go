// Package domainrouting liga a intenção persistida de bloqueio por domínio ao
// runtime alimentado por dnstap, e é o lugar que suspende uma intenção ativa
// enquanto o boot não provou que estruturas, chains e rotas estão prontas.
//
// Havia uma segunda capacidade, "direcionar" (escolher a WAN por domínio), que
// saiu da versão cloud com o multi-WAN. Linhas antigas com ela continuam
// legíveis e aparecem suspensas, para a tela poder mostrar e apagar; nunca são
// publicadas no runtime.
package domainrouting

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/giovanibalarini/linkguard-cloud/internal/domtargets"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
	"github.com/giovanibalarini/linkguard-cloud/internal/validate"
)

var (
	// ErrInvalid identifica uma requisição que não pode representar uma
	// intenção segura.
	ErrInvalid = errors.New("intenção por domínio inválida")
	// ErrNotFound identifica um alvo que já não existe.
	ErrNotFound = errors.New("alvo por domínio não encontrado")
	// ErrConflict identifica dois alvos com o mesmo domínio normalizado.
	ErrConflict = errors.New("domínio já cadastrado")
)

const (
	ReasonBootPending   = "boot_pending"
	ReasonInvalidIntent = "invalid_intent"
)

// Runtime é a parte do alimentador que o coordenador precisa. A troca da lista
// é atômica dentro de domtargets; Estado fornece a visão do índice e do kernel.
type Runtime interface {
	DefinirAlvos([]domtargets.Alvo)
	Estado(context.Context) domtargets.Estado
}

// Input contém apenas os campos editáveis. Stage não aparece aqui de
// propósito: promoção e retorno a ensaio usam SetStage explicitamente.
type Input struct {
	Domain     string `json:"domain"`
	Capability string `json:"capability"`
	Note       string `json:"note"`
}

// TargetView combina a intenção persistida, a decisão efetiva desta rodada e
// a telemetria transitória. Só a primeira parte sobrevive a um reboot.
type TargetView struct {
	ID               string    `json:"id"`
	Domain           string    `json:"domain"`
	Capability       string    `json:"capability"`
	Stage            string    `json:"stage"`
	EffectiveStage   string    `json:"effective_stage"`
	Note             string    `json:"note"`
	Suspended        bool      `json:"suspended"`
	SuspensionReason string    `json:"suspension_reason,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`

	NoKernel          *int   `json:"no_kernel"`
	NoIndex           int    `json:"no_index"`
	AtLimit           bool   `json:"at_limit"`
	Limit             int    `json:"limit"`
	Overflows         uint64 `json:"overflows"`
	Rejected          uint64 `json:"rejected"`
	RejectedOwn       uint64 `json:"rejected_own"`
	NoRefcountSlot    uint64 `json:"no_refcount_slot"`
	LastLearned       int64  `json:"last_learned"`
	Rotation          int    `json:"rotation"`
	RotationTruncated bool   `json:"rotation_truncated"`
}

// State é a resposta observável da capacidade. Runtime contém os totais do
// alimentador/kernel; Targets torna cada intenção atribuível.
type State struct {
	Ready            bool              `json:"ready"`
	Generation       uint64            `json:"generation"`
	LastReconciledAt time.Time         `json:"last_reconciled_at"`
	LastError        string            `json:"last_error,omitempty"`
	Runtime          domtargets.Estado `json:"runtime"`
	Targets          []TargetView      `json:"targets"`
}

// Coordinator serializa CRUD, leituras e publicação no runtime. Isso evita
// que uma promoção concorra com outra mudança e publique uma combinação que
// nunca existiu no banco.
type Coordinator struct {
	mu      sync.Mutex
	db      *storage.DB
	runtime Runtime

	ready            bool
	generation       uint64
	lastReconciledAt time.Time
	lastError        string
	targets          []TargetView
}

func New(db *storage.DB, runtime Runtime) *Coordinator {
	return &Coordinator{db: db, runtime: runtime, targets: []TargetView{}}
}

// Prepare abre o gate de boot e só o mantém aberto se um snapshot completo
// puder ser publicado. Antes dele, Reconcile sempre força intenções a ensaio.
func (c *Coordinator) Prepare(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.ready = true
	if err := c.reconcileLocked(ctx); err != nil {
		c.ready = false
		return err
	}
	return nil
}

// Hold fecha o gate quando uma passada de provisionamento deixa de conseguir
// provar que estruturas, chains e rotas estão prontas. Também republica a
// lista imediatamente para remover do runtime qualquer intenção ativa.
func (c *Coordinator) Hold(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ready = false
	return c.reconcileLocked(ctx)
}

// Reconcile lê os alvos e publica a lista completa no runtime de uma vez.
func (c *Coordinator) Reconcile(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reconcileLocked(ctx)
}

func (c *Coordinator) reconcileLocked(context.Context) error {
	targets, err := c.db.ListDomainTargets()
	if err != nil {
		c.lastError = err.Error()
		return err
	}

	views := make([]TargetView, 0, len(targets))
	alvos := make([]domtargets.Alvo, 0, len(targets))
	for _, stored := range targets {
		view, alvo, valid := c.resolve(stored)
		views = append(views, view)
		if valid {
			alvos = append(alvos, alvo)
		}
	}

	if c.runtime != nil {
		c.runtime.DefinirAlvos(alvos)
	}
	c.targets = views
	c.lastReconciledAt = time.Now()
	c.lastError = ""
	c.generation++
	return nil
}

func (c *Coordinator) resolve(stored storage.DomainTarget) (TargetView, domtargets.Alvo, bool) {
	view := TargetView{
		ID: stored.ID, Domain: stored.Domain, Capability: stored.Capability,
		Stage: stored.Stage, EffectiveStage: stored.Stage,
		Note: stored.Note, CreatedAt: stored.CreatedAt, UpdatedAt: stored.UpdatedAt,
	}

	// Capacidade que não é barrar (a "direcionar" de antes, ou lixo) nunca é
	// publicada: aparece suspensa para ser vista e apagada.
	domain, ok := validate.NormalizeDomainTarget(stored.Domain)
	if !ok || stored.Capability != storage.DomainCapBarrar ||
		(stored.Stage != storage.DomainStageEnsaio && stored.Stage != storage.DomainStageAtivo) {
		suspend(&view, ReasonInvalidIntent)
		return view, domtargets.Alvo{}, false
	}
	view.Domain = domain

	alvo := domtargets.Alvo{
		Dominio: domain, Capacidade: domtargets.Capacidade(stored.Capability),
		Estagio: domtargets.Estagio(stored.Stage),
	}
	if stored.Stage == storage.DomainStageAtivo && !c.ready {
		suspend(&view, ReasonBootPending)
	}

	alvo.Estagio = domtargets.Estagio(view.EffectiveStage)
	return view, alvo, true
}

func suspend(view *TargetView, reason string) {
	view.Suspended = true
	view.SuspensionReason = reason
	view.EffectiveStage = storage.DomainStageEnsaio
}

// State copia primeiro a configuração publicada e só depois consulta o
// runtime. Assim uma leitura lenta de nft não segura o lock de CRUD/failover.
func (c *Coordinator) State(ctx context.Context) State {
	c.mu.Lock()
	state := State{
		Ready: c.ready, Generation: c.generation,
		LastReconciledAt: c.lastReconciledAt, LastError: c.lastError,
		Targets: append([]TargetView(nil), c.targets...),
	}
	runtime := c.runtime
	c.mu.Unlock()

	if runtime == nil {
		return state
	}
	state.Runtime = runtime.Estado(ctx)
	metrics := make(map[string]domtargets.EstadoDominio, len(state.Runtime.Dominios))
	for _, row := range state.Runtime.Dominios {
		metrics[row.Dominio] = row
	}
	for idx := range state.Targets {
		row, ok := metrics[state.Targets[idx].Domain]
		if !ok {
			continue
		}
		mergeMetrics(&state.Targets[idx], row)
	}
	return state
}

func mergeMetrics(view *TargetView, row domtargets.EstadoDominio) {
	if row.NoKernel != nil {
		value := *row.NoKernel
		view.NoKernel = &value
	}
	view.NoIndex = row.NoIndice
	view.AtLimit = row.NoTeto
	view.Limit = row.Teto
	view.Overflows = row.Estouros
	view.Rejected = row.Recusados
	view.RejectedOwn = row.RecusadosProprios
	view.NoRefcountSlot = row.SemVaga
	view.LastLearned = row.UltimoAprendizado
	view.Rotation = row.Rotatividade
	view.RotationTruncated = row.RotatividadeTruncada
}

// Create sempre cria em ensaio, independentemente de qualquer campo que um
// cliente tente inferir. SetStage é a única promoção.
func (c *Coordinator) Create(ctx context.Context, input Input) (State, error) {
	target, err := c.targetFromInput(input)
	if err != nil {
		return State{}, err
	}

	c.mu.Lock()
	if err := c.ensureUniqueDomain(target.Domain, ""); err != nil {
		c.mu.Unlock()
		return State{}, err
	}
	if err := c.db.CreateDomainTarget(&target); err != nil {
		c.mu.Unlock()
		return State{}, classifyStorageError(err)
	}
	if err := c.reconcileLocked(ctx); err != nil {
		c.mu.Unlock()
		return State{}, err
	}
	c.mu.Unlock()
	return c.State(ctx), nil
}

// Update preserva o estágio persistido.
func (c *Coordinator) Update(ctx context.Context, id string, input Input) (State, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return State{}, fmt.Errorf("%w: id ausente", ErrInvalid)
	}
	target, err := c.targetFromInput(input)
	if err != nil {
		return State{}, err
	}

	c.mu.Lock()
	if err := c.ensureUniqueDomain(target.Domain, id); err != nil {
		c.mu.Unlock()
		return State{}, err
	}
	if err := c.db.UpdateDomainTarget(id, target); err != nil {
		c.mu.Unlock()
		return State{}, classifyStorageError(err)
	}
	if err := c.reconcileLocked(ctx); err != nil {
		c.mu.Unlock()
		return State{}, err
	}
	c.mu.Unlock()
	return c.State(ctx), nil
}

// SetStage é a única operação que promove uma intenção para ativo.
func (c *Coordinator) SetStage(ctx context.Context, id, stage string) (State, error) {
	id, stage = strings.TrimSpace(id), strings.TrimSpace(stage)
	if id == "" || (stage != storage.DomainStageEnsaio && stage != storage.DomainStageAtivo) {
		return State{}, fmt.Errorf("%w: estágio deve ser ensaio ou ativo", ErrInvalid)
	}
	c.mu.Lock()
	if err := c.db.SetDomainTargetStage(id, stage); err != nil {
		c.mu.Unlock()
		return State{}, classifyStorageError(err)
	}
	if err := c.reconcileLocked(ctx); err != nil {
		c.mu.Unlock()
		return State{}, err
	}
	c.mu.Unlock()
	return c.State(ctx), nil
}

func (c *Coordinator) Delete(ctx context.Context, id string) (State, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return State{}, fmt.Errorf("%w: id ausente", ErrInvalid)
	}
	c.mu.Lock()
	if err := c.db.DeleteDomainTargetByID(id); err != nil {
		c.mu.Unlock()
		return State{}, classifyStorageError(err)
	}
	if err := c.reconcileLocked(ctx); err != nil {
		c.mu.Unlock()
		return State{}, err
	}
	c.mu.Unlock()
	return c.State(ctx), nil
}

func (c *Coordinator) targetFromInput(input Input) (storage.DomainTarget, error) {
	domain, ok := validate.NormalizeDomainTarget(input.Domain)
	if !ok {
		return storage.DomainTarget{}, fmt.Errorf("%w: domínio inválido", ErrInvalid)
	}
	input.Capability = strings.TrimSpace(input.Capability)
	input.Note = strings.TrimSpace(input.Note)
	if input.Capability == "" {
		input.Capability = storage.DomainCapBarrar
	}
	if input.Capability != storage.DomainCapBarrar {
		return storage.DomainTarget{}, fmt.Errorf("%w: a capacidade é barrar (escolher a WAN por domínio saiu com o multi-WAN)", ErrInvalid)
	}
	if utf8.RuneCountInString(input.Note) > storage.MaxDomainTargetNoteRunes || strings.ContainsFunc(input.Note, unicode.IsControl) {
		return storage.DomainTarget{}, fmt.Errorf("%w: observação inválida", ErrInvalid)
	}

	return storage.DomainTarget{Domain: domain, Capability: input.Capability, Note: input.Note}, nil
}

func (c *Coordinator) ensureUniqueDomain(domain, exceptID string) error {
	targets, err := c.db.ListDomainTargets()
	if err != nil {
		return err
	}
	for _, target := range targets {
		if target.Domain == domain && target.ID != exceptID {
			return fmt.Errorf("%w: %s", ErrConflict, domain)
		}
	}
	return nil
}

func classifyStorageError(err error) error {
	switch {
	case errors.Is(err, storage.ErrDomainTargetNotFound):
		return fmt.Errorf("%w: %v", ErrNotFound, err)
	case strings.Contains(err.Error(), "UNIQUE constraint failed: domain_targets.domain"):
		return fmt.Errorf("%w: %v", ErrConflict, err)
	default:
		return err
	}
}
