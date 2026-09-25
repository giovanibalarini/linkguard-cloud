package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/giovanibalarini/linkguard-cloud/internal/alerts"
	"github.com/giovanibalarini/linkguard-cloud/internal/netsvc"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
	"github.com/giovanibalarini/linkguard-cloud/internal/validate"
)

// NetsvcHandler é a tela de DNS: encaminhadores, log de consultas, dnstap e
// lista de bloqueio. Até 25/09/2026 era também a tela de DHCP; na nuvem quem
// serve DHCP é a própria Oracle.
//
// Toda mutação arma uma aplicação com atraso (autoApplier): várias mudanças em
// sequência viram um reload só. O botão "Aplicar agora" pula o atraso.
type NetsvcHandler struct {
	db       *storage.DB
	provider netsvc.Provider
	alertSvc *alerts.Service
	applier  *autoApplier
	dnsMapa  mapaDeDominios
}

// autoApplyDelay junta mudanças seguidas num reload só.
const autoApplyDelay = 1500 * time.Millisecond

// applyBudget cobre uma instalação sob demanda do unbound num link lento.
const applyBudget = 15 * time.Minute

func NewNetsvcHandler(db *storage.DB, provider netsvc.Provider, alertSvc *alerts.Service) *NetsvcHandler {
	h := &NetsvcHandler{db: db, provider: provider, alertSvc: alertSvc}
	h.applier = newAutoApplier(autoApplyDelay, func() {
		ctx, cancel := context.WithTimeout(context.Background(), applyBudget)
		defer cancel()
		_ = h.doReload(ctx)
	})
	return h
}

// As chaves do banco. netsvc_config veio do linkguard-fw e segue sendo lida:
// os campos de DHCP que um banco antigo traz são ignorados.
const netsvcCfgKey = "netsvc_config"
const netsvcApplyStatusKey = "netsvc_last_apply"

// applyStatus é o resultado da última aplicação, gravado para a tela.
// Warning existe porque "aplicou" e "tudo o que você configurou está valendo"
// divergem quando o backend descarta uma entrada ruim da lista.
type applyStatus struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	Warning string `json:"warning,omitempty"`
	At      int64  `json:"at"` // unix seconds
}

// doReload regera e recarrega o DNS, grava o resultado e alerta na falha. É o
// mesmo caminho da aplicação com atraso e do botão "Aplicar agora".
func (h *NetsvcHandler) doReload(ctx context.Context) error {
	bl, _ := h.db.ListDNSBlocklist()
	res, err := h.provider.ReloadConfigs(ctx, h.getConfig(), bl)
	st := applyStatus{OK: err == nil, At: time.Now().Unix()}
	if len(res.Warnings) > 0 {
		st.Warning = strings.Join(res.Warnings, " ")
		slog.Warn("DNS aplicado com ressalvas", "avisos", res.Warnings)
	}
	if err != nil {
		st.Error = err.Error()
		if h.alertSvc != nil {
			// Pacote ausente e não instalável é uma condição própria, com
			// recuperação própria — não um erro de regra de firewall.
			var prereq *netsvc.PrereqError
			if errors.As(err, &prereq) {
				_ = h.alertSvc.NetsvcDepsMissing(prereq.Error())
			} else {
				_ = h.alertSvc.RuleError("Falha ao aplicar o DNS: " + err.Error())
			}
		}
	} else if h.alertSvc != nil {
		if len(res.Installed) > 0 {
			_ = h.alertSvc.NetsvcDepsOK(strings.Join(res.Installed, ", "))
		} else {
			// Aplicou sem instalar nada — inclusive quando o admin resolveu à
			// mão por SSH. Fecha em silêncio um alerta de dependência que não
			// existe mais.
			h.alertSvc.AutoResolve(alerts.TypeNetsvcDepsMissing, "")
		}
	}
	if b, mErr := json.Marshal(st); mErr == nil {
		_ = h.db.SetSetting(netsvcApplyStatusKey, string(b))
	}
	return err
}

// ReloadCurrent expõe o caminho canônico de reload a outros serviços (hoje, o
// WireGuard). Não aceita configuração de fora: a gravada no banco é a única
// fonte.
func (h *NetsvcHandler) ReloadCurrent(ctx context.Context) error {
	return h.doReload(ctx)
}

// scheduleApply arma a aplicação com atraso depois de uma mutação.
func (h *NetsvcHandler) scheduleApply() {
	if h.applier != nil {
		h.applier.schedule()
	}
}

// lastApplyStatus devolve o resultado da última aplicação, ou nil se nada foi
// aplicado ainda: "nunca tentou" e "tentou e falhou" são estados diferentes, e
// juntá-los mostrava um falso "última aplicação falhou" em toda instalação nova.
func (h *NetsvcHandler) lastApplyStatus() *applyStatus {
	raw, _ := h.db.GetSetting(netsvcApplyStatusKey)
	if raw == "" {
		return nil
	}
	var st applyStatus
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		return nil
	}
	return &st
}

func netsvcConfigFromDB(db *storage.DB) netsvc.Config {
	cfg := netsvc.DefaultConfig()
	if raw, _ := db.GetSetting(netsvcCfgKey); raw != "" {
		_ = json.Unmarshal([]byte(raw), &cfg)
	}
	if cfg.Upstreams == nil {
		cfg.Upstreams = []string{}
	}
	return cfg
}

func (h *NetsvcHandler) getConfig() netsvc.Config {
	return netsvcConfigFromDB(h.db)
}

func (h *NetsvcHandler) saveConfig(c netsvc.Config) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return h.db.SetSetting(netsvcCfgKey, string(b))
}

// GetDNS devolve a configuração, a lista de bloqueio e o resultado da última
// aplicação.
func (h *NetsvcHandler) GetDNS(w http.ResponseWriter, r *http.Request) {
	bl, _ := h.db.ListDNSBlocklist()
	if bl == nil {
		bl = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"config":     h.getConfig(),
		"blocklist":  bl,
		"last_apply": h.lastApplyStatus(),
	})
}

// UpdateDNSConfig grava encaminhadores, log de consultas e dnstap.
func (h *NetsvcHandler) UpdateDNSConfig(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Upstreams     []string `json:"upstreams"`
		LogQueries    bool     `json:"log_queries"`
		DNSTapEnabled bool     `json:"dnstap_enabled"`
	}
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	ups := []string{}
	for _, u := range b.Upstreams {
		if u = strings.TrimSpace(u); u != "" {
			ups = append(ups, u)
		}
	}
	cfg := h.getConfig()
	cfg.Upstreams = ups
	cfg.LogQueries = b.LogQueries
	cfg.DNSTapEnabled = b.DNSTapEnabled
	if err := netsvc.ValidaConfig(cfg); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := h.saveConfig(cfg); err != nil {
		writeInternalError(w, err)
		return
	}
	auditAction(h.db, r, "dns.config", "netsvc", "")
	h.scheduleApply()
	writeJSON(w, http.StatusOK, cfg)
}

// AddBlocklist / DeleteBlocklist gerenciam os domínios bloqueados.
func (h *NetsvcHandler) AddBlocklist(w http.ResponseWriter, r *http.Request) {
	h.blocklist(w, r, true)
}
func (h *NetsvcHandler) DeleteBlocklist(w http.ResponseWriter, r *http.Request) {
	h.blocklist(w, r, false)
}
func (h *NetsvcHandler) blocklist(w http.ResponseWriter, r *http.Request, add bool) {
	var b struct{ Domain string }
	if err := decodeJSON(r, &b); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	d := strings.ToLower(strings.TrimSpace(b.Domain))
	if d == "" {
		writeError(w, http.StatusBadRequest, "domínio vazio")
		return
	}
	// Valida só ao adicionar: remover tem que conseguir apagar uma entrada já
	// gravada, inclusive uma aceita por uma regra antiga mais frouxa.
	if add && !validate.Domain(d) {
		writeError(w, http.StatusBadRequest, "domínio inválido")
		return
	}
	var err error
	if add {
		err = h.db.AddDNSBlocklist(d)
		auditAction(h.db, r, "dns.blocklist.add", d, "")
	} else {
		err = h.db.DeleteDNSBlocklist(d)
		auditAction(h.db, r, "dns.blocklist.del", d, "")
	}
	if err != nil {
		writeInternalError(w, err)
		return
	}
	h.scheduleApply()
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Preview devolve a config renderizada, sem aplicar. Uma config que não pode
// ser gerada também não pode ser mostrada: seria mostrar um arquivo que nunca
// vai ser escrito.
func (h *NetsvcHandler) Preview(w http.ResponseWriter, r *http.Request) {
	bl, _ := h.db.ListDNSBlocklist()
	files, err := h.provider.GenerateConfigs(h.getConfig(), bl)
	if err != nil {
		writeError(w, http.StatusBadRequest, "não foi possível gerar a configuração: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, files)
}

// Apply é o "Aplicar agora": recarrega na hora, sem o atraso. A falha volta com
// o motivo de verdade — ele já está gravado no status que a própria tela mostra
// — e um pré-requisito ausente responde 503, porque nada está quebrado: a
// máquina só ainda não consegue servir DNS, e a mensagem diz o que fazer.
func (h *NetsvcHandler) Apply(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), applyBudget)
	defer cancel()
	if err := h.doReload(ctx); err != nil {
		slog.Error("falha ao aplicar o DNS", "err", err)
		var prereq *netsvc.PrereqError
		if errors.As(err, &prereq) {
			writeError(w, http.StatusServiceUnavailable, prereq.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, "falha ao aplicar: "+err.Error())
		return
	}
	auditAction(h.db, r, "dns.apply", "unbound", "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "aplicado"})
}
