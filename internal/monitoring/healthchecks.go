package monitoring

import (
	"context"
	"regexp"
	"strings"

	"github.com/giovanibalarini/linkguard-cloud/internal/timesync"
)

type transition int

const (
	transNone transition = iota
	transDown
	transUp
)

// downConfirm is the number of consecutive "down" observations required before
// declaring an outage (anti-flap). With a 30s tick this debounces ~30–60s.
const downConfirm = 2

type itemState struct {
	name      string
	kind      string // "service" | "link" | "resource"
	up        bool
	since     int64
	failCount int
	known     bool
}

// serviceNameRe guards shell-embedded service names (defense-in-depth).
var serviceNameRe = regexp.MustCompile(`^[a-zA-Z0-9@._-]+$`)

// observe folds a raw up/down reading into the item's state and returns whether
// this reading is a real transition. Down transitions require downConfirm
// consecutive failures; up transitions are immediate.
func (c *Collector) observe(key string, up bool, now int64) transition {
	c.healthMu.Lock()
	defer c.healthMu.Unlock()
	st := c.health[key]
	if st == nil {
		if !up {
			// Born down (e.g. service dead at startup): seed as up with one failure
			// so the next confirming tick fires the outage, instead of silently
			// treating "already down" as steady state and never alerting.
			c.health[key] = &itemState{up: true, since: now, failCount: 1, known: true}
			return transNone
		}
		c.health[key] = &itemState{up: up, since: now, known: true}
		return transNone
	}
	if up {
		st.failCount = 0
		if !st.up {
			st.up = true
			st.since = now
			return transUp
		}
		return transNone
	}
	// down reading
	if !st.up {
		return transNone // already down
	}
	st.failCount++
	if st.failCount >= downConfirm {
		st.up = false
		st.since = now
		return transDown
	}
	return transNone
}

// setHealthDirect records an item's state without observe's anti-flap
// debounce. For signals that cannot flap — e.g. apt's cached package state,
// read a few times a day — requiring two consecutive readings would just
// delay the truth by a full interval (and a restart would reset the count).
func (c *Collector) setHealthDirect(key string, up bool, now int64) {
	c.healthMu.Lock()
	defer c.healthMu.Unlock()
	st := c.health[key]
	if st == nil {
		st = &itemState{known: true, since: now}
		c.health[key] = st
	}
	if st.up != up {
		st.up, st.since = up, now
	}
}

// Snapshot returns the current health of every tracked item (services, links,
// resources) for the dashboard.
func (c *Collector) Snapshot() []HealthItem {
	c.healthMu.Lock()
	defer c.healthMu.Unlock()
	out := make([]HealthItem, 0, len(c.health))
	for _, st := range c.health {
		out = append(out, HealthItem{Name: st.name, Kind: st.kind, Up: st.up, Since: st.since})
	}
	return out
}

// HealthItem is one row of the dashboard health panel.
type HealthItem struct {
	Name  string `json:"name"`
	Kind  string `json:"kind"`
	Up    bool   `json:"up"`
	Since int64  `json:"since"`
}

// checkServices polls each configured service via systemctl and raises/clears
// alerts on confirmed transitions.
func (c *Collector) checkServices(cfg Config) {
	now := c.nowFn()
	for _, svc := range cfg.Services {
		key := "service:" + svc
		verdict := c.probeService(svc)
		if verdict == svcNotOurs {
			// Nem queda nem saúde: a unidade não está na máquina (pacote sob
			// demanda que o admin nunca ligou) ou foi mascarada por decisão
			// de quem administra. Sai do mapa de saúde em vez de aparecer
			// vermelha no painel: item vermelho para algo que ninguém pediu
			// é dado falso, e alerta crítico para isso treina o operador a
			// ignorar a tela.
			c.forgetHealth(key)
			continue
		}
		up := verdict == svcUp
		tr := c.observe(key, up, now)
		c.ensureMeta(key, svc, "service")
		if c.rec != nil {
			state := "down"
			if up {
				state = "up"
			}
			c.rec.State("service", svc, state)
		}
		switch tr {
		case transDown:
			_ = c.alertSvc.ServiceOffline(svc)
		case transUp:
			_ = c.alertSvc.ServiceOnline(svc)
		}
	}
}

// forgetHealth removes an item the vigia can no longer say anything true
// about, so Snapshot (the painel) stops showing it.
func (c *Collector) forgetHealth(key string) {
	c.healthMu.Lock()
	defer c.healthMu.Unlock()
	delete(c.health, key)
}

// checkResource applies transition + anti-flap alerting to a host resource
// (cpu / memory / disk). "up" means healthy (below the threshold); crossing the
// threshold fires `high` once, and dropping back below fires `normal`. Because
// observe() requires two consecutive over-threshold readings, a one-tick spike
// (e.g. the CPU burst during boot) is suppressed instead of spamming.
func (c *Collector) checkResource(key, name string, pct float64, thresholdPct int, high, normal func(float64) error) {
	now := c.nowFn()
	tr := c.observe(key, pct < float64(thresholdPct), now)
	c.ensureMeta(key, name, "resource")
	switch tr {
	case transDown:
		_ = high(pct)
	case transUp:
		_ = normal(pct)
	}
}

// trackLinks reflects link status into the health map for the dashboard. Link
// UP/DOWN alerts stay owned by the monitor's OnStatusChange path (Task 9).
func (c *Collector) trackLinks() {
	links, err := c.db.GetLinks()
	if err != nil {
		return
	}
	now := c.nowFn()
	for _, l := range links {
		key := "link:" + l.ID
		c.observe(key, l.Status == "online", now)
		c.ensureMeta(key, l.Name, "link")
	}
}

// ensureMeta sets the display name/kind on an item the first time we see it.
func (c *Collector) ensureMeta(key, name, kind string) {
	c.healthMu.Lock()
	defer c.healthMu.Unlock()
	if st := c.health[key]; st != nil {
		if st.name == "" {
			st.name = name
		}
		if st.kind == "" {
			st.kind = kind
		}
	}
}

// serviceVerdict is what the vigia can honestly conclude about a monitored
// unit. O terceiro valor é o que faltava: "não é para estar rodando" não é
// queda.
type serviceVerdict int

const (
	svcUp serviceVerdict = iota
	svcDown
	// svcNotOurs: a unidade não existe na máquina, ou foi mascarada. Não há
	// queda para relatar.
	svcNotOurs
)

// probeService decide se uma unidade vigiada caiu.
//
// A pergunta antiga era `systemctl is-active`, e ela produzia um alerta
// CRITICAL falso — reproduzido em VM pelada, duas vezes:
//
//	nftables  is-active=inactive  is-enabled=enabled  LoadState=loaded
//	          ActiveState=inactive  Type=oneshot
//	[vigia] alert created type=service_offline severity=critical
//	        title="Serviço offline: nftables"
//
// Nada estava errado. O `nftables.service` é `Type=oneshot`: ele carrega o
// /etc/nftables.conf no boot e termina — não é um daemon, e "inactive" é o
// repouso normal dele. Mais que isso: quem o deixa parado é o próprio
// LinkGuard, de propósito e por escrito (bootstrapdeps.EnsureNftablesUnitEnabled
// habilita a unidade mas NUNCA a inicia, porque o `ExecStop` do unit do
// Debian é `nft flush ruleset` e iniciá-la agora recarregaria o arquivo por
// cima do ruleset vivo). O vigia acusava de queda exatamente a decisão que o
// produto tomou. Numa máquina recém-instalada, que ainda não rebootou, o
// alerta nascia ~60 s depois de subir e só se fechava quando alguém
// reiniciasse a máquina.
//
// A pergunta certa para uma unidade oneshot não é "está ativa?", é "ela
// falhou?". Um `nft -f` recusado no boot deixa a unidade em `failed`, e ISSO
// continua sendo alerta — é o caso que importa, porque aí as regras não
// foram carregadas.
//
// E o mesmo raciocínio cobre os outros dois vigiados (kea-dhcp4-server e
// unbound, que são daemons de verdade): eles são instalados SOB DEMANDA,
// quando o admin liga DHCP/DNS no painel. Numa máquina onde ele nunca ligou,
// a unidade nem existe (`LoadState=not-found`) e o vigia dizia "Serviço
// offline: kea-dhcp4-server". Ausência não é queda.
//
// O nome do serviço é validado contra serviceNameRe antes de chegar ao shell
// (defense-in-depth).
func (c *Collector) probeService(svc string) serviceVerdict {
	if !serviceNameRe.MatchString(svc) {
		return svcNotOurs
	}
	// `systemctl show` responde 0 mesmo para unidade que não existe (devolve
	// LoadState=not-found), então o erro aqui significa "não consegui
	// perguntar" — sem systemd, timeout, binário ausente. Nesse caso a
	// resposta honesta é "não sei", nunca "caiu": um critical falso é pior
	// que alerta nenhum.
	out, err := c.exec.ExecuteRead(context.Background(), "systemctl", "show", svc,
		"-p", "LoadState", "-p", "ActiveState", "-p", "Type")
	if err != nil {
		return svcNotOurs
	}
	props := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			props[k] = v
		}
	}

	switch props["LoadState"] {
	case "":
		// Saída vazia/irreconhecível: mesmo raciocínio do erro acima.
		return svcNotOurs
	case "not-found":
		// Pacote sob demanda que o admin nunca ligou.
		return svcNotOurs
	case "masked", "masked-runtime":
		// Mascarar é decisão explícita de quem administra a máquina.
		return svcNotOurs
	}

	switch props["ActiveState"] {
	case "failed":
		// Vale para daemon e para oneshot: a unidade tentou e não conseguiu.
		return svcDown
	case "active", "activating", "reloading", "refreshing":
		return svcUp
	}

	// Sobram "inactive" e "deactivating".
	if props["Type"] == "oneshot" {
		// Carregar e sair (ou ainda não ter rodado nesta sessão) é o repouso
		// normal de uma oneshot. "Up" aqui quer dizer "não falhou".
		return svcUp
	}
	return svcDown
}

// checkNTP verifies the system clock is NTP-synchronized and raises/clears
// alerts.TypeNTPUnsynced on a confirmed transition.
func (c *Collector) checkNTP() {
	up := timesync.IsSynced(context.Background(), c.exec)
	now := c.nowFn()
	tr := c.observe("ntp:sync", up, now)
	c.ensureMeta("ntp:sync", "ntp-sync", "resource")
	switch tr {
	case transDown:
		_ = c.alertSvc.NTPUnsynced()
	case transUp:
		_ = c.alertSvc.NTPSynced()
	}
}
