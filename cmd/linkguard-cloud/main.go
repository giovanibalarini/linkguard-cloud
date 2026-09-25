package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	linkguardcloud "github.com/giovanibalarini/linkguard-cloud"
	"github.com/giovanibalarini/linkguard-cloud/internal/ai"
	"github.com/giovanibalarini/linkguard-cloud/internal/alerts"
	"github.com/giovanibalarini/linkguard-cloud/internal/api"
	"github.com/giovanibalarini/linkguard-cloud/internal/api/handlers"
	"github.com/giovanibalarini/linkguard-cloud/internal/auth"
	"github.com/giovanibalarini/linkguard-cloud/internal/backup"
	"github.com/giovanibalarini/linkguard-cloud/internal/bootstrapdeps"
	"github.com/giovanibalarini/linkguard-cloud/internal/comportamento"
	"github.com/giovanibalarini/linkguard-cloud/internal/config"
	"github.com/giovanibalarini/linkguard-cloud/internal/dnstap"
	"github.com/giovanibalarini/linkguard-cloud/internal/domainrouting"
	"github.com/giovanibalarini/linkguard-cloud/internal/domtargets"
	"github.com/giovanibalarini/linkguard-cloud/internal/firewall"
	"github.com/giovanibalarini/linkguard-cloud/internal/firewallrules"
	"github.com/giovanibalarini/linkguard-cloud/internal/hostflows"
	"github.com/giovanibalarini/linkguard-cloud/internal/hostquota"
	"github.com/giovanibalarini/linkguard-cloud/internal/hosts"
	"github.com/giovanibalarini/linkguard-cloud/internal/hosttraffic"
	"github.com/giovanibalarini/linkguard-cloud/internal/iptables"
	"github.com/giovanibalarini/linkguard-cloud/internal/metrics"
	"github.com/giovanibalarini/linkguard-cloud/internal/monitoring"
	"github.com/giovanibalarini/linkguard-cloud/internal/netif"
	"github.com/giovanibalarini/linkguard-cloud/internal/netsvc"
	"github.com/giovanibalarini/linkguard-cloud/internal/nftables"
	"github.com/giovanibalarini/linkguard-cloud/internal/notify"
	"github.com/giovanibalarini/linkguard-cloud/internal/platform"
	"github.com/giovanibalarini/linkguard-cloud/internal/routes"
	"github.com/giovanibalarini/linkguard-cloud/internal/saida"
	"github.com/giovanibalarini/linkguard-cloud/internal/secrets"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
	"github.com/giovanibalarini/linkguard-cloud/internal/sysprep"
	"github.com/giovanibalarini/linkguard-cloud/internal/system"
	"github.com/giovanibalarini/linkguard-cloud/internal/tlscert"
	"github.com/giovanibalarini/linkguard-cloud/internal/tsdb"
	"github.com/giovanibalarini/linkguard-cloud/internal/unbound"
	"github.com/giovanibalarini/linkguard-cloud/internal/wireguard"
)

var version = "dev"

// pkgInstallTimeout is the deadline for a single apt-get run. Sized for a
// package download over a bad link, not for a local command: unbound +
// dns-root-data or wireguard-tools over a slow mirror, and the measurement that motivated this was a
// first apply taking ~40s on a healthy office link — with a 30s executor
// underneath it.
//
// It is a ceiling for a hung apt, not an expectation. Nothing waits on it
// synchronously any more: the boot path runs it off the critical path (see
// the goroutine below) and the HTTP path runs it on a request whose context
// is deliberately detached from the client's.
const pkgInstallTimeout = 10 * time.Minute

// captureTimeout é o teto do executor da captura de pacotes: a maior janela
// que o pktcapture aceita, com folga para o processo subir e sair. Não é a
// duração da captura — essa vem do pedido do admin, limitada em
// pktcapture.MaxDurationSec.
const captureTimeout = 3 * time.Minute

func main() {
	os.Exit(run())
}

// algumaPlacaPorDHCP diz se alguma placa da máquina pega endereço por DHCP.
//
// Decide se a chain input precisa aceitar udp/68: a renovação unicast em T1
// passa por conntrack, mas o REBIND sai de 0.0.0.0:68 para broadcast e não casa
// a tupla de retorno. Sem a linha, a WAN nunca mais renova depois de um flap de
// link — e o sintoma aparece dias depois, como "a internet caiu sozinha".
//
// Lê o KERNEL (o flag `dynamic` do endereço), e não a tabela de interfaces
// editadas pelo painel: na nuvem ninguém edita a placa, e a VNIC primária da
// Oracle pega endereço por DHCP. A tabela vazia fazia esta função dizer "não"
// justamente na máquina que depende da linha.
//
// Erro de leitura devolve TRUE: emitir a linha à toa numa máquina estática não
// abre nada (ninguém manda DHCP para ela), enquanto omiti-la numa máquina que
// precisa dela derruba a internet. O lado seguro é o permissivo aqui, e só aqui.
func algumaPlacaPorDHCP(ctx context.Context, svc *netif.Service) bool {
	views, err := svc.List(ctx)
	if err != nil {
		return true
	}
	for _, v := range views {
		if !v.Live.System && v.AddrMode == netif.AddrModeDHCP {
			return true
		}
	}
	return false
}

func run() int {
	configPath := flag.String("config", "/etc/linkguard-cloud/config.json", "Path to config file")
	addr := flag.String("addr", "", "Listen address override")
	port := flag.Int("port", 0, "Listen port override")
	dryRun := flag.Bool("dry-run", false, "Run in dry-run mode")
	debug := flag.Bool("debug", false, "Enable debug logs")
	showVersion := flag.Bool("version", false, "Print version and exit")
	notifyDown := flag.Bool("notify-down", false, "Send a 'service down' notification and exit (systemd OnFailure)")
	prepareSystem := flag.Bool("prepare-system", false, "Create the filesystem paths the systemd unit needs before it can start, then exit")
	prepareSystemAtStart := flag.Bool("prepare-system-at-start", false, "Same as --prepare-system plus the paths that may only be created outside a dpkg transaction (called by the unit's ExecStartPre), then exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return 0
	}

	// Chamado pelos TRÊS caminhos de instalação (postinst do .deb,
	// deploy/install.sh, `make install`) logo depois de copiar o binário,
	// para que os três deixem a máquina no MESMO estado. Ver
	// internal/sysprep: sem isso a unidade morre em 226/NAMESPACE, em loop
	// de restart, disparando o OnFailure a cada tentativa — e sem nunca
	// executar uma linha do binário que instalaria a base.
	//
	// --prepare-system-at-start é o mesmo trabalho feito pela unidade, no
	// ExecStartPre, para os caminhos que um instalador não pode criar por
	// pertencerem a outro pacote (/etc/nftables.conf é conffile do
	// `nftables`): criá-lo dentro da transação do dpkg fazia o `apt install`
	// numa máquina pelada parar no prompt de conffile. Ver internal/sysprep,
	// tipo Stage.
	if *prepareSystem || *prepareSystemAtStart {
		stage := sysprep.StageInstall
		if *prepareSystemAtStart {
			stage = sysprep.StageServiceStart
		}
		created, err := sysprep.Prepare("", stage)
		for _, line := range created {
			fmt.Println("[INFO] criado: " + line)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "[ERRO] "+err.Error())
			return 1
		}
		return 0
	}

	setFlags := map[string]bool{}
	flag.Visit(func(f *flag.Flag) {
		setFlags[f.Name] = true
	})

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load config", "path", *configPath, "err", err)
		return 1
	}
	if err := cfg.Validate(); err != nil {
		slog.Error("configuração inválida", "err", err)
		return 1
	}

	if setFlags["addr"] {
		cfg.ListenAddr = *addr
	}
	if setFlags["port"] {
		cfg.Port = *port
	}
	if setFlags["dry-run"] {
		cfg.DryRun = *dryRun
	}
	if setFlags["debug"] {
		cfg.Debug = *debug
	}

	level := slog.LevelInfo
	if cfg.Debug {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})))

	if *notifyDown {
		return notifyDownRun(cfg.DBPath)
	}

	db, err := openStore(cfg)
	if err != nil {
		return 1
	}
	defer db.Close()

	// Em que máquina estamos, e o que ela deixa o produto fazer. Tem que vir
	// antes de buildServices porque é dali para baixo que o resto deriva, e
	// depois de openStore porque o resultado é cacheado na tabela settings.
	// Nunca derruba o boot — ver detectPlatformOnBoot.
	plat := detectPlatformOnBoot(db)

	s, err := buildServices(cfg, db, plat)
	if err != nil {
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	writers := startBackground(ctx, s)
	return serveHTTP(ctx, s, writers)
}

// notifyDownRun é o caminho do --notify-down: avisa que o serviço caiu e sai.
// Devolve o código de saída do processo.
//
// A unidade que chama é Type=oneshot (deploy/linkguard-cloud-notify-down.service,
// disparada pelo OnFailure= da unidade principal), então este código de saída
// vira o estado da unidade — aparece no `systemctl status`, no `is-failed` e no
// journal. Ele é a única forma de quem olha a máquina depois distinguir "o aviso
// saiu" de "o aviso não saiu".
//
// O defeito que isto fecha (issue #60): o storage.Open era seguido de
// `if err == nil { … }` sem else, sem log, e a função terminava em `return 0`.
// Com o banco ilegível o processo dizia "avisei" tendo enviado nada. É o pior
// modo de falha possível — silencioso, no mecanismo que existe para avisar que
// algo deu errado, e disparado justamente quando algo deu errado. Banco
// ilegível no momento em que o serviço caiu é sinal de problema MAIOR, não
// menor.
//
// O mapeamento dos códigos:
//
//	banco não abre, chave órfã, chave não carrega → 1 (não dá para nem tentar)
//	todos os canais habilitados falharam          → 1 (o aviso não saiu)
//	ao menos um canal entregou                    → 0
//	nenhum canal habilitado                       → 0
//
// O último merece a explicação: não ter canal configurado é escolha do admin,
// não falha. Sair 1 aí deixaria uma unidade permanentemente vermelha em toda
// instalação sem notificação — e uma unidade que vive vermelha é uma que
// ninguém mais olha, o que custaria justamente o sinal que este código de saída
// existe para dar.
func notifyDownRun(dbPath string) int {
	db, err := storage.Open(dbPath)
	if err != nil {
		slog.Error("notify-down: banco inacessível, nenhum aviso foi enviado",
			"path", dbPath, "err", err)
		return 1
	}
	defer db.Close() //nolint:errcheck // processo saindo

	if orphanErr := secrets.CheckNotOrphaned(secretKeyPath, db); orphanErr != nil {
		slog.Error("notify-down: refusing to start", "err", orphanErr)
		return 1
	}
	key, keyErr := secrets.LoadOrGenerateKey(secretKeyPath)
	if keyErr != nil {
		slog.Error("notify-down: failed to load secret key", "err", keyErr)
		return 1
	}

	sec := secrets.NewService(db, key)
	errs := notify.NewService(db, sec).SendNow("critical",
		"LinkGuard caiu", "O serviço linkguard-cloud parou inesperadamente no firewall.")

	// send() devolve uma entrada por canal HABILITADO: slice vazia é "nenhum
	// canal configurado", que não é o mesmo que "todos falharam".
	failed := 0
	for _, e := range errs {
		if e != nil {
			failed++
			slog.Warn("notify-down send failed", "err", e)
		}
	}
	if len(errs) > 0 && failed == len(errs) {
		slog.Error("notify-down: todos os canais falharam, nenhum aviso saiu",
			"canais", len(errs))
		return 1
	}
	if len(errs) == 0 {
		slog.Warn("notify-down: nenhum canal de notificação está habilitado; nada foi enviado")
	}
	return 0
}

// openStore abre o banco e semeia o que precisa existir antes de qualquer
// serviço: o administrador inicial e os papéis de RBAC.
//
// Os slog.Error ficam AQUI, com o mesmo texto e os mesmos campos de antes, e
// quem chama só devolve 1 sem logar de novo. Log de boot de firewall é lido em
// emergência: um refactor pode mudar de onde a linha sai, não o que ela diz.
func openStore(cfg *config.Config) (*storage.DB, error) {
	db, err := storage.Open(cfg.DBPath)
	if err != nil {
		slog.Error("failed to open database", "path", cfg.DBPath, "err", err)
		return nil, err
	}

	// O administrador inicial vem ANTES dos papéis: é o EnsureDefaultRoles que
	// amarra o papel de admin à conta, e a conta precisa existir para a
	// foreign key aceitar. (O EnsureDefaultRoles também confere a existência,
	// então a ordem é uma garantia a mais, não a única.)
	if err := seedInitialAdmin(db); err != nil {
		slog.Error("failed to seed initial admin", "err", err)
		db.Close() //nolint:errcheck // já estamos abortando o boot
		return nil, err
	}

	if err := seedDefaultRoles(db); err != nil {
		slog.Error("failed to seed default roles", "err", err)
		db.Close() //nolint:errcheck // já estamos abortando o boot
		return nil, err
	}
	return db, nil
}

// services é tudo o que o boot monta, nomeado. Existe para que a MONTAGEM
// possa ser exercitada por um teste (boot_wiring_runtime_test.go) sem passar
// pelo main: antes disto, a única forma de perguntar "o Service saiu com a
// guarda ligada?" era ler main.go como texto.
//
// Os nomes dos campos são os nomes das variáveis locais que a montagem usa,
// para que ler buildServices e ler este struct dê a mesma imagem.
type services struct {
	cfg *config.Config
	db  *storage.DB

	// plat é a plataforma detectada no boot, por VALOR: não há
	// platform.Current() global, e o zero-value é permissivo, então um
	// caminho que esqueça de preenchê-la se comporta como o produto se
	// comporta hoje. Ver internal/platform.
	plat platform.Snapshot

	// exec é o executor da aplicação (30 s). pkgExec é o dos gerenciadores de
	// pacote (10 min) — ver pkgInstallTimeout.
	exec    firewall.Executor
	pkgExec firewall.Executor

	secretsSvc   *secrets.Service
	alertSvc     *alerts.Service
	notifySvc    *notify.Service
	authSvc      *auth.Service
	iptSvc       *iptables.Service
	routeSvc     *routes.Service
	nftSvc       *nftables.Service
	frSvc        *firewallrules.Service
	unboundSvc   *unbound.Service
	netSvc       netsvc.Provider
	trafficSvc   *hosttraffic.Service
	fluxosSvc    *hostflows.Servico
	hostSvc      *hosts.Service
	nomesSvc     *hosts.Nomes
	sysCollector *system.Collector
	rrdSvc       *tsdb.Service
	hostSampler  *hosttraffic.Sampler
	hostQuotaSvc *hostquota.Service
	wgSvc        *wireguard.Service
	aiClient     *ai.Client

	promReg          *prometheus.Registry
	appMetrics       *metrics.Metrics
	metricsCollector *monitoring.Collector
	backupSched      *backup.Scheduler
	journalSched     *monitoring.JournalScheduler
	updatesSched     *monitoring.UpdatesScheduler

	server    *api.Server
	dnstapSvc *dnstap.Servico
	// domSvc é o alimentador de alvo por domínio (#123). Escreve no KERNEL e
	// não no banco, então não é um spawnWriter — ver startBackground.
	domSvc        *domtargets.Servico
	domainRouting *domainrouting.Coordinator
	sondaSaida    *saida.Sonda

	// ntpInputState é a MESMA fonte que foi entregue a
	// nftSvc.SetInputChainSources, guardada aqui porque a reconciliação de
	// boot (em startBackground) também precisa dela — e as duas discordarem
	// sobre o que está configurado é o que a Fase C2 existe para impedir.
	ntpInputState func() ([]string, bool, error)

	// interval é a cadência do coletor de métricas.
	interval time.Duration
}

// secretKeyPath é o arquivo da chave que cifra os segredos do banco.
//
// É var, e não const, por um motivo só: buildServices é exercitada por teste
// (o que esta issue existe para permitir) e o teste não pode escrever em /etc.
// Nada em produção troca este valor.
var secretKeyPath = "/etc/linkguard-cloud/secret.key"

// buildServices monta os ~25 serviços do produto e devolve todos nomeados.
//
// A LIGAÇÃO ENTRE OS SERVIÇOS MORA AQUI, e não numa função de "wiring"
// separada, apesar de a issue #24 propor o contrário. O motivo é o que a
// própria issue reclama: hoje a ligação é "opcional e silenciosa", e uma
// função de ligação separada mantém essa propriedade — passa a existir um
// *services completo, com todos os campos preenchidos, que ninguém guardou.
// Ligando aqui, quem tem um *services tem um nftSvc com a guarda do Persist e
// com as duas fontes da chain input, porque não há outro caminho para obtê-lo.
// É a aproximação de "não compila um Service sem PersistGuard" que se
// consegue sem mexer na API de internal/nftables — ver o relatório da issue
// para por que a versão literal daquele critério esbarra num ciclo
// (nftables.Service precisa de firewallrules.Service, que precisa de
// nftables.Service).
//
// Os slog.Error ficam aqui pelo mesmo motivo de openStore.
func buildServices(cfg *config.Config, db *storage.DB, plat platform.Snapshot) (*services, error) {
	if err := secrets.CheckNotOrphaned(secretKeyPath, db); err != nil {
		slog.Error("refusing to start", "err", err)
		return nil, err
	}
	secretKey, err := secrets.LoadOrGenerateKey(secretKeyPath)
	if err != nil {
		slog.Error("failed to load or generate secret key", "err", err)
		return nil, err
	}
	secretsSvc := secrets.NewService(db, secretKey)
	if err := secrets.MigrateFromSettings(db, secretsSvc); err != nil {
		slog.Error("failed to migrate legacy secrets", "err", err)
		return nil, err
	}

	var exec firewall.Executor = firewall.NewRealExecutor(30 * time.Second)
	if cfg.DryRun {
		exec = firewall.NewDryRunExecutor()
	}

	// pkgExec is the executor for anything that runs a package manager. The
	// application's `exec` has a 30s deadline — right for `nft`, `ip` or
	// `systemctl`, far too short for an apt-get fetching packages, and worse
	// than too short: when the deadline fires, the apt does NOT die with it
	// (systemd-run's transient unit finishes the transaction), so LinkGuard
	// reports a failure that is not happening. Every apt path — the base at
	// boot, the on-demand DHCP/DNS install, chrony — uses this one.
	pkgExec := exec
	if !cfg.DryRun {
		pkgExec = firewall.NewRealExecutor(pkgInstallTimeout)
	}

	// A captura de pacotes tem prazo próprio pelo mesmo motivo, ao contrário:
	// ela roda por até pktcapture.MaxDurationSec, e os 30 s do executor da
	// aplicação matariam toda captura mais longa que meio minuto reportando
	// falha que não houve. A janela real de cada captura continua sendo
	// imposta lá dentro; este prazo é só o teto que não pode ser menor que ela.
	capExec := exec
	if !cfg.DryRun {
		capExec = firewall.NewRealExecutor(captureTimeout)
	}

	alertSvc := alerts.NewService(db)
	// Close state-derived alerts left open by a previous process before any
	// watcher starts observing again: the health state that gates whether a
	// condition is "new" lives only in memory, so every restart forgets
	// what was already true. Whatever is still genuinely wrong gets
	// re-raised within the first tick or two; whatever was fixed while the
	// service was down (three alerts had to be resolved by hand on
	// 2026-08-11 for exactly this reason) stays closed. Must run before the
	// collectors/schedulers below start, so a still-true condition is
	// re-raised by the first tick rather than racing this cleanup.
	alertSvc.ResolveStaleOnStartup()
	notifySvc := notify.NewService(db, secretsSvc)
	alertSvc.SetNotifier(notifySvc)
	authSvc := auth.NewService(db, cfg.JWTSecret, secretsSvc)
	iptSvc := iptables.NewService(exec)
	routeSvc := routes.NewService(exec)
	nftSvc := nftables.NewService(exec)
	frSvc := firewallrules.NewService(db, nftSvc)
	// Bloqueio administrativo que não está mais na lista de grupos é motivo
	// para alcançar o operador onde ele estiver, não só para deixar a faixa
	// vermelha na tela do firewall.
	frSvc.SetAlerter(alertSvc)
	// A chain input tem um renderizador só (Fase C2): ela é reconstruída
	// inteira, com a proteção do NTP E os jumps dos grupos de escopo input,
	// venha a passada de onde vier. Quem reconcilia o NTP sabe o estado do
	// NTP e precisa dos grupos; quem reconcilia os grupos sabe os grupos e
	// precisa do estado do NTP — estas duas funções são o que fecha esse
	// círculo sem internal/nftables importar internal/storage.
	//
	// Ligado aqui, junto da construção, e não perto de um dos reconciles: sem
	// isto, salvar um grupo apagaria a proteção do NTP da chain input.
	// TestMainWiresTheInputChainSources guarda essa ligação contra deriva.
	//
	// O erro de leitura viaja junto e NÃO vira "servir NTP está desligado" —
	// ver ntpInputStateFrom.
	// A versão de nuvem não serve hora para a rede: a Oracle entrega em
	// 169.254.169.254. A fonte de NTP da chain input segue ligada, sempre
	// desligada, até o redesenho do firewall tirar o NTP de dentro do nftables.
	ntpInputState := func() ([]string, bool, error) { return nil, false, nil }
	nftSvc.SetInputChainSources(frSvc.StoredGroups, ntpInputState)
	// E a guarda do /etc/nftables.conf (I-1 da revisão final da Fase C2):
	// enquanto houver uma mudança aguardando confirmação, o ruleset vivo NÃO vai
	// para o arquivo que o nftables.service carrega no boot — senão uma queda de
	// energia dentro dos 90 segundos faz a máquina voltar com a regra não
	// confirmada valendo, antes de o LinkGuard subir para reverter. Ligada aqui,
	// junto da construção, pelo mesmo motivo da linha acima; guardada contra
	// deriva por TestMainWiresThePersistGuard.
	nftSvc.SetPersistGuard(frSvc.UnconfirmedChangePending)
	unboundSvc := unbound.NewService(exec)
	// O caminho sob demanda (o admin liga o DNS no painel) instala
	// unbound + dns-root-data. Sem isto ele herdava o executor de 30s
	// e, ao estourar, mentia dizendo que não conseguiu instalar enquanto o
	// apt terminava a instalação com sucesso.
	unboundSvc.SetInstallExecutor(pkgExec)
	// O resolv.conf sozinho não prova nada: se a busca do NSS não chegar ao
	// módulo dns, ele fica correto e irrelevante (issue #195). Quem mede isso é
	// o vigia monitoring.Collector.checkCaminhoNSS, a cada tique — e não este
	// serviço, que reconcilia o arquivo uma vez por processo. Alerta que só
	// nasce e morre no boot deixa o painel vermelho até o próximo reboot.
	var netSvc netsvc.Provider = unboundSvc
	trafficSvc := hosttraffic.NewService(exec)
	// O nome de cada máquina da VCN vem do DNS reverso do resolvedor da
	// própria VCN, perguntado direto: o resolv.conf desta caixa aponta para o
	// unbound da VPN, que não conhece a zona interna da Oracle. Fora da OCI
	// não há esse resolvedor, e a pergunta vai ao resolvedor do sistema.
	servidorDeNomes := ""
	if plat.Facts.Kind == platform.KindOCI {
		servidorDeNomes = hosts.ResolvedorOCI
	}
	nomesSvc := hosts.NovosNomes(servidorDeNomes, db.SetHostnames)
	hostSvc := hosts.NewService(db, nftSvc, nomesSvc)
	netifSvc := netif.NewService(exec, db, func() ([]string, error) { return wansEfetivas(context.Background(), exec, plat) })
	// Regra que cita uma interface inexistente carrega no nft SEM ERRO e nunca
	// casa — o painel mostra a regra ativa e ela não protege nada. Aconteceu em
	// produção (reshuffle de PCI, enp4s0 → enp5s0). Esta ligação é o que permite
	// ao produto AVISAR; corrigir sozinho seria adivinhar qual interface o admin
	// queria, e desativar a regra em silêncio é o mesmo defeito com outro nome.
	// A postura do firewall (issue #78). As duas fontes andam juntas: sem a de
	// acesso administrativo, uma política restritiva renderiza sem saber o que
	// manter aberto — e é assim que o admin se tranca fora. O renderizador
	// aborta nesse caso, e esta ligação é o que faz o caso não acontecer.
	nftSvc.SetInputPolicySource(frSvc.InputPolicy)
	// A decisão de fechar a gerência nas WANs é lida a cada reconciliação, e não
	// guardada em memória, pelo mesmo motivo da política: a reversão automática
	// da janela de 90 s reescreve o valor no banco, e a reconciliação seguinte
	// tem de obedecer ao que a reversão gravou — não ao que o processo lembrava.
	nftSvc.SetWANMgmtClosedSource(frSvc.WANMgmtClosed)
	// Alerta que NOMEIA aparelho só sai da caixa com escolha explícita (#117).
	// Ver tiposQueNomeiamAparelho em internal/alerts e a regra escrita em
	// internal/metrics/exposicao.go.
	alertSvc.SetNotificarAparelho(func() (bool, error) {
		return notifySvc.LoadConfig().NotificarAparelho, nil
	})
	// A contenção de tentativa repetida (#127) é opt-in e lida a cada
	// reconciliação, pelo mesmo motivo das outras: o valor pode mudar pela tela
	// e tem de valer na reconciliação seguinte, sem reiniciar nada.
	nftSvc.SetEdgeContainmentSource(frSvc.EdgeContainment)
	nftSvc.SetForwardPolicySource(frSvc.ForwardPolicy)
	// O EIXO DAS REGRAS DE FIREWALL SAI DAQUI.
	//
	// Numa caixa com várias interfaces, "veio de dentro" é `iifname != { WANs
	// }` — a forma que a produção tem hoje, byte a byte. Numa VM de nuvem com
	// UMA placa, entra e sai pela mesma interface e essa frase não discrimina
	// nada: o eixo passa a ser o CIDR da rede local. Ver internal/nftables/zone.go.
	//
	// Lido a cada reconciliação, e não capturado uma vez: a sub-rede pode ser
	// configurada pela tela depois do boot, e o eixo tem de acompanhar sem
	// reiniciar nada — mesma disciplina das outras fontes acima.
	nftSvc.SetZoneFactsSource(func() (nftables.ZoneFacts, error) {
		return nftables.ZoneFacts{
			// Capable() e não o campo Capabilities: um instantâneo vazio ou de
			// plataforma desconhecida devolve o conjunto PERMISSIVO, isto é,
			// RoutedTransit true, isto é, o eixo de interface de sempre.
			Hairpin:   !plat.Capable().RoutedTransit,
			LocalNets: redesLocais(db, plat),
			// A MTU do CAMINHO externo, quando a plataforma a afirma — e 0,
			// que é "não sei", em todo o resto. É o número que o ajuste de MSS
			// usa numa VM de nuvem, onde `rt mtu` leria a MTU que a placa
			// ANUNCIA (9000) em vez da que o caminho suporta (1500).
			//
			// uplinkDaPlataforma, E NÃO uplinkEfetivo: A MTU DO CAMINHO É UM
			// FATO DA REDE, NÃO UMA CONSEQUÊNCIA DE QUEM ESCOLHEU O UPLINK.
			// Pelo efetivo, cadastrar o link pela tela — que é o que já foi
			// feito no bastion — zerava este número, e aí a mss_clamp não
			// voltava para `rt mtu` coisa nenhuma: `rt mtu` mora no ramo
			// PerLink(), que é falso em hairpin, então a chain simplesmente
			// nascia VAZIA e o `docker pull` voltava a pendurar sem nada
			// falhar. O caminho continua suportando 1500 quer o admin tenha
			// digitado "ens3" num formulário, quer não.
			//
			// A guarda continua estreita do mesmo jeito, porque é a mesma:
			// nuvem + IMDS autoritativo + VNIC única. Fora disso o número é 0 e
			// a produção segue por `rt mtu`, byte a byte.
			PathMTU: uplinkDaPlataforma(plat).PathMTU,
		}, nil
	})
	nftSvc.SetAdminAccessSource(func() (nftables.AdminAccess, error) {
		// As sub-redes das placas, como a fabric informa. Nunca um default
		// cravado: essa lista existe justamente para o admin não se trancar
		// para fora, e uma rede de terceiro aqui dentro seria buraco.
		redes := redesDasPlacas(plat)
		// A porta do painel NÃO é fixa: 8080 é o default do binário, 9997 o do
		// .deb, e quem põe proxy usa outra. Fixá-la aqui deixaria o anti-lockout
		// mudo justamente em quem não usa o padrão.
		// A porta do SSH sai de onde o sshd está ESCUTANDO, não de um literal.
		// Fixá-la em 22 era o mesmo erro que o comentário acima denuncia para a
		// porta do painel, cometido para o outro serviço: numa caixa com
		// `Port 2222`, a regra que existe para não trancar o admin descartaria
		// exatamente a porta por onde ele entra.
		return nftables.AdminAccess{
			PanelPort:   cfg.Port,
			SSHPorts:    system.SSHPorts(context.Background(), exec),
			ExtraPorts:  cfg.ExtraPorts,
			LANNetworks: redes,
			WANIsDHCP:   algumaPlacaPorDHCP(context.Background(), netifSvc),
		}, nil
	})

	frSvc.SetIfaceLister(func() ([]string, error) {
		views, err := netifSvc.List(context.Background())
		if err != nil {
			return nil, err
		}
		nomes := make([]string, 0, len(views))
		for _, v := range views {
			nomes = append(nomes, v.Name)
		}
		return nomes, nil
	})
	sysCollector := system.NewCollector()
	// O consumo por host passa a vir dos contadores do nftables (#112), e não
	// mais das conexões vivas do conntrack — que perdiam os bytes assim que a
	// conexão fechava. Ver internal/nftables/accounting.go.
	trafficSvc.SetCounterSource(nftSvc)

	// O registro de conversa por host (#115) fica numa TABELA nft PRÓPRIA, que o
	// Persist não dumpa — ver o topo de internal/nftables/flows.go. Nasce
	// desligado; quem liga é o administrador, na tela.
	fluxosSvc := hostflows.NovoServico(nftSvc, db)

	// A opção de registrar bloqueios (#122) é lida do banco a cada
	// reconciliação, e não guardada em memória: o admin pode ligá-la pelo
	// painel, e o valor tem de valer na reconciliação seguinte sem reiniciar
	// nada. Mesmo desenho da política padrão da chain input.
	nftSvc.SetBlockLogSource(func() (bool, error) { return handlers.BlockLogEnabled(db) })

	// A proteção de entrada das WANs (#119) lê a MESMA lista que o masquerade e
	// a contabilidade, e pelo mesmo motivo lê a cada reconciliação em vez de
	// guardar em memória: trocar a interface de um link tem de valer na
	// reconciliação seguinte, sem reiniciar nada.
	//
	// E é wansEfetivas, e não o laço sobre os links: numa VM de nuvem sem link
	// cadastrado a lista passa a ser a do uplink derivado da plataforma, e a
	// proteção de entrada (mais a tela de exposição) deixa de dizer "sem WAN
	// conhecida" numa máquina que tem uma.
	nftSvc.SetWANInterfacesSource(func() ([]string, error) { return wansEfetivas(context.Background(), exec, plat) })

	rrdSvc := tsdb.NewService(db)

	// A série de consumo por host (#113) usa as três peças que já existem: os
	// contadores do nftables (#112), a tabela de vizinhança para resolver o
	// MAC, e o tsdb como gravador — com o rollup e a retenção que ele já tem.
	hostSampler := hosttraffic.NewSampler(nftSvc, hostSvc, rrdSvc)

	// A cota por APARELHO (#126) consome os MESMOS deltas de byte que alimentam
	// as séries por host — ver hosttraffic.UsageSink. O sink é ligado aqui,
	// antes de qualquer Run: o amostrador lê o campo sem lock dentro do
	// SampleOnce, e ligá-lo depois do laço começar seria escrita concorrente.
	//
	// Ele MEDE E AVISA, e não corta nem limita nada. Ver o cabeçalho do pacote
	// antes de considerar ligar qualquer enforcement aqui.
	hostQuotaSvc := hostquota.NewService(db, alertSvc)
	hostSampler.SetUsageSink(hostQuotaSvc)

	// WireGuard owns its desired state and secrets. The client config points at
	// the public address the admin informs: in the cloud it is the reserved IP,
	// which exists on no interface and so cannot be discovered here.
	wgSvc := wireguard.NewService(db, secretsSvc, exec)
	wgSvc.SetInstallExecutor(pkgExec)
	// These callbacks are read at every reconcile. No WireGuard state is
	// duplicated into nftables or netsvc persistence, so boot and retries are
	// idempotent and a disabled tunnel removes both projections.
	nftSvc.SetWireGuardInputSource(wgSvc.InputPort)
	unboundSvc.SetDNSBindingSource(wgSvc.DNSBinding)

	// Optional AI advisory layer (BYOK): disabled by default (ai.LoadConfig's
	// Enabled defaults to false), and swallows its own failures.
	aiBudget := ai.NewBudgetGuard(db)
	aiClient := ai.NewClient(secretsSvc, aiBudget, func() ai.Config { return ai.LoadConfig(db) })

	promReg := prometheus.NewRegistry()
	appMetrics := metrics.New(promReg)
	metricsCollector := monitoring.NewCollector(db, appMetrics, alertSvc, exec, rrdSvc)
	// O item "Regras no próximo boot" da Saúde do sistema. Sem esta linha o
	// vigia não tem como saber nada sobre o /etc/nftables.conf e o item
	// simplesmente não aparece — a falha do Persist voltaria a ser só um WARN no
	// journal, que é exatamente o que o §10 da validação em VM mediu. Guardada
	// contra deriva por TestMainWiresTheBootPersistSource.
	metricsCollector.SetBootPersistSource(nftSvc)
	// O vigia de NAT compara o kernel contra a MESMA lista que o firewall
	// escreve. Sem esta linha ele retorna cedo com lista vazia, isto é, fica
	// cego exatamente onde o NAT é escrito.
	metricsCollector.SetWANSource(func() ([]string, error) { return wansEfetivas(context.Background(), exec, plat) })
	backupSched := backup.NewScheduler(db, secretsSvc, notifySvc, alertSvc, version)
	journalSched := monitoring.NewJournalScheduler(metricsCollector)
	updatesSched := monitoring.NewUpdatesScheduler(metricsCollector)

	// Criado ANTES do servidor: api.New monta o roteador na mesma chamada, e as
	// rotas leem o coletor na hora do registro (#116).
	dnstapSvc := dnstap.NovoServico()
	// Alvo por domínio (#123): o alimentador ouve as respostas que o coletor já
	// extraiu, em vez de abrir um segundo consumidor do socket. Ligado AQUI,
	// antes de qualquer Run, porque o observador é lido sem lock pelas
	// goroutines de conexão — ver SetObservador.
	domSvc := domtargets.NovoServico(nftSvc)
	domainRouting := domainrouting.New(db, domSvc)
	// Os endereços da PRÓPRIA caixa, que o filtro de categoria do índice não
	// tem como recusar: o endereço público pelo qual a VPN é alcançada (o IP
	// reservado da Oracle não aparece em placa nenhuma), o endereço privado de
	// cada VNIC e o roteador virtual da VCN. Sem esta lista, um domínio hostil
	// que responde com qualquer um deles põe o firewall contra a própria caixa.
	// Recarregada a cada poda: o endereço da VPN se edita pela tela.
	domSvc.DefinirFonteDeEnderecosProprios(func() []string {
		return enderecosProprios(plat, wgSvc)
	})
	dnstapSvc.SetObservador(domSvc.Observar)

	// UMA definição de "o coletor de DNS está ligado", usada por todo mundo que
	// precisa dela. Lida A CADA CHAMADA porque o admin liga e desliga o dnstap
	// na tela de serviços de rede sem reiniciar nada — um valor lido aqui no
	// arranque estaria errado a partir do primeiro clique.
	dnstapLigado := func() bool {
		netCfg := netsvc.DefaultConfig()
		if raw, _ := db.GetSetting("netsvc_config"); raw != "" {
			_ = json.Unmarshal([]byte(raw), &netCfg)
		}
		return netCfg.DNSTapEnabled
	}
	// O alvo por domínio aprende SÓ pelo dnstap. Com o coletor desligado ele
	// nunca recebe um endereço, e a tela mostraria rotatividade zero e último
	// aprendizado zero em todo domínio listado — igualzinho a "ninguém acessou
	// estes nomes". As duas leituras levam a ações opostas, e é por isso que a
	// resposta da API tem de dizer qual das duas é. Ver Estado.Observando.
	domSvc.DefinirFonteDeObservacao(dnstapLigado)

	// O destino do fluxo ganha nome pelo mesmo mapa da #116. Sem coletor de
	// dnstap ligado o mapa fica vazio e a tela mostra o endereço cru dizendo por
	// quê — o que não pode é a tela deixar o admin achar que o destino não tem
	// nome quando o produto é que não está olhando o DNS.
	//
	// O SEGUNDO ARGUMENTO NÃO É ENFEITE. dnstap.Servico.Mapa() nunca devolve
	// nil, e esta chamada é incondicional — então um `s.nomes != nil` do outro
	// lado dava `true` em toda máquina, e o aviso "o mapa está desligado" era
	// código morto. Quem sabe se o coletor está ligado é a configuração de
	// serviços de rede, lida A CADA CONSULTA porque o admin liga e desliga o
	// dnstap na tela sem reiniciar nada.
	fluxosSvc.SetNomes(dnstapSvc.Mapa(), dnstapLigado)
	// Séries por aparelho para o coletor do cliente (#118). Fora do registro
	// aberto do Prometheus de propósito — ver internal/metrics/exposicao.go.
	porHost := metrics.NovoPorHost()
	hostSampler.SetPorHost(porHost)

	// A sonda de saída para a Internet: no lugar do monitor de link, que media
	// cada WAN cadastrada. Grava as séries no tsdb e abre/fecha o alerta de
	// queda. Ver internal/saida.
	sondaSaida := saida.Nova(rrdSvc, alertSvc)

	server := api.New(api.Config{
		Addr:          cfg.Addr(),
		DryRun:        cfg.DryRun,
		WebFS:         linkguardcloud.WebFS,
		PromReg:       promReg,
		Version:       version,
		PkgExec:       pkgExec,
		CaptureExec:   capExec,
		DNSTap:        dnstapSvc,
		PorHost:       porHost,
		Fluxos:        fluxosSvc,
		HostQuota:     hostQuotaSvc,
		DomainRouting: domainRouting,
		// A MESMA derivação que o firewall usa para decidir o que escrever: a
		// tela e o kernel não podem discordar sobre quais são as WANs desta
		// máquina. Ver cmd/linkguard-cloud/uplink.go.
		WANSource: func() ([]string, error) { return wansEfetivas(context.Background(), exec, plat) },
		Uplink: func(ctx context.Context) handlers.UplinkView {
			v := uplinkParaTela(ctx, exec, plat)
			l := sondaSaida.Atual()
			v.Saude = handlers.UplinkHealth{Estado: l.Estado, LatenciaMs: l.LatenciaMs, PerdaPct: l.PerdaPct, VerificadoEm: l.VerificadoEm, Alvos: l.Alvos}
			return v
		},
		WireGuard: wgSvc,
	}, db, exec, iptSvc, routeSvc, alertSvc, authSvc, hostSvc, netifSvc, nftSvc, frSvc, netSvc, notifySvc, trafficSvc, sysCollector, rrdSvc, promReg, metricsCollector, secretsSvc, aiClient, backupSched)

	interval := time.Duration(cfg.MonitorInterval) * time.Second

	return &services{
		cfg:              cfg,
		db:               db,
		plat:             plat,
		exec:             exec,
		pkgExec:          pkgExec,
		secretsSvc:       secretsSvc,
		alertSvc:         alertSvc,
		notifySvc:        notifySvc,
		authSvc:          authSvc,
		iptSvc:           iptSvc,
		routeSvc:         routeSvc,
		nftSvc:           nftSvc,
		frSvc:            frSvc,
		unboundSvc:       unboundSvc,
		netSvc:           netSvc,
		trafficSvc:       trafficSvc,
		fluxosSvc:        fluxosSvc,
		hostSvc:          hostSvc,
		nomesSvc:         nomesSvc,
		sysCollector:     sysCollector,
		rrdSvc:           rrdSvc,
		hostSampler:      hostSampler,
		hostQuotaSvc:     hostQuotaSvc,
		wgSvc:            wgSvc,
		aiClient:         aiClient,
		promReg:          promReg,
		appMetrics:       appMetrics,
		metricsCollector: metricsCollector,
		backupSched:      backupSched,
		journalSched:     journalSched,
		updatesSched:     updatesSched,
		server:           server,
		ntpInputState:    ntpInputState,
		interval:         interval,
		dnstapSvc:        dnstapSvc,
		domSvc:           domSvc,
		domainRouting:    domainRouting,
		sondaSaida:       sondaSaida,
	}, nil
}

// startBackground sobe TUDO que roda em segundo plano: o provisionamento da
// máquina (o que o LinkGuard faz no boot que mexe em nftables/rotas/NTP), o
// timer do confirmar-ou-reverte e as goroutinas de coleta.
//
// Devolve o WaitGroup das goroutines que ESCREVEM no banco — ver o comentário
// da declaração dele. Quem chama tem que esperá-lo DEPOIS de o HTTP parar
// (serveHTTP faz isso), senão o tsdb volta a perder o balde da janela corrente
// a cada reinício.
//
// Os serviços são reapontados para variáveis locais com os MESMOS nomes que a
// montagem usa (frSvc, nftSvc, …) de propósito: a sequência abaixo é guardada
// contra deriva por testes de AST que procuram `frSvc.RevertPendingOnBoot`,
// `nftSvc.ReconcileNTPInput` e afins como chamadas em identificadores simples.
// Escrever `s.frSvc.…` aqui deixaria esses guardas cegos sem uma linha sequer
// mudar de comportamento — que é exatamente o modo de falha que eles existem
// para pegar.
func startBackground(ctx context.Context, s *services) *sync.WaitGroup {
	db := s.db
	pkgExec := s.pkgExec
	frSvc, nftSvc := s.frSvc, s.nftSvc
	routeSvc := s.routeSvc
	trafficSvc, unboundSvc, alertSvc := s.trafficSvc, s.unboundSvc, s.alertSvc
	metricsCollector, rrdSvc := s.metricsCollector, s.rrdSvc
	hostQuotaSvc := s.hostQuotaSvc
	wgSvc, server := s.wgSvc, s.server
	hostSampler := s.hostSampler
	backupSched, journalSched, updatesSched := s.backupSched, s.journalSched, s.updatesSched
	aiClient := s.aiClient
	domainRouting := s.domainRouting
	ntpInputState := s.ntpInputState
	interval := s.interval

	// bootPendingChecked prende a verificação de boot do confirmar-ou-reverte
	// à primeira passada de provisionSystem que a tenha CONCLUÍDO.
	// provisionSystem é reexecutado quando uma tentativa posterior de instalar
	// a base finalmente dá certo — e isso pode acontecer meia hora depois da
	// subida, com o operador já no painel. Sem a trava, essa segunda passada
	// reverteria uma janela de confirmação que ele tivesse acabado de abrir,
	// como se a máquina tivesse reiniciado. "No boot" tem que querer dizer no
	// boot.
	//
	// N-4 — por que uma trava explícita e não um sync.Once. A primeira passada
	// roda mesmo quando o bootstrap FALHOU (`if done || attempt == 0`), e numa
	// máquina onde o `nft` ainda nem existe é justamente a passada em que a
	// reversão de boot não tem como se completar. Um sync.Once queimava ali, e
	// a passada que finalmente dava certo não repetia a verificação. Marcando
	// só quando ela conclui, a passada seguinte retoma o trabalho.
	//
	// O que isso custa, dito por inteiro: se a verificação falhou porque a
	// LEITURA do pendente falhou (e não havia pendente nenhum), uma passada
	// posterior pode reverter uma janela aberta no intervalo. É o caso raro de
	// um caso raro, e ele falha na direção segura — o operador mantém o acesso
	// e reaplica a alteração; o inverso (deixar de reverter) é ele trancado
	// fora de uma máquina remota. Quando a falha foi da reversão em si, repetir
	// é exatamente o certo: o pendente continua no banco e é o mesmo.
	//
	// Escrita e lida por uma goroutine só (a do laço de bootstrap, mais
	// abaixo), que é de onde provisionSystem é chamado.
	bootPendingChecked := false

	// provisionSystem é tudo o que o LinkGuard faz no boot que MEXE na
	// máquina: forwarding, policy routing, bootstrap/reconciliação do
	// nftables, accounting do conntrack, NTP e resolv.conf.
	//
	// Tudo isto depende de o `nft`/`ip` existirem, então continua vindo
	// DEPOIS de garantir a base — mas fora do caminho crítico da subida (ver
	// a goroutine logo abaixo). É idempotente de ponta a ponta, e por isso
	// pode ser chamado de novo quando uma tentativa posterior de instalar a
	// base finalmente der certo.
	provisionSystem := func() {
		// O gate dos alvos por domínio só abre no fim se TODAS as peças de que
		// o enforcement depende tiverem sido comprovadas nesta passada.
		domainBootReady := true
		// A primeira coisa DESTA função, antes de qualquer reconciliação
		// (Fase C2, spec §5.1): se ficou uma mudança de firewall aplicada e
		// não confirmada, reverta — tenha ela expirado ou não.
		//
		// A ordem é a proteção, não uma preferência de organização. Reverter
		// DEPOIS de já ter reconciliado significaria aplicar mais uma vez, na
		// máquina que acabou de voltar, exatamente a regra que pode tê-la
		// derrubado — e regra de escopo input derruba o acesso do OPERADOR
		// (SSH, painel), numa máquina remota, sem conserto local.
		//
		// m-1 — o que isto NÃO é: não é o primeiro instante do boot.
		// provisionSystem só roda depois de bootstrapdeps.Ensure, que num
		// link ruim pode levar meia hora (ver a goroutine mais abaixo). O que
		// cobre esse intervalo é frSvc.WatchPending, que já está de pé desde
		// a subida: a janela dura 90 s, então na prática é ele quem reverte
		// primeiro, e esta chamada é a rede para o caso de o processo ter
		// reiniciado com a janela ainda correndo. A garantia real é "antes de
		// o LinkGuard reconciliar", não "antes de tudo".
		//
		// Reverter mesmo dentro do prazo é decisão registrada: o operador não
		// estava lá para confirmar, e um reboot dentro da janela normalmente
		// significa que a máquina caiu por causa da mudança. Ver
		// RevertPendingOnBoot.
		//
		// Erro aqui não derruba o boot nem desarma nada: fica no journal, o
		// pendente CONTINUA no banco (a faixa do painel segue pedindo
		// confirmação ou reversão) e o WatchPending retoma a reversão. É o
		// que salva a máquina cuja tabela `inet linkguard` precisou ser
		// recriada — aqui, algumas linhas antes do EnsureTable, a
		// reconciliação da reversão falha de forma determinística. E a trava
		// só é marcada quando a verificação CONCLUI (N-4): uma passada que não
		// conseguiu terminar não gasta a única chance de "no boot".
		if !bootPendingChecked {
			if err := frSvc.RevertPendingOnBoot(ctx); err != nil {
				slog.Error("não foi possível reverter no boot a mudança de firewall não confirmada", "err", err)
			} else {
				bootPendingChecked = true
			}
		}

		// Enable IPv4 forwarding so the box can route between LAN and WAN; it
		// defaults to 0 on a fresh system and a firewall/router needs it on.
		routeSvc.EnsureForwarding()

		// The tunnel is reconciled before firewall groups/input and before
		// unbound is reloaded. This establishes the address that unbound must
		// bind and repairs each peer's managed firewall group first.
		wireGuardReady := false
		wireGuardConfigured := false
		if row, err := db.GetWireGuardConfig(); err != nil {
			slog.Warn("não foi possível ler a configuração WireGuard no boot", "err", err)
		} else {
			wireGuardConfigured = row != nil
			if err := wgSvc.Reconcile(ctx); err != nil {
				slog.Warn("não foi possível reconciliar o WireGuard no boot", "err", err)
			} else {
				wireGuardReady = true
			}
		}

		// Bootstrap `table inet linkguard` if it doesn't exist yet — every other
		// nftables operation (block host, port forward, custom rule) assumes the
		// table is already there. On every install to date this table was created
		// by hand once; this makes a fresh install self-sufficient instead of
		// silently failing the first time an admin uses the Firewall screen.
		// A TABELA NASCE JÁ COM O NAT. wansEfetivas devolve as WANs
		// cadastradas ou, quando não há nenhuma e a plataforma sabe
		// responder, o uplink implícito — que é o que faz uma VM de nuvem
		// recém-criada bootar liberando tráfego em vez de com a chain
		// postrouting vazia.
		//
		// Erro de leitura NÃO cancela o bootstrap: sem tabela a máquina
		// fica sem firewall nenhum, o que é pior do que uma tabela criada
		// sem a linha de masquerade — que é exatamente o que acontecia
		// antes desta entrega. A reconciliação logo abaixo, no mesmo boot,
		// escreve a regra assim que a leitura voltar.
		wanInterfaces, err := wansEfetivas(ctx, s.exec, s.plat)
		if err != nil {
			slog.Warn("não foi possível derivar as WANs para o bootstrap da tabela; ela nasce sem a regra de NAT e a reconciliação seguinte a escreve", "err", err)
			wanInterfaces = nil
		}
		if nftSvc.EnsureTable(ctx, wanInterfaces) {
			// The table was just created empty — restore whatever was saved on
			// the last mutation (blocklist, user rules, host blocks,
			// port forwards) so a from-scratch install with a restored database
			// comes back with the same firewall it had, not a blank one. Only
			// runs right after a bootstrap: reapplying a snapshot on every
			// ordinary restart would risk clobbering a running firewall with
			// stale state instead.
			if snapshot, _ := db.GetSetting(nftables.LiveSnapshotSettingKey); snapshot != "" {
				if _, err := nftSvc.Restore(ctx, snapshot); err != nil {
					slog.Warn("bootstrapped nftables table but could not restore the saved elements", "err", err)
				} else {
					slog.Info("restored saved nftables elements after bootstrap (blocklist/user rules/port forwards)")
				}
			}
		}

		// O que o multi-WAN deixou na tabela de uma caixa migrada do
		// linkguard-fw: as chains de marcação por link e o map de
		// direcionamento por host. Depois do EnsureTable/Restore (que podem
		// tê-los trazido de volta do snapshot) e antes das reconciliações que
		// persistem. Ver nftables.RemoverHerancaMultiWAN.
		if _, err := nftSvc.RemoverHerancaMultiWAN(ctx); err != nil {
			slog.Warn("não foi possível apagar as estruturas do multi-WAN da tabela", "err", err)
		}

		// A configuração de unbound só é reaplicada quando a VPN já foi
		// configurada alguma vez. Isso restaura/adiciona o listener quando
		// ativa e o remove quando desativa, sem instalar o unbound numa
		// caixa que nunca usou a VPN.
		if wireGuardConfigured && wireGuardReady {
			if err := server.ReconcileVPNDNS(ctx); err != nil {
				wgSvc.RecordIntegrationError(err)
				slog.Warn("não foi possível reconciliar o DNS do túnel WireGuard no boot", "err", err)
			}
		}

		// Reconcile the masquerade rule on EVERY boot, not just when the table
		// had to be created. EnsureTable is a no-op on an already-provisioned
		// box, so before this the NAT rule kept whatever interface names it was
		// born with — in production a renamed NIC (enp4s0 -> enp5s0) silently
		// took WAN1's NAT down until an operator intervened by hand.
		//
		// A LISTA SAI DE wansEfetivas, e é aqui que o produto passa a
		// funcionar de primeira: numa VM de nuvem sem link cadastrado ela
		// devolve o uplink que a plataforma afirma, e ReconcileMasquerade
		// — com a guarda de lista vazia INTACTA — finalmente tem o que
		// escrever. Erro de leitura deixa a lista vazia de propósito: a
		// guarda então mantém a regra que já estiver valendo, em vez de
		// derrubá-la por causa de um SELECT que falhou.
		enabledWANs, err := wansEfetivas(ctx, s.exec, s.plat)
		if err != nil {
			slog.Warn("não foi possível derivar as WANs no boot; as reconciliações deste ciclo seguem com lista vazia e nada é derrubado", "err", err)
			enabledWANs = nil
		}
		if err := nftSvc.ReconcileMasquerade(ctx, enabledWANs); err != nil {
			slog.Warn("não foi possível reconciliar a regra de NAT no boot", "err", err)
		}

		// A contabilidade por host (#112) usa a MESMA lista de WANs, e pelo
		// mesmo motivo do masquerade precisa ser reconciliada em todo boot:
		// EnsureTable é no-op em máquina já provisionada, então sem isto
		// uma instalação existente nunca ganharia a chain.
		if err := nftSvc.EnsureAccounting(ctx, enabledWANs); err != nil {
			slog.Warn("não foi possível reconciliar a contabilidade por host no boot", "err", err)
		}

		// Registro de conversa por host (#115). Reconciliado em todo boot
		// pelo mesmo motivo da contabilidade — EnsureTable é no-op em
		// máquina já provisionada — e com uma diferença que importa: aqui a
		// reconciliação também DERRUBA a tabela quando a feature está
		// desligada, para uma caixa cujo admin desligou o registro não voltar
		// do boot com a base chain de volta no hook forward.
		//
		// A tabela é própria e o Persist não a enxerga, então ela nunca
		// sobrevive ao reboot sozinha: quem a recria é esta linha, e só se o
		// admin tiver pedido.
		if err := s.fluxosSvc.Reconciliar(ctx, enabledWANs); err != nil {
			slog.Warn("não foi possível reconciliar o registro de conversa por host no boot", "err", err)
		}

		// Ajuste de MSS (#130): também deriva da lista de WANs, e é no-op
		// por construção onde a MTU é 1500 — ver EnsureMSSClamp.
		if err := nftSvc.EnsureMSSClamp(ctx, enabledWANs); err != nil {
			slog.Warn("não foi possível reconciliar o ajuste de MSS no boot", "err", err)
		}

		// Bloqueio de máquina: o set blocked_hosts nasce vazio a cada tabela
		// recriada, e o banco é quem lembra quem está bloqueado. É também o
		// que leva para o set os bloqueios que a migração 102 converteu de
		// endereço físico para IP.
		s.hostSvc.SincronizaBloqueios(ctx)

		// Estruturas de alvo por domínio (#123): garantidas E ESVAZIADAS
		// no boot.
		//
		// O esvaziamento é incondicional de propósito. O que elas guardam é
		// cache do que o resolver respondeu, e endereço de CDN é de um site
		// hoje e de outro daqui a dez minutos. Cache que sobrevive ao
		// reboot afirma sobre endereços o que ninguém mais confirmou — a
		// mesma razão pela qual o mapa da #116 vive só em memória.
		//
		// E há um caminho pelo qual esse cache VOLTARIA sozinho: Persist
		// despeja o `nft list table` inteiro, elementos inclusive, em
		// /etc/nftables.conf, e o nftables.service recarrega esse arquivo
		// ANTES de o LinkGuard subir. Sem esta linha, endereços aprendidos
		// há semanas voltariam a valer sem ninguém para reconfirmá-los.
		if err := s.nftSvc.EnsureDomainStructures(ctx); err != nil {
			domainBootReady = false
			slog.Warn("não foi possível garantir as estruturas de alvo por domínio no boot", "err", err)
		} else if err := s.nftSvc.FlushDomainStructures(ctx); err != nil {
			domainBootReady = false
			slog.Warn("não foi possível esvaziar as estruturas de alvo por domínio no boot", "err", err)
		}

		// Proteção de entrada das WANs (#119). Reconciliada em todo boot
		// pela mesma razão da contabilidade: EnsureTable é no-op em máquina
		// já provisionada, então sem isto uma instalação existente nunca
		// ganharia a proteção.
		if err := nftSvc.ReconcileInputProtection(ctx); err != nil {
			slog.Warn("não foi possível reconciliar a proteção de entrada das WANs no boot", "err", err)
		}

		// EnsureSystemGroups vem PRIMEIRO, antes de qualquer coisa que
		// reconcilie, e a ordem é o ponto: ele cria, uma única vez, as
		// duas linhas de grupo que representam os bloqueios (hosts e
		// destinos) nas posições 0 e 1, empurrando os grupos do admin
		// para depois. É a lista de grupos que passa a decidir se os
		// bloqueios existem na chain forward — e as duas migrações
		// abaixo reconciliam por dentro, então rodá-las antes desta
		// abriria uma janela em que a forward é reconstruída com a lista
		// ainda sem os bloqueios. A defesa de firewallrules recusa
		// exatamente esse estado (ver ensureSystemGroupsPresent): com a
		// ordem invertida, as duas migrações do boot de upgrade
		// falhariam em vez de migrar.
		//
		// Não depende de nenhuma das duas: só lê a própria trava e
		// insere as duas linhas, deslocando as posições existentes.
		// TestEnsureSystemGroupsRunsBeforeTheMigrationsThatReconcile
		// guarda essa ordem contra deriva.
		//
		// Um erro aqui não derruba o boot: os grupos não são criados, e
		// tudo que reconcilia a seguir se recusa a reconstruir a forward
		// (o firewall segue valendo com a última forward aplicada, que
		// tem os bloqueios dentro), com apply-status não-ok e alerta
		// crítico. A próxima inicialização tenta de novo.
		if err := frSvc.EnsureSystemGroups(ctx); err != nil {
			domainBootReady = false
			slog.Warn("não foi possível criar os grupos do sistema (hosts e destinos bloqueados)", "err", err)
		}

		// Phase B (firewall page redesign spec §4.1): the admin's own rules
		// now live in the DB, not just inside nft. On a box upgrading from
		// Phase A, ImportOnce brings whatever is in the live user_rules
		// chain into the DB exactly once (guarded by a settings flag, never
		// by "is the table empty" — see its doc comment for why that
		// distinction matters), preserving order; a fresh install has
		// nothing to import and just sets the guard.
		//
		// MigrateRulesIntoDefaultGroup runs right after: it adopts whatever
		// rules are still ungrouped — including whatever ImportOnce just
		// brought in — into the "Minhas regras" group, once, guarded the
		// same way. The order between these two is not arbitrary: inverting
		// them would make a box still on Phase A (nothing in the DB yet,
		// the real rules only living in the legacy user_rules chain) run
		// the group migration against an empty rule set, then have
		// ImportOnce bring the rules in afterwards as orphans nobody ever
		// adopts into a group.
		//
		// Reconcile (Fase C1) is what actually renders the forward chain
		// (blocks, then the group jumps) and every grp_ chain from the DB —
		// see its doc comment. It is called unconditionally last, on every
		// boot, same as the other reconciles above. This is not redundant
		// with the two calls above even though both of them also reconcile
		// internally when they do real work (MigrateRulesIntoDefaultGroup
		// must, to safely retire the legacy user_rules chain — see its doc
		// comment): on a box with nothing to migrate, that function returns
		// without reconciling at all, which would leave the forward chain
		// stuck on whatever was last written to /etc/nftables.conf.
		if err := frSvc.ImportOnce(ctx); err != nil {
			slog.Warn("não foi possível importar as regras existentes de user_rules para o banco", "err", err)
		}
		if err := frSvc.MigrateRulesIntoDefaultGroup(ctx); err != nil {
			slog.Warn("não foi possível migrar as regras soltas para o grupo padrão", "err", err)
		}
		if err := frSvc.Reconcile(ctx); err != nil {
			domainBootReady = false
			slog.Warn("não foi possível reconciliar os grupos de regras (chain forward) a partir do banco no boot", "err", err)

			// m1 da revisão da Fase C2: frSvc.Reconcile → nftSvc.ReconcileGroups
			// já reconstrói a chain input INTEIRA (passo 3b, ver o doc-comment
			// de ReconcileGroups) a partir da mesma fonte de estado do NTP que
			// ntpInputState lê abaixo — no caminho feliz, chamar
			// nftSvc.ReconcileNTPInput de novo aqui só duplicava o trabalho.
			// Duplicar não é de graça: cada reconstrução da chain input abre uma
			// janela entre o `flush chain` e o `add rule` do bloqueio de udp/123
			// em que ela fica vazia com `policy accept` — NTP de qualquer origem
			// passaria nesse instante —, e dobrar a chamada dobra essa janela por
			// boot, além de duplicar o Persist() em /etc/nftables.conf.
			//
			// O valor que sobra é estreito mas real: se frSvc.Reconcile FALHOU
			// (por exemplo abortou em ensureSystemGroupsPresent, antes mesmo de
			// chamar ReconcileGroups), a chain input pode não ter sido tocada por
			// ele nesta passada — e é só este `if` que ainda garante que a
			// proteção do NTP suba no boot. Por isso a chamada fica presa a este
			// ramo de erro em vez de rodar solta como antes.
			// TestNTPInputIsReconciledAfterTheGroupChainsExist guarda isto.
			//
			// A ordem continua sendo o ponto (I-4 da revisão da Fase C2): desde a
			// Fase C2 a chain input carrega também um `jump` por grupo de escopo
			// input, e quem CRIA as chains grp_ é o passo 1 de ReconcileGroups,
			// chamado (com sucesso ou não) dentro de frSvc.Reconcile acima. Numa
			// máquina cujo ruleset foi recriado do zero por EnsureTable
			// (recuperação de desastre, como em 2026-08-10) e cujo banco tenha um
			// grupo de escopo input, emitir o jump antes disso falha com "No such
			// file or directory": a passada seguinte conserta, mas o log de boot
			// fica com um erro que não é erro — e log de boot de firewall é lido
			// em emergência.
			//
			// Erro de LEITURA não vira reconciliação: reconstruir a chain com
			// "servir NTP: desligado" que na verdade é "não consegui ler"
			// apagaria a proteção do serviço de hora do firewall vivo (I-1).
			if networks, serving, err := ntpInputState(); err != nil {
				slog.Warn("não foi possível ler a configuração de NTP no boot; a chain input não foi tocada nesta passada", "err", err)
			} else if err := nftSvc.ReconcileNTPInput(ctx, networks, serving); err != nil {
				slog.Warn("não foi possível reconciliar a chain de proteção do NTP no boot", "err", err)
			}
		}

		// Só agora sets/map e grupos estão coerentes. Uma falha em qualquer
		// etapa fecha o gate de novo e publica ensaio/boot_pending, inclusive
		// numa tentativa posterior de provisionamento.
		if domainRouting != nil {
			if domainBootReady {
				if err := domainRouting.Prepare(ctx); err != nil {
					slog.Warn("não foi possível ativar os alvos por domínio no boot", "err", err)
				}
			} else if err := domainRouting.Hold(ctx); err != nil {
				slog.Warn("não foi possível manter os alvos por domínio suspensos no boot", "err", err)
			}
		}

		// Enable conntrack byte accounting so per-host traffic (top talkers) can be
		// computed; without it /proc/net/nf_conntrack has no byte counters.
		trafficSvc.EnsureAccounting()

		// Point /etc/resolv.conf at the local unbound and stop dhclient from
		// undoing it on lease renewal (see EnsureResolvConf's doc comment).
		unboundSvc.EnsureResolvConf(ctx)
	}

	// O painel e o monitor de failover sobem PRIMEIRO; a base e o
	// provisionamento vão para segundo plano.
	//
	// Antes, bootstrapdeps.Ensure rodava síncrono aqui: com o executor de
	// pacote (10 min por comando) o pior caso era install + apt-get update +
	// install ≈ 30 minutos sem monitor de failover, sem balanceamento e sem
	// painel. E o cenário em que o apt trava devagar é justamente "a WAN
	// caiu" — exatamente quando o failover é a única coisa que importa. É o
	// padrão do incidente de 2026-07-24, em que uma migração sem transação
	// travou o boot desta aplicação por 50+ minutos numa máquina de
	// produção.
	//
	// Por que esta ordem e não simplesmente limitar o prazo total do Ensure:
	// um teto no Ensure escolhe entre "esperar menos" e "instalar a base" —
	// os dois importam, e num link ruim qualquer teto que caiba num boot
	// aceitável é curto demais para um apt honesto. Subir antes remove a
	// escolha: o painel aparece em milissegundos, o failover está de pé, e a
	// instalação tem todo o tempo de que precisa.
	//
	// Numa máquina já provisionada isto custa quatro dpkg-query e o
	// provisionamento roda igual, poucos milissegundos depois da subida.
	//
	// O laço existe porque Ensure roda uma vez por tentativa e o motivo mais
	// comum de falhar logo depois do boot é o apt-daily/unattended-upgrades
	// estar com o lock do dpkg — nada que uma segunda tentativa alguns
	// minutos depois não resolva. Sem ele, a base nunca era instalada nesse
	// boot. Cada tentativa bem-sucedida reprovisiona (é aí que o `nft`
	// finalmente existe para a reconciliação valer).
	go func() {
		for attempt := 0; ; attempt++ {
			done := bootstrapdeps.Ensure(ctx, pkgExec, alertSvc)
			if done || attempt == 0 {
				provisionSystem()
			}
			if done {
				return
			}
			delay := bootstrapdeps.RetryDelay(attempt)
			slog.Warn("base incompleta; o LinkGuard vai tentar instalar de novo", "em", delay)
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
			}
		}
	}()

	// O timer em memória do confirmar-ou-reverte: enquanto o processo vive,
	// é ele que desfaz a mudança de firewall quando o prazo de 90 s termina
	// sem confirmação. A rede embaixo dele é a verificação de boot acima —
	// esta goroutine morre junto com o processo, e é justamente o processo
	// morrer dentro da janela o caso que não pode deixar a regra valendo.
	//
	// Ele sobe AQUI, fora do caminho do bootstrap, e é por isso que numa
	// máquina que ainda está instalando a base (o que pode demorar meia hora)
	// existe alguém observando o pendente desde o primeiro segundo — a
	// verificação de boot, dentro de provisionSystem, só roda depois do
	// bootstrapdeps.Ensure (m-1). É também ele quem RETOMA uma reversão que
	// não pôde ser concluída no nft: nesse caso o pendente continua no banco
	// justamente para dar a ele o que tentar de novo, com backoff.
	//
	// Cinco segundos: a contagem que o operador vê sai de expires_at (do
	// servidor), então isto é só a granularidade da reversão. Custa um SELECT
	// numa tabela de no máximo uma linha.
	go frSvc.WatchPending(ctx, 5*time.Second)

	// As goroutines que ESCREVEM no banco são esperadas no desligamento; as de
	// leitura pura, não.
	//
	// A distinção é o ponto: `httpServer.Shutdown` espera as requisições HTTP e
	// o processo sai, abandonando as goroutines onde estiverem. Para quem só lê
	// (leitura do journal, por exemplo) isso é inofensivo. Para quem tem
	// estado em memória para gravar, não é — o tsdb perdia o balde da janela
	// corrente a cada reinício, e o auto-update reinicia.
	var writers sync.WaitGroup
	spawnWriter := func(name string, fn func()) {
		writers.Add(1)
		go func() {
			defer writers.Done()
			fn()
			slog.Debug("goroutine de escrita encerrada", "nome", name)
		}()
	}

	spawnWriter("metrics", func() { metricsCollector.Run(ctx, interval) })
	go s.sondaSaida.Run(ctx)
	// Escritor: grava no banco os nomes que o DNS reverso da VCN devolve.
	spawnWriter("nomes", func() { s.nomesSvc.Run(ctx) })
	spawnWriter("tsdb", func() { rrdSvc.Run(ctx) })
	// Escritor: o Run grava o acumulado do minuto na saída, e perder isso a
	// cada reinício abriria um buraco na contagem que a cota existe para fazer.
	spawnWriter("cota-por-aparelho", func() { hostQuotaSvc.Run(ctx) })
	// Escritor: grava a série por host, e perder a última amostra num
	// reinício abre buraco justamente na série que o histórico existe para ter.
	spawnWriter("consumo-por-host", func() { hostSampler.Run(ctx) })
	// Detectores de comportamento (#117): cruzam o histórico por aparelho com o
	// inventário. Cadência de 5 minutos — a série é gravada a cada 10 segundos,
	// e olhar mais rápido só geraria o ruído que a issue manda evitar.
	go func() {
		comp := comportamento.NovoServico(s.db, s.alertSvc)
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				comp.Verificar()
			}
		}
	}()

	// O coordenador publica a intenção ainda atrás do gate de boot. Assim a API
	// já mostra tudo como boot_pending e o alimentador só recebe ensaio até as
	// estruturas/chains serem verificadas por provisionSystem.
	if domainRouting != nil {
		if err := domainRouting.Reconcile(ctx); err != nil {
			slog.Warn("alvo por domínio: não consegui carregar a intenção no boot", "err", err)
		}
	}
	go s.domSvc.Run(ctx)

	// Coletor de dnstap (#116). Sobe sempre; quem decide se há entrega é o
	// unbound, e ele só entrega quando o admin liga o recurso na tela.
	//
	// Falhar aqui NÃO derruba o produto — dnstap é acessório. Mas também não
	// pode falhar em silêncio: sem esta linha, o admin ligaria na tela e não
	// teria como saber por que o mapa fica vazio para sempre.
	go func() {
		if err := s.dnstapSvc.Run(ctx); err != nil {
			slog.Warn("dnstap: o coletor não subiu; o mapa endereço → nome fica vazio", "err", err)
		}
	}()
	spawnWriter("backup", func() { backupSched.Run(ctx) })
	go journalSched.Run(ctx)
	go updatesSched.Run(ctx)
	// O resumo diário lia a saúde de cada link WAN; sem links, ele resume os
	// alertas do dia. A análise de ataque e de tráfego de saída é a próxima
	// forma da camada de IA.
	go ai.RunDigest(ctx, aiClient, rrdSvc, alertSvc, db, func() []string { return nil })

	return &writers
}

// serveHTTP é o fim do boot: sobe o painel e fica nele até o processo receber
// o sinal de desligamento. Devolve o código de saída do processo.
//
// Recebe o WaitGroup das goroutines de escrita porque a ORDEM do desligamento
// é dele: primeiro o HTTP para, só depois se espera quem tem estado em memória
// para gravar — ver o comentário do WaitGroup em startBackground.
func serveHTTP(ctx context.Context, s *services, writers *sync.WaitGroup) int {
	cfg, server := s.cfg, s.server

	httpServer := &http.Server{
		Addr:              cfg.Addr(),
		Handler:           server.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		// Carimba cada conexão com o instante do accept (issue #86).
		//
		// Sem esta linha o "Confirmar acesso" volta a aceitar a conexão que já
		// existia antes da mudança — e essa conexão responde mesmo com o acesso
		// cortado, porque uma chain que aceita `ct state established` a mantém
		// de pé. O operador testaria, confirmaria, e descobriria na próxima
		// reconexão.
		//
		// Tirar isto daqui não quebra teste nenhum e não aparece em lugar
		// nenhum: a decisão degrada para "não verificável", que é o lado seguro
		// mas silencioso. Por isso o aviso fica no ponto em que alguém mexeria.
		ConnContext: handlers.ConnContext,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			slog.Error("server shutdown failed", "err", err)
		}
	}()

	slog.Info("linkguard-cloud starting", "version", version, "addr", cfg.Addr(),
		"dry_run", cfg.DryRun, "tls", cfg.TLSEnabled)

	serve := httpServer.ListenAndServe
	if cfg.TLSEnabled {
		if err := tlscert.EnsureSelfSigned(cfg.TLSCert, cfg.TLSKey); err != nil {
			slog.Error("tls certificate setup failed", "err", err)
			return 1
		}
		serve = func() error { return httpServer.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey) }
	}
	serveErr := serve()

	// Só depois que o HTTP parou: dar às goroutines de escrita a chance de
	// gravar o que têm em memória. O teto é curto de propósito — o systemd
	// manda SIGKILL depois do TimeoutStopSec, e é melhor perder o resíduo de
	// uma delas do que atrasar o desligamento inteiro do serviço.
	if !waitTimeout(writers, 3*time.Second) {
		slog.Warn("desligando com goroutine de escrita ainda em andamento; algum dado em memória pode não ter sido gravado")
	}

	if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
		slog.Error("server failed", "err", serveErr)
		return 1
	}
	slog.Info("linkguard-cloud stopped")
	return 0
}

// waitTimeout espera o WaitGroup, devolvendo false se o prazo estourar antes.
func waitTimeout(wg *sync.WaitGroup, d time.Duration) bool {
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

// seedDefaultRoles seeds the built-in RBAC roles (defined in the auth catalog)
// on first run, without overwriting any later admin customizations.
func seedDefaultRoles(db *storage.DB) error {
	seeds := make([]storage.RoleSeed, 0, len(auth.DefaultRoles))
	adminRoleID := ""
	for _, dr := range auth.DefaultRoles {
		perms := make([]string, len(dr.Permissions))
		for i, p := range dr.Permissions {
			perms[i] = string(p)
			if p == auth.PermUsersManage {
				adminRoleID = dr.ID
			}
		}
		seeds = append(seeds, storage.RoleSeed{
			ID:          dr.ID,
			Name:        dr.Name,
			Description: dr.Description,
			Permissions: perms,
			// Keep the admin role in sync with the catalog across upgrades.
			AlwaysSync: dr.ID == adminRoleID,
		})
	}
	return db.EnsureDefaultRoles(seeds, adminRoleID)
}

// initialAdminPasswordFile é onde a senha gerada na primeira instalação fica
// legível para quem instalou — e só para o root. O journal também a registra,
// mas ele rotaciona; o arquivo é o que ainda está lá no dia seguinte.
const initialAdminPasswordFile = "/etc/linkguard-cloud/initial-admin-password"

// seedInitialAdmin cria o administrador da primeira instalação com uma senha
// ALEATÓRIA, e a entrega ao operador pelo log e por um arquivo 0600.
//
// Até a v1.0.82 toda instalação nascia com admin/admin — hash constante numa
// linha de INSERT — sem troca obrigatória, num painel que escuta a LAN inteira.
// Bastava alguém na rede interna conhecer o produto.
//
// Não faz nada quando já existe usuário, então instalação que já roda não é
// afetada: para essas, o caminho é POST /api/auth/change-password, que também
// passou a existir agora.
func seedInitialAdmin(db *storage.DB) error {
	pw, err := generateInitialPassword()
	if err != nil {
		return fmt.Errorf("gerar a senha inicial: %w", err)
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		return fmt.Errorf("cifrar a senha inicial: %w", err)
	}
	created, err := db.SeedInitialAdmin(hash)
	if err != nil {
		return err
	}
	if !created {
		return nil
	}

	// 0600: a senha em claro só interessa a quem tem root, que já poderia
	// redefini-la de qualquer jeito.
	if err := os.WriteFile(initialAdminPasswordFile, []byte(pw+"\n"), 0600); err != nil {
		// Não é fatal — a senha ainda vai para o log, e sem ela a instalação
		// fica inacessível, o que seria pior do que um arquivo faltando.
		slog.Warn("não consegui gravar a senha inicial em arquivo",
			"path", initialAdminPasswordFile, "err", err)
	}
	slog.Warn("PRIMEIRA EXECUÇÃO: administrador criado",
		"usuario", "admin",
		"senha", pw,
		"arquivo", initialAdminPasswordFile,
		"acao", "entre no painel, troque a senha e apague o arquivo")
	return nil
}

// generateInitialPassword devolve 24 caracteres de um alfabeto sem os pares que
// se confundem à mão (0/O, 1/l/I) — a senha é lida de um terminal e digitada de
// novo pelo menos uma vez.
func generateInitialPassword() (string, error) {
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	const length = 24
	out := make([]byte, length)
	for i := range out {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		out[i] = alphabet[n.Int64()]
	}
	return string(out), nil
}
