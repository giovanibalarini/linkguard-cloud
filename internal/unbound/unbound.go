// Package unbound é o backend de DNS do LinkGuard Cloud: gera a configuração
// do unbound, instala o pacote sob demanda, valida antes de gravar e recarrega
// o daemon sem derrubá-lo quando dá.
//
// Até 25/09/2026 este pacote era o keaunbound e cuidava também do DHCP (Kea).
// Na nuvem quem entrega endereço às máquinas é a própria Oracle, então o Kea
// saiu e o unbound ficou com o papel que tem aqui: resolvedor da VPN, fonte do
// log de consultas, do bloqueio de domínios e do dnstap.
package unbound

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/giovanibalarini/linkguard-cloud/internal/bootstrapdeps"
	"github.com/giovanibalarini/linkguard-cloud/internal/dnstap"
	"github.com/giovanibalarini/linkguard-cloud/internal/firewall"
	"github.com/giovanibalarini/linkguard-cloud/internal/netsvc"
	"github.com/giovanibalarini/linkguard-cloud/internal/sysprep"
)

// DNSTapSocketPath é onde o coletor de dnstap do produto escuta e o unbound
// entrega as respostas. Fica sob o RuntimeDirectory do serviço (gravável sob
// ProtectSystem=strict), e o unbound só alcança o caminho porque o produto
// escreve a regra no ponto de extensão do perfil AppArmor dele (ver
// internal/dnstap.EscreverRegraAppArmor).
const DNSTapSocketPath = "/run/linkguard-cloud/dnstap.sock"

const (
	UnboundConfPath  = "/etc/unbound/unbound.conf.d/linkguard.conf"
	ResolvConfPath   = "/etc/resolv.conf"
	DhclientConfPath = "/etc/dhcp/dhclient.conf"

	unboundService         = "unbound"
	unboundCheckBinDefault = "/usr/sbin/unbound-checkconf"

	// unbound é Recommends: do pacote, não Depends:, então uma caixa pode
	// chegar sem ele; o LinkGuard o instala quando precisa aplicar o DNS.
	unboundPackage = "unbound"

	// dnsRootDataPackage vai nomeado porque a instalação roda com
	// --no-install-recommends: o unbound só *recomenda* o dns-root-data, mas o
	// drop-in que ele instala aponta a âncora DNSSEC para
	// /var/lib/unbound/root.key sem condição. Sem o pacote, o unbound morre na
	// subida com "module init for module validator failed".
	dnsRootDataPackage = "dns-root-data"

	// unboundActivatedMarker é a cópia da config que o daemon está servindo de
	// fato — a última ATIVADA, não a última escrita. A decisão de reiniciar
	// compara contra ela: o arquivo do /etc é gravado antes do reload, então
	// uma aplicação que escreveu e morreu no meio faria a seguinte acreditar
	// que nada mudou. Gravado só depois do reload bem-sucedido.
	unboundActivatedMarker = "/var/lib/linkguard-cloud/unbound-applied.conf"
)

// Service é o provedor de DNS. Caminhos e o binário de validação são campos
// para os testes apontarem para um diretório temporário.
type Service struct {
	exec firewall.Executor
	// installExec é usado SÓ na instalação sob demanda, com prazo de download
	// de pacote: um `systemctl` que não responde em 30 s está travado, um
	// apt-get baixando o unbound num link lento não. main.go o aponta para um
	// executor de prazo longo; nos testes e no dry-run é o próprio exec.
	installExec     firewall.Executor
	unboundConf     string
	unboundApplied  string
	unboundCheckBin string
	resolvConf      string
	dhclientConf    string
	// dnsBindingSource fornece o endereço de escuta e a rede autorizada que
	// pertencem a outro serviço (hoje, o WireGuard). Nunca são gravados na
	// config de DNS: o túnel é a fonte, lida de novo a cada geração.
	dnsBindingSource func() (address, network string, enabled bool, err error)
}

// NewService cria o provedor.
func NewService(exec firewall.Executor) *Service {
	return &Service{
		exec:            exec,
		installExec:     exec,
		unboundConf:     UnboundConfPath,
		unboundApplied:  unboundActivatedMarker,
		unboundCheckBin: unboundCheckBinDefault,
		resolvConf:      ResolvConfPath,
		dhclientConf:    DhclientConfPath,
	}
}

// SetInstallExecutor aponta a instalação sob demanda para um executor com
// prazo de download de pacote.
func (s *Service) SetInstallExecutor(e firewall.Executor) {
	if e != nil {
		s.installExec = e
	}
}

// SetDNSBindingSource liga a fonte do endereço de escuta do túnel.
func (s *Service) SetDNSBindingSource(source func() (address, network string, enabled bool, err error)) {
	s.dnsBindingSource = source
}

func (s *Service) withRuntimeDNSBindings(c netsvc.Config) (netsvc.Config, error) {
	if s.dnsBindingSource == nil {
		return c, nil
	}
	address, network, enabled, err := s.dnsBindingSource()
	if err != nil {
		return c, fmt.Errorf("resolver DNS do túnel indisponível: %w", err)
	}
	if !enabled {
		return c, nil
	}
	c.ExtraListenAddresses = append(c.ExtraListenAddresses, address)
	c.ExtraAccessNetworks = append(c.ExtraAccessNetworks, network)
	return c, nil
}

// ensurePackages garante o unbound instalado antes de configurá-lo.
//
// dns-root-data só é pré-requisito duro quando é o LinkGuard que vai instalar o
// unbound nesta passada: um unbound recém-instalado sem a âncora nem sobe.
// Numa caixa onde o unbound já está servindo, a falta dela vira aviso — exigir
// trancaria toda mudança de DNS justamente quando a rede está ruim.
//
// Devolve os pacotes que instalou (vazio em toda aplicação depois da primeira)
// e os avisos.
func (s *Service) ensurePackages(ctx context.Context) ([]string, []string, error) {
	if s.exec.IsDryRun() {
		return nil, nil, nil
	}
	required := []string{unboundPackage}
	freshUnbound := len(bootstrapdeps.Missing(ctx, s.exec, unboundPackage)) > 0
	if freshUnbound {
		required = append(required, dnsRootDataPackage)
	}
	installed, err := bootstrapdeps.EnsureInstalled(ctx, s.installExec, required...)
	if err != nil {
		return installed, nil, &netsvc.PrereqError{Msg: err.Error()}
	}
	var warnings []string
	if !freshUnbound {
		got, derr := bootstrapdeps.EnsureInstalled(ctx, s.installExec, dnsRootDataPackage)
		installed = append(installed, got...)
		if derr != nil {
			slog.Warn("dns-root-data ausente e não instalável; DNS aplicado assim mesmo", "err", derr)
			warnings = append(warnings, "O pacote "+dnsRootDataPackage+" não está instalado e o LinkGuard não "+
				"conseguiu instalá-lo agora. A configuração foi aplicada e o DNS continua respondendo, mas "+
				"falta a âncora DNSSEC da raiz (/var/lib/unbound/root.key): se o unbound for reiniciado sem "+
				"ela, pode não voltar a subir e a VPN fica sem DNS. Instale quando a máquina tiver rede: "+
				"apt-get install -y "+dnsRootDataPackage+".")
		}
	}
	if err := writableDir(filepath.Dir(s.unboundConf)); err != nil {
		return installed, warnings, &netsvc.PrereqError{Msg: sandboxHint(filepath.Dir(s.unboundConf), err)}
	}
	return installed, warnings, nil
}

// writableDir reports whether this process can create a file in dir — the
// question that actually matters, answered the same way the code that
// follows will ask it (os.CreateTemp), instead of inferring it from
// permission bits that a read-only mount overrides anyway.
//
// The probe name deliberately has no ".conf" suffix: this runs inside
// /etc/unbound/unbound.conf.d, which Debian's unbound.conf pulls in with
// `include-toplevel: ".../*.conf"` — same reasoning as validateUnbound's own
// temp file.
//
// The name is also fixed rather than random (it used to be os.CreateTemp):
// a process killed between creating the probe and removing it left the file
// behind, and nothing ever collected it — one more piece of litter in /etc
// per unlucky restart. With a fixed name there can only ever be one, and the
// sweep below removes it (plus anything left by the old random-suffix
// version) before probing again.
//
// Concurrency-safe by construction: two applies racing on the same directory
// can only make each other's Remove find the file already gone, which is not
// an error here — the question being answered is "can this process create a
// file in dir", and it was answered by the create.
func writableDir(dir string) error {
	for _, leftover := range globQuiet(filepath.Join(dir, writeProbeName+"*")) {
		_ = os.Remove(leftover)
	}
	path := filepath.Join(dir, writeProbeName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	f.Close()
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// writeProbeName is the fixed name of the write probe. See writableDir.
const writeProbeName = ".linkguard-write-probe"

func globQuiet(pattern string) []string {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil
	}
	return matches
}

// sandboxHint delegates to sysprep.SandboxHint: the sentence is identical
// for DHCP, DNS and NTP, and it belongs next to the code that pre-creates
// those directories in the first place (internal/sysprep).
func sandboxHint(dir string, err error) string {
	return sysprep.SandboxHint(dir, err)
}

// EnsureResolvConf makes the box actually use its own resolver (unbound on
// 127.0.0.1) instead of whatever nameservers the WAN's DHCP lease proposes.
//
// Found in production on 2026-08-10: /etc/resolv.conf pointed at the ISP,
// and nothing in this codebase managed that file — so the appliance was
// silently bypassing its own DNS, losing the blocklist and the query
// visibility unbound provides. Rewriting resolv.conf alone would not hold:
// dhclient rewrites it on every lease renewal, which is why this also adds
// a `supersede domain-name-servers` directive so dhclient stops proposing
// the ISP's servers in the first place (working with dhclient rather than
// fighting it).
//
// Self-heals on every start, like the other Ensure* calls. Best-effort: a
// failure is logged as a warning rather than blocking startup. A dedicated
// dns-resolver health check to surface this failure in the UI is planned
// but not implemented yet.
//
// Gated on unbound actually being enabled: the Debian package lists unbound
// as `Recommends:`, never `Depends:`, so it can legitimately be absent (or
// present but failed to start). Unconditionally pointing resolv.conf at
// 127.0.0.1 on such a box, and stripping the ISP's servers from dhclient's
// config, would leave nothing answering DNS at all — silently breaking the
// updater's fetch from GitHub releases, Telegram/webhook notifications, the
// AI digest, and chrony's pool hostnames. Do NOT remove this guard "to
// simplify" without re-reading this comment: it is the difference between
// gaining a resolver and losing name resolution entirely.
//
// `systemctl is-enabled` (not `is-active`) is used deliberately: it answers
// from unit configuration rather than current process state, so it gives
// the same answer regardless of where in the boot sequence this runs,
// instead of racing unbound's own startup.
func (s *Service) EnsureResolvConf(ctx context.Context) {
	out, err := s.exec.ExecuteRead(ctx, "systemctl", "is-enabled", "unbound")
	if err != nil || strings.TrimSpace(out) != "enabled" {
		slog.Info("resolver local (unbound) não está instalado/habilitado; resolv.conf foi deixado como está", "path", s.resolvConf, "systemctl_output", strings.TrimSpace(out), "err", err)
		return
	}

	const body = "# managed by linkguard\nnameserver 127.0.0.1\n"
	if err := s.exec.WriteFile(s.resolvConf, []byte(body), 0o644); err != nil {
		slog.Warn("não foi possível apontar o resolv.conf para o resolver local", "path", s.resolvConf, "err", err)
	} else {
		// Escrever o arquivo não é a mesma coisa que a caixa passar a usá-lo, e
		// este log deliberadamente não afirma que passa. Quem responde isso é o
		// vigia do caminho de resolução (monitoring.Collector.checkCaminhoNSS),
		// que lê o /etc/nsswitch.conf a cada tique — e não aqui, que roda uma
		// vez por processo. Ver a doc de checkCaminhoNSS para o porquê.
		//
		// Também não afirma que o arquivo mudou: em dry-run o WriteFile devolve
		// nil sem tocar em disco, e "apontei o resolv.conf" seria falso ali.
		slog.Info("resolv.conf reconciliado para o resolver local (unbound)",
			"path", s.resolvConf, "dry_run", s.exec.IsDryRun())
	}

	const directive = "supersede domain-name-servers 127.0.0.1;"
	current, err := os.ReadFile(s.dhclientConf)
	if err != nil && !os.IsNotExist(err) {
		slog.Warn("não foi possível ler a config do dhclient; o DNS do provedor pode voltar na renovação do lease", "path", s.dhclientConf, "err", err)
		return
	}
	updated := ensureSupersedeDirective(string(current), directive)
	if updated == string(current) {
		return // already in place, exactly as we want it — this runs on every boot
	}
	if err := s.exec.WriteFile(s.dhclientConf, []byte(updated), 0o644); err != nil {
		slog.Warn("não foi possível fixar o DNS local na config do dhclient", "path", s.dhclientConf, "err", err)
	}
}

// ensureSupersedeDirective returns dhclient.conf content updated so exactly
// one *active* `supersede domain-name-servers` statement is present, with
// the given directive's value. LinkGuard owns this option outright — the
// whole point of the feature is that the box always resolves through its
// own unbound — so any other active statement for it is wrong and gets
// replaced in place, not left alongside a second, conflicting one (dhclient
// treats two modifier statements for one option as at best last-wins, at
// worst a parse failure that breaks DHCP on that WAN at lease renewal).
//
// Matching is line-based, not a full dhclient.conf grammar parse: a line is
// "active" if, after stripping leading whitespace, it does not start with
// `#` and its whitespace-separated fields start with "supersede",
// "domain-name-servers". This is deliberately field-based rather than a
// literal substring match, so it isn't fooled by a commented-out leftover
// (which must never count as "already in place") and isn't blind to a
// pre-existing directive that merely differs in spacing or value (which
// must be replaced, not duplicated). Everything else in the file is left
// untouched, in order.
func ensureSupersedeDirective(content, directive string) string {
	lines := strings.Split(content, "\n")
	out := make([]string, 0, len(lines)+1)
	found := false
	for _, line := range lines {
		if isActiveSupersedeDomainNameServers(line) {
			if found {
				continue // drop a redundant duplicate active statement
			}
			found = true
			if strings.TrimSpace(line) == directive {
				out = append(out, line) // already exactly right, leave untouched
			} else {
				out = append(out, directive) // wrong value/spacing: replace in place
			}
			continue
		}
		out = append(out, line)
	}
	if found {
		return strings.Join(out, "\n")
	}

	// No active directive found (file absent, or only commented-out
	// occurrences) — append ours.
	updated := strings.Join(out, "\n")
	if updated != "" && !strings.HasSuffix(updated, "\n") {
		updated += "\n"
	}
	updated += "\n# managed by linkguard — mantém o resolver local mesmo após renovação de lease\n" + directive + "\n"
	return updated
}

// isActiveSupersedeDomainNameServers reports whether line is a live (not
// commented-out) dhclient.conf `supersede domain-name-servers ...`
// statement, regardless of its value or exact spacing.
func isActiveSupersedeDomainNameServers(line string) bool {
	trimmed := strings.TrimLeft(line, " \t")
	if strings.HasPrefix(trimmed, "#") {
		return false
	}
	fields := strings.Fields(trimmed)
	return len(fields) >= 2 && fields[0] == "supersede" && fields[1] == "domain-name-servers"
}

// GenerateConfigs renderiza a config do unbound para a prévia.
func (s *Service) GenerateConfigs(c netsvc.Config, blocked []string) ([]netsvc.ConfigFile, error) {
	c, err := s.withRuntimeDNSBindings(c)
	if err != nil {
		return nil, err
	}
	content, _, err := GenerateUnboundConfig(c, blocked)
	if err != nil {
		return nil, err
	}
	return []netsvc.ConfigFile{{Path: s.unboundConf, Content: content}}, nil
}

// ReloadConfigs grava a config e recarrega o unbound.
//
// A ordem é a que protege o DNS de uma config ruim: instala o que falta, gera,
// confere que os endereços de escuta existem, valida com unbound-checkconf e só
// então grava e recarrega. Uma recusa em qualquer passo deixa a config em
// execução intacta. O reload é o gracioso (SIGHUP) quando só a lista de
// bloqueio ou os encaminhadores mudaram; um restart de verdade só quando muda
// onde o unbound ESCUTA, porque o SIGHUP não reabre sockets.
func (s *Service) ReloadConfigs(ctx context.Context, c netsvc.Config, blocked []string) (netsvc.ApplyResult, error) {
	c, err := s.withRuntimeDNSBindings(c)
	if err != nil {
		return netsvc.ApplyResult{}, err
	}
	installed, warnings, err := s.ensurePackages(ctx)
	if err != nil {
		return netsvc.ApplyResult{Warnings: warnings, Installed: installed}, err
	}
	content, renderWarnings, err := GenerateUnboundConfig(c, blocked)
	warnings = append(warnings, renderWarnings...)
	if err != nil {
		return netsvc.ApplyResult{Warnings: warnings, Installed: installed}, fmt.Errorf("config do unbound inválida (nada aplicado): %w", err)
	}
	// Um endereço de escuta que não existe na máquina faz o unbound morrer no
	// restart ("can't bind socket"). O do túnel é de outro serviço: escrevê-lo
	// sem o endereço derrubaria o DNS, e omiti-lo em silêncio anunciaria uma
	// VPN cujo DNS não funciona. Nada é aplicado.
	for _, address := range c.ExtraListenAddresses {
		if err := s.enderecoBindavel(ctx, address); err != nil {
			return netsvc.ApplyResult{Warnings: warnings, Installed: installed},
				fmt.Errorf("endereço DNS do túnel indisponível (nada aplicado): %w", err)
		}
	}
	// A regra de AppArmor é parte de ligar o dnstap: o perfil de fábrica do
	// unbound não autoriza o socket, e sem ela o mapa fica vazio sem erro em
	// lugar nenhum. Escrita junto da config que referencia o socket.
	if c.DNSTapEnabled {
		if err := dnstap.EscreverRegraAppArmor(s.exec, ctx); err != nil {
			return netsvc.ApplyResult{Warnings: warnings, Installed: installed},
				fmt.Errorf("o dnstap não pôde ser autorizado no AppArmor do unbound (sem isso o mapa fica vazio): %w", err)
		}
	}
	if err := s.validateUnbound(ctx, content); err != nil {
		return netsvc.ApplyResult{Warnings: warnings, Installed: installed}, fmt.Errorf("config do unbound inválida (nada aplicado): %w", err)
	}
	restart := slices.Contains(installed, unboundPackage) ||
		unboundNeedsRestart(readFileOrEmpty(s.unboundApplied), content)
	if err := s.exec.WriteFile(s.unboundConf, []byte(content), 0o644); err != nil {
		return netsvc.ApplyResult{Warnings: warnings, Installed: installed}, fmt.Errorf("write %s: %w", s.unboundConf, err)
	}
	action := "reload-or-restart"
	if restart {
		action = "restart"
	}
	// Limpa um estado failed antigo antes: esgotado o limite de restarts do
	// systemd, todo start responde "Start request repeated too quickly" em vez
	// do erro de verdade. Não esconde nada — se continuar quebrado, o comando
	// abaixo falha de novo com o motivo real.
	_, _ = s.exec.Execute(ctx, "systemctl", "reset-failed", unboundService)
	out, err := s.exec.Execute(ctx, "systemctl", action, unboundService)
	result := netsvc.ApplyResult{Output: unboundService + ": " + out, Warnings: warnings, Installed: installed}
	if err != nil {
		return result, fmt.Errorf("reload %s: %w", unboundService, err)
	}
	if err := s.exec.WriteFile(s.unboundApplied, []byte(content), 0o600); err != nil {
		// O custo de perder o marcador é um restart a mais na próxima
		// aplicação — o lado seguro da dúvida.
		slog.Warn("não foi possível registrar a config do unbound ativada; a próxima aplicação pode reiniciar o unbound sem necessidade",
			"path", s.unboundApplied, "err", err)
	}
	return result, nil
}

// unboundNeedsRestart reports whether the change between two rendered
// unbound configs requires a real restart instead of the graceful reload.
//
// Debian's unbound.service has `ExecReload=/bin/kill -HUP $MAINPID`, and
// SIGHUP makes unbound re-read its configuration but NOT re-open its
// listening sockets. Measured on the test VM: after an on-demand install the
// daemon was listening only on 127.0.0.1 (the package's own default), the
// LinkGuard drop-in with `interface: 192.168.3.3` was written, the reload
// ran, systemd reported success, the panel showed "aplicado" — and the LAN
// had no DNS at all. `systemctl restart` fixed it instantly. "Config
// aplicada ≠ funcionando" (FEATURES.md) is exactly this.
//
// Restarting on every save would be the easy answer and the wrong one: it
// drops the resolver (and its cache) for every blocklist entry an admin
// adds. So only a change in what unbound LISTENS on forces the restart;
// everything else — blocklist, forwarders, cache tuning — keeps the
// graceful reload SIGHUP is fine for.
func unboundNeedsRestart(oldConf, newConf string) bool {
	return listenLines(oldConf) != listenLines(newConf)
}

// listenLines reduces an unbound config to its `interface:` directives, in
// order, as a single comparable string.
func listenLines(conf string) string {
	var got []string
	for _, line := range strings.Split(conf, "\n") {
		if line = strings.TrimSpace(line); strings.HasPrefix(line, "interface:") {
			got = append(got, strings.Join(strings.Fields(line), " "))
		}
	}
	return strings.Join(got, "\n")
}

// readFileOrEmpty returns a file's contents, or "" when it cannot be read —
// which for this caller is the same answer ("nothing is configured yet, so
// this is a change").
func readFileOrEmpty(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// enderecoBindavel confere que o endereço em que o unbound vai escutar existe
// nesta máquina.
//
// Vazio não é erro: não há endereço extra a conferir.
func (s *Service) enderecoBindavel(ctx context.Context, addr string) error {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil
	}
	out, err := s.exec.ExecuteRead(ctx, "ip", "-o", "addr", "show")
	if err != nil {
		// Não conseguir perguntar NÃO vira "pode escrever". Um apply que segue
		// adiante às cegas aqui é o apagão de volta — e a alternativa, recusar,
		// custa uma alteração adiada.
		return fmt.Errorf("não consegui conferir se %s existe nesta máquina; o servidor de DNS pode não conseguir escutar nele: %w", addr, err)
	}
	for _, linha := range strings.Split(out, "\n") {
		for _, campo := range strings.Fields(linha) {
			if campo == addr || strings.HasPrefix(campo, addr+"/") {
				return nil
			}
		}
	}
	return fmt.Errorf("o endereço %s não existe em nenhuma interface desta máquina, então o servidor de DNS não pode escutar nele", addr)
}

// validateUnbound writes the candidate unbound config to a temp file and
// runs unbound-checkconf against it — added because ReloadConfigs used to
// write unbound.conf with
// no pre-apply check at all (finding #3, input-validation-audit.md): a
// broken config landed on disk and survived a reboot, taking DNS down at
// the next boot with no admin action in between (confirmed as a real
// production incident, not a hypothetical, in the session that produced the
// audit).
//
// The temp file is created next to the real unbound config. unbound-checkconf
// has no AppArmor profile confining it on Debian, so this placement isn't
// strictly required, but it is the pattern the old Kea validator needed
// (kea-dhcp4 IS confined and refuses a config outside /etc/kea), it keeps the
// temp file on the same filesystem as its destination, and it costs nothing.
//
// unbound-checkconf is optional at runtime: Debian's unbound package is a
// Recommends:, not a Depends:, of this project (see EnsureResolvConf's doc
// comment for why that guard exists elsewhere too) — a box can legitimately
// run without unbound installed, or with unbound installed but its checker
// missing (a minimal/manually-trimmed install). Treating a missing checker
// as a hard failure would block every DHCP/DNS apply on such a box, which
// is strictly worse than the gap this validation closes — so a missing
// binary is logged and treated as "validation not possible here, proceed",
// never as a validation failure.
func (s *Service) validateUnbound(ctx context.Context, content string) error {
	// I-6: "the checker isn't installed" is decided HERE, by looking for the
	// binary, before it is ever run — not afterwards by pattern-matching the
	// error text. firewall.RealExecutor folds the command's stderr into the
	// error string, and plenty of genuine unbound-checkconf rejections name
	// a file that is missing ("… /var/lib/unbound/root.key: no such file or
	// directory"), which the old substring match read as "tool absent,
	// proceed". That turned a validation whose entire purpose is to fail
	// closed into one that failed open on exactly the configs it exists to
	// stop. After this point every error from the checker is a real
	// rejection and aborts the apply.
	if err := binaryInstalled(s.unboundCheckBin); err != nil {
		slog.Warn("unbound-checkconf não encontrado; pulando validação pré-apply do unbound.conf (o pacote unbound é Recommends:, não Depends:, deste projeto)", "bin", s.unboundCheckBin, "err", err)
		return nil
	}

	// I-5: the suffix must NOT be ".conf". This temp file is created inside
	// /etc/unbound/unbound.conf.d (see above), and Debian's unbound.conf
	// pulls in that whole directory with `include-toplevel:
	// "/etc/unbound/unbound.conf.d/*.conf"`. Kill this process between the
	// CreateTemp and the deferred Remove — a crash, an OOM kill, a package
	// upgrade restarting the service — and a leftover fragment with a
	// duplicate `interface:`/`local-zone` stays behind for unbound to load
	// at the next start: DNS dead at the next boot, with nobody having
	// touched anything. ".tmp" keeps the file on the same filesystem (the
	// reason it is here at all) while staying outside the glob.
	f, err := os.CreateTemp(filepath.Dir(s.unboundConf), "unbound-validate-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return err
	}
	f.Close()

	_, err = s.exec.ExecuteRead(ctx, s.unboundCheckBin, f.Name())
	return err
}

// binaryInstalled reports (as an error) whether bin can actually be run.
// exec.LookPath answers exactly that question for both spellings — a path
// (checked for existence and the execute bit) and a bare command name
// (searched in $PATH) — which is the same resolution os/exec itself would
// perform a moment later. This is the only honest way to tell "the tool
// isn't installed here" from "the tool ran and rejected the config": the
// executor reports both as a plain error string, and only the first may be
// treated as "validation not possible, proceed".
func binaryInstalled(bin string) error {
	_, err := exec.LookPath(bin)
	return err
}

var reUnboundDomain = regexp.MustCompile(`^[a-z0-9_]([a-z0-9._-]*[a-z0-9_])?$`)

func validRenderDomain(d string) bool {
	return d != "" && len(d) <= 253 && reUnboundDomain.MatchString(d)
}

// GenerateUnboundConfig renderiza o fragmento de config do unbound.
//
// Todo valor interpolado é validado de novo aqui, e não só confiado ao
// chamador: esta é a última parada antes de um daemon root ler o resultado, e
// ela tem chamadores que pulam o handler (um backup restaurado, uma linha
// gravada por versão anterior).
//
// O unbound escuta em 127.0.0.1 e nos endereços extras (o do túnel), e só
// responde a quem vem dessas redes. Um endereço extra inválido falha a geração
// inteira — escuta é singular, pular deixaria a VPN sem DNS com o apply
// relatando sucesso. Uma entrada de lista inválida (domínio bloqueado,
// encaminhador) é pulada e contada como aviso: uma entrada ruim não derruba as
// boas.
func GenerateUnboundConfig(c netsvc.Config, blocked []string) (string, []string, error) {
	var warnings []string
	var b strings.Builder
	w := func(s string) { b.WriteString(s); b.WriteString("\n") }

	w("# Managed by LinkGuard Cloud — do not edit by hand.")
	w("server:")
	w("  interface: 127.0.0.1")
	w("  access-control: 127.0.0.0/8 allow")
	seenInterfaces := map[string]bool{"127.0.0.1": true}
	for _, raw := range c.ExtraListenAddresses {
		ip := net.ParseIP(strings.TrimSpace(raw))
		if ip == nil {
			return "", warnings, fmt.Errorf("endereço adicional do unbound inválido: %q", raw)
		}
		canonical := ip.String()
		if !seenInterfaces[canonical] {
			w("  interface: " + canonical)
			seenInterfaces[canonical] = true
		}
	}
	seenNetworks := map[string]bool{"127.0.0.0/8": true}
	for _, raw := range c.ExtraAccessNetworks {
		_, network, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err != nil {
			return "", warnings, fmt.Errorf("rede adicional do unbound inválida: %q", raw)
		}
		canonical := network.String()
		if !seenNetworks[canonical] {
			w("  access-control: " + canonical + " allow")
			seenNetworks[canonical] = true
		}
	}
	w("  hide-identity: yes")
	w("  hide-version: yes")
	w("  prefetch: yes")
	w("  num-threads: 2")
	w("  msg-cache-size: 64m")
	w("  rrset-cache-size: 128m")
	if c.LogQueries {
		w("  log-queries: yes")
	}

	// dnstap: as RESPOSTAS saem por socket binário para o coletor do produto. É
	// o que transforma todo destino de número em nome na análise de tráfego.
	if c.DNSTapEnabled {
		w("dnstap:")
		w("  dnstap-enable: yes")
		w("  dnstap-socket-path: \"" + DNSTapSocketPath + "\"")
		w("  dnstap-send-identity: no")
		w("  dnstap-send-version: no")
		w("  dnstap-log-client-response-messages: yes")
		w("server:")
	}

	if len(blocked) > 0 {
		var validBlocked []string
		skipped := 0
		for _, d := range blocked {
			if !validRenderDomain(d) {
				slog.Warn("domínio inválido descartado na renderização do unbound.conf (blocklist)", "domain", d)
				skipped++
				continue
			}
			validBlocked = append(validBlocked, d)
		}
		if skipped > 0 {
			warnings = append(warnings, fmt.Sprintf("%d domínio(s) da lista de bloqueio são inválidos e não foram aplicados ao DNS", skipped))
		}
		if len(validBlocked) > 0 {
			w("  # DNS filtering (blocklist) — NXDOMAIN")
			sort.Strings(validBlocked)
			for _, d := range validBlocked {
				w("  local-zone: \"" + d + ".\" always_nxdomain")
			}
		}
	}

	if len(c.Upstreams) > 0 {
		var valid []string
		skipped := 0
		for _, up := range c.Upstreams {
			if net.ParseIP(strings.TrimSpace(up)) == nil {
				slog.Warn("upstream DNS inválido descartado na renderização do unbound.conf", "upstream", up)
				skipped++
				continue
			}
			valid = append(valid, strings.TrimSpace(up))
		}
		if skipped > 0 {
			warnings = append(warnings, fmt.Sprintf("%d servidor(es) DNS de encaminhamento são inválidos e não foram aplicados", skipped))
		}
		if len(valid) > 0 {
			w("forward-zone:")
			w("  name: \".\"")
			for _, up := range valid {
				w("  forward-addr: " + up)
			}
		}
	}
	return b.String(), warnings, nil
}

// compile-time check.
var _ netsvc.Provider = (*Service)(nil)
