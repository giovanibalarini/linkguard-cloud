// API type definitions for LinkGuard Cloud

export type AlertSeverity = 'info' | 'warning' | 'critical';

// MsgLevel é como uma mensagem de tela deve SOAR. Os dois primeiros já
// existiam implicitamente (verde, ou vermelho quando o texto começa com
// "Erro"); 'warn' existe porque há um recado que não é nenhum dos dois: "o
// prazo acabou sem confirmação e a alteração foi revertida" não é uma boa
// notícia — em verde, ele induz o operador a achar que a mudança dele valeu.
export type MsgLevel = 'ok' | 'warn' | 'error';

// ─── Uplink ─────────────────────────────────────────────────────────────────

// Uplink é por onde a máquina sai para a Internet AGORA: a VNIC primária que a
// plataforma afirmou ou, quando ela não respondeu, a placa da rota default.
// Somente leitura (GET /api/uplink): o que se muda é a VNIC, no console da
// Oracle, e não um registro.
export interface Uplink {
  interface: string;
  // path_mtu é o que o CAMINHO suporta, não o que a placa anuncia. 0 =
  // desconhecido, e a tela tem de dizer "desconhecida", nunca "0".
  path_mtu: number;
  source: 'platform' | 'kernel' | 'none';
  platform: string;
  // A última medição da sonda de saída: a Internet responde daqui?
  health: UplinkHealth;
}

export type UplinkStatus = 'desconhecida' | 'online' | 'degradada' | 'offline';

export interface UplinkHealth {
  status: UplinkStatus;
  latency_ms: number;
  loss_pct: number;
  checked_at: string;
  targets: string[];
}

export interface TimelinePoint {
  ts: number;
  min: number;
  avg: number;
  max: number;
}

export interface TimelineSeries {
  name: string;
  label: string;
  points: TimelinePoint[];
}

export interface TimelineState {
  kind: string;
  label: string;
  state: string;
  started_at: number;
  ended_at?: number;
}

export interface TimelineAlert {
  ts: number;
  type: string;
  severity: string;
  title: string;
}

export interface TimelineResponse {
  step_seconds: number;
  series: TimelineSeries[];
  states: TimelineState[];
  alerts: TimelineAlert[];
}

export interface SystemMetrics {
  uptime_seconds: number;
  uptime_str: string;
  cpu_percent: number;
  mem_total_bytes: number;
  mem_used_bytes: number;
  mem_percent: number;
  disk_total_bytes: number;
  disk_used_bytes: number;
  disk_percent: number;
  load_avg: [number, number, number];
  interfaces: InterfaceMetrics[];
}

export interface InterfaceMetrics {
  name: string;
  alias?: string;
  addresses?: InterfaceAddress[];
  rx_bytes: number;
  tx_bytes: number;
  rx_packets: number;
  tx_packets: number;
  rx_errors: number;
  tx_errors: number;
  rx_dropped: number;
  tx_dropped: number;
}

export interface InterfaceAddress {
  family: string;
  ip: string;
  subnet: string;
  cidr: string;
}

export interface Alert {
  id: string;
  type: string;
  severity: AlertSeverity;
  title: string;
  message: string;
  link_id: string;
  resolved: boolean;
  created_at: string;
  resolved_at: string | null;
}

export interface AuditLog {
  id: string;
  user: string;
  action: string;
  resource: string;
  details: string;
  ip: string;
  created_at: string;
}

export interface Route {
  destination: string;
  gateway: string;
  interface: string;
  metric: string;
  protocol: string;
  scope: string;
  raw: string;
}

export interface IpRule {
  priority: string;
  selector: string;
  action: string;
  table: string;
  fwmark?: string;
  raw: string;
}

export interface InterfaceOption {
  name: string;
}

export interface IptablesTable {
  name: string;
  chains: IptablesChain[];
}

export interface IptablesChain {
  name: string;
  policy: string;
  rules: IptablesRule[];
}

export interface IptablesRule {
  num: string;
  raw: string;
  pkts: string;
  bytes: string;
  target: string;
  prot: string;
  in: string;
  out: string;
  source: string;
  dest: string;
  options: string[];
}

export interface IptablesBackup {
  id: string;
  label: string;
  rules: string;
  created_at: string;
}

export interface LoginResponse {
  token: string;
  user: {
    id: string;
    username: string;
    role: string;
  };
}

export interface HealthStatus {
  status: string;
  version?: string;
}

// ─── RBAC ──────────────────────────────────────────────────────────────────

export interface AppUser {
  id: string;
  username: string;
  role: string;
  role_ids: string[];
  created_at: string;
  updated_at: string;
}

export interface AppRole {
  id: string;
  name: string;
  description: string;
  builtin: boolean;
  permissions: string[];
  created_at: string;
  updated_at: string;
}

export interface PermissionCatalogEntry {
  key: string;
  area: string;
  label: string;
  description: string;
}

export interface MeResponse {
  id: string;
  username: string;
  role_ids: string[];
  permissions: string[];
}

export interface NftManaged {
  blocklist: string[];
  blocked_hosts: string[];
}


// FirewallPendingChange é a janela de confirmação em aberto, como GET
// /api/nftables/pending a devolve (handlers.pendingView).
//
// `id` NÃO é decoração: confirmar e reverter o exigem no corpo, e ele é
// conferido contra a janela atual — sem ele, um admin confirmando cancelaria a
// rede de proteção de uma mudança de outro admin que ele nunca viu.
//
// `reverting` separa os dois estados possíveis, e a faixa PRECISA dos dois
// porque os botões que cabem são outros em cada um: aguardando confirmação
// cabem "Confirmar acesso" e "Reverter agora"; com a reversão já em curso não
// cabe nenhum dos dois (o backend recusa confirmar), e o texto tem que dizer
// que a reversão está acontecendo.
export interface FirewallPendingChange {
  id: string;
  summary: string;
  applied_by: string;
  // expires_at é o instante em que o LinkGuard reverte sozinho, em hora do
  // SERVIDOR. É a verdade persistida da janela.
  expires_at: string;
  // seconds_left é quanto falta, medido pelo relógio DO SERVIDOR e recalculado
  // a cada resposta. A contagem da tela parte daqui, e não de
  // `expires_at - Date.now()`: aquela conta mistura a hora do firewall com a da
  // estação do operador, e um relógio deslocado erra o número na mesma medida —
  // "45 s" quando restam 5 é o caso ruim, porque é esse número que ele usa para
  // decidir se ainda dá tempo de testar o SSH.
  seconds_left: number;
  created_at: string;
  reverting: boolean;
  reverting_at?: string;
}

// FirewallPendingResponse é o corpo do GET. `pending` é null explícito quando
// não há janela — a ausência do campo nunca deve ser lida como "não há nada".
export interface FirewallPendingResponse {
  pending: FirewallPendingChange | null;
}


export interface NetsvcConfig {
  upstreams: string[];
  log_queries: boolean;
  /** Entrega das RESPOSTAS de DNS ao coletor, que alimenta o mapa endereço → nome (#116). */
  dnstap_enabled?: boolean;
}
// warning (I-7): o apply terminou bem, mas o backend descartou entradas
// inválidas que a tela ainda mostra como configuradas (domínio de bloqueio,
// upstream de DNS). É um terceiro estado entre "falhou" e
// "tudo em vigor" — nunca deve ser exibido como sucesso puro.
export interface LastApply { ok: boolean; error?: string; warning?: string; at: number; }
export interface DNSData { config: NetsvcConfig; blocklist: string[]; last_apply?: LastApply; }


export interface HostTraffic { ip: string; rx_bytes: number; tx_bytes: number; }

/**
 * Uma máquina do inventário, identificada pelo IP.
 *
 * `vcn` é máquina da conta (de qualquer sub-rede); `vpn` é pessoa conectada
 * pelo túnel. `hostname` é o nome da instância no DNS reverso da VCN, ou o
 * usuário dono do peer da VPN. `online` = trafegou nos últimos 10 minutos.
 */
export type HostKind = 'vcn' | 'vpn';

export interface NetHost {
  ip: string;
  kind: HostKind;
  online: boolean;
  hostname?: string;
  alias?: string;
  blocked: boolean;
  first_seen?: string;
  last_seen?: string;
}

export interface TrafficHistoryPoint {
  interface: string;
  step_seconds: number;
  timestamp: number;
  /**
   * `null` é **não medido**, e nunca zero.
   *
   * O backend serializa isto como ponteiro e sem `omitempty`, de propósito
   * (`internal/tsdb`, commit 63dbd91): campo omitido desserializaria como `0`
   * aqui, que é o mesmo dado falso com outra cara. Um zero inventado faz um
   * link fora do ar parecer um link ocioso.
   */
  rx_bps: number | null;
  tx_bps: number | null;
}

export interface TrafficHistoryResponse {
  interface: string;
  range: string;
  step_seconds: number;
  points: TrafficHistoryPoint[];
}

export interface TrafficRetentionResponse {
  profile: '30d' | '1y' | '5y';
}

// ─── Monitoring (Vigia) ──────────────────────────────────────────────────────

export interface HealthItem { name: string; kind: 'service' | 'resource'; up: boolean; since: number; }
export interface PendingPackage {
  name: string;
  current_version: string;
  new_version: string;
  origin: string;
  security: boolean;
}
export interface UpdatesReport { total: number; security: number; packages: PendingPackage[]; }
export interface MonitoringConfig {
  enabled: boolean;
  services: string[];
  disk_threshold_pct: number;
  journal_verify_interval_days: number;
}

// ─── Backup & Restore ──────────────────────────────────────────────────────

export interface RestoreResult {
  settings: number;
  blocklist: number;
  secrets_to_reconfigure: string[];
}

export interface BackupPassphraseStatusResponse {
  configured: boolean;
}

export type BackupSchedule = 'off' | 'daily' | 'weekly' | 'monthly';

export interface BackupScheduleResponse {
  schedule: BackupSchedule;
}

export interface BackupLastRunResponse {
  ok: boolean;
  error?: string;
  at: number; // unix seconds, 0 se nunca rodou
}

// ─── Assistente de IA (BYOK) ────────────────────────────────────────────────

export interface AIStatus {
  configured: boolean;
  hint: string;
  enabled: boolean;
  model: string;
  effort: string;
  monthly_budget_usd: number;
  spent_this_month_usd: number;
}

export interface AIConfig {
  enabled: boolean;
  model: string;
  effort: string;
  monthly_budget_usd: number;
  telemetry_consent: Record<string, boolean>;
  digest_hour: number;
}

// ─── Network interfaces (inventory) ─────────────────────────────────────────

export type IfaceKind = 'physical' | 'vlan' | 'bridge';
export type IfaceAddrMode = 'static' | 'dhcp' | 'none';
export type IfaceRole = 'wan' | 'lan' | 'unassigned';

export interface IfaceAddress {
  family: 'ipv4' | 'ipv6';
  ip: string;
  cidr: string;
}

export interface IfaceLiveState {
  carrier: boolean;
  mac?: string;
  mtu?: number;
  addresses?: IfaceAddress[];
  rx_errors: number;
  tx_errors: number;
  rx_dropped: number;
  tx_dropped: number;
  system: boolean;
}

export interface IfaceView {
  name: string;
  kind: IfaceKind;
  alias?: string;
  description?: string;
  parent?: string;
  vlan_id?: number;
  members?: string[];
  addr_mode: IfaceAddrMode;
  cidr?: string;
  gateway?: string;
  role: IfaceRole;
  live: IfaceLiveState;
}

// ─── Captura de pacotes (issue #114) ─────────────────────────────────────────
// Só cabeçalho: o backend captura com snaplen curto e o parser descarta o
// texto que o tcpdump deriva de payload. Não existe campo de conteúdo aqui, e
// isso é proposital.

export interface CapturePacket {
  time: string;
  src: string;
  dst: string;
  proto: string;
  len: number;
  flags: string;
}

export interface CaptureCount {
  key: string;
  count: number;
  bytes: number;
}

export interface CaptureBucket {
  sec: number;
  packets: number;
  bytes: number;
}

export interface CaptureHandshake {
  src: string;
  dst: string;
  time: string;
  tries: number;
}

export interface CaptureSummary {
  packets: number;
  bytes: number;
  duration_sec: number;
  protos: CaptureCount[];
  pairs: CaptureCount[];
  ports: CaptureCount[];
  per_second: CaptureBucket[];
  unanswered: CaptureHandshake[];
  refused: CaptureHandshake[];
  unanswered_total: number;
  refused_total: number;
  retransmits: number;
}

export interface CaptureFilter {
  host: string;
  port: number;
  proto: string;
  direction: string;
}

export interface CaptureRun {
  id: string;
  interface: string;
  filter: CaptureFilter;
  filter_expr: string;
  duration_sec: number;
  max_packets: number;
  snaplen: number;
  state: string; // running | done | aborted | error
  message: string;
  started_by: string;
  started_at: string;
  ended_at: string;
  packets: CapturePacket[];
  rows_shown: number;
  truncated: boolean;
  summary: CaptureSummary;
  has_file: boolean;
  file_bytes: number;
}

export interface CaptureStatus {
  state: string; // idle quando nunca rodou
  available: boolean; // o tcpdump está instalado?
  limits: {
    max_duration_sec: number;
    max_packets: number;
    snaplen: number;
    file_ttl_sec: number;
  };
  capture?: CaptureRun;
}

// ─── Cota por máquina (issue #126) ──────────────────────────────────────────
// limit_gb e o consumo são em GB DECIMAIS (10^9). O consumo é medido dos
// contadores por endereço do nftables, que são IPv4 — a tela diz isso.
//
// Não existe campo de "cortar" nem de "limitar banda", e não é esquecimento:
// ver o cabeçalho de internal/hostquota no backend.

export type HostQuotaPeriod = 'monthly' | 'daily';

export interface HostQuotaStatus {
  /** A máquina — é a chave da cota. */
  ip: string;
  /** Apelido, com queda para o nome da instância e o IP. */
  name: string;
  configured: boolean;
  /**
   * O AVISO está ligado. Chama-se alert_enabled, e não enabled, de propósito:
   * "enabled" numa linha de cota por máquina é a palavra que qualquer
   * leitor entende como "aplicar a cota", e esta feature não aplica nada.
   * Quem o define é o backend, a partir do limite — o PUT não o manda.
   */
  alert_enabled: boolean;
  limit_gb: number;
  period: HostQuotaPeriod;
  cycle_day: number;
  alert_pct: number;
  cycle_start: number;
  cycle_end: number;
  rx_bytes: number;
  tx_bytes: number;
  used_bytes: number;
  used_pct: number;
  /**
   * A máquina está no inventário.
   *
   * NÃO É "a máquina ainda existe": host_info guarda a linha para sempre
   * depois do primeiro avistamento, então a instância destruída ontem continua
   * presente hoje. Quem responde a essa pergunta são os dois campos abaixo.
   */
  present: boolean;
  /** Quando o inventário viu a máquina pela última vez (unix, 0 = nunca). */
  last_seen: number;
  /** Quando a medição DESTE ciclo foi atualizada (unix, 0 = nada medido). */
  measured_at: number;
}

/** Um ciclo fechado do histórico de consumo de uma máquina. */
export interface HostUsageCycle {
  ip: string;
  /** Diário ou mensal: sem isto, um ciclo de um dia e um de um mês se parecem. */
  period: HostQuotaPeriod;
  cycle_start: number;
  rx_bytes: number;
  tx_bytes: number;
  updated_at: number;
}


