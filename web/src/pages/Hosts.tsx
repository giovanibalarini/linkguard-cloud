import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { RefreshCw, Pencil, Ban, ShieldCheck, Circle, TrendingUp, ArrowDown, ArrowUp, AlertTriangle, KeyRound, Server } from 'lucide-react';
import client from '../api/client';
import { useAuth } from '../context/AuthContext';
import { useI18n } from '../i18n';
import { blockEnforcement } from '../lib/blockGroups';
import type { NetHost, HostKind, HostTraffic } from '../types';
import type { EstadoFW } from '../types/firewall';
import Panel from '../components/ui/Panel';
import HostHistory from '../components/HostHistory';
import HostFlows from '../components/HostFlows';
import HostQuota from '../components/HostQuota';
import Modal from '../components/ui/Modal';

/** Como a máquina é chamada: apelido, nome da instância (ou usuário da VPN), IP. */
function nomeDe(h: NetHost): string {
  return h.alias || h.hostname || h.ip;
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const u = ['KB', 'MB', 'GB', 'TB'];
  let v = n / 1024, i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(1)} ${u[i]}`;
}

export default function Hosts() {
  const { can } = useAuth();
  const { t } = useI18n();
  const canManage = can('hosts.block');
  const canReadFirewall = can('firewall.read');
  // Ver COM QUEM uma máquina falou tem permissão própria (#115): ver o
  // gráfico de consumo é uma coisa, ler os destinos de cada máquina é outra.
  // Ver auth.PermTrafficFlows.
  const canReadFlows = can('traffic.flows');
  const [hosts, setHosts] = useState<NetHost[]>([]);
  // Estado dos bloqueios no firewall por zonas: null = não consultado,
  // true = bloqueios em vigor, false = pendentes ou não aplicados.
  const [bloqueiosAplicados, setBloqueiosAplicados] = useState<boolean | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [filter, setFilter] = useState('');
  // Histórico de consumo da máquina (#113). Aberto pelo nome na lista, e
  // não pela coluna de ações: ver consumo é leitura, não gestão.
  const [historyFor, setHistoryFor] = useState<NetHost | null>(null);
  const [aliasFor, setAliasFor] = useState<NetHost | null>(null);
  const [aliasValue, setAliasValue] = useState('');
  const [aliasError, setAliasError] = useState('');
  const [saving, setSaving] = useState(false);
  const [confirmFor, setConfirmFor] = useState<NetHost | null>(null);
  const [confirmError, setConfirmError] = useState('');
  const [confirming, setConfirming] = useState(false);

  const [talkers, setTalkers] = useState<HostTraffic[]>([]);

  const fetchHosts = async () => {
    setLoading(true);
    setError(false);
    try {
      const res = await client.get<NetHost[]>('/api/hosts');
      setHosts(res.data ?? []);
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
    // Top talkers — best-effort (requires conntrack accounting).
    try {
      const t = await client.get<HostTraffic[]>('/api/hosts/traffic');
      setTalkers(t.data ?? []);
    } catch { /* ignore */ }
    await fetchBlockGroup();
  };

  // Estado dos bloqueios no firewall — melhor esforço, exige firewall.read.
  const fetchBlockGroup = async () => {
    if (!canReadFirewall) { setBloqueiosAplicados(null); return; }
    try {
      const { data } = await client.get<EstadoFW>('/api/firewall/estado');
      setBloqueiosAplicados(data?.bloqueios_aplicados ?? null);
    } catch {
      setBloqueiosAplicados(null);
    }
  };

  useEffect(() => { fetchHosts(); }, []);
  // As permissões chegam depois da primeira renderização (/api/auth/me é
  // assíncrono): sem este efeito, a consulta acima seria pulada em toda
  // navegação direta para esta página e a tela nunca saberia se o bloqueio
  // está em vigor — calada, como se estivesse.
  useEffect(() => { fetchBlockGroup(); }, [canReadFirewall]);

  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return hosts;
    return hosts.filter((h) =>
      [h.ip, h.alias, h.hostname, h.kind].some((v) => v?.toLowerCase().includes(q)),
    );
  }, [hosts, filter]);

  const onlineCount = useMemo(() => hosts.filter((h) => h.online).length, [hosts]);
  const blockedCount = useMemo(() => hosts.filter((h) => h.blocked).length, [hosts]);

  // enforcement é a resposta a "bloquear aqui adianta alguma coisa?".
  const enforcement = useMemo(() => blockEnforcement(bloqueiosAplicados), [bloqueiosAplicados]);
  const notEnforced = enforcement.status === 'not_applied';
  const enforcementReason = enforcement.reasonKey ? t(enforcement.reasonKey) : '';
  const enforcementFix = enforcement.fixKey ? t(enforcement.fixKey) : '';

  const openAlias = (h: NetHost) => {
    setAliasFor(h);
    setAliasValue(h.alias ?? '');
    setAliasError('');
  };

  const saveAlias = async () => {
    if (!aliasFor) return;
    setSaving(true);
    setAliasError('');
    try {
      await client.put('/api/hosts/alias', { ip: aliasFor.ip, alias: aliasValue.trim() });
      setAliasFor(null);
      await fetchHosts();
    } catch (err: any) {
      setAliasError(err.response?.data?.error || t('svc.hosts.alias.saveError'));
    } finally {
      setSaving(false);
    }
  };

  const openConfirm = (h: NetHost) => {
    setConfirmFor(h);
    setConfirmError('');
  };

  const confirmToggleBlock = async () => {
    const h = confirmFor;
    if (!h) return;
    const failMsg = h.blocked ? t('svc.hosts.err.unblock') : t('svc.hosts.err.block');
    setConfirming(true);
    setConfirmError('');
    try {
      await client.post('/api/hosts/block', { ip: h.ip, blocked: !h.blocked });
      setConfirmFor(null);
      await fetchHosts();
    } catch (err: any) {
      setConfirmError(err.response?.data?.error || failMsg);
    } finally {
      setConfirming(false);
    }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-white">{t('svc.hosts.title')}</h1>
          <p className="text-gray-500 text-sm">
            {t('svc.hosts.subtitle', { online: onlineCount, total: hosts.length })}
          </p>
        </div>
        <div className="flex gap-2 w-full sm:w-auto">
          <input
            className="input flex-1 sm:w-64"
            placeholder={t('svc.hosts.filter.placeholder')}
            aria-label={t('svc.hosts.filter.aria')}
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
          <button onClick={fetchHosts} disabled={loading} className="btn-secondary flex items-center gap-2 whitespace-nowrap disabled:opacity-50">
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> {t('svc.common.refresh')}
          </button>
        </div>
      </div>

      {error && <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm">{t('svc.common.loadFailed')} <button onClick={fetchHosts} className="underline">{t('svc.common.tryAgain')}</button></div>}

      {/* "Bloqueado" no inventário não é mais garantia de bloqueio em vigor:
          o grupo do sistema que descarta esses hosts pode estar desligado,
          pode não estar aplicado, ou pode ter sido arrastado para depois de
          um grupo do admin que libera antes. Quando isso acontece, o painel
          diz — com o motivo e o caminho para resolver —, em vez de mostrar um
          selo vermelho de bloqueio que o tráfego desmente. */}
      {blockedCount > 0 && notEnforced && (
        <div className="card border border-orange-500/40 bg-orange-500/10 text-sm">
          <div className="flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 text-orange-400 shrink-0 mt-0.5" aria-hidden="true" />
            <div className="min-w-0">
              <p className="text-orange-300">
                {blockedCount === 1 ? t('svc.hosts.notEnforced.one') : t('svc.hosts.notEnforced.many', { n: blockedCount })}
              </p>
              <p className="text-gray-300 text-xs mt-1">{enforcementReason}</p>
              <p className="text-gray-400 text-xs mt-1">
                {enforcementFix}{' '}
                <Link to="/firewall?tab=regras&zona=flutuante" className="text-blue-400 hover:text-blue-300 underline">{t('svc.hosts.openGroups')}</Link>
              </p>
            </div>
          </div>
        </div>
      )}
      {blockedCount > 0 && enforcement.status === 'unknown' && enforcementReason && (
        <div className="card border border-gray-700 text-sm text-gray-400">
          <span className="text-gray-300">{enforcementReason}</span>{' '}
          {t('svc.hosts.unknownEnforcement')} {enforcementFix}
        </div>
      )}

      {talkers.length > 0 && (
        <Panel title={<span className="flex items-center gap-2"><TrendingUp className="w-4 h-4 text-blue-400" /><span className="text-white font-semibold">{t('svc.hosts.talkers.title')}</span><span className="text-xs text-gray-600 font-normal">{t('svc.hosts.talkers.hint')}</span></span>}>
          <div className="space-y-2.5">
            {talkers.slice(0, 8).map((tk) => {
              const total = tk.rx_bytes + tk.tx_bytes;
              const max = (talkers[0].rx_bytes + talkers[0].tx_bytes) || 1;
              const host = hosts.find((h) => h.ip === tk.ip);
              const name = host ? nomeDe(host) : tk.ip;
              return (
                <div key={tk.ip} className="flex items-center gap-3">
                  <div className="w-36 sm:w-44 shrink-0 min-w-0">
                    <div className="text-white text-sm truncate">{name}</div>
                    <div className="text-gray-600 text-xs font-mono truncate">{tk.ip}</div>
                  </div>
                  <div className="flex-1 h-2 rounded-full bg-gray-800 overflow-hidden">
                    <div className="h-full bg-blue-500" style={{ width: `${(total / max) * 100}%` }} />
                  </div>
                  <div className="shrink-0 text-xs text-gray-400 flex items-center justify-end gap-3 w-32 sm:w-40">
                    <span className="inline-flex items-center gap-1" title={t('svc.hosts.talkers.down')}><ArrowDown className="w-3 h-3 text-green-400" />{fmtBytes(tk.rx_bytes)}</span>
                    <span className="inline-flex items-center gap-1" title={t('svc.hosts.talkers.up')}><ArrowUp className="w-3 h-3 text-orange-400" />{fmtBytes(tk.tx_bytes)}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </Panel>
      )}

      {/* Cota por máquina (#126). Depois do "quem mais consome agora" e antes
          da lista: a pergunta "quanto já foi neste ciclo" é a continuação
          natural, e é o lugar onde o admin decide onde declarar um teto. */}
      {can('hosts.read') && <HostQuota canEdit={canManage} />}

      <Panel>
        {loading && hosts.length === 0 ? (
          <div className="text-gray-500 text-center py-8 animate-pulse">{t('common.loading')}</div>
        ) : error && hosts.length === 0 ? (
          <div className="text-center py-12 text-gray-500">{t('svc.hosts.loadError')}</div>
        ) : filtered.length === 0 ? (
          <div className="text-center py-12 text-gray-500">
            {hosts.length === 0 ? t('svc.hosts.empty') : t('svc.hosts.noMatch')}
          </div>
        ) : (
          <>
            {/* Mobile: stacked cards (< sm) */}
            <div className="sm:hidden space-y-2">
              {filtered.map((h) => (
                <div
                  key={h.ip}
                  className={`rounded-lg border bg-gray-950/40 p-3 ${h.blocked ? 'border-l-2 border-l-red-500 border-gray-800 opacity-75' : 'border-gray-800'}`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <button
                        onClick={() => setHistoryFor(h)}
                        className="text-white font-medium truncate hover:text-blue-400 transition-colors text-left"
                        title={t('svc.hosts.history.open')}
                      >
                        {nomeDe(h)}
                      </button>
                      <EstadoMaquina h={h} />
                    </div>
                    {canManage && (
                      <div className="flex shrink-0 gap-3">
                        <button
                          onClick={() => openAlias(h)}
                          aria-label={t('svc.hosts.alias')}
                          className="text-gray-400 hover:text-blue-400 transition-colors"
                        >
                          <Pencil className="w-5 h-5" />
                        </button>
                        <button
                          onClick={() => openConfirm(h)}
                          aria-label={h.blocked ? t('svc.hosts.unblock') : t('svc.hosts.block')}
                          className={`transition-colors ${h.blocked ? 'text-red-400 hover:text-green-400' : 'text-gray-400 hover:text-red-400'}`}
                        >
                          {h.blocked ? <ShieldCheck className="w-5 h-5" /> : <Ban className="w-5 h-5" />}
                        </button>
                      </div>
                    )}
                  </div>
                  <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
                    <dt className="text-gray-500">{t('svc.hosts.col.ip')}</dt>
                    <dd className="text-gray-400 font-mono">{h.ip}</dd>
                    <dt className="text-gray-500">{t('svc.hosts.col.kind')}</dt>
                    <dd><OrigemMaquina kind={h.kind} /></dd>
                  </dl>
                  {h.blocked && (
                    <span
                      className={`mt-2 inline-flex items-center gap-1 text-xs ${notEnforced ? 'text-orange-400' : 'text-red-400'}`}
                      title={notEnforced ? enforcementReason : undefined}
                    >
                      <Ban className="w-3 h-3" /> {notEnforced ? t('svc.hosts.badge.notEnforced') : t('svc.hosts.badge.blocked')}
                    </span>
                  )}
                </div>
              ))}
            </div>

            {/* Desktop: table (>= sm) */}
            <div className="hidden sm:block overflow-x-auto">
              <table className="hidden sm:table w-full text-sm">
                <thead>
                  <tr className="text-left text-gray-500 border-b border-gray-800">
                    <th className="pb-3 pr-4 font-medium">{t('svc.hosts.col.host')}</th>
                    <th className="pb-3 pr-4 font-medium">{t('svc.hosts.col.ip')}</th>
                    <th className="pb-3 pr-4 font-medium">{t('svc.hosts.col.kind')}</th>
                    <th className="pb-3 pr-4 font-medium" title={t('svc.hosts.state.hint')}>{t('svc.hosts.col.state')}</th>
                    {canManage && <th className="pb-3 font-medium">{t('svc.hosts.col.actions')}</th>}
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((h) => (
                    <tr key={h.ip} className={`table-row ${h.blocked ? 'border-l-2 border-l-red-500 opacity-75' : ''}`}>
                      <td className="py-3 pr-4">
                        <button
                          onClick={() => setHistoryFor(h)}
                          className="text-white font-medium hover:text-blue-400 transition-colors text-left"
                          title={t('svc.hosts.history.open')}
                        >
                          {nomeDe(h)}
                        </button>
                        {/* Com apelido, o nome que a Oracle (ou a VPN) dá
                            continua visível: é ele que o resto da equipe
                            reconhece no console. */}
                        {h.alias && h.hostname && h.alias !== h.hostname && (
                          <div className="text-gray-500 text-xs">{h.hostname}</div>
                        )}
                        {h.blocked && (
                          <span
                            className={`inline-flex items-center gap-1 text-xs ${notEnforced ? 'text-orange-400' : 'text-red-400'}`}
                            title={notEnforced ? enforcementReason : undefined}
                          >
                            <Ban className="w-3 h-3" /> {notEnforced ? t('svc.hosts.badge.notEnforced') : t('svc.hosts.badge.blocked')}
                          </span>
                        )}
                      </td>
                      <td className="py-3 pr-4 text-gray-400 font-mono text-xs">{h.ip}</td>
                      <td className="py-3 pr-4"><OrigemMaquina kind={h.kind} /></td>
                      <td className="py-3 pr-4"><EstadoMaquina h={h} /></td>
                      {canManage && (
                        <td className="py-3">
                          <div className="flex gap-2">
                            <button
                              onClick={() => openAlias(h)}
                              title={t('svc.hosts.alias')}
                              aria-label={t('svc.hosts.alias')}
                              className="text-gray-400 hover:text-blue-400 transition-colors"
                            >
                              <Pencil className="w-4 h-4" />
                            </button>
                            <button
                              onClick={() => openConfirm(h)}
                              title={h.blocked ? t('svc.hosts.unblock') : t('svc.hosts.block')}
                              aria-label={h.blocked ? t('svc.hosts.unblock') : t('svc.hosts.block')}
                              className={`transition-colors ${h.blocked ? 'text-red-400 hover:text-green-400' : 'text-gray-400 hover:text-red-400'}`}
                            >
                              {h.blocked ? <ShieldCheck className="w-4 h-4" /> : <Ban className="w-4 h-4" />}
                            </button>
                          </div>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </Panel>

      <Modal
        open={historyFor !== null}
        onClose={() => setHistoryFor(null)}
        title={<div><span className="text-white font-semibold">{t('svc.hosts.history.title')}</span>{historyFor && <p className="text-gray-500 text-xs mt-1 font-mono font-normal">{historyFor.ip}</p>}</div>}
        size="lg"
      >
        {historyFor && (
          <HostHistory ip={historyFor.ip} titulo={nomeDe(historyFor)} />
        )}

        {/* O registro de conversa (#115) entra no MESMO modal do histórico: as
            duas perguntas — "quanto" e "com quem" — são sobre a mesma
            máquina, e separá-las em duas telas obrigaria o admin a casar os
            dois na cabeça. Só aparece com a permissão própria. */}
        {historyFor && canReadFlows && (
          <div className="mt-6 pt-6 border-t border-gray-800">
            <HostFlows ip={historyFor.ip} />
          </div>
        )}
      </Modal>

      <Modal
        open={aliasFor !== null}
        onClose={() => setAliasFor(null)}
        title={<div><span className="text-white font-semibold">{t('svc.hosts.aliasModal.title')}</span>{aliasFor && <p className="text-gray-500 text-xs mt-1 font-mono font-normal">{aliasFor.ip}</p>}</div>}
        size="xs"
        className="bg-gray-900 border border-gray-800 rounded-xl"
      >
        {aliasFor && (
        <div className="p-6 space-y-4">
              <input
                className="input w-full"
                placeholder={t('svc.hosts.aliasModal.placeholder')}
                value={aliasValue}
                onChange={(e) => setAliasValue(e.target.value)}
                autoFocus
              />
              {aliasError && (
                <div className="rounded-lg border border-red-500/30 bg-red-500/10 text-red-400 text-sm px-3 py-2">{aliasError}</div>
              )}
              <div className="flex gap-3">
                <button onClick={saveAlias} disabled={saving} className="btn-primary flex-1 disabled:opacity-50">
                  {saving ? t('common.saving') : t('common.save')}
                </button>
                <button onClick={() => setAliasFor(null)} className="btn-secondary flex-1">{t('common.cancel')}</button>
              </div>
        </div>
        )}
      </Modal>

      <Modal
        open={confirmFor !== null}
        onClose={() => setConfirmFor(null)}
        title={<div><span className="text-white font-semibold">{confirmFor ? (confirmFor.blocked ? t('svc.hosts.unblockModal.title') : t('svc.hosts.blockModal.title')) : ''}</span>{confirmFor && <p className="text-gray-500 text-xs mt-1 font-mono font-normal">{confirmFor.ip}</p>}</div>}
        size="xs"
        className="bg-gray-900 border border-gray-800 rounded-xl"
      >
        {confirmFor && (
        <div className="p-6 space-y-4">
              <p className="text-sm text-gray-300">
                {confirmFor.blocked ? t('svc.hosts.confirm.unblock') : t('svc.hosts.confirm.block')}{' '}
                <span className="text-white font-medium">{nomeDe(confirmFor)}</span>?
              </p>
              {/* Bloquear com o grupo desligado, não aplicado ou embaixo de um
                  grupo que libera devolveria "sucesso" e não bloquearia nada.
                  Dizer isso ANTES do clique é o ponto: depois, a máquina já
                  aparece bloqueada na lista. */}
              {!confirmFor.blocked && notEnforced && (
                <div className="rounded-lg border border-orange-500/40 bg-orange-500/10 px-3 py-2 text-xs">
                  <p className="text-orange-300 flex items-start gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-px" aria-hidden="true" />
                    <span>{t('svc.hosts.confirm.wontApply')}</span>
                  </p>
                  <p className="text-gray-300 mt-1">{enforcementReason}</p>
                  <p className="text-gray-400 mt-1">
                    {enforcementFix}{' '}
                    <Link to="/firewall?tab=regras&zona=flutuante" className="text-blue-400 hover:text-blue-300 underline">{t('svc.hosts.openGroups')}</Link>
                  </p>
                </div>
              )}
              {confirmError && (
                <div className="rounded-lg border border-red-500/30 bg-red-500/10 text-red-400 text-sm px-3 py-2">{confirmError}</div>
              )}
              <div className="flex gap-3">
                <button
                  onClick={confirmToggleBlock}
                  disabled={confirming}
                  className={`flex-1 disabled:opacity-50 ${confirmFor.blocked ? 'btn-primary' : 'btn-primary bg-red-600 hover:bg-red-500'}`}
                >
                  {confirming ? t('svc.hosts.processing') : confirmFor.blocked ? t('svc.hosts.unblock') : t('svc.hosts.block')}
                </button>
                <button onClick={() => setConfirmFor(null)} disabled={confirming} className="btn-secondary flex-1 disabled:opacity-50">
                  {t('common.cancel')}
                </button>
              </div>
        </div>
        )}
      </Modal>
    </div>
  );
}

/** De onde a máquina fala: da VCN (qualquer sub-rede) ou da VPN. */
function OrigemMaquina({ kind }: { kind: HostKind }) {
  const { t } = useI18n();
  const vpn = kind === 'vpn';
  return (
    <span
      className={`inline-flex items-center gap-1 text-xs ${vpn ? 'text-purple-300' : 'text-sky-300'}`}
      title={vpn ? t('svc.hosts.kind.vpnHint') : t('svc.hosts.kind.vcnHint')}
    >
      {vpn ? <KeyRound className="w-3 h-3" aria-hidden="true" /> : <Server className="w-3 h-3" aria-hidden="true" />}
      {vpn ? t('svc.hosts.kind.vpn') : t('svc.hosts.kind.vcn')}
    </span>
  );
}

/** Ativa = trafegou pelo firewall nos últimos 10 minutos. */
function EstadoMaquina({ h }: { h: NetHost }) {
  const { t } = useI18n();
  return (
    <span
      className={`inline-flex items-center gap-1.5 text-xs ${h.online ? 'text-green-400' : 'text-gray-600'}`}
      title={t('svc.hosts.state.hint')}
    >
      <Circle className={`w-2 h-2 ${h.online ? 'fill-green-400' : 'fill-gray-600'}`} />
      {h.online ? t('svc.hosts.state.active') : t('svc.hosts.state.idle')}
    </span>
  );
}
