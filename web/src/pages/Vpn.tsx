import { useCallback, useEffect, useState } from 'react';
import { ChevronDown, ChevronRight, RefreshCw, Server, Shield, UserPlus } from 'lucide-react';
import client, { INSTALL_TIMEOUT_MS, isTimeout } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { useI18n } from '../i18n';
import Panel from '../components/ui/Panel';
import type { HostGroup } from '../types';
import ConfigDelivery from '../components/vpn/ConfigDelivery';
import MyVpn from '../components/vpn/MyVpn';
import PeerAccessModal from '../components/vpn/PeerAccessModal';
import PeerList from '../components/vpn/PeerList';
import { apiError, type VPNConfig, type VPNEnrollment, type VPNOverview, type VPNPeer } from '../components/vpn/vpnTypes';

const defaultConfig: VPNConfig = {
  enabled: false,
  listen_port: 51820,
  address: '10.7.0.1/24',
  endpoint_host: '',
};

type Message = { kind: 'ok' | 'error' | 'warn'; text: string } | null;

// A tela de VPN mostra a cada pessoa só o que ela pode fazer:
// - quem só usa a VPN (vpn.enroll) vê a própria, e nada mais;
// - quem administra (vpn.write) vê quem tem acesso e até onde, entrega o acesso
//   de alguém já restrito e cuida do servidor.
export default function Vpn() {
  const { user, can, permsLoaded } = useAuth();
  const { t } = useI18n();
  const canRead = can('vpn.read');
  const canWrite = can('vpn.write');
  const canEnroll = can('vpn.enroll');

  const [overview, setOverview] = useState<VPNOverview | null>(null);
  const [draft, setDraft] = useState<VPNConfig>(defaultConfig);
  const [hostGroups, setHostGroups] = useState<HostGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<Message>(null);
  const [serverOpen, setServerOpen] = useState<boolean | null>(null);
  const [accessModal, setAccessModal] = useState<{ mode: 'new' | 'edit'; peer?: VPNPeer } | null>(null);
  const [delivery, setDelivery] = useState<{ enrollment: VPNEnrollment; forUser?: string } | null>(null);
  const [myVpnKey, setMyVpnKey] = useState(0);

  const load = useCallback(async () => {
    if (!permsLoaded) return;
    setLoading(true);
    try {
      if (canRead) {
        const [vpnRes, groupsRes] = await Promise.all([
          client.get<VPNOverview>('/api/vpn'),
          client.get<HostGroup[]>('/api/hostgroups').catch(() => ({ data: [] as HostGroup[] })),
        ]);
        setOverview(vpnRes.data);
        setDraft(vpnRes.data.config);
        setHostGroups(groupsRes.data ?? []);
      }
    } catch (e) {
      setMessage({ kind: 'error', text: apiError(e, t('vpn.error.load')) });
    } finally {
      setLoading(false);
    }
  }, [canRead, canWrite, permsLoaded, t]);

  useEffect(() => { load(); }, [load]);

  const run = async (work: () => Promise<void>) => {
    setBusy(true);
    setMessage(null);
    try {
      await work();
    } catch (e) {
      setMessage({
        kind: isTimeout(e) ? 'warn' : 'error',
        text: isTimeout(e) ? t('vpn.error.timeout') : apiError(e, t('vpn.error.operation')),
      });
    } finally {
      setBusy(false);
    }
  };

  const refreshAll = async () => {
    await load();
    setMyVpnKey((k) => k + 1);
  };

  const deliver = (enrollment: VPNEnrollment, peer: VPNPeer | { username: string; user_id?: string }) =>
    setDelivery({ enrollment, forUser: peer.user_id === user?.id ? undefined : peer.username });

  const reissue = (peer: VPNPeer) => run(async () => {
    const { data } = await client.post<VPNEnrollment>(`/api/vpn/peers/${encodeURIComponent(peer.user_id)}/config`, null, {
      timeout: INSTALL_TIMEOUT_MS,
    });
    deliver(data, peer);
    await refreshAll();
  });

  const rotate = (peer: VPNPeer) => {
    if (!window.confirm(t('vpn.list.rotateConfirm', { user: peer.username }))) return;
    run(async () => {
      const { data } = await client.post<VPNEnrollment>(`/api/vpn/peers/${encodeURIComponent(peer.user_id)}/enrollment`, null, {
        timeout: INSTALL_TIMEOUT_MS,
      });
      deliver(data, peer);
      await refreshAll();
    });
  };

  const revoke = (peer: VPNPeer) => {
    if (!window.confirm(t('vpn.list.revokeConfirm', { user: peer.username }))) return;
    run(async () => {
      if (peer.user_id === user?.id) await client.delete('/api/vpn/enrollment', { timeout: INSTALL_TIMEOUT_MS });
      else await client.delete(`/api/vpn/peers/${encodeURIComponent(peer.user_id)}`, { timeout: INSTALL_TIMEOUT_MS });
      setMessage({ kind: 'ok', text: t('vpn.list.revoked', { user: peer.username }) });
      await refreshAll();
    });
  };

  const saveServer = () => run(async () => {
    await client.put('/api/vpn', draft, { timeout: INSTALL_TIMEOUT_MS });
    setMessage({ kind: 'ok', text: t('vpn.saved') });
    await refreshAll();
  });

  if (!permsLoaded || (loading && canRead)) {
    return <div className="p-6"><div className="card text-center py-8 text-gray-500 animate-pulse">{t('common.loading')}</div></div>;
  }

  const serverHealthy = !!overview && overview.config.enabled && overview.running && overview.last_apply_ok;
  const showServer = serverOpen ?? !serverHealthy;

  return (
    <div className="p-4 sm:p-6 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2"><Shield className="w-5 h-5 text-blue-400" /> {t('vpn.title')}</h1>
          <p className="text-gray-500 text-sm">{canRead ? t('vpn.subtitle') : t('vpn.subtitleMine')}</p>
        </div>
        <button onClick={refreshAll} disabled={busy} className="btn-secondary flex items-center gap-2 disabled:opacity-50 self-start">
          <RefreshCw className="w-4 h-4" /> {t('vpn.refresh')}
        </button>
      </div>

      {message && (
        <div className={`card border text-sm ${message.kind === 'error'
          ? 'border-red-500/30 bg-red-500/10 text-red-400'
          : message.kind === 'warn'
            ? 'border-amber-500/30 bg-amber-500/10 text-amber-300'
            : 'border-green-500/30 bg-green-500/10 text-green-400'}`}>
          {message.text}
        </div>
      )}

      {overview && !overview.last_apply_ok && overview.last_apply_error && (
        <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm">
          {t('vpn.lastApplyFailed', { error: overview.last_apply_error })}
        </div>
      )}

      {canRead && overview && (
        <Panel
          title={<span className="text-white font-semibold">{t('vpn.list.title', { count: overview.peers.length })}</span>}
          action={canWrite && overview.config.enabled ? (
            <button onClick={() => setAccessModal({ mode: 'new' })} disabled={busy} className="btn-primary text-sm flex items-center gap-2 disabled:opacity-50">
              <UserPlus className="w-4 h-4" /> {t('vpn.give.open')}
            </button>
          ) : undefined}
        >
          <PeerList
            peers={overview.peers}
            hostGroups={hostGroups}
            currentUserId={user?.id}
            canWrite={canWrite}
            busy={busy}
            onReissue={reissue}
            onEdit={(peer) => setAccessModal({ mode: 'edit', peer })}
            onRotate={rotate}
            onRevoke={revoke}
          />
        </Panel>
      )}

      {canEnroll && <MyVpn key={myVpnKey} onChanged={load} />}

      {canWrite && overview && (
        <Panel
          title={
            <button onClick={() => setServerOpen(!showServer)} className="flex items-center gap-2 text-white font-semibold" aria-expanded={showServer}>
              {showServer ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
              <Server className="w-4 h-4 text-blue-400" /> {t('vpn.server.title')}
              <span className={`text-xs font-normal ${serverHealthy ? 'text-emerald-400' : 'text-amber-300'}`}>
                {!overview.config.enabled ? t('vpn.status.disabled') : overview.running ? t('vpn.status.running') : t('vpn.status.stopped')}
              </span>
            </button>
          }
        >
          {showServer && (
            <div className="space-y-4">
              <label className="flex items-center gap-2 text-sm text-gray-300">
                <input type="checkbox" checked={draft.enabled} onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })} />
                {t('vpn.config.enable')}
              </label>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <label>
                  <span className="label">{t('vpn.config.address')}</span>
                  <input className="input w-full font-mono" value={draft.address} onChange={(e) => setDraft({ ...draft, address: e.target.value })} />
                </label>
                <label>
                  <span className="label">{t('vpn.config.port')}</span>
                  <input type="number" min={1} max={65535} className="input w-full" value={draft.listen_port} onChange={(e) => setDraft({ ...draft, listen_port: Number(e.target.value) })} />
                </label>
                <label>
                  <span className="label">{t('vpn.config.explicitEndpoint')}</span>
                  <input className="input w-full" placeholder="159.112.185.238 ou vpn.exemplo.com" value={draft.endpoint_host} onChange={(e) => setDraft({ ...draft, endpoint_host: e.target.value })} />
                </label>
              </div>
              <p className="text-xs text-gray-500">{t('vpn.config.endpointHint')}</p>
              {overview.public_key && (
                <div>
                  <div className="text-gray-500 text-xs">{t('vpn.status.publicKey')}</div>
                  <code className="block mt-1 text-xs text-gray-300 break-all">{overview.public_key}</code>
                </div>
              )}
              <button onClick={saveServer} disabled={busy} className="btn-primary disabled:opacity-50">{t('vpn.config.save')}</button>
            </div>
          )}
        </Panel>
      )}

      <PeerAccessModal
        mode={accessModal?.mode ?? null}
        peer={accessModal?.peer}
        hostGroups={hostGroups}
        onClose={() => setAccessModal(null)}
        onDelivered={(enrollment, username) => {
          setAccessModal(null);
          setDelivery({ enrollment, forUser: username });
          refreshAll();
        }}
        onSaved={(peer) => {
          setAccessModal(null);
          setMessage({ kind: 'ok', text: t('vpn.edit.saved', { user: peer.username }) });
          refreshAll();
        }}
      />
      <ConfigDelivery enrollment={delivery?.enrollment ?? null} forUser={delivery?.forUser} onClose={() => setDelivery(null)} />
    </div>
  );
}
