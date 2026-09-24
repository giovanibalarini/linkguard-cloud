import { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, Download, KeyRound, RefreshCw } from 'lucide-react';
import client, { INSTALL_TIMEOUT_MS, isTimeout } from '../../api/client';
import Panel from '../ui/Panel';
import { useI18n } from '../../i18n';
import ConfigDelivery from './ConfigDelivery';
import { apiError, lastSeen, portsText, type MyVPN, type VPNEnrollment } from './vpnTypes';

// A VPN de quem está logado — e só ela. É tudo o que alguém com o papel
// "Usuário VPN" enxerga no painel.
//
// Antes (até 24/09/2026) essa pessoa abria a tela sem saber se já tinha
// identidade, e o único botão — "Gerar configuração" — trocava a chave sem
// avisar, derrubando o arquivo que ela já usava.
export default function MyVpn({ onChanged }: { onChanged?: () => void }) {
  const { t } = useI18n();
  const [mine, setMine] = useState<MyVPN | null>(null);
  const [delivery, setDelivery] = useState<VPNEnrollment | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    try {
      const { data } = await client.get<MyVPN>('/api/vpn/me');
      setMine(data);
      setError('');
    } catch (e) {
      setError(apiError(e, t('vpn.error.load')));
    }
  }, [t]);

  useEffect(() => { load(); }, [load]);

  const act = async (path: string) => {
    setBusy(true);
    setError('');
    try {
      const { data } = await client.post<VPNEnrollment>(path, null, { timeout: INSTALL_TIMEOUT_MS });
      setDelivery(data);
      await load();
      onChanged?.();
    } catch (e) {
      setError(isTimeout(e) ? t('vpn.error.timeout') : apiError(e, t('vpn.error.operation')));
    } finally {
      setBusy(false);
    }
  };

  const rotate = () => {
    if (!window.confirm(t('vpn.me.rotateConfirm'))) return;
    act('/api/vpn/enrollment');
  };

  const peer = mine?.peer;
  const tunnelNote = peer
    ? peer.access_mode === 'restricted'
      ? null
      : peer.tunnel_mode === 'split'
        ? t('vpn.me.reachNetwork', { routes: ['VPN', ...(peer.extra_routes || [])].join(', ') })
        : t('vpn.me.reachAll')
    : null;

  return (
    <Panel title={<span className="flex items-center gap-2 text-white font-semibold"><KeyRound className="w-4 h-4 text-blue-400" /> {t('vpn.me.title')}</span>}>
      {!mine ? (
        error ? <p className="text-sm text-red-400">{error}</p> : <p className="text-sm text-gray-500 animate-pulse">{t('common.loading')}</p>
      ) : !mine.enabled ? (
        <p className="text-sm text-gray-400">{t('vpn.me.disabled')}</p>
      ) : !peer ? (
        <div className="space-y-3">
          <p className="text-sm text-gray-300">{t('vpn.me.none')}</p>
          <button onClick={() => act('/api/vpn/enrollment')} disabled={busy} className="btn-primary flex items-center gap-2 disabled:opacity-50">
            {busy ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />} {t('vpn.me.create')}
          </button>
        </div>
      ) : (
        <div className="space-y-4">
          <dl className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-sm">
            <div>
              <dt className="text-gray-500 text-xs">{t('vpn.me.ip')}</dt>
              <dd className="font-mono text-blue-300">{peer.address.replace(/\/32$/, '')}</dd>
            </div>
            <div>
              <dt className="text-gray-500 text-xs">{t('vpn.me.status')}</dt>
              <dd className={peer.online ? 'text-emerald-400' : 'text-gray-300'}>{lastSeen(peer, t)}</dd>
            </div>
            {mine.endpoint && (
              <div>
                <dt className="text-gray-500 text-xs">{t('vpn.me.server')}</dt>
                <dd className="font-mono text-gray-300 break-all">{mine.endpoint}</dd>
              </div>
            )}
          </dl>

          <div>
            <div className="text-xs text-gray-500 mb-1">{t('vpn.me.reach')}</div>
            {peer.access_mode === 'restricted' ? (
              mine.reach.length === 0 ? (
                <p className="text-sm text-amber-300">{t('vpn.me.reachNothing')}</p>
              ) : (
                <ul className="space-y-1">
                  {mine.reach.map((r) => (
                    <li key={r.name} className="text-sm text-gray-200">
                      <span className="font-medium">{r.name}</span>
                      <span className="text-gray-400">: </span>
                      <span className="font-mono text-gray-300">{r.hosts.join(', ')}</span>
                      <span className="text-gray-400">
                        {' · '}{r.ports ? portsText(r.ports, 'vpn.me', t) : t('vpn.me.allPorts')}
                      </span>
                    </li>
                  ))}
                </ul>
              )
            ) : (
              <p className="text-sm text-gray-200">{tunnelNote}</p>
            )}
          </div>

          {peer.config_stale && (
            <p className="flex items-start gap-2 text-sm text-amber-300">
              <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" /> {t('vpn.me.stale')}
            </p>
          )}

          <div className="flex flex-wrap gap-2">
            <button onClick={() => act('/api/vpn/enrollment/config')} disabled={busy} className="btn-primary flex items-center gap-2 disabled:opacity-50">
              {busy ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />} {t('vpn.me.download')}
            </button>
            <button onClick={rotate} disabled={busy} className="btn-secondary flex items-center gap-2 disabled:opacity-50">
              <KeyRound className="w-4 h-4" /> {t('vpn.me.rotate')}
            </button>
          </div>
          <p className="text-xs text-gray-500">{t('vpn.me.hint')}</p>
        </div>
      )}
      {mine && error && <p className="mt-3 text-sm text-red-400">{error}</p>}
      <ConfigDelivery enrollment={delivery} onClose={() => setDelivery(null)} />
    </Panel>
  );
}
