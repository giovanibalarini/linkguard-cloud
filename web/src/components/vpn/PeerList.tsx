import { AlertTriangle, Download, Globe, KeyRound, Lock, Route, Shield, Trash2 } from 'lucide-react';
import { useI18n } from '../../i18n';
import type { AliasFW } from '../../types/firewall';
import { formatBytes, lastSeen, portsText, type VPNPeer } from './vpnTypes';

interface Props {
  peers: VPNPeer[];
  aliases: AliasFW[];
  currentUserId?: string;
  canWrite: boolean;
  busy: boolean;
  onReissue: (peer: VPNPeer) => void;
  onEdit: (peer: VPNPeer) => void;
  onRotate: (peer: VPNPeer) => void;
  onRevoke: (peer: VPNPeer) => void;
}

// Quem tem VPN e até onde vai, uma pessoa por cartão. Cartão e não tabela:
// a tabela antiga tinha nove colunas, rolava de lado no celular e repetia o
// botão de revogar em cada linha.
export default function PeerList({ peers, aliases, currentUserId, canWrite, busy, onReissue, onEdit, onRotate, onRevoke }: Props) {
  const { t } = useI18n();
  if (peers.length === 0) return <p className="text-sm text-gray-500">{t('vpn.list.empty')}</p>;

  const groupName = (id: string) => aliases.find((g) => g.id === id)?.nome || id.slice(0, 8);

  return (
    <ul className="divide-y divide-gray-800/70">
      {peers.map((peer) => {
        const restricted = peer.access_mode === 'restricted';
        const groups = peer.allowed_host_groups || [];
        return (
          <li key={peer.user_id} className="py-3.5 flex flex-col lg:flex-row lg:items-center gap-3">
            <div className="min-w-0 flex-1 space-y-1.5">
              <div className="flex flex-wrap items-center gap-2">
                <span className={`w-2 h-2 rounded-full ${peer.online ? 'bg-emerald-400' : 'bg-gray-600'}`} aria-hidden />
                <span className="font-medium text-white">{peer.username}</span>
                {peer.user_id === currentUserId && (
                  <span className="text-[10px] uppercase tracking-wider bg-blue-500/20 text-blue-300 px-1.5 py-0.5 rounded">{t('vpn.list.you')}</span>
                )}
                <code className="font-mono text-xs text-blue-300">{peer.address.replace(/\/32$/, '')}</code>
                <span className={`text-xs ${peer.online ? 'text-emerald-400' : 'text-gray-400'}`}>
                  {lastSeen(peer, t)}
                  {peer.online && peer.latency_ms ? ` · ${peer.latency_ms.toFixed(0)} ms` : ''}
                </span>
              </div>

              <div className="flex flex-wrap items-center gap-1.5 text-xs">
                {restricted ? (
                  <>
                    <span className="inline-flex items-center gap-1 text-purple-300">
                      <Shield className="w-3.5 h-3.5" /> {t('vpn.list.only')}
                    </span>
                    {groups.length === 0 ? (
                      <span className="text-amber-300">{t('vpn.list.nothing')}</span>
                    ) : (
                      groups.map((id) => (
                        <span key={id} className="bg-gray-900 border border-gray-800 text-gray-200 px-1.5 py-0.5 rounded">{groupName(id)}</span>
                      ))
                    )}
                    {groups.length > 0 && (
                      <span className="text-gray-400">
                        {peer.allowed_ports ? portsText(peer.allowed_ports, 'vpn.list', t) : t('vpn.list.allPorts')}
                      </span>
                    )}
                  </>
                ) : (
                  <span className="inline-flex items-center gap-1 text-emerald-300">
                    <Globe className="w-3.5 h-3.5" /> {t('vpn.list.full')}
                  </span>
                )}
                <span className="inline-flex items-center gap-1 text-gray-400" title={(peer.extra_routes || []).join(', ')}>
                  <Route className="w-3.5 h-3.5" />
                  {peer.tunnel_mode === 'split' ? t('vpn.list.tunnelSplit') : t('vpn.list.tunnelFull')}
                </span>
                {peer.config_stale && (
                  <span className="inline-flex items-center gap-1 text-amber-300" title={t('vpn.list.staleHint')}>
                    <AlertTriangle className="w-3.5 h-3.5" /> {t('vpn.list.stale')}
                  </span>
                )}
                {(peer.transfer_rx || peer.transfer_tx) ? (
                  <span className="text-gray-500 font-mono">↓ {formatBytes(peer.transfer_rx || 0)} ↑ {formatBytes(peer.transfer_tx || 0)}</span>
                ) : null}
              </div>
            </div>

            {canWrite && (
              <div className="flex flex-wrap gap-1.5 shrink-0">
                <button onClick={() => onReissue(peer)} disabled={busy} className="btn-secondary text-xs inline-flex items-center gap-1 py-1 px-2.5 disabled:opacity-50" title={t('vpn.list.reissueHint')}>
                  <Download className="w-3.5 h-3.5" /> {t('vpn.list.reissue')}
                </button>
                <button onClick={() => onEdit(peer)} disabled={busy} className="btn-secondary text-xs inline-flex items-center gap-1 py-1 px-2.5 disabled:opacity-50">
                  <Lock className="w-3.5 h-3.5" /> {t('vpn.list.edit')}
                </button>
                <button onClick={() => onRotate(peer)} disabled={busy} className="btn-secondary text-xs inline-flex items-center gap-1 py-1 px-2.5 disabled:opacity-50">
                  <KeyRound className="w-3.5 h-3.5" /> {t('vpn.list.rotate')}
                </button>
                <button onClick={() => onRevoke(peer)} disabled={busy} className="btn-secondary text-xs text-red-400 hover:text-red-300 inline-flex items-center gap-1 py-1 px-2.5 disabled:opacity-50">
                  <Trash2 className="w-3.5 h-3.5" /> {t('vpn.list.revoke')}
                </button>
              </div>
            )}
          </li>
        );
      })}
    </ul>
  );
}
