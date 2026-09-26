import { useEffect, useState } from 'react';
import { RefreshCw } from 'lucide-react';
import client, { INSTALL_TIMEOUT_MS } from '../../api/client';
import Modal from '../ui/Modal';
import { useI18n } from '../../i18n';
import type { AliasFW } from '../../types/firewall';
import AccessForm from './AccessForm';
import {
  apiError,
  profileOf,
  restrictedProfile,
  type AccessProfile,
  type Candidate,
  type VPNEnrollment,
  type VPNPeer,
} from './vpnTypes';

interface Props {
  // Sem peer: dar acesso a alguém que ainda não tem VPN. Com peer: editar.
  mode: 'new' | 'edit' | null;
  peer?: VPNPeer | null;
  aliases: AliasFW[];
  onClose: () => void;
  onDelivered: (enrollment: VPNEnrollment, username: string) => void;
  onSaved: (peer: VPNPeer) => void;
}

export default function PeerAccessModal({ mode, peer, aliases, onClose, onDelivered, onSaved }: Props) {
  const { t } = useI18n();
  const [candidates, setCandidates] = useState<Candidate[] | null>(null);
  const [userId, setUserId] = useState('');
  const [profile, setProfile] = useState<AccessProfile>(restrictedProfile);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!mode) return;
    setError('');
    setBusy(false);
    if (mode === 'edit' && peer) {
      setProfile(profileOf(peer));
      return;
    }
    setProfile(restrictedProfile);
    setUserId('');
    setCandidates(null);
    client
      .get<Candidate[]>('/api/vpn/candidates')
      .then(({ data }) => {
        setCandidates(data ?? []);
        if (data && data.length === 1) setUserId(data[0].id);
      })
      .catch((e) => {
        setCandidates([]);
        setError(apiError(e, t('vpn.error.load')));
      });
  }, [mode, peer, t]);

  if (!mode) return null;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      if (mode === 'new') {
        const who = candidates?.find((c) => c.id === userId);
        if (!who) {
          setError(t('vpn.give.pickUser'));
          return;
        }
        const { data } = await client.post<VPNEnrollment>(
          `/api/vpn/peers/${encodeURIComponent(who.id)}/enrollment`,
          profile,
          { timeout: INSTALL_TIMEOUT_MS },
        );
        onDelivered(data, who.username);
      } else if (peer) {
        await client.put(`/api/vpn/peers/${encodeURIComponent(peer.user_id)}/access`, profile, {
          timeout: INSTALL_TIMEOUT_MS,
        });
        onSaved(peer);
      }
    } catch (err) {
      setError(apiError(err, t('vpn.error.operation')));
    } finally {
      setBusy(false);
    }
  };

  const title = mode === 'new' ? t('vpn.give.title') : t('vpn.edit.title', { user: peer?.username || '' });

  return (
    <Modal open onClose={onClose} title={title} size="md" className="bg-gray-900 border border-gray-800 rounded-xl">
      <form onSubmit={submit} className="p-5 space-y-5">
        {mode === 'new' && (
          <label className="block">
            <span className="block text-xs font-semibold text-gray-200 mb-1.5">{t('vpn.give.who')}</span>
            {candidates === null ? (
              <p className="text-sm text-gray-500 animate-pulse">{t('common.loading')}</p>
            ) : candidates.length === 0 ? (
              <p className="p-3 bg-gray-900 border border-gray-800 rounded-lg text-xs text-amber-300">{t('vpn.give.noCandidates')}</p>
            ) : (
              <select value={userId} onChange={(e) => setUserId(e.target.value)} className="input w-full" required>
                <option value="">{t('vpn.give.pickUser')}</option>
                {candidates.map((c) => (
                  <option key={c.id} value={c.id}>{c.username}</option>
                ))}
              </select>
            )}
            <span className="block text-[11px] text-gray-500 mt-1.5">{t('vpn.give.roleHint')}</span>
          </label>
        )}

        {mode === 'edit' && <p className="text-xs text-gray-400">{t('vpn.edit.note')}</p>}

        <AccessForm value={profile} onChange={setProfile} aliases={aliases} />

        {error && <p className="text-sm text-red-400">{error}</p>}

        <div className="flex justify-end gap-2 pt-3 border-t border-gray-800">
          <button type="button" onClick={onClose} disabled={busy} className="btn-secondary">
            {t('common.cancel')}
          </button>
          <button
            type="submit"
            disabled={busy || (mode === 'new' && !userId)}
            className="btn-primary flex items-center gap-2 disabled:opacity-50"
          >
            {busy && <RefreshCw className="w-4 h-4 animate-spin" />}
            {mode === 'new' ? t('vpn.give.submit') : t('vpn.edit.submit')}
          </button>
        </div>
      </form>
    </Modal>
  );
}
