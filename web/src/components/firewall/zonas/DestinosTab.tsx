import React, { useCallback, useEffect, useState } from 'react';
import { Plus, Trash2, Ban } from 'lucide-react';
import client from '../../../api/client';
import { useI18n } from '../../../i18n';
import LoadError from './LoadError';
import Panel from '../../ui/Panel';

interface Props {
  canWrite: boolean;
  children?: React.ReactNode;
}

export default function DestinosTab({ canWrite, children }: Props) {
  const { t } = useI18n();
  const [blocklist, setBlocklist] = useState<string[]>([]);
  const [novoIP, setNovoIP] = useState('');
  const [loading, setLoading] = useState(true);
  const [erroCarga, setErroCarga] = useState(false);
  const [salvando, setSalvando] = useState(false);
  const [erro, setErro] = useState('');

  const fetchBlocklist = useCallback(async () => {
    try {
      const { data } = await client.get<{ blocklist: string[] }>('/api/nftables/managed');
      setBlocklist(data?.blocklist ?? []);
      setErroCarga(false);
    } catch {
      setErroCarga(true);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchBlocklist();
  }, [fetchBlocklist]);

  const handleAdicionar = async (e: React.FormEvent) => {
    e.preventDefault();
    const cidr = novoIP.trim();
    if (!cidr || !canWrite) return;

    setSalvando(true);
    setErro('');
    try {
      await client.post('/api/nftables/blocklist', { cidr });
      setNovoIP('');
      await fetchBlocklist();
    } catch (err: any) {
      setErro(err.response?.data?.error || t('common.error'));
    } finally {
      setSalvando(false);
    }
  };

  const handleRemover = async (cidr: string) => {
    if (!canWrite) return;
    setErro('');
    try {
      await client.delete('/api/nftables/blocklist', { data: { cidr } });
      await fetchBlocklist();
    } catch (err: any) {
      setErro(err.response?.data?.error || t('common.error'));
    }
  };

  return (
    <div className="space-y-6">
      {erroCarga && <LoadError onRetry={() => fetchBlocklist()} />}
      <Panel
        title={
          <div className="flex items-center gap-2">
            <Ban className="w-5 h-5 text-red-400" />
            <span className="text-white font-semibold">{t('fwz.destinos.managed_titulo')}</span>
          </div>
        }
      >
        <p className="text-xs text-gray-400 mb-4">{t('fwz.destinos.managed_desc')}</p>

        {erro && (
          <div className="p-3 mb-4 rounded border border-red-500/30 bg-red-500/10 text-red-400 text-xs">
            {erro}
          </div>
        )}

        {canWrite && (
          <form onSubmit={handleAdicionar} className="flex gap-2 mb-4">
            <input
              type="text"
              className="input flex-1 font-mono text-sm"
              placeholder={t('fwz.destinos.ip_placeholder')}
              value={novoIP}
              onChange={(e) => setNovoIP(e.target.value)}
              disabled={salvando}
            />
            <button
              type="submit"
              disabled={salvando || !novoIP.trim()}
              className="btn-primary flex items-center gap-1.5 whitespace-nowrap"
            >
              <Plus className="w-4 h-4" />
              <span>{salvando ? t('common.loading') : t('fwz.destinos.adicionar')}</span>
            </button>
          </form>
        )}

        {loading ? (
          <div className="py-6 text-center text-xs text-gray-500">{t('common.loading')}</div>
        ) : blocklist.length === 0 && !erroCarga ? (
          <div className="py-6 text-center text-xs text-gray-500">{t('fwz.destinos.vazio')}</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <tbody>
                {blocklist.map((ip) => (
                  <tr key={ip} className="border-b border-gray-800 hover:bg-gray-800/40">
                    <td className="py-2.5 px-3 font-mono text-gray-200">{ip}</td>
                    {canWrite && (
                      <td className="py-2.5 px-3 text-right">
                        <button
                          onClick={() => handleRemover(ip)}
                          className="p-1 text-gray-500 hover:text-red-400 transition-colors"
                          title={t('fwz.destinos.remover')}
                          aria-label={t('fwz.destinos.remover')}
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      {/* DomainTargets */}
      {children}
    </div>
  );
}
