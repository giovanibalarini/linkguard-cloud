import { useCallback, useEffect, useState } from 'react';
import { RotateCcw, History, User, Clock, FileText } from 'lucide-react';
import client from '../../../api/client';
import { useI18n } from '../../../i18n';
import Panel from '../../ui/Panel';
import type { MsgLevel } from '../../../types';

interface RevisaoFW {
  id: string;
  resumo: string;
  motivo: string;
  aplicado_em: number;
  aplicado_por: string;
}

interface Props {
  canWrite: boolean;
  onRefreshGlobal?: () => void;
  onMsg?: (text: string, level?: MsgLevel) => void;
}

export default function HistoryTab({ canWrite, onRefreshGlobal, onMsg }: Props) {
  const { t } = useI18n();
  const [revisoes, setRevisoes] = useState<RevisaoFW[]>([]);
  const [loading, setLoading] = useState(true);
  const [restaurandoId, setRestaurandoId] = useState<string | null>(null);

  const fetchHistorico = useCallback(async () => {
    try {
      const { data } = await client.get<RevisaoFW[]>('/api/firewall/historico');
      setRevisoes(data ?? []);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchHistorico();
  }, [fetchHistorico]);

  const handleRestaurar = async (rev: RevisaoFW) => {
    if (!canWrite) return;
    if (!confirm(t('fwz.historico.restaurar.confirm'))) return;

    setRestaurandoId(rev.id);
    try {
      await client.post(`/api/firewall/historico/${rev.id}/restaurar`);
      onMsg?.(t('fwz.historico.restaurado_sucesso'), 'ok');
      onRefreshGlobal?.();
    } catch (err: any) {
      onMsg?.(err.response?.data?.error || t('common.error'), 'error');
    } finally {
      setRestaurandoId(null);
    }
  };

  const formatData = (epochSec: number) => {
    if (!epochSec) return '-';
    return new Date(epochSec * 1000).toLocaleString();
  };

  return (
    <Panel
      title={
        <div className="flex items-center gap-2">
          <History className="w-5 h-5 text-blue-400" />
          <span className="text-white font-semibold">{t('fwz.historico.titulo')}</span>
        </div>
      }
    >
      <p className="text-xs text-gray-400 mb-4">{t('fwz.historico.desc')}</p>

      {loading ? (
        <div className="py-8 text-center text-xs text-gray-500">{t('common.loading')}</div>
      ) : revisoes.length === 0 ? (
        <div className="py-8 text-center text-xs text-gray-500">{t('fwz.historico.vazio')}</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-gray-800 text-gray-400">
                <th className="py-2.5 px-3 font-medium whitespace-nowrap">{t('fwz.historico.aplicado_em')}</th>
                <th className="py-2.5 px-3 font-medium whitespace-nowrap">{t('fwz.historico.aplicado_por')}</th>
                <th className="py-2.5 px-3 font-medium">{t('fwz.historico.resumo')}</th>
                <th className="py-2.5 px-3 font-medium">{t('fwz.historico.motivo')}</th>
                {canWrite && (
                  <th className="py-2.5 px-3 font-medium text-right whitespace-nowrap">
                    {t('common.actions')}
                  </th>
                )}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/60">
              {revisoes.map((rev) => (
                <tr key={rev.id} className="hover:bg-gray-800/30">
                  <td className="py-2.5 px-3 whitespace-nowrap font-mono text-gray-400">
                    <div className="flex items-center gap-1.5">
                      <Clock className="w-3.5 h-3.5 text-gray-500" />
                      <span>{formatData(rev.aplicado_em)}</span>
                    </div>
                  </td>
                  <td className="py-2.5 px-3 whitespace-nowrap text-gray-300">
                    <div className="flex items-center gap-1.5">
                      <User className="w-3.5 h-3.5 text-gray-500" />
                      <span>{rev.aplicado_por || '-'}</span>
                    </div>
                  </td>
                  <td className="py-2.5 px-3 text-gray-200">
                    <div className="flex items-center gap-1.5">
                      <FileText className="w-3.5 h-3.5 text-gray-500 shrink-0" />
                      <span>{rev.resumo || '-'}</span>
                    </div>
                  </td>
                  <td className="py-2.5 px-3 text-gray-400 italic">
                    {rev.motivo || '-'}
                  </td>
                  {canWrite && (
                    <td className="py-2.5 px-3 text-right whitespace-nowrap">
                      <button
                        onClick={() => handleRestaurar(rev)}
                        disabled={restaurandoId === rev.id}
                        className="btn-secondary text-xs py-1 px-2.5 inline-flex items-center gap-1.5"
                      >
                        <RotateCcw className={`w-3.5 h-3.5 ${restaurandoId === rev.id ? 'animate-spin' : ''}`} />
                        <span>{t('fwz.historico.restaurar')}</span>
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
  );
}
