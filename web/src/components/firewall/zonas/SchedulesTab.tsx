import { useCallback, useEffect, useState } from 'react';
import { Plus, Pencil, Trash2, Clock, AlertCircle } from 'lucide-react';
import client from '../../../api/client';
import { useI18n } from '../../../i18n';
import Panel from '../../ui/Panel';
import ScheduleEditor from './ScheduleEditor';
import type { AgendamentoFW } from '../../../types/firewall';

interface Props {
  canWrite: boolean;
  onRefreshGlobal?: () => void;
}

export default function SchedulesTab({ canWrite, onRefreshGlobal }: Props) {
  const { t } = useI18n();

  const [schedules, setSchedules] = useState<AgendamentoFW[]>([]);
  const [loading, setLoading] = useState(true);
  const [editorTarget, setEditorTarget] = useState<AgendamentoFW | null | 'new'>(null);
  const [erroUso, setErroUso] = useState<{ nome: string; usos: string[] } | null>(null);

  const fetchSchedules = useCallback(async () => {
    try {
      const { data } = await client.get<AgendamentoFW[]>('/api/firewall/agendamentos');
      setSchedules(data ?? []);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSchedules();
  }, [fetchSchedules]);

  const handleSalvar = async (data: Partial<AgendamentoFW>) => {
    if (data.id) {
      await client.put(`/api/firewall/agendamentos/${data.id}`, data);
    } else {
      await client.post('/api/firewall/agendamentos', data);
    }
    await fetchSchedules();
    onRefreshGlobal?.();
  };

  const handleApagar = async (ag: AgendamentoFW) => {
    if (!confirm(t('fwz.agendamentos.apagar.confirm', { nome: ag.nome }))) return;
    setErroUso(null);

    try {
      await client.delete(`/api/firewall/agendamentos/${ag.id}`);
      await fetchSchedules();
      onRefreshGlobal?.();
    } catch (err: any) {
      if (err.response?.status === 409 && err.response?.data?.usos) {
        setErroUso({
          nome: ag.nome,
          usos: err.response.data.usos,
        });
      } else {
        alert(err.response?.data?.error || t('common.error'));
      }
    }
  };

  const formatDias = (diasStr: string) => {
    if (!diasStr) return t('fwz.agendamentos.todos_dias');
    const dias = diasStr.split(',').filter(Boolean);
    if (dias.length === 7) return t('fwz.agendamentos.todos_dias');
    if (diasStr === 'mon,tue,wed,thu,fri') return t('fwz.agendamentos.dias_uteis');
    if (diasStr === 'sat,sun') return t('fwz.agendamentos.fim_semana');
    return dias.map((d) => t(`fwz.agendamentos.dia.${d}`)).join(', ');
  };

  return (
    <div className="space-y-6">
      {/* Barra de ações superior */}
      <div className="flex items-center justify-between gap-3">
        <p className="text-xs text-gray-400">
          {t('fwz.tab.agendamentos')}
        </p>
        {canWrite && (
          <button
            onClick={() => setEditorTarget('new')}
            className="btn-primary flex items-center gap-2 shrink-0"
          >
            <Plus className="w-4 h-4" />
            {t('fwz.agendamentos.novo')}
          </button>
        )}
      </div>

      {/* Aviso de erro ao apagar agendamento em uso (409) */}
      {erroUso && (
        <div className="p-4 bg-amber-500/10 border border-amber-500/40 rounded-lg text-sm text-amber-300 space-y-2">
          <div className="flex items-center gap-2 font-medium">
            <AlertCircle className="w-4 h-4 text-amber-400" />
            <span>{t('fwz.agendamentos.em_uso_erro')}</span>
          </div>
          <ul className="list-disc list-inside space-y-1 text-xs text-gray-300 pl-4">
            {erroUso.usos.map((u, i) => (
              <li key={i}>{u}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Tabela de Agendamentos */}
      <Panel className="p-0 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-gray-900/60 text-gray-400 border-b border-gray-800 text-xs uppercase tracking-wider">
              <tr>
                <th className="px-4 py-3 font-medium">{t('fwz.agendamentos.nome')}</th>
                <th className="px-4 py-3 font-medium">{t('fwz.agendamentos.horario')}</th>
                <th className="px-4 py-3 font-medium">{t('fwz.agendamentos.dias')}</th>
                <th className="px-4 py-3 font-medium">{t('fwz.agendamentos.descricao')}</th>
                <th className="px-4 py-3 font-medium text-center">{t('fwz.tabela.acoes')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {loading ? (
                <tr>
                  <td colSpan={5} className="p-8 text-center text-gray-500">
                    {t('common.loading')}
                  </td>
                </tr>
              ) : schedules.length === 0 ? (
                <tr>
                  <td colSpan={5} className="p-8 text-center text-gray-500">
                    {t('fwz.agendamentos.vazio')}
                  </td>
                </tr>
              ) : (
                schedules.map((ag) => (
                  <tr key={ag.id} className="hover:bg-gray-800/40 transition-colors">
                    <td className="px-4 py-3 font-mono font-medium text-white flex items-center gap-2">
                      <Clock className="w-3.5 h-3.5 text-blue-400 shrink-0" />
                      <span>{ag.nome}</span>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-gray-300">
                      {ag.inicio} – {ag.fim}
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-300">
                      {formatDias(ag.dias)}
                    </td>
                    <td className="px-4 py-3 text-xs text-gray-400">
                      <div>{ag.descricao || '—'}</div>
                      <div className="text-[11px] text-gray-500 mt-0.5">
                        {ag.usos && ag.usos > 0
                          ? t('fwz.agendamentos.usado_por', { n: ag.usos })
                          : t('fwz.agendamentos.usado_por_nenhum')}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-center">
                      {canWrite ? (
                        <div className="flex items-center justify-center gap-2">
                          <button
                            onClick={() => setEditorTarget(ag)}
                            className="text-gray-400 hover:text-white p-1"
                            title={t('fwz.agendamentos.editar')}
                          >
                            <Pencil className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => handleApagar(ag)}
                            className="text-gray-400 hover:text-red-400 p-1"
                            title={t('common.delete')}
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      ) : (
                        <span className="text-xs text-gray-600">—</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </Panel>

      {/* Modal Editor */}
      {editorTarget && (
        <ScheduleEditor
          schedule={editorTarget === 'new' ? null : editorTarget}
          onSave={handleSalvar}
          onClose={() => setEditorTarget(null)}
          canWrite={canWrite}
        />
      )}
    </div>
  );
}
