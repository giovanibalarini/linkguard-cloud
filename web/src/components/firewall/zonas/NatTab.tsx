import { useCallback, useEffect, useState } from 'react';
import { Plus, Pencil, Trash2, ArrowRightLeft, ShieldCheck } from 'lucide-react';
import client from '../../../api/client';
import { useI18n } from '../../../i18n';
import Panel from '../../ui/Panel';
import NatEditor from './NatEditor';
import type { EncaminhamentoFW } from '../../../types/firewall';

interface Props {
  canWrite: boolean;
  onRefreshGlobal?: () => void;
}

export default function NatTab({ canWrite, onRefreshGlobal }: Props) {
  const { t } = useI18n();

  const [entries, setEntries] = useState<EncaminhamentoFW[]>([]);
  const [loading, setLoading] = useState(true);
  const [editorTarget, setEditorTarget] = useState<EncaminhamentoFW | null | 'new'>(null);

  const fetchNat = useCallback(async () => {
    try {
      const { data } = await client.get<EncaminhamentoFW[]>('/api/firewall/nat');
      setEntries(data ?? []);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchNat();
  }, [fetchNat]);

  const handleSalvar = async (data: Partial<EncaminhamentoFW>) => {
    if (data.id) {
      await client.put(`/api/firewall/nat/${data.id}`, data);
    } else {
      await client.post('/api/firewall/nat', data);
    }
    await fetchNat();
    onRefreshGlobal?.();
  };

  const handleToggleAtivo = async (enc: EncaminhamentoFW) => {
    if (!canWrite) return;
    try {
      await client.put(`/api/firewall/nat/${enc.id}`, {
        ...enc,
        ativo: !enc.ativo,
      });
      await fetchNat();
      onRefreshGlobal?.();
    } catch (e: any) {
      alert(e.response?.data?.error || t('common.error'));
    }
  };

  const handleApagar = async (enc: EncaminhamentoFW) => {
    if (!confirm(t('fwz.nat.apagar.confirm', { nome: enc.nome }))) return;

    try {
      await client.delete(`/api/firewall/nat/${enc.id}`);
      await fetchNat();
      onRefreshGlobal?.();
    } catch (e: any) {
      alert(e.response?.data?.error || t('common.error'));
    }
  };

  return (
    <div className="space-y-6">
      {/* Topo com botão Novo Encaminhamento */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
        <p className="text-xs text-gray-400">
          {t('fwz.nat.nota')}
        </p>
        {canWrite && (
          <button
            onClick={() => setEditorTarget('new')}
            className="btn-primary flex items-center gap-2 shrink-0"
          >
            <Plus className="w-4 h-4" />
            {t('fwz.nat.novo')}
          </button>
        )}
      </div>

      {/* Tabela de Port Forwarding */}
      <Panel className="p-0 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-gray-900/60 text-gray-400 border-b border-gray-800 text-xs uppercase tracking-wider">
              <tr>
                <th className="px-4 py-3 font-medium text-center w-12">{t('fwz.nat.ativo')}</th>
                <th className="px-4 py-3 font-medium">{t('fwz.nat.nome')}</th>
                <th className="px-4 py-3 font-medium">{t('fwz.nat.proto')}</th>
                <th className="px-4 py-3 font-medium">{t('fwz.nat.porta_ext')}</th>
                <th className="px-4 py-3 font-medium">{t('fwz.nat.ip_dest')}</th>
                <th className="px-4 py-3 font-medium text-center">{t('fwz.tabela.acoes')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {loading ? (
                <tr>
                  <td colSpan={6} className="p-8 text-center text-gray-500">
                    {t('common.loading')}
                  </td>
                </tr>
              ) : entries.length === 0 ? (
                <tr>
                  <td colSpan={6} className="p-8 text-center text-gray-500">
                    {t('fwz.nat.vazio')}
                  </td>
                </tr>
              ) : (
                entries.map((enc) => (
                  <tr
                    key={enc.id}
                    className={`hover:bg-gray-800/40 transition-colors ${
                      !enc.ativo ? 'opacity-50' : ''
                    }`}
                  >
                    <td className="px-4 py-3 text-center">
                      <input
                        type="checkbox"
                        checked={enc.ativo}
                        onChange={() => handleToggleAtivo(enc)}
                        disabled={!canWrite}
                        className="rounded border-gray-700 bg-gray-900 text-blue-500 focus:ring-0 cursor-pointer disabled:cursor-not-allowed"
                      />
                    </td>
                    <td className="px-4 py-3 font-medium text-white">
                      <span>{enc.nome}</span>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs uppercase text-gray-300">
                      {enc.proto}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-blue-300">
                      {enc.porta_externa}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-gray-300">
                      {enc.ip_destino}:{enc.porta_destino}
                    </td>
                    <td className="px-4 py-3 text-center">
                      {canWrite ? (
                        <div className="flex items-center justify-center gap-2">
                          <button
                            onClick={() => setEditorTarget(enc)}
                            className="text-gray-400 hover:text-white p-1"
                            title={t('fwz.nat.editar')}
                          >
                            <Pencil className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => handleApagar(enc)}
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

      {/* Cartão de Saída (Masquerade) */}
      <Panel
        title={
          <div className="flex items-center gap-2 text-white font-semibold">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span>{t('fwz.nat.saida_titulo')}</span>
          </div>
        }
      >
        <p className="text-xs text-gray-400 leading-relaxed">
          {t('fwz.nat.saida')}
        </p>
      </Panel>

      {/* Editor Modal */}
      {editorTarget && (
        <NatEditor
          enc={editorTarget === 'new' ? null : editorTarget}
          onSave={handleSalvar}
          onClose={() => setEditorTarget(null)}
          canWrite={canWrite}
        />
      )}
    </div>
  );
}
