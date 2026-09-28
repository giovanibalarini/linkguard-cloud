import { Fragment, useCallback, useEffect, useState } from 'react';
import { Plus, Pencil, Trash2, Shield, Lock, Search, AlertCircle, Save } from 'lucide-react';
import client from '../../../api/client';
import { useI18n } from '../../../i18n';
import { errMsg } from '../../../lib/apiError';
import Panel from '../../ui/Panel';
import AliasEditor from './AliasEditor';
import InlineConfirm from './InlineConfirm';
import type { MsgLevel } from '../../../types';
import type { AliasFW } from '../../../types/firewall';

interface Props {
  canWrite: boolean;
  onRefreshGlobal?: () => void;
  onMsg?: (text: string, level?: MsgLevel) => void;
}

export default function AliasesTab({ canWrite, onRefreshGlobal, onMsg }: Props) {
  const { t } = useI18n();

  const [aliases, setAliases] = useState<AliasFW[]>([]);
  const [loading, setLoading] = useState(true);
  const [busca, setBusca] = useState('');
  const [editorTarget, setEditorTarget] = useState<AliasFW | null | 'new'>(null);
  const [apagando, setApagando] = useState<AliasFW | null>(null);
  const [erroUso, setErroUso] = useState<{ nome: string; usos: string[] } | null>(null);

  // Redes extras da VCN
  const [vcnExtrasTexto, setVcnExtrasTexto] = useState('');
  const [salvandoExtras, setSalvandoExtras] = useState(false);
  const [sucessoExtras, setSucessoExtras] = useState(false);

  const fetchAliases = useCallback(async () => {
    try {
      const [resAliases, resAjustes] = await Promise.all([
        client.get<AliasFW[]>('/api/firewall/aliases'),
        client.get<{ redes_vcn_extras?: string[] }>('/api/firewall/ajustes').catch(() => ({ data: { redes_vcn_extras: [] } })),
      ]);
      setAliases(resAliases.data ?? []);
      setVcnExtrasTexto((resAjustes.data.redes_vcn_extras ?? []).join('\n'));
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAliases();
  }, [fetchAliases]);

  const handleSalvarAlias = async (data: Partial<AliasFW>) => {
    if (data.id) {
      await client.put(`/api/firewall/aliases/${data.id}`, data);
    } else {
      await client.post('/api/firewall/aliases', data);
    }
    await fetchAliases();
    onRefreshGlobal?.();
  };

  const handleApagar = async (alias: AliasFW) => {
    setApagando(null);
    setErroUso(null);

    try {
      await client.delete(`/api/firewall/aliases/${alias.id}`);
      await fetchAliases();
      onRefreshGlobal?.();
    } catch (err: any) {
      if (err.response?.status === 409 && err.response?.data?.usos) {
        setErroUso({
          nome: alias.nome,
          usos: err.response.data.usos,
        });
      } else {
        onMsg?.(errMsg(err, t), 'error');
      }
    }
  };

  const handleSalvarVCNExtras = async () => {
    const redes = vcnExtrasTexto
      .split(/[\n,]+/)
      .map((s) => s.trim())
      .filter(Boolean);

    setSalvandoExtras(true);
    setSucessoExtras(false);
    try {
      await client.put('/api/firewall/aliases/sys:vcn/extras', { redes });
      await fetchAliases();
      onRefreshGlobal?.();
      setSucessoExtras(true);
      setTimeout(() => setSucessoExtras(false), 3000);
    } catch (e) {
      onMsg?.(errMsg(e, t), 'error');
    } finally {
      setSalvandoExtras(false);
    }
  };

  const filtered = aliases.filter((a) => {
    const q = busca.toLowerCase().trim();
    if (!q) return true;
    return (
      a.nome.toLowerCase().includes(q) ||
      a.descricao.toLowerCase().includes(q) ||
      a.itens.some((it) => it.toLowerCase().includes(q))
    );
  });

  return (
    <div className="space-y-6">
      {/* Barra superior de busca e novo alias */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="w-4 h-4 text-gray-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            className="input w-full pl-9 text-sm"
            placeholder={t('fwz.aliases.busca')}
            value={busca}
            onChange={(e) => setBusca(e.target.value)}
          />
        </div>
        {canWrite && (
          <button
            onClick={() => setEditorTarget('new')}
            className="btn-primary flex items-center gap-2 shrink-0"
          >
            <Plus className="w-4 h-4" />
            {t('fwz.aliases.novo')}
          </button>
        )}
      </div>

      {/* Aviso de erro ao apagar alias em uso (409) */}
      {erroUso && (
        <div className="p-4 bg-amber-500/10 border border-amber-500/40 rounded-lg text-sm text-amber-300 space-y-2">
          <div className="flex items-center gap-2 font-medium">
            <AlertCircle className="w-4 h-4 text-amber-400" />
            <span>{t('fwz.aliases.em_uso_erro')}</span>
          </div>
          <ul className="list-disc list-inside space-y-1 text-xs text-gray-300 pl-4">
            {erroUso.usos.map((u, i) => (
              <li key={i}>{u}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Tabela de Aliases */}
      <Panel className="p-0 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead className="bg-gray-900/60 text-gray-400 border-b border-gray-800 text-xs uppercase tracking-wider">
              <tr>
                <th className="px-4 py-3 font-medium">{t('fwz.aliases.nome')}</th>
                <th className="px-4 py-3 font-medium">{t('fwz.aliases.tipo')}</th>
                <th className="px-4 py-3 font-medium">{t('fwz.aliases.itens')}</th>
                <th className="px-4 py-3 font-medium">{t('fwz.aliases.descricao')}</th>
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
              ) : filtered.length === 0 ? (
                <tr>
                  <td colSpan={5} className="p-8 text-center text-gray-500">
                    {t('fwz.aliases.vazio')}
                  </td>
                </tr>
              ) : (
                filtered.map((alias) => {
                  const isBuiltin = alias.embutido;
                  return (
                    <Fragment key={alias.id}>
                      <tr
                        className={`hover:bg-gray-800/40 transition-colors ${
                          isBuiltin ? 'bg-gray-900/30' : ''
                        }`}
                      >
                        <td className="px-4 py-3 font-mono font-medium text-white flex items-center gap-2">
                          {isBuiltin && (
                            <span title={t('fwz.aliases.embutido')}>
                              <Lock className="w-3.5 h-3.5 text-blue-400 shrink-0" />
                            </span>
                          )}
                          <span>{alias.nome}</span>
                          {isBuiltin && (
                            <span className="text-[10px] bg-blue-500/20 text-blue-300 px-1.5 py-0.5 rounded font-sans">
                              {t('fwz.aliases.embutido')}
                            </span>
                          )}
                        </td>
                        <td className="px-4 py-3 text-xs text-gray-400">
                          {alias.tipo === 'enderecos'
                            ? t('fwz.aliases.tipo.enderecos')
                            : t('fwz.aliases.tipo.portas')}
                        </td>
                        <td className="px-4 py-3">
                          <div className="font-mono text-xs text-gray-300 max-w-xs truncate" title={alias.itens.join(', ')}>
                            {alias.itens.slice(0, 3).join(', ')}
                            {alias.itens.length > 3 && (
                              <span className="text-gray-500 ml-1">
                                (+{alias.itens.length - 3})
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="px-4 py-3 text-xs text-gray-400">
                          <div>{alias.descricao}</div>
                          <div className="text-[11px] text-gray-500 mt-0.5">
                            {alias.usos && alias.usos > 0
                              ? t('fwz.aliases.usado_por', { n: alias.usos })
                              : t('fwz.aliases.usado_por_nenhum')}
                          </div>
                        </td>
                        <td className="px-4 py-3 text-center">
                          {!isBuiltin && canWrite ? (
                            <div className="flex items-center justify-center gap-2">
                              <button
                                onClick={() => setEditorTarget(alias)}
                                className="text-gray-400 hover:text-white p-1"
                                title={t('fwz.aliases.editar')}
                                aria-label={t('fwz.aliases.editar')}
                              >
                                <Pencil className="w-4 h-4" />
                              </button>
                              <button
                                onClick={() => setApagando(alias)}
                                className="text-gray-400 hover:text-red-400 p-1"
                                title={t('common.delete')}
                                aria-label={t('common.delete')}
                              >
                                <Trash2 className="w-4 h-4" />
                              </button>
                            </div>
                          ) : (
                            <span className="text-xs text-gray-600">—</span>
                          )}
                        </td>
                      </tr>
                      {apagando?.id === alias.id && (
                        <tr>
                          <td colSpan={5} className="px-4 py-3">
                            <InlineConfirm
                              mensagem={t('fwz.aliases.apagar.confirm', { nome: alias.nome })}
                              onConfirm={() => handleApagar(alias)}
                              onCancel={() => setApagando(null)}
                            />
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </Panel>

      {/* Seção especial: Redes Extras da VCN */}
      <Panel
        title={
          <div className="flex items-center gap-2 text-white font-semibold">
            <Shield className="w-4 h-4 text-blue-400" />
            <span>{t('fwz.aliases.extras_vcn')}</span>
          </div>
        }
      >
        <div className="space-y-3">
          <p className="text-xs text-gray-400">
            {t('fwz.aliases.extras_vcn.ajuda')}
          </p>
          <textarea
            className="input w-full font-mono text-sm"
            rows={3}
            placeholder="10.1.0.0/16&#10;172.16.0.0/12"
            value={vcnExtrasTexto}
            onChange={(e) => setVcnExtrasTexto(e.target.value)}
            disabled={!canWrite || salvandoExtras}
          />
          {sucessoExtras && (
            <p className="text-xs text-green-400">
              {t('fwz.aliases.extras_vcn.sucesso')}
            </p>
          )}
          {canWrite && (
            <div className="flex justify-end">
              <button
                onClick={handleSalvarVCNExtras}
                disabled={salvandoExtras}
                className="btn-secondary text-xs flex items-center gap-2"
              >
                <Save className="w-3.5 h-3.5" />
                {salvandoExtras ? t('fwz.editor.salvando') : t('fwz.aliases.extras_vcn.salvar')}
              </button>
            </div>
          )}
        </div>
      </Panel>

      {/* Editor Modal */}
      {editorTarget && (
        <AliasEditor
          alias={editorTarget === 'new' ? null : editorTarget}
          onSave={handleSalvarAlias}
          onClose={() => setEditorTarget(null)}
          canWrite={canWrite}
        />
      )}
    </div>
  );
}
