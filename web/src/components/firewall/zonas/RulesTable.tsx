import { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  ArrowDown,
  ArrowUp,
  ChevronDown,
  ChevronUp,
  Clock,
  Copy,
  ExternalLink,
  FileText,
  GripVertical,
  Pencil,
  Power,
  Trash2,
} from 'lucide-react';
import { useI18n } from '../../../i18n';
import { idsAposMover, nomePonta, nomePorta } from '../../../lib/fwZonas';
import type { LinhaFW, RegraFW, Zona } from '../../../types/firewall';

interface RulesTableProps {
  zona: Zona;
  linhas: LinhaFW[];
  canWrite: boolean;
  editDisabled: boolean;
  onEdit: (regra: RegraFW) => void;
  onToggle: (id: string, ativa: boolean) => Promise<void>;
  onDuplicate: (id: string) => Promise<void>;
  onDelete: (id: string, desc: string) => Promise<void>;
  onReorder: (ids: string[]) => Promise<void>;
}

export default function RulesTable({
  zona,
  linhas,
  canWrite,
  editDisabled,
  onEdit,
  onToggle,
  onDuplicate,
  onDelete,
  onReorder,
}: RulesTableProps) {
  const { t, lang } = useI18n();
  const [dragIndex, setDragIndex] = useState<number | null>(null);
  const [implicitasOpen, setImplicitasOpen] = useState(false);

  const implicitas = linhas.filter((l) => l.tipo === 'implicita');
  const principais = linhas.filter((l) => l.tipo !== 'implicita');

  const adminLinhas = principais.filter((l) => l.tipo === 'admin');
  const totalAdmin = adminLinhas.length;

  const handleDragStart = (e: React.DragEvent, adminIdx: number) => {
    if (!canWrite || editDisabled) return;
    e.dataTransfer.setData('text/plain', String(adminIdx));
    e.dataTransfer.effectAllowed = 'move';
    setDragIndex(adminIdx);
  };

  const handleDrop = (adminIdx: number) => {
    if (dragIndex === null || dragIndex === adminIdx) {
      setDragIndex(null);
      return;
    }
    const newIds = idsAposMover(linhas, dragIndex, adminIdx);
    onReorder(newIds);
    setDragIndex(null);
  };

  const handleMove = (adminIdx: number, delta: number) => {
    const targetIdx = adminIdx + delta;
    if (targetIdx < 0 || targetIdx >= totalAdmin) return;
    const newIds = idsAposMover(linhas, adminIdx, targetIdx);
    onReorder(newIds);
  };

  const renderEditarEm = (editarEm?: string) => {
    if (!editarEm) return null;
    let path = '';
    let labelKey = 'fwz.tabela.local.' + editarEm;
    switch (editarEm) {
      case 'vpn':
        path = '/vpn';
        break;
      case 'nat':
        path = '?tab=nat';
        break;
      case 'maquinas':
        path = '/hosts';
        break;
      case 'destinos':
        path = '?tab=destinos';
        break;
      case 'ajustes':
        path = '?tab=avancado';
        break;
      default:
        path = '#';
    }
    return (
      <Link
        to={path}
        className="inline-flex items-center gap-1 text-[11px] text-blue-400 hover:text-blue-300 transition-colors"
      >
        <span>{t('fwz.tabela.editar_em', { local: t(labelKey) })}</span>
        <ExternalLink className="w-3 h-3" />
      </Link>
    );
  };

  const formatarContador = (c: LinhaFW['contador']) => {
    if (!c.medido) return '—';
    const pkts = c.pacotes.toLocaleString(lang);
    const kbytes = (c.bytes / 1024).toLocaleString(lang, { maximumFractionDigits: 1 });
    return `${pkts} pkts (${kbytes} KB)`;
  };

  return (
    <div className="space-y-4">
      {zona === 'flutuante' && implicitas.length > 0 && (
        <div className="rounded-xl border border-gray-800 bg-gray-950/40 overflow-hidden text-xs">
          <button
            type="button"
            onClick={() => setImplicitasOpen(!implicitasOpen)}
            className="w-full flex items-center justify-between p-3.5 hover:bg-gray-900/40 transition-colors text-left font-medium text-gray-300"
          >
            <div className="flex items-center gap-2">
              <span className="text-gray-400">
                {t('fwz.tabela.implicitas.titulo', { qtd: String(implicitas.length) })}
              </span>
              <span className="text-[11px] text-gray-500 font-normal">
                {t('fwz.tabela.implicitas.ajuda')}
              </span>
            </div>
            {implicitasOpen ? (
              <ChevronUp className="w-4 h-4 text-gray-400" />
            ) : (
              <ChevronDown className="w-4 h-4 text-gray-400" />
            )}
          </button>

          {implicitasOpen && (
            <div className="p-3 border-t border-gray-800/80 bg-gray-950/80 overflow-x-auto">
              <table className="w-full text-left text-gray-400">
                <thead>
                  <tr className="border-b border-gray-800 text-[11px] text-gray-500">
                    <th className="pb-2 font-medium">{t('fwz.tabela.acao')}</th>
                    <th className="pb-2 font-medium">{t('fwz.tabela.descricao')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800/50">
                  {implicitas.map((imp) => (
                    <tr key={imp.chave} className="py-2">
                      <td className="py-2 pr-4">
                        <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                          {t('fwz.acao.accept')}
                        </span>
                      </td>
                      <td className="py-2 text-gray-300">
                        {imp.desc_chave ? t(imp.desc_chave, imp.desc_vars) : imp.regra.descricao}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Visualização Mobile: Cards empilhados (< sm) */}
      <div className="sm:hidden space-y-3">
        {principais.map((linha) => {
          const isAdmin = linha.tipo === 'admin';
          const isTravada = linha.tipo === 'travada';
          const isPadrao = linha.tipo === 'padrao';
          const adminIdx = isAdmin ? adminLinhas.findIndex((a) => a.regra.id === linha.regra.id) : -1;

          return (
            <div
              key={linha.chave}
              className={`rounded-xl border p-4 space-y-3 ${
                isTravada
                  ? 'border-gray-800/60 bg-gray-950/30'
                  : isPadrao
                  ? 'border-gray-800/40 bg-gray-950/20'
                  : 'border-gray-800 bg-gray-900/40'
              } ${!linha.regra.ativa && !isPadrao ? 'opacity-50' : ''}`}
            >
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-2 flex-wrap">
                  <span
                    className={`px-2 py-0.5 rounded text-xs font-semibold ${
                      linha.regra.acao === 'accept'
                        ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                        : linha.regra.acao === 'drop'
                        ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                        : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                    }`}
                  >
                    {t(`fwz.acao.${linha.regra.acao}`)}
                  </span>

                  {isTravada && (
                    <span className="px-1.5 py-0.5 rounded text-[10px] uppercase font-mono bg-gray-800 text-gray-400 border border-gray-700">
                      {t('fwz.tabela.travada')}
                    </span>
                  )}

                  {linha.mudanca && (
                    <span className="px-1.5 py-0.5 rounded text-[10px] uppercase font-mono bg-blue-500/20 text-blue-400 border border-blue-500/30">
                      {linha.mudanca === 'criada' ? t('fwz.tabela.nova') : t('fwz.tabela.alterada')}
                    </span>
                  )}
                </div>

                {isAdmin && canWrite && !editDisabled && (
                  <div className="flex items-center gap-1">
                    <button
                      type="button"
                      disabled={adminIdx === 0}
                      onClick={() => handleMove(adminIdx, -1)}
                      className="p-1 text-gray-400 hover:text-white disabled:opacity-30"
                      title={t('fwz.tabela.subir')}
                    >
                      <ArrowUp className="w-3.5 h-3.5" />
                    </button>
                    <button
                      type="button"
                      disabled={adminIdx === totalAdmin - 1}
                      onClick={() => handleMove(adminIdx, 1)}
                      className="p-1 text-gray-400 hover:text-white disabled:opacity-30"
                      title={t('fwz.tabela.descer')}
                    >
                      <ArrowDown className="w-3.5 h-3.5" />
                    </button>
                    <button
                      type="button"
                      onClick={() => onToggle(linha.regra.id, !linha.regra.ativa)}
                      className={`p-1 ${linha.regra.ativa ? 'text-emerald-400' : 'text-gray-500'}`}
                      title={linha.regra.ativa ? t('fwz.tabela.desativar') : t('fwz.tabela.ativar')}
                    >
                      <Power className="w-3.5 h-3.5" />
                    </button>
                    <button
                      type="button"
                      onClick={() => onEdit(linha.regra)}
                      className="p-1 text-blue-400 hover:text-blue-300"
                      title={t('fwz.tabela.editar')}
                    >
                      <Pencil className="w-3.5 h-3.5" />
                    </button>
                    <button
                      type="button"
                      onClick={() => onDuplicate(linha.regra.id)}
                      className="p-1 text-gray-400 hover:text-white"
                      title={t('fwz.tabela.duplicar')}
                    >
                      <Copy className="w-3.5 h-3.5" />
                    </button>
                    <button
                      type="button"
                      onClick={() => onDelete(linha.regra.id, linha.regra.descricao)}
                      className="p-1 text-rose-400 hover:text-rose-300"
                      title={t('fwz.tabela.apagar')}
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                )}
              </div>

              <div className="text-sm font-medium text-white">
                {isPadrao
                  ? (linha.desc_chave ? t(linha.desc_chave, linha.desc_vars) : t(`fwz.padrao.${zona}`))
                  : linha.desc_chave
                  ? t(linha.desc_chave, linha.desc_vars)
                  : linha.regra.descricao || '—'}
              </div>

              {!isPadrao && (
                <div className="grid grid-cols-2 gap-2 text-xs text-gray-300">
                  <div>
                    <span className="text-gray-500 block text-[11px]">{t('fwz.tabela.origem')}:</span>
                    <span>{nomePonta(linha.regra.origem, linha.nomes.origem, t)}</span>
                  </div>
                  <div>
                    <span className="text-gray-500 block text-[11px]">{t('fwz.tabela.destino')}:</span>
                    <span>{nomePonta(linha.regra.destino, linha.nomes.destino, t)}</span>
                  </div>
                  <div>
                    <span className="text-gray-500 block text-[11px]">{t('fwz.tabela.proto')}:</span>
                    <span className="uppercase">{linha.regra.proto || 'Qualquer'}</span>
                  </div>
                  <div>
                    <span className="text-gray-500 block text-[11px]">{t('fwz.tabela.porta')}:</span>
                    <span>{nomePorta(linha.regra.porta_destino, linha.nomes.porta, t)}</span>
                  </div>
                </div>
              )}

              <div className="flex items-center justify-between text-xs text-gray-500 pt-2 border-t border-gray-800/60">
                <div className="flex items-center gap-3">
                  {linha.regra.agendamento_id && (
                    <span className="flex items-center gap-1 text-amber-400" title={linha.nomes.agendamento}>
                      <Clock className="w-3.5 h-3.5" />
                      <span>{linha.nomes.agendamento || t('fwz.tabela.agendamento')}</span>
                    </span>
                  )}
                  {linha.regra.registrar && (
                    <span className="flex items-center gap-1 text-blue-400" title={t('fwz.tabela.registrar')}>
                      <FileText className="w-3.5 h-3.5" />
                      <span>{t('fwz.tabela.registrar')}</span>
                    </span>
                  )}
                </div>

                <div className="flex items-center gap-2">
                  {isTravada && renderEditarEm(linha.editar_em)}
                  <span className="font-mono text-[11px]">{formatarContador(linha.contador)}</span>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Visualização Desktop: Tabela (>= sm) */}
      <div className="hidden sm:block overflow-x-auto rounded-xl border border-gray-800 bg-gray-950/60">
        <table className="w-full text-xs text-left border-collapse">
          <thead>
            <tr className="border-b border-gray-800 text-gray-500 bg-gray-900/40">
              <th className="py-3 px-2 w-8 text-center">{t('fwz.tabela.arrastar')}</th>
              <th className="py-3 px-2 w-10 text-center">{t('fwz.tabela.num')}</th>
              <th className="py-3 px-3 w-20">{t('fwz.tabela.acao')}</th>
              <th className="py-3 px-3 w-16">{t('fwz.tabela.proto')}</th>
              <th className="py-3 px-3">{t('fwz.tabela.origem')}</th>
              <th className="py-3 px-3">{t('fwz.tabela.destino')}</th>
              <th className="py-3 px-3 w-24">{t('fwz.tabela.porta')}</th>
              <th className="py-3 px-2 w-8 text-center" title={t('fwz.tabela.agendamento')}>
                <Clock className="w-3.5 h-3.5 mx-auto" />
              </th>
              <th className="py-3 px-2 w-8 text-center" title={t('fwz.tabela.registrar')}>
                <FileText className="w-3.5 h-3.5 mx-auto" />
              </th>
              <th className="py-3 px-3">{t('fwz.tabela.descricao')}</th>
              <th className="py-3 px-3 w-32">{t('fwz.tabela.pacotes')}</th>
              <th className="py-3 px-3 w-28 text-right">{t('fwz.tabela.acoes')}</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/60">
            {principais.map((linha) => {
              const isAdmin = linha.tipo === 'admin';
              const isTravada = linha.tipo === 'travada';
              const isPadrao = linha.tipo === 'padrao';
              const adminIdx = isAdmin ? adminLinhas.findIndex((a) => a.regra.id === linha.regra.id) : -1;
              const draggable = canWrite && !editDisabled && isAdmin;

              return (
                <tr
                  key={linha.chave}
                  draggable={draggable}
                  onDragStart={(e) => isAdmin && handleDragStart(e, adminIdx)}
                  onDragOver={(e) => {
                    if (draggable) e.preventDefault();
                  }}
                  onDrop={() => isAdmin && handleDrop(adminIdx)}
                  className={`transition-colors ${
                    isTravada
                      ? 'bg-gray-950/40 text-gray-300'
                      : isPadrao
                      ? 'bg-gray-950/20 text-gray-400 font-medium'
                      : 'hover:bg-gray-900/40 text-gray-200'
                  } ${!linha.regra.ativa && !isPadrao ? 'opacity-40' : ''}`}
                >
                  <td className="py-2.5 px-2 text-center text-gray-600">
                    {draggable && (
                      <span className="cursor-grab active:cursor-grabbing inline-block p-1 hover:text-gray-300">
                        <GripVertical className="w-3.5 h-3.5" />
                      </span>
                    )}
                  </td>

                  <td className="py-2.5 px-2 text-center font-mono text-[11px] text-gray-500">
                    {isAdmin ? adminIdx + 1 : '—'}
                  </td>

                  <td className="py-2.5 px-3">
                    <div className="flex items-center gap-1.5">
                      <span
                        className={`px-2 py-0.5 rounded text-[11px] font-semibold ${
                          linha.regra.acao === 'accept'
                            ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                            : linha.regra.acao === 'drop'
                            ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                            : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                        }`}
                      >
                        {t(`fwz.acao.${linha.regra.acao}`)}
                      </span>
                      {isTravada && (
                        <span className="px-1 py-0.5 rounded text-[9px] uppercase font-mono bg-gray-800 text-gray-400 border border-gray-700">
                          {t('fwz.tabela.travada')}
                        </span>
                      )}
                      {linha.mudanca && (
                        <span className="px-1 py-0.5 rounded text-[9px] uppercase font-mono bg-blue-500/20 text-blue-400 border border-blue-500/30">
                          {linha.mudanca === 'criada' ? t('fwz.tabela.nova') : t('fwz.tabela.alterada')}
                        </span>
                      )}
                    </div>
                  </td>

                  <td className="py-2.5 px-3 font-mono uppercase text-gray-400">
                    {isPadrao ? '—' : linha.regra.proto || 'Qualquer'}
                  </td>

                  <td className="py-2.5 px-3">
                    {isPadrao ? '—' : nomePonta(linha.regra.origem, linha.nomes.origem, t)}
                  </td>

                  <td className="py-2.5 px-3">
                    {isPadrao ? '—' : nomePonta(linha.regra.destino, linha.nomes.destino, t)}
                  </td>

                  <td className="py-2.5 px-3 font-mono">
                    {isPadrao ? '—' : nomePorta(linha.regra.porta_destino, linha.nomes.porta, t)}
                  </td>

                  <td className="py-2.5 px-2 text-center">
                    {linha.regra.agendamento_id ? (
                      <span className="text-amber-400 inline-block" title={linha.nomes.agendamento}>
                        <Clock className="w-3.5 h-3.5" />
                      </span>
                    ) : (
                      <span className="text-gray-700">—</span>
                    )}
                  </td>

                  <td className="py-2.5 px-2 text-center">
                    {linha.regra.registrar ? (
                      <span className="text-blue-400 inline-block" title={t('fwz.tabela.registrar')}>
                        <FileText className="w-3.5 h-3.5" />
                      </span>
                    ) : (
                      <span className="text-gray-700">—</span>
                    )}
                  </td>

                  <td className="py-2.5 px-3 text-gray-300">
                    {isPadrao
                      ? (linha.desc_chave ? t(linha.desc_chave, linha.desc_vars) : t(`fwz.padrao.${zona}`))
                      : linha.desc_chave
                      ? t(linha.desc_chave, linha.desc_vars)
                      : linha.regra.descricao || '—'}
                  </td>

                  <td className="py-2.5 px-3 font-mono text-[11px] text-gray-400">
                    {formatarContador(linha.contador)}
                  </td>

                  <td className="py-2.5 px-3 text-right">
                    {isTravada ? (
                      renderEditarEm(linha.editar_em)
                    ) : isAdmin && canWrite && !editDisabled ? (
                      <div className="flex items-center justify-end gap-1">
                        <button
                          type="button"
                          disabled={adminIdx === 0}
                          onClick={() => handleMove(adminIdx, -1)}
                          className="p-1 text-gray-500 hover:text-gray-200 disabled:opacity-20"
                          title={t('fwz.tabela.subir')}
                        >
                          <ArrowUp className="w-3.5 h-3.5" />
                        </button>
                        <button
                          type="button"
                          disabled={adminIdx === totalAdmin - 1}
                          onClick={() => handleMove(adminIdx, 1)}
                          className="p-1 text-gray-500 hover:text-gray-200 disabled:opacity-20"
                          title={t('fwz.tabela.descer')}
                        >
                          <ArrowDown className="w-3.5 h-3.5" />
                        </button>
                        <button
                          type="button"
                          onClick={() => onToggle(linha.regra.id, !linha.regra.ativa)}
                          className={`p-1 ${linha.regra.ativa ? 'text-emerald-400 hover:text-emerald-300' : 'text-gray-600 hover:text-gray-400'}`}
                          title={linha.regra.ativa ? t('fwz.tabela.desativar') : t('fwz.tabela.ativar')}
                        >
                          <Power className="w-3.5 h-3.5" />
                        </button>
                        <button
                          type="button"
                          onClick={() => onEdit(linha.regra)}
                          className="p-1 text-blue-400 hover:text-blue-300"
                          title={t('fwz.tabela.editar')}
                        >
                          <Pencil className="w-3.5 h-3.5" />
                        </button>
                        <button
                          type="button"
                          onClick={() => onDuplicate(linha.regra.id)}
                          className="p-1 text-gray-400 hover:text-gray-200"
                          title={t('fwz.tabela.duplicar')}
                        >
                          <Copy className="w-3.5 h-3.5" />
                        </button>
                        <button
                          type="button"
                          onClick={() => onDelete(linha.regra.id, linha.regra.descricao)}
                          className="p-1 text-rose-400 hover:text-rose-300"
                          title={t('fwz.tabela.apagar')}
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    ) : null}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
