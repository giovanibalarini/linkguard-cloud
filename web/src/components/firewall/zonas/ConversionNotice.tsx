import { useState } from 'react';
import { CheckCircle2, ChevronDown, ChevronUp, Info } from 'lucide-react';
import client from '../../../api/client';
import { useI18n } from '../../../i18n';
import type { ItemRelatorioConversao } from '../../../types/firewall';

interface ConversionNoticeProps {
  items: ItemRelatorioConversao[] | null;
  onDismiss: () => Promise<void>;
  canWrite: boolean;
}

export default function ConversionNotice({ items, onDismiss, canWrite }: ConversionNoticeProps) {
  const { t } = useI18n();
  const [expanded, setExpanded] = useState(false);
  const [busy, setBusy] = useState(false);

  if (!items || items.length === 0) return null;

  const handleEntendi = async () => {
    setBusy(true);
    try {
      await client.post('/api/firewall/conversao/entendi');
      await onDismiss();
    } catch (e) {
      console.error(e);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="rounded-xl border border-indigo-500/40 bg-indigo-950/30 p-4 space-y-3">
      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
        <div className="flex items-start gap-3">
          <div className="p-2 rounded-lg bg-indigo-500/20 text-indigo-400 shrink-0 mt-0.5">
            <Info className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-white">
              {t('fwz.conversao.titulo')}
            </h3>
            <p className="text-xs text-indigo-200/80 mt-0.5 leading-relaxed">
              {t('fwz.conversao.desc')}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 self-end sm:self-auto shrink-0">
          <button
            type="button"
            onClick={() => setExpanded(!expanded)}
            className="btn-secondary text-xs flex items-center gap-1 py-1.5 px-2.5"
          >
            {expanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
            {expanded ? 'Recolher detalhes' : `Ver detalhes (${items.length})`}
          </button>
          {canWrite && (
            <button
              type="button"
              disabled={busy}
              onClick={handleEntendi}
              className="btn-primary text-xs flex items-center gap-1.5 py-1.5 px-3 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50"
            >
              <CheckCircle2 className="w-3.5 h-3.5" />
              {t('fwz.conversao.entendi')}
            </button>
          )}
        </div>
      </div>

      {expanded && (
        <div className="mt-3 pt-3 border-t border-indigo-500/20 overflow-x-auto">
          <table className="w-full text-xs text-left">
            <thead>
              <tr className="text-indigo-300/70 border-b border-indigo-500/20">
                <th className="pb-2 font-medium">{t('fwz.conversao.col_grupo')}</th>
                <th className="pb-2 font-medium">{t('fwz.conversao.col_regra')}</th>
                <th className="pb-2 font-medium">{t('fwz.conversao.col_zona')}</th>
                <th className="pb-2 font-medium">{t('fwz.conversao.col_acao')}</th>
                <th className="pb-2 font-medium">{t('fwz.conversao.col_motivo')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-indigo-500/10">
              {items.map((it, idx) => (
                <tr key={idx} className="text-indigo-100">
                  <td className="py-2 pr-3 font-mono">{it.grupo}</td>
                  <td className="py-2 pr-3">{it.regra}</td>
                  <td className="py-2 pr-3 font-medium uppercase text-indigo-300">{it.zona_destino}</td>
                  <td className="py-2 pr-3">{it.acao}</td>
                  <td className="py-2 text-indigo-200/80">
                    {it.motivo}
                    {it.aviso && (
                      <span className="block text-amber-300 font-medium mt-0.5">{it.aviso}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
