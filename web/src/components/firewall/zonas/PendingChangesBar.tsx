import { useState, useMemo } from 'react';
import { AlertCircle, AlertTriangle, Check, Eye, RotateCcw } from 'lucide-react';
import client from '../../../api/client';
import { useI18n } from '../../../i18n';
import type { ConfirmOrRevert } from '../../../lib/useConfirmOrRevert';
import type { PendenciasFW } from '../../../types/firewall';
import DiffModal from './DiffModal';

interface PendingChangesBarProps {
  pendencias: PendenciasFW | null;
  cor: ConfirmOrRevert;
  onRefresh: () => Promise<void>;
  canWrite: boolean;
}

export default function PendingChangesBar({
  pendencias,
  cor,
  onRefresh,
  canWrite,
}: PendingChangesBarProps) {
  const { t } = useI18n();
  const [diffOpen, setDiffOpen] = useState(false);
  const [confirmingDiscard, setConfirmingDiscard] = useState(false);

  const numMudancas = pendencias?.mudancas?.length || 0;
  const isPendente = !!pendencias?.pendente || numMudancas > 0;

  const erros = useMemo(() => {
    return (pendencias?.problemas || []).filter((p) => p.severidade === 'erro');
  }, [pendencias?.problemas]);

  const avisos = useMemo(() => {
    return (pendencias?.problemas || []).filter((p) => p.severidade === 'aviso');
  }, [pendencias?.problemas]);

  const hasErrors = erros.length > 0;
  const applyDisabled = !canWrite || cor.busy || cor.editDisabled || hasErrors;

  if (!isPendente && !confirmingDiscard) {
    return null;
  }

  const handleAplicar = async () => {
    const ok = await cor.run(
      () => client.post('/api/firewall/aplicar'),
      t('fwz.pendencias.sucesso'),
    );
    if (ok) {
      await onRefresh();
    }
  };

  const handleDescartar = async () => {
    setConfirmingDiscard(false);
    const ok = await cor.run(
      () => client.post('/api/firewall/descartar'),
      t('fwz.pendencias.descartado_sucesso'),
    );
    if (ok) {
      await onRefresh();
    }
  };

  return (
    <>
      <div className="rounded-xl border border-blue-500/40 bg-blue-950/40 p-4 space-y-3 shadow-lg shadow-blue-950/20">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-blue-500/20 text-blue-400 shrink-0">
              <AlertCircle className="w-5 h-5" />
            </div>
            <div className="text-sm">
              <p className="font-medium text-white">
                {t('fwz.pendencias.aviso', { n: String(numMudancas) })}
              </p>
              {pendencias?.precisa_janela && (
                <p className="text-xs text-amber-300/90 mt-0.5 flex items-center gap-1">
                  <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                  {t('fwz.diff.aviso_janela')}
                </p>
              )}
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap shrink-0">
            <button
              type="button"
              onClick={() => setDiffOpen(true)}
              className="btn-secondary text-xs flex items-center gap-1.5 py-1.5 px-3"
            >
              <Eye className="w-3.5 h-3.5" />
              {t('fwz.pendencias.ver_diff')}
            </button>

            {canWrite && !confirmingDiscard && (
              <button
                type="button"
                disabled={cor.busy || cor.editDisabled}
                onClick={() => setConfirmingDiscard(true)}
                className="btn-secondary text-xs flex items-center gap-1.5 py-1.5 px-3 text-rose-300 hover:text-rose-200 hover:bg-rose-950/30 border-rose-800/40"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                {t('fwz.pendencias.descartar')}
              </button>
            )}

            {canWrite && !confirmingDiscard && (
              <button
                type="button"
                disabled={applyDisabled}
                onClick={handleAplicar}
                className="btn-primary text-xs flex items-center gap-1.5 py-1.5 px-4 bg-blue-600 hover:bg-blue-500 disabled:opacity-50"
              >
                <Check className="w-3.5 h-3.5" />
                {cor.busy ? t('fwz.pendencias.aplicando') : t('fwz.pendencias.aplicar')}
              </button>
            )}
          </div>
        </div>

        {confirmingDiscard && (
          <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-500/30 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
            <span className="text-rose-200">{t('fwz.pendencias.descartar.confirm')}</span>
            <div className="flex items-center gap-2 shrink-0">
              <button
                type="button"
                disabled={cor.busy}
                onClick={handleDescartar}
                className="px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-medium transition-colors"
              >
                {cor.busy ? t('fwz.pendencias.descartando') : t('fwz.pendencias.descartar.sim')}
              </button>
              <button
                type="button"
                disabled={cor.busy}
                onClick={() => setConfirmingDiscard(false)}
                className="btn-secondary px-3 py-1.5"
              >
                {t('fwz.pendencias.descartar.cancelar')}
              </button>
            </div>
          </div>
        )}

        {hasErrors && (
          <div className="p-3 rounded-lg bg-red-950/30 border border-red-500/30 text-xs text-red-300 space-y-1">
            <p className="font-medium text-red-200">{t('fwz.pendencias.com_erros')}</p>
            <ul className="list-disc pl-4 space-y-0.5">
              {erros.map((e, idx) => (
                <li key={idx}>{t(e.chave, e.vars)}</li>
              ))}
            </ul>
          </div>
        )}

        {avisos.length > 0 && !hasErrors && (
          <div className="p-3 rounded-lg bg-amber-950/20 border border-amber-500/20 text-xs text-amber-300 space-y-1">
            <ul className="list-disc pl-4 space-y-0.5">
              {avisos.map((a, idx) => (
                <li key={idx}>{t(a.chave, a.vars)}</li>
              ))}
            </ul>
          </div>
        )}
      </div>

      <DiffModal
        open={diffOpen}
        onClose={() => setDiffOpen(false)}
        pendencias={pendencias}
      />
    </>
  );
}
