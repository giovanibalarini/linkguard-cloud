import { useState } from 'react';
import { AlertTriangle, Code, List, X } from 'lucide-react';
import Modal from '../../ui/Modal';
import { useI18n } from '../../../i18n';
import type { MudancaFW, PendenciasFW } from '../../../types/firewall';

interface DiffModalProps {
  open: boolean;
  onClose: () => void;
  pendencias: PendenciasFW | null;
}

export default function DiffModal({ open, onClose, pendencias }: DiffModalProps) {
  const { t } = useI18n();
  const [showNft, setShowNft] = useState(false);

  if (!pendencias) return null;

  const renderMudancaTexto = (m: MudancaFW) => {
    const key = `fwz.diff.${m.objeto}.${m.tipo}`;
    const vars: Record<string, string> = {
      desc: m.nome || m.id,
      nome: m.nome || m.id,
      zona: m.zona ? t(`fwz.zona.${m.zona}`) : '',
      campos: (m.campos || []).join(', '),
    };
    return t(key, vars);
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={
        <div className="flex items-center justify-between w-full">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-white">{t('fwz.diff.titulo')}</span>
            <span className="text-xs font-mono bg-blue-500/20 text-blue-400 px-2 py-0.5 rounded-full">
              {pendencias.mudancas?.length || 0}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setShowNft(!showNft)}
              className="btn-secondary text-xs flex items-center gap-1.5 py-1 px-2.5"
            >
              {showNft ? (
                <>
                  <List className="w-3.5 h-3.5" />
                  {t('fwz.diff.ver_resumo')}
                </>
              ) : (
                <>
                  <Code className="w-3.5 h-3.5" />
                  {t('fwz.diff.ver_nft')}
                </>
              )}
            </button>
            <button
              type="button"
              onClick={onClose}
              className="text-gray-400 hover:text-white p-1 rounded-lg hover:bg-gray-800 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>
      }
      size="lg"
      className="bg-gray-950 border border-gray-800 rounded-xl"
    >
      <div className="p-6 space-y-4">
        {pendencias.precisa_janela && (
          <div className="flex items-start gap-3 p-3.5 rounded-lg border border-amber-500/40 bg-amber-500/10 text-amber-300 text-xs">
            <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
            <p className="leading-relaxed">{t('fwz.diff.aviso_janela')}</p>
          </div>
        )}

        {showNft ? (
          <div className="rounded-lg border border-gray-800 bg-gray-900/80 p-3 overflow-x-auto max-h-[50vh]">
            {pendencias.diff_nft ? (
              <pre className="font-mono text-xs leading-relaxed">
                {pendencias.diff_nft.split('\n').map((line, idx) => {
                  let lineStyle = 'text-gray-400';
                  if (line.startsWith('+') && !line.startsWith('+++')) {
                    lineStyle = 'text-emerald-400 bg-emerald-950/30';
                  } else if (line.startsWith('-') && !line.startsWith('---')) {
                    lineStyle = 'text-rose-400 bg-rose-950/30';
                  } else if (line.startsWith('@@')) {
                    lineStyle = 'text-cyan-400 font-semibold';
                  }
                  return (
                    <div key={idx} className={`${lineStyle} px-1.5 py-0.5 rounded whitespace-pre`}>
                      {line || ' '}
                    </div>
                  );
                })}
              </pre>
            ) : (
              <p className="text-gray-500 text-xs text-center py-4">{t('fwz.diff.sem_mudancas')}</p>
            )}
          </div>
        ) : (
          <div className="space-y-2 max-h-[50vh] overflow-y-auto">
            {(!pendencias.mudancas || pendencias.mudancas.length === 0) ? (
              <p className="text-gray-500 text-xs text-center py-6">{t('fwz.diff.sem_mudancas')}</p>
            ) : (
              pendencias.mudancas.map((m, idx) => (
                <div
                  key={`${m.objeto}-${m.id}-${idx}`}
                  className="flex items-start gap-2.5 p-2.5 rounded-lg border border-gray-800/80 bg-gray-900/40 text-xs text-gray-200"
                >
                  <span
                    className={`px-1.5 py-0.5 rounded text-[10px] font-mono shrink-0 uppercase font-semibold ${
                      m.tipo === 'criada'
                        ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                        : m.tipo === 'removida'
                        ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                        : m.tipo === 'movida'
                        ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30'
                        : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                    }`}
                  >
                    {m.tipo}
                  </span>
                  <span className="leading-relaxed flex-1">{renderMudancaTexto(m)}</span>
                </div>
              ))
            )}
          </div>
        )}

        <div className="flex justify-end pt-2 border-t border-gray-800/80">
          <button type="button" onClick={onClose} className="btn-secondary text-xs px-4 py-2">
            {t('fwz.diff.fechar')}
          </button>
        </div>
      </div>
    </Modal>
  );
}
