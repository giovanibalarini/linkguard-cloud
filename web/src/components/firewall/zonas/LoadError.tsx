import { AlertTriangle, RefreshCw } from 'lucide-react';
import { useI18n } from '../../../i18n';

/**
 * O aviso de que a leitura de uma aba falhou.
 *
 * Antes cada aba só fazia console.error, e uma lista que não carregou ficava
 * igual a uma lista vazia — o operador concluía "não tenho nenhum alias" e
 * criava de novo. A falha tem de aparecer onde os dados apareceriam, com o
 * caminho para tentar outra vez.
 */
export default function LoadError({ onRetry }: { onRetry: () => void }) {
  const { t } = useI18n();
  return (
    <div
      role="alert"
      className="card border border-red-800 bg-red-950/40 text-sm text-red-200 flex flex-col sm:flex-row sm:items-center gap-3"
    >
      <AlertTriangle className="w-4 h-4 shrink-0 text-red-400" aria-hidden="true" />
      <p className="flex-1">{t('fwz.carga.erro')}</p>
      <button onClick={onRetry} className="btn-secondary text-xs shrink-0 flex items-center justify-center gap-2">
        <RefreshCw className="w-3.5 h-3.5" aria-hidden="true" /> {t('fwz.carga.tentar')}
      </button>
    </div>
  );
}
