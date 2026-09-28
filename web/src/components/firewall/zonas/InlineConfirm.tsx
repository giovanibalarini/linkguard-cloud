import { useI18n } from '../../../i18n';

interface InlineConfirmProps {
  /** Pergunta já traduzida, com o nome do item afetado. */
  mensagem: string;
  onConfirm: () => void;
  onCancel: () => void;
}

/**
 * Confirmação de ação destrutiva no próprio lugar, sem window.confirm(): a
 * faixa aparece junto do item, com a pergunta e os botões Confirmar/Cancelar.
 * Mesmo desenho da confirmação de descarte em PendingChangesBar.
 */
export default function InlineConfirm({ mensagem, onConfirm, onCancel }: InlineConfirmProps) {
  const { t } = useI18n();

  return (
    <div
      role="alert"
      className="p-3 rounded-lg bg-rose-950/40 border border-rose-500/30 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs"
    >
      <span className="text-rose-200">{mensagem}</span>
      <div className="flex items-center gap-2 shrink-0">
        <button
          type="button"
          onClick={onConfirm}
          className="px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-medium transition-colors"
        >
          {t('common.confirm')}
        </button>
        {/* O foco começa no botão seguro e leva a faixa para a tela em listas longas. */}
        <button type="button" onClick={onCancel} autoFocus className="btn-secondary px-3 py-1.5">
          {t('common.cancel')}
        </button>
      </div>
    </div>
  );
}
