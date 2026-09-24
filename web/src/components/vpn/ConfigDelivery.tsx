import { useState } from 'react';
import { AlertTriangle, Copy, Download, X } from 'lucide-react';
import Modal from '../ui/Modal';
import { useI18n } from '../../i18n';
import { safeName, type VPNEnrollment } from './vpnTypes';

interface Props {
  enrollment: VPNEnrollment | null;
  // Preenchido quando o admin entrega a configuração de OUTRA pessoa.
  forUser?: string;
  onClose: () => void;
}

// A configuração com a chave privada aparece uma vez, aqui, e some ao fechar:
// ela nunca vai para localStorage, URL ou log.
export default function ConfigDelivery({ enrollment, forUser, onClose }: Props) {
  const { t } = useI18n();
  const [copy, setCopy] = useState<'ok' | 'fail' | null>(null);
  if (!enrollment) return null;
  const name = forUser || enrollment.peer.username || 'client';

  const download = () => {
    const url = URL.createObjectURL(new Blob([enrollment.client_config], { type: 'text/plain;charset=utf-8' }));
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `linkguard-${safeName(name)}.conf`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const copyConfig = async () => {
    try {
      await navigator.clipboard.writeText(enrollment.client_config);
      setCopy('ok');
    } catch {
      setCopy('fail');
    }
  };

  const close = () => {
    setCopy(null);
    onClose();
  };

  return (
    <Modal
      open
      onClose={close}
      size="lg"
      className="bg-gray-900 border border-gray-800 rounded-xl"
      title={forUser ? t('vpn.delivery.titleFor', { user: forUser }) : t('vpn.delivery.titleMine')}
    >
      <div className="p-5 space-y-4">
        <p className="flex items-start gap-2 text-sm text-amber-200">
          <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0 text-amber-300" />
          {t('vpn.delivery.once')}
        </p>
        {enrollment.apply_error && <p className="text-sm text-red-400">{enrollment.apply_error}</p>}
        {enrollment.warning && <p className="text-sm text-amber-300">{enrollment.warning}</p>}

        <div className="grid grid-cols-1 md:grid-cols-[minmax(0,1fr)_14rem] gap-4">
          <textarea
            readOnly
            rows={11}
            value={enrollment.client_config}
            aria-label={t('vpn.delivery.configLabel')}
            className="input w-full font-mono text-xs resize-y"
          />
          {enrollment.qr_data_url ? (
            <div className="rounded-lg bg-white p-3 self-start max-w-[14rem]">
              <img src={enrollment.qr_data_url} alt={t('vpn.delivery.qrAlt')} className="w-full aspect-square" />
            </div>
          ) : (
            <p className="text-gray-500 text-sm">{t('vpn.delivery.noQR')}</p>
          )}
        </div>

        <div className="flex flex-wrap gap-2">
          <button onClick={download} className="btn-primary flex items-center gap-2">
            <Download className="w-4 h-4" /> {t('vpn.delivery.download')}
          </button>
          <button onClick={copyConfig} className="btn-secondary flex items-center gap-2">
            <Copy className="w-4 h-4" /> {t('vpn.delivery.copy')}
          </button>
          <button onClick={close} className="btn-secondary flex items-center gap-2">
            <X className="w-4 h-4" /> {t('vpn.delivery.close')}
          </button>
        </div>
        {copy === 'ok' && <p className="text-xs text-green-400">{t('vpn.delivery.copied')}</p>}
        {copy === 'fail' && <p className="text-xs text-red-400">{t('vpn.delivery.copyFailed')}</p>}
        <p className="text-xs text-gray-400">
          {forUser ? t('vpn.delivery.forNote', { user: forUser }) : t('vpn.delivery.mineNote')}
        </p>
      </div>
    </Modal>
  );
}
