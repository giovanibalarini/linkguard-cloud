import { Link } from 'react-router-dom';
import WidgetCard, { WidgetNote, usePolled } from './WidgetCard';
import Tag from '../ui/Tag';
import { useI18n } from '../../i18n';
import { healthNumbers, healthTag } from '../../lib/uplinkHealth';
import type { Uplink } from '../../types';

/**
 * A saída para a Internet: se ela responde daqui, com que latência e perda, e
 * por qual placa. Numa caixa de NAT é a Internet de todas as instâncias atrás
 * dela, por isso fica na primeira dobra do painel.
 */
export default function UplinkWidget() {
  const { t } = useI18n();
  const { data: uplink, state } = usePolled<Uplink>('/api/uplink');
  const tag = healthTag(uplink?.health);
  const nums = healthNumbers(uplink?.health);

  return (
    <WidgetCard
      title={t('wid.uplink.title')}
      action={
        <Link to="/interfaces" className="shrink-0 text-xs text-gray-500 hover:text-gray-300">
          {t('wid.view.all')}
        </Link>
      }
    >
      {state === 'loading' && <WidgetNote>{t('wid.loading')}</WidgetNote>}
      {state === 'error' && <WidgetNote>{t('wid.uplink.error')}</WidgetNote>}
      {state === 'ok' && uplink && (
        <div className="space-y-3">
          <Tag variant={tag.variant} dot>{t(tag.key)}</Tag>
          <dl className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-sm">
            <dt className="text-gray-500">{t('net.uplink.iface')}</dt>
            <dd className="text-gray-200 font-mono truncate">{uplink.interface || '—'}</dd>
            <dt className="text-gray-500">{t('net.uplink.health.latency')}</dt>
            <dd className="text-gray-200 font-mono">{nums.latency}</dd>
            <dt className="text-gray-500">{t('net.uplink.health.loss')}</dt>
            <dd className="text-gray-200 font-mono">{nums.loss}</dd>
          </dl>
        </div>
      )}
    </WidgetCard>
  );
}
