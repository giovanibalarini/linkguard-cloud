import { useEffect, useState } from 'react';
import { Globe } from 'lucide-react';
import client from '../api/client';
import { useI18n } from '../i18n';
import type { Uplink } from '../types';
import Tag from './ui/Tag';
import { healthNumbers, healthTag } from '../lib/uplinkHealth';

/**
 * Por onde esta máquina sai para a Internet, e de onde veio essa resposta.
 *
 * SOMENTE LEITURA. A origem importa para quem diagnostica: "platform" é a
 * Oracle confirmando a VNIC primária; "kernel" quer dizer que a plataforma não
 * respondeu neste boot e a resposta é a rota default (o NAT funciona, o ajuste
 * de MSS não); "none" é a única em que há trabalho a fazer.
 */
export default function UplinkCard() {
  const { t } = useI18n();
  const [uplink, setUplink] = useState<Uplink | null>(null);

  useEffect(() => {
    let alive = true;
    client
      .get<Uplink>('/api/uplink')
      .then(({ data }) => { if (alive) setUplink(data ?? null); })
      .catch(() => { if (alive) setUplink(null); });
    return () => { alive = false; };
  }, []);

  if (!uplink) return null;
  const none = uplink.source === 'none' || !uplink.interface;
  const tag = healthTag(uplink.health);
  const nums = healthNumbers(uplink.health);
  return (
    <div className={`card border ${none ? 'border-amber-500/30 bg-amber-500/5' : 'border-blue-500/30 bg-blue-500/5'}`}>
      <div className="flex items-start gap-3">
        <Globe className={`w-5 h-5 shrink-0 mt-0.5 ${none ? 'text-amber-400' : 'text-blue-400'}`} />
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-white font-medium">{t('net.uplink.title')}</span>
            <Tag variant={tag.variant} dot>{t(tag.key)}</Tag>
          </div>
          <p className="text-gray-400 text-sm mt-1">{t(`net.uplink.source.${none ? 'none' : uplink.source}`)}</p>
          {!none && (
            <div className="flex flex-wrap gap-x-6 gap-y-1 mt-3 text-sm">
              <span className="text-gray-500">
                {t('net.uplink.iface')}: <span className="text-gray-200 font-mono">{uplink.interface}</span>
              </span>
              <span className="text-gray-500">
                {t('net.uplink.mtu')}:{' '}
                <span className="text-gray-200 font-mono">
                  {uplink.path_mtu > 0 ? uplink.path_mtu : t('net.uplink.mtu.unknown')}
                </span>
              </span>
              <span className="text-gray-500">
                {t('net.uplink.platform')}: <span className="text-gray-200 font-mono">{uplink.platform}</span>
              </span>
              <span className="text-gray-500">
                {t('net.uplink.health.latency')}: <span className="text-gray-200 font-mono">{nums.latency}</span>
              </span>
              <span className="text-gray-500">
                {t('net.uplink.health.loss')}: <span className="text-gray-200 font-mono">{nums.loss}</span>
              </span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
