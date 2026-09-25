import type { TagVariant } from '../components/ui/Tag';
import type { UplinkHealth } from '../types';

/** O que a tela mostra de cada estado da sonda de saída. */
export function healthTag(h: UplinkHealth | undefined): { variant: TagVariant; key: string } {
  switch (h?.status) {
    case 'online': return { variant: 'ok', key: 'net.uplink.health.online' };
    case 'degradada': return { variant: 'warn', key: 'net.uplink.health.degraded' };
    case 'offline': return { variant: 'crit', key: 'net.uplink.health.offline' };
    default: return { variant: 'idle', key: 'net.uplink.health.unknown' };
  }
}

/** Latência e perda só valem com medição: antes da primeira, "—". */
export function healthNumbers(h: UplinkHealth | undefined): { latency: string; loss: string } {
  if (!h || h.status === 'desconhecida') return { latency: '—', loss: '—' };
  return {
    latency: h.loss_pct >= 100 ? '—' : `${h.latency_ms.toFixed(0)} ms`,
    loss: `${h.loss_pct.toFixed(0)}%`,
  };
}
