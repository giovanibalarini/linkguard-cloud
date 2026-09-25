import Tag, { type TagVariant } from './ui/Tag';
import type { AlertSeverity } from '../types';

interface AlertBadgeProps {
  severity: AlertSeverity | string;
}

const severityConfig: Record<string, { label: string; variant: TagVariant }> = {
  info: { label: 'Info', variant: 'neutral' },
  warning: { label: 'Aviso', variant: 'warn' },
  critical: { label: 'Crítico', variant: 'crit' },
};

export function AlertBadge({ severity }: AlertBadgeProps) {
  const cfg = severityConfig[severity] ?? severityConfig.info;
  return <Tag variant={cfg.variant}>{cfg.label}</Tag>;
}
