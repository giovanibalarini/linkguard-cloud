import { useState, useMemo, useEffect } from 'react';
import Combo, { type ComboItem } from '../../ui/Combo';
import { useI18n } from '../../../i18n';
import { useNetTargets } from '../../../lib/useNetTargets';
import type { AliasFW, Ponta, PontaTipo } from '../../../types/firewall';

interface PontaPickerProps {
  label: string;
  value: Ponta;
  onChange: (ponta: Ponta) => void;
  isDestino?: boolean;
  aliases: AliasFW[];
  error?: string;
  disabled?: boolean;
}

type Mode = 'any' | 'self' | 'alias' | 'machine' | 'addr';

export default function PontaPicker({
  label,
  value,
  onChange,
  isDestino = false,
  aliases,
  error,
  disabled = false,
}: PontaPickerProps) {
  const { t } = useI18n();
  const { targets } = useNetTargets();

  const initialMode = useMemo<Mode>(() => {
    if (value.kind === 'any') return 'any';
    if (value.kind === 'self') return 'self';
    if (value.kind === 'alias') return 'alias';
    if (value.kind === 'addr') {
      const isTarget = targets.some((tg) => tg.value === value.value);
      if (isTarget) return 'machine';
      return 'addr';
    }
    return 'any';
  }, [value, targets]);

  const [mode, setMode] = useState<Mode>(initialMode);

  useEffect(() => {
    if (value.kind === 'any' && mode !== 'any') setMode('any');
    else if (value.kind === 'self' && mode !== 'self') setMode('self');
    else if (value.kind === 'alias' && mode !== 'alias') setMode('alias');
  }, [value.kind]);

  const aliasItems = useMemo<ComboItem[]>(() => {
    const items: ComboItem[] = [
      { id: 'sys:vcn', label: 'VCN (Redes locais)', hint: 'sys:vcn', group: 'Sistema' },
      { id: 'sys:vpn', label: 'VPN (Rede WireGuard)', hint: 'sys:vpn', group: 'Sistema' },
    ];
    for (const a of aliases) {
      if (a.tipo === 'enderecos') {
        items.push({
          id: a.id,
          label: a.nome,
          hint: a.itens.join(', '),
          group: 'Aliases personalizados',
        });
      }
    }
    return items;
  }, [aliases]);

  const machineItems = useMemo<ComboItem[]>(() => {
    return targets.map((tg) => ({
      id: tg.value,
      label: tg.label,
      hint: tg.hint,
      dot: tg.online,
    }));
  }, [targets]);

  const handleModeChange = (newMode: Mode) => {
    setMode(newMode);
    if (newMode === 'any') {
      onChange({ kind: 'any' });
    } else if (newMode === 'self') {
      onChange({ kind: 'self' });
    } else if (newMode === 'alias') {
      const defaultAlias = aliasItems[0]?.id || '';
      onChange({ kind: 'alias', value: defaultAlias });
    } else if (newMode === 'machine') {
      const defaultMachine = machineItems[0]?.id || '';
      onChange({ kind: 'addr', value: defaultMachine });
    } else if (newMode === 'addr') {
      onChange({ kind: 'addr', value: '' });
    }
  };

  return (
    <div className="space-y-1.5">
      <label className="block text-xs font-medium text-gray-300">{label}</label>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-1.5 p-1 bg-gray-950/60 rounded-lg border border-gray-800">
        <button
          type="button"
          disabled={disabled}
          onClick={() => handleModeChange('any')}
          className={`px-2.5 py-1 text-xs rounded font-medium transition-colors ${
            mode === 'any' ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white'
          }`}
        >
          {t('fwz.ponta.any')}
        </button>

        {isDestino && (
          <button
            type="button"
            disabled={disabled}
            onClick={() => handleModeChange('self')}
            className={`px-2.5 py-1 text-xs rounded font-medium transition-colors ${
              mode === 'self' ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white'
            }`}
          >
            {t('fwz.ponta.self')}
          </button>
        )}

        <button
          type="button"
          disabled={disabled}
          onClick={() => handleModeChange('alias')}
          className={`px-2.5 py-1 text-xs rounded font-medium transition-colors ${
            mode === 'alias' ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white'
          }`}
        >
          {t('fwz.ponta.alias')}
        </button>

        <button
          type="button"
          disabled={disabled}
          onClick={() => handleModeChange('machine')}
          className={`px-2.5 py-1 text-xs rounded font-medium transition-colors ${
            mode === 'machine' ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white'
          }`}
        >
          {t('fwz.ponta.machine')}
        </button>

        <button
          type="button"
          disabled={disabled}
          onClick={() => handleModeChange('addr')}
          className={`px-2.5 py-1 text-xs rounded font-medium transition-colors ${
            mode === 'addr' ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white'
          }`}
        >
          {t('fwz.ponta.addr')}
        </button>
      </div>

      {mode === 'alias' && (
        <Combo
          items={aliasItems}
          value={value.kind === 'alias' ? value.value || '' : ''}
          onPick={(item) => onChange({ kind: 'alias', value: item?.id || '' })}
          placeholder={t('fwz.ponta.picker.select')}
          disabled={disabled}
        />
      )}

      {mode === 'machine' && (
        <Combo
          items={machineItems}
          value={value.kind === 'addr' ? value.value || '' : ''}
          onPick={(item) => onChange({ kind: 'addr', value: item?.id || '' })}
          placeholder={t('fwz.ponta.picker.select')}
          disabled={disabled}
        />
      )}

      {mode === 'addr' && (
        <input
          type="text"
          disabled={disabled}
          value={value.kind === 'addr' ? value.value || '' : ''}
          onChange={(e) => onChange({ kind: 'addr', value: e.target.value.trim() })}
          placeholder="Ex: 192.168.1.100 ou 10.0.0.0/24"
          className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
        />
      )}

      {error && <p className="text-xs text-red-400">{error}</p>}
    </div>
  );
}
