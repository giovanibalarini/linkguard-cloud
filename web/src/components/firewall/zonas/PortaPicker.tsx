import { useState, useMemo, useEffect } from 'react';
import Combo, { type ComboItem } from '../../ui/Combo';
import { useI18n } from '../../../i18n';
import { SERVICES } from '../../../lib/services';
import type { AliasFW, Porta } from '../../../types/firewall';

interface PortaPickerProps {
  label: string;
  value: Porta;
  proto: string;
  onChange: (porta: Porta) => void;
  aliases: AliasFW[];
  error?: string;
  disabled?: boolean;
}

type Mode = 'any' | 'port' | 'alias' | 'service';

export default function PortaPicker({
  label,
  value,
  proto,
  onChange,
  aliases,
  error,
  disabled = false,
}: PortaPickerProps) {
  const { t } = useI18n();
  const isTcpUdp = proto === 'tcp' || proto === 'udp' || proto === 'tcp/udp';

  const initialMode = useMemo<Mode>(() => {
    if (value.kind === 'any') return 'any';
    if (value.kind === 'alias') return 'alias';
    if (value.kind === 'port') {
      const isKnownService = SERVICES.some((s) => s.port === value.value);
      if (isKnownService) return 'service';
      return 'port';
    }
    return 'any';
  }, [value]);

  const [mode, setMode] = useState<Mode>(initialMode);

  useEffect(() => {
    if (!isTcpUdp && value.kind !== 'any') {
      onChange({ kind: 'any' });
      setMode('any');
    }
  }, [isTcpUdp, value.kind]);

  const aliasItems = useMemo<ComboItem[]>(() => {
    const items: ComboItem[] = [
      { id: 'sys:gerencia', label: 'Gerência (SSH + Web)', hint: 'sys:gerencia', group: 'Sistema' },
    ];
    for (const a of aliases) {
      if (a.tipo === 'portas') {
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

  const serviceItems = useMemo<ComboItem[]>(() => {
    return SERVICES.map((s) => ({
      id: s.port,
      label: `${s.name} (${s.port}/${s.proto})`,
      hint: s.what,
    }));
  }, []);

  const handleModeChange = (newMode: Mode) => {
    setMode(newMode);
    if (newMode === 'any') {
      onChange({ kind: 'any' });
    } else if (newMode === 'port') {
      onChange({ kind: 'port', value: '' });
    } else if (newMode === 'alias') {
      const defaultAlias = aliasItems[0]?.id || '';
      onChange({ kind: 'alias', value: defaultAlias });
    } else if (newMode === 'service') {
      const defaultService = serviceItems[0]?.id || '80';
      onChange({ kind: 'port', value: defaultService });
    }
  };

  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <label className="block text-xs font-medium text-gray-300">{label}</label>
        {!isTcpUdp && (
          <span className="text-[11px] text-gray-500 italic">
            {t('fwz.editor.porta_ajuda')}
          </span>
        )}
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-1.5 p-1 bg-gray-950/60 rounded-lg border border-gray-800">
        <button
          type="button"
          disabled={disabled}
          onClick={() => handleModeChange('any')}
          className={`px-2.5 py-1 text-xs rounded font-medium transition-colors ${
            mode === 'any' ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white'
          }`}
        >
          {t('fwz.porta.any')}
        </button>

        <button
          type="button"
          disabled={disabled || !isTcpUdp}
          onClick={() => handleModeChange('port')}
          className={`px-2.5 py-1 text-xs rounded font-medium transition-colors ${
            mode === 'port' ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white disabled:opacity-40 disabled:hover:text-gray-400'
          }`}
        >
          {t('fwz.porta.port')}
        </button>

        <button
          type="button"
          disabled={disabled || !isTcpUdp}
          onClick={() => handleModeChange('alias')}
          className={`px-2.5 py-1 text-xs rounded font-medium transition-colors ${
            mode === 'alias' ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white disabled:opacity-40 disabled:hover:text-gray-400'
          }`}
        >
          {t('fwz.porta.alias')}
        </button>

        <button
          type="button"
          disabled={disabled || !isTcpUdp}
          onClick={() => handleModeChange('service')}
          className={`px-2.5 py-1 text-xs rounded font-medium transition-colors ${
            mode === 'service' ? 'bg-blue-600 text-white' : 'text-gray-400 hover:text-white disabled:opacity-40 disabled:hover:text-gray-400'
          }`}
        >
          {t('fwz.porta.service')}
        </button>
      </div>

      {mode === 'port' && isTcpUdp && (
        <input
          type="text"
          disabled={disabled}
          value={value.kind === 'port' ? value.value || '' : ''}
          onChange={(e) => onChange({ kind: 'port', value: e.target.value.trim() })}
          placeholder={t('fwz.porta.picker.digitar')}
          className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 font-mono"
        />
      )}

      {mode === 'alias' && isTcpUdp && (
        <Combo
          items={aliasItems}
          value={value.kind === 'alias' ? value.value || '' : ''}
          onPick={(item) => onChange({ kind: 'alias', value: item?.id || '' })}
          placeholder={t('fwz.porta.picker.select')}
          disabled={disabled}
        />
      )}

      {mode === 'service' && isTcpUdp && (
        <Combo
          items={serviceItems}
          value={value.kind === 'port' ? value.value || '' : ''}
          onPick={(item) => onChange({ kind: 'port', value: item?.id || '' })}
          placeholder={t('fwz.porta.picker.select')}
          disabled={disabled}
        />
      )}

      {error && <p className="text-xs text-red-400">{error}</p>}
    </div>
  );
}
