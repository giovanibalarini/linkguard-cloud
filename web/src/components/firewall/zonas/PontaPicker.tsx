import { useState, useMemo } from 'react';
import Combo, { type ComboItem } from '../../ui/Combo';
import { useI18n } from '../../../i18n';
import {
  chaveDoValor,
  modoDaPonta,
  opcoesDeAlias,
  type EscolhaDeModo,
  type ModoPonta,
} from '../../../lib/fwZonas';
import { useNetTargets } from '../../../lib/useNetTargets';
import type { AliasFW, Ponta } from '../../../types/firewall';

interface PontaPickerProps {
  label: string;
  value: Ponta;
  onChange: (ponta: Ponta) => void;
  isDestino?: boolean;
  aliases: AliasFW[];
  error?: string;
  disabled?: boolean;
}

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

  const aliasItems = useMemo<ComboItem[]>(
    () => opcoesDeAlias(aliases, 'enderecos', t),
    [aliases, t],
  );

  const machineItems = useMemo<ComboItem[]>(() => {
    return targets.map((tg) => ({
      id: tg.value,
      label: tg.label,
      hint: tg.hint,
      dot: tg.online,
    }));
  }, [targets]);

  // O modo sai do valor (o editor pode trocar de regra com o seletor montado);
  // `escolha` só desempata máquina x endereço digitado. Ver modoDaPonta.
  const [escolha, setEscolha] = useState<EscolhaDeModo<ModoPonta> | null>(null);
  const mode = modoDaPonta(value, machineItems.map((m) => m.id), escolha);

  const emitir = (modo: ModoPonta, ponta: Ponta) => {
    setEscolha({ modo, chave: chaveDoValor(ponta) });
    onChange(ponta);
  };

  const handleModeChange = (newMode: ModoPonta) => {
    if (newMode === 'any') {
      emitir(newMode, { kind: 'any' });
    } else if (newMode === 'self') {
      emitir(newMode, { kind: 'self' });
    } else if (newMode === 'alias') {
      const defaultAlias = aliasItems[0]?.id || '';
      emitir(newMode, { kind: 'alias', value: defaultAlias });
    } else if (newMode === 'machine') {
      const defaultMachine = machineItems[0]?.id || '';
      emitir(newMode, { kind: 'addr', value: defaultMachine });
    } else if (newMode === 'addr') {
      emitir(newMode, { kind: 'addr', value: '' });
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
          onPick={(item) => emitir('alias', { kind: 'alias', value: item?.id || '' })}
          placeholder={t('fwz.ponta.picker.select')}
          disabled={disabled}
        />
      )}

      {mode === 'machine' && (
        <Combo
          items={machineItems}
          value={value.kind === 'addr' ? value.value || '' : ''}
          onPick={(item) => emitir('machine', { kind: 'addr', value: item?.id || '' })}
          placeholder={t('fwz.ponta.picker.select')}
          disabled={disabled}
        />
      )}

      {mode === 'addr' && (
        <input
          type="text"
          disabled={disabled}
          value={value.kind === 'addr' ? value.value || '' : ''}
          onChange={(e) => emitir('addr', { kind: 'addr', value: e.target.value.trim() })}
          placeholder={t('fwz.ponta.addr_placeholder')}
          className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
        />
      )}

      {error && <p className="text-xs text-red-400">{error}</p>}
    </div>
  );
}
