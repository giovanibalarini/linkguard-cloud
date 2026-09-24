import { useState } from 'react';
import { ChevronDown, ChevronRight, Globe, Shield } from 'lucide-react';
import { useI18n } from '../../i18n';
import type { HostGroup } from '../../types';
import type { AccessProfile } from './vpnTypes';

interface Props {
  value: AccessProfile;
  onChange: (profile: AccessProfile) => void;
  hostGroups: HostGroup[];
}

// O perfil de acesso de um peer, na ordem em que o admin pensa: primeiro "até
// onde essa pessoa vai", depois os detalhes. Até 24/09/2026 a tela pedia modo
// de acesso e modo de túnel como duas decisões soltas, e a combinação mais
// comum — só alguns destinos, sem mandar a internet inteira pela nuvem — exigia
// acertar as duas.
export default function AccessForm({ value, onChange, hostGroups }: Props) {
  const { t } = useI18n();
  const [advanced, setAdvanced] = useState(
    // Abre sozinho quando o perfil salvo foge das duas combinações comuns.
    (value.access_mode === 'restricted') !== (value.tunnel_mode === 'split') ||
      value.extra_routes.length > 0 || value.mtu > 0,
  );
  const [routes, setRoutes] = useState(value.extra_routes.join(', '));
  const set = (patch: Partial<AccessProfile>) => onChange({ ...value, ...patch });

  const toggleGroup = (id: string) =>
    set({
      allowed_host_groups: value.allowed_host_groups.includes(id)
        ? value.allowed_host_groups.filter((g) => g !== id)
        : [...value.allowed_host_groups, id],
    });

  const choice = (active: boolean) =>
    `flex items-start gap-3 p-3 rounded-lg border cursor-pointer transition-colors ${
      active ? 'border-blue-500/50 bg-blue-500/5 text-white' : 'border-gray-800 bg-gray-900/50 text-gray-300 hover:border-gray-700'
    }`;

  return (
    <div className="space-y-4">
      <fieldset className="space-y-2">
        <legend className="text-xs font-semibold text-gray-200 mb-2">{t('vpn.access.question')}</legend>
        <label className={choice(value.access_mode === 'restricted')}>
          <input
            type="radio"
            name="vpn-access"
            checked={value.access_mode === 'restricted'}
            onChange={() => set({ access_mode: 'restricted', tunnel_mode: 'split' })}
            className="mt-1"
          />
          <span>
            <span className="flex items-center gap-1.5 text-sm font-medium">
              <Shield className="w-4 h-4 text-purple-400" /> {t('vpn.access.restricted')}
            </span>
            <span className="block text-xs text-gray-400 mt-0.5">{t('vpn.access.restrictedDesc')}</span>
          </span>
        </label>
        <label className={choice(value.access_mode === 'full')}>
          <input
            type="radio"
            name="vpn-access"
            checked={value.access_mode === 'full'}
            onChange={() => set({ access_mode: 'full', tunnel_mode: 'full' })}
            className="mt-1"
          />
          <span>
            <span className="flex items-center gap-1.5 text-sm font-medium">
              <Globe className="w-4 h-4 text-emerald-400" /> {t('vpn.access.full')}
            </span>
            <span className="block text-xs text-gray-400 mt-0.5">{t('vpn.access.fullDesc')}</span>
          </span>
        </label>
      </fieldset>

      {value.access_mode === 'restricted' && (
        <div className="space-y-3 border-t border-gray-800 pt-3">
          <div>
            <div className="text-xs font-medium text-gray-300 mb-1.5">{t('vpn.access.groups')}</div>
            {hostGroups.length === 0 ? (
              <p className="p-3 bg-gray-900 border border-gray-800 rounded-lg text-xs text-amber-300">{t('vpn.access.noGroups')}</p>
            ) : (
              <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                {hostGroups.map((g) => (
                  <label key={g.id} className="flex items-start gap-2.5 p-2.5 rounded-lg border border-gray-800 bg-gray-900/40 hover:border-gray-700 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={value.allowed_host_groups.includes(g.id)}
                      onChange={() => toggleGroup(g.id)}
                      className="mt-0.5"
                    />
                    <span className="min-w-0">
                      <span className="block text-sm text-white">{g.name}</span>
                      <span className="block text-[11px] font-mono text-gray-500 truncate">
                        {(g.hosts || []).map((h) => h.replace(/\/32$/, '')).join(', ')}
                      </span>
                    </span>
                  </label>
                ))}
              </div>
            )}
            {hostGroups.length > 0 && value.allowed_host_groups.length === 0 && (
              <p className="text-[11px] text-amber-300 mt-1.5">{t('vpn.access.noGroupChosen')}</p>
            )}
          </div>
          <label className="block">
            <span className="block text-xs font-medium text-gray-300 mb-1">{t('vpn.access.ports')}</span>
            <input
              type="text"
              value={value.allowed_ports}
              onChange={(e) => set({ allowed_ports: e.target.value })}
              placeholder="6443, 22"
              className="input w-full font-mono text-sm"
            />
            <span className="block text-[11px] text-gray-500 mt-1">{t('vpn.access.portsHelp')}</span>
          </label>
        </div>
      )}

      <div className="border-t border-gray-800 pt-3">
        <button
          type="button"
          onClick={() => setAdvanced((open) => !open)}
          className="flex items-center gap-1 text-xs font-medium text-gray-400 hover:text-white"
          aria-expanded={advanced}
        >
          {advanced ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
          {t('vpn.access.advanced')}
        </button>
        {advanced && (
          <div className="mt-3 space-y-3">
            <fieldset className="space-y-1.5">
              <legend className="text-xs font-medium text-gray-300 mb-1">{t('vpn.access.tunnel')}</legend>
              <label className="flex items-start gap-2 text-xs text-gray-300">
                <input
                  type="radio"
                  name="vpn-tunnel"
                  checked={value.tunnel_mode === 'split'}
                  onChange={() => set({ tunnel_mode: 'split' })}
                  className="mt-0.5"
                />
                <span>{t('vpn.access.tunnelSplit')}</span>
              </label>
              <label className="flex items-start gap-2 text-xs text-gray-300">
                <input
                  type="radio"
                  name="vpn-tunnel"
                  checked={value.tunnel_mode === 'full'}
                  onChange={() => set({ tunnel_mode: 'full' })}
                  className="mt-0.5"
                />
                <span>{t('vpn.access.tunnelFull')}</span>
              </label>
            </fieldset>
            {value.tunnel_mode === 'split' && (
              <label className="block">
                <span className="block text-xs font-medium text-gray-300 mb-1">{t('vpn.access.routes')}</span>
                <input
                  type="text"
                  value={routes}
                  onChange={(e) => {
                    setRoutes(e.target.value);
                    set({ extra_routes: e.target.value.split(/[\s,]+/).filter(Boolean) });
                  }}
                  placeholder="192.168.50.0/24"
                  className="input w-full font-mono text-sm"
                />
                <span className="block text-[11px] text-gray-500 mt-1">{t('vpn.access.routesHelp')}</span>
              </label>
            )}
            <label className="block">
              <span className="block text-xs font-medium text-gray-300 mb-1">{t('vpn.access.mtu')}</span>
              <input
                type="number"
                value={value.mtu || ''}
                onChange={(e) => set({ mtu: e.target.value === '' ? 0 : Number(e.target.value) || 0 })}
                placeholder="1420"
                className="input w-full font-mono text-sm"
              />
              <span className="block text-[11px] text-gray-500 mt-1">{t('vpn.access.mtuHelp')}</span>
            </label>
          </div>
        )}
      </div>
    </div>
  );
}
