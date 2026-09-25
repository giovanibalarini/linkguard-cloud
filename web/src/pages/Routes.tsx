import { useEffect, useState } from 'react';
import { RefreshCw, Route as RouteIcon, ListTree } from 'lucide-react';
import client from '../api/client';
import { useI18n } from '../i18n';
import type { Route, IpRule } from '../types';

/**
 * Rotas e regras de roteamento do kernel — SÓ LEITURA.
 *
 * Na nuvem a rota é da VCN: a default vem do DHCP da Oracle, e o que desvia o
 * tráfego das outras máquinas para cá é a route table da VCN, no console. Uma
 * rota escrita por aqui brigaria com as duas e sumiria no próximo reboot. A
 * tela fica para diagnóstico: ver por onde o kernel manda cada destino.
 */
export default function Routes() {
  const { t } = useI18n();
  const [routes, setRoutes] = useState<Route[]>([]);
  const [rules, setRules] = useState<IpRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState<'routes' | 'rules'>('routes');

  const fetchData = async () => {
    setLoading(true);
    try {
      const [r, ru] = await Promise.all([
        client.get<Route[]>('/api/routes'),
        client.get<IpRule[]>('/api/routes/rules'),
      ]);
      setRoutes(r.data ?? []);
      setRules(ru.data ?? []);
      setError('');
    } catch (e) {
      setError(t('net.msg.error', { e: e instanceof Error ? e.message : String(e) }));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void fetchData(); }, []);

  const tabClass = (id: 'routes' | 'rules') =>
    `px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors whitespace-nowrap ${activeTab === id ? 'border-blue-500 text-blue-400' : 'border-transparent text-gray-500 hover:text-gray-300'}`;

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-white">{t('net.routes.title')}</h1>
          <p className="text-gray-500 text-sm">{t('net.routes.subtitle')}</p>
        </div>
        <button onClick={() => void fetchData()} className="btn-secondary flex items-center gap-2">
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> {t('net.action.refresh')}
        </button>
      </div>

      {error && <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm">{error}</div>}

      <div className="flex gap-2 border-b border-gray-800 overflow-x-auto">
        <button onClick={() => setActiveTab('routes')} className={tabClass('routes')}>
          <RouteIcon className="w-4 h-4 inline mr-1.5" />{t('net.routes.tab.routes', { n: routes.length })}
        </button>
        <button onClick={() => setActiveTab('rules')} className={tabClass('rules')}>
          <ListTree className="w-4 h-4 inline mr-1.5" />{t('net.routes.tab.rules', { n: rules.length })}
        </button>
      </div>

      {activeTab === 'routes' ? (
        <div className="card overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-gray-500 border-b border-gray-800">
                <th className="pb-3 pr-4 font-medium">{t('net.routes.col.destination')}</th>
                <th className="pb-3 pr-4 font-medium">{t('net.routes.col.gateway')}</th>
                <th className="pb-3 pr-4 font-medium">{t('net.routes.col.interface')}</th>
                <th className="pb-3 pr-4 font-medium">{t('net.routes.col.protocol')}</th>
                <th className="pb-3 pr-4 font-medium">{t('net.routes.col.metric')}</th>
                <th className="pb-3 font-medium">{t('net.routes.col.scope')}</th>
              </tr>
            </thead>
            <tbody>
              {routes.map((r) => (
                <tr key={r.raw} className="table-row" title={r.raw}>
                  <td className="py-2.5 pr-4 font-mono text-white">{r.destination}</td>
                  <td className="py-2.5 pr-4 font-mono text-gray-400">{r.gateway || '—'}</td>
                  <td className="py-2.5 pr-4 font-mono text-gray-400">{r.interface || '—'}</td>
                  <td className="py-2.5 pr-4 text-gray-400">{r.protocol || '—'}</td>
                  <td className="py-2.5 pr-4 font-mono text-gray-400">{r.metric || '—'}</td>
                  <td className="py-2.5 text-gray-400">{r.scope || '—'}</td>
                </tr>
              ))}
              {!loading && routes.length === 0 && (
                <tr><td colSpan={6} className="py-6 text-center text-gray-500">{t('net.routes.empty')}</td></tr>
              )}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="card overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-gray-500 border-b border-gray-800">
                <th className="pb-3 pr-4 font-medium">{t('net.rules.col.priority')}</th>
                <th className="pb-3 pr-4 font-medium">{t('net.rules.col.selector')}</th>
                <th className="pb-3 pr-4 font-medium">{t('net.rules.col.fwmark')}</th>
                <th className="pb-3 pr-4 font-medium">{t('net.rules.col.action')}</th>
                <th className="pb-3 font-medium">{t('net.rules.col.table')}</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((r) => (
                <tr key={r.raw} className="table-row" title={r.raw}>
                  <td className="py-2.5 pr-4 font-mono text-gray-400">{r.priority}</td>
                  <td className="py-2.5 pr-4 font-mono text-white">{r.selector}</td>
                  <td className="py-2.5 pr-4 font-mono text-gray-400">{r.fwmark || '—'}</td>
                  <td className="py-2.5 pr-4 text-gray-400">{r.action}</td>
                  <td className="py-2.5 font-mono text-gray-400">{r.table || '—'}</td>
                </tr>
              ))}
              {!loading && rules.length === 0 && (
                <tr><td colSpan={5} className="py-6 text-center text-gray-500">{t('net.rules.empty')}</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
