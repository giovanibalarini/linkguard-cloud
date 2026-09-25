import { useEffect, useState } from 'react';
import { Activity, RefreshCw } from 'lucide-react';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts';
import client from '../api/client';
import Panel from '../components/ui/Panel';
import type { SystemMetrics } from '../types';
import { useI18n } from '../i18n';

interface HistoryPoint {
  time: string;
  [key: string]: number | string;
}

export default function Monitoring() {
  const { t } = useI18n();
  const [sys, setSys] = useState<SystemMetrics | null>(null);
  const [cpuHistory, setCpuHistory] = useState<HistoryPoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [now, setNow] = useState(() => Date.now());

  const fetchData = async () => {
    setLoading(true);
    try {
      const sysRes = await client.get<SystemMetrics>('/api/system/status');
      const newSys = sysRes.data;
      setSys(newSys);

      // Accumulate history (last 20 points)
      const timeLabel = new Date().toLocaleTimeString();

      const cpuPoint: HistoryPoint = { time: timeLabel, CPU: newSys?.cpu_percent ?? 0, Memória: newSys?.mem_percent ?? 0 };
      setCpuHistory(prev => [...prev.slice(-19), cpuPoint]);
      setLastUpdated(new Date());
      setError(false);
    } catch (e) {
      console.error(e);
      setError(true);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, []);

  // Tick once per second to refresh the "atualizado há Xs" caption
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  const secondsAgo = lastUpdated ? Math.max(0, Math.floor((now - lastUpdated.getTime()) / 1000)) : null;

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-white">{t('mon.title')}</h1>
          <p className="text-gray-500 text-sm">{t('mon.subtitle')}</p>
          <p className="text-gray-600 text-xs mt-0.5">
            {t('mon.autoRefresh.10s')}
            {secondsAgo !== null && t('mon.updatedAgo', { s: secondsAgo })}
          </p>
        </div>
        <button onClick={fetchData} className="btn-secondary flex items-center gap-2">
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          {t('mon.refresh')}
        </button>
      </div>

      {/* Error banner */}
      {error && <div className="card border border-red-500/30 bg-red-500/10 text-red-400 text-sm flex items-center justify-between"><span>{t('mon.error.load')}</span><button onClick={fetchData} className="btn-secondary">{t('mon.error.retry')}</button></div>}

      {/* Initial loading skeleton */}
      {loading && !sys && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {[0, 1, 2].map(i => (
            <div key={i} className="card text-gray-500 text-sm animate-pulse">{t('mon.loading')}</div>
          ))}
        </div>
      )}

      {/* CPU / Memory chart */}
      <Panel title={<span className="flex items-center gap-2"><Activity className="w-4 h-4 text-purple-400" /><span className="text-white font-semibold">{t('mon.chart.cpuMem.title')}</span></span>}>
        {cpuHistory.length > 1 ? (
          <ResponsiveContainer width="100%" height={220}>
            <LineChart data={cpuHistory}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
              <XAxis dataKey="time" tick={{ fill: '#6b7280', fontSize: 11 }} />
              <YAxis domain={[0, 100]} tick={{ fill: '#6b7280', fontSize: 11 }} />
              <Tooltip contentStyle={{ background: '#111827', border: '1px solid #374151', borderRadius: 8 }} />
              <Legend />
              <Line type="monotone" dataKey="CPU" stroke="#3b82f6" dot={false} strokeWidth={2} />
              <Line type="monotone" dataKey="Memória" name={t('mon.chart.series.memory')} stroke="#8b5cf6" dot={false} strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        ) : (
          <p className="text-gray-500 text-sm text-center py-12">{t('mon.chart.collecting')}</p>
        )}
      </Panel>

      {/* Interface traffic */}
      {sys && sys.interfaces && sys.interfaces.length > 0 && (
        <Panel title={t('mon.iface.panel.title')}>
          {/* Mobile: stacked cards (< sm) */}
          <div className="sm:hidden space-y-2">
            {sys.interfaces.filter(i => i.name !== 'lo').map(iface => (
              <div key={iface.name} className="rounded-lg border bg-gray-950/40 p-3 border-gray-800">
                <div className="text-white font-mono font-medium truncate">{iface.name}</div>
                <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
                  <dt className="text-gray-500">{t('mon.iface.rxTotal')}</dt>
                  <dd className="text-gray-400 font-mono">{formatBytes(iface.rx_bytes)}</dd>
                  <dt className="text-gray-500">{t('mon.iface.txTotal')}</dt>
                  <dd className="text-gray-400 font-mono">{formatBytes(iface.tx_bytes)}</dd>
                  <dt className="text-gray-500">{t('mon.iface.rxPackets')}</dt>
                  <dd className="text-gray-400 font-mono">{iface.rx_packets.toLocaleString()}</dd>
                  <dt className="text-gray-500">{t('mon.iface.txPackets')}</dt>
                  <dd className="text-gray-400 font-mono">{iface.tx_packets.toLocaleString()}</dd>
                  <dt className="text-gray-500">{t('mon.iface.errors')}</dt>
                  <dd className="text-gray-400 font-mono">{iface.rx_errors + iface.tx_errors}</dd>
                </dl>
              </div>
            ))}
          </div>

          {/* Desktop: table (>= sm) */}
          <div className="hidden sm:block overflow-x-auto">
            <table className="hidden sm:table w-full text-sm">
              <thead>
                <tr className="text-left text-gray-500 border-b border-gray-800">
                  <th className="pb-3 pr-4 font-medium">{t('mon.link.interface')}</th>
                  <th className="pb-3 pr-4 font-medium">{t('mon.iface.rxTotal')}</th>
                  <th className="pb-3 pr-4 font-medium">{t('mon.iface.txTotal')}</th>
                  <th className="pb-3 pr-4 font-medium">{t('mon.iface.rxPackets')}</th>
                  <th className="pb-3 pr-4 font-medium">{t('mon.iface.txPackets')}</th>
                  <th className="pb-3 font-medium">{t('mon.iface.errors')}</th>
                </tr>
              </thead>
              <tbody>
                {sys.interfaces.filter(i => i.name !== 'lo').map(iface => (
                  <tr key={iface.name} className="table-row">
                    <td className="py-3 pr-4 text-white font-mono">{iface.name}</td>
                    <td className="py-3 pr-4 text-gray-400">{formatBytes(iface.rx_bytes)}</td>
                    <td className="py-3 pr-4 text-gray-400">{formatBytes(iface.tx_bytes)}</td>
                    <td className="py-3 pr-4 text-gray-400">{iface.rx_packets.toLocaleString()}</td>
                    <td className="py-3 pr-4 text-gray-400">{iface.tx_packets.toLocaleString()}</td>
                    <td className="py-3 text-gray-400">{iface.rx_errors + iface.tx_errors}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}
