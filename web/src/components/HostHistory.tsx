import { useCallback, useEffect, useState } from 'react';
import { Loader2 } from 'lucide-react';
import client from '../api/client';
import { useI18n } from '../i18n';
import TrafficChart from './TrafficChart';
import { TRAFFIC_WINDOWS, pointsFromHistory } from '../lib/series';
import type { Point, ScaleMode } from '../lib/series';
import type { TrafficHistoryResponse } from '../types';

interface Props {
  /** A máquina. É o IP porque é assim que a série é rotulada. */
  ip: string;
  /** Nome que o admin reconhece, só para o cabeçalho do gráfico. */
  titulo: string;
}

/**
 * HostHistory mostra quanto UMA máquina consumiu ao longo do tempo (issue
 * #113). Até aqui o painel só sabia responder "quem consome agora"; a série
 * por máquina é o que permite perguntar "quanto o banco gastou ontem".
 *
 * A consulta é pelo IP: é a identidade que o inventário, o bloqueio, o apelido
 * e a cota usam — o IP de uma VNIC não muda enquanto ela existe.
 */
export default function HostHistory({ ip, titulo }: Props) {
  const { t } = useI18n();
  const [range, setRange] = useState<string>(TRAFFIC_WINDOWS[0].range);
  const [points, setPoints] = useState<Point[]>([]);
  const [mode, setMode] = useState<ScaleMode>('linear');
  const [loading, setLoading] = useState(true);
  const [erro, setErro] = useState('');

  const carregar = useCallback(async () => {
    setLoading(true); setErro('');
    try {
      const { data } = await client.get<TrafficHistoryResponse>(
        `/api/hosts/traffic/history?ip=${encodeURIComponent(ip)}&range=${range}`,
      );
      setPoints(pointsFromHistory(data.points ?? []));
    } catch {
      setErro(t('svc.hosts.history.error'));
    } finally {
      setLoading(false);
    }
  }, [ip, range, t]);

  useEffect(() => { carregar(); }, [carregar]);

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-1 text-xs" role="group">
        {TRAFFIC_WINDOWS.map((w) => (
          <button
            key={w.range}
            type="button"
            onClick={() => setRange(w.range)}
            aria-pressed={range === w.range}
            className={`px-2 py-1 rounded ${
              range === w.range ? 'bg-blue-500/20 text-blue-300' : 'text-gray-400 hover:text-gray-200'
            }`}
          >
            {w.label}
          </button>
        ))}
        {loading && <Loader2 className="w-3.5 h-3.5 animate-spin text-gray-500 ml-1" />}
      </div>

      {erro ? (
        <p className="text-red-400 text-sm">{erro}</p>
      ) : (
        <>
          <TrafficChart
            points={points}
            iface={titulo}
            mode={mode}
            onModeChange={setMode}
            loading={loading}
            height={160}
          />
          {/* A série começa a existir quando o aparelho passa a trafegar depois
              da atualização — dizer isso evita o "o gráfico está quebrado". */}
          {!loading && points.length === 0 && (
            <p className="text-gray-600 text-xs">{t('svc.hosts.history.empty')}</p>
          )}
        </>
      )}
    </div>
  );
}
