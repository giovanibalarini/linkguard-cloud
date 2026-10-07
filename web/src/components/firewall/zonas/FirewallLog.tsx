import { useCallback, useEffect, useState, useRef } from 'react';
import { Search, RefreshCw, AlertCircle, ShieldAlert, ShieldCheck, ShieldX } from 'lucide-react';
import client from '../../../api/client';
import { useI18n } from '../../../i18n';
import LoadError from './LoadError';
import type { MsgLevel } from '../../../types';
import type { RegistroFW } from '../../../types/firewall';

interface Props {
  canWrite?: boolean;
  onMsg?: (text: string, level?: MsgLevel) => void;
}

export default function FirewallLog({}: Props) {
  const { t } = useI18n();
  const [entradas, setEntradas] = useState<RegistroFW[]>([]);
  const [loading, setLoading] = useState(true);
  const [erroCarga, setErroCarga] = useState(false);
  const [busca, setBusca] = useState('');
  const [debouncedBusca, setDebouncedBusca] = useState('');
  const timerRef = useRef<NodeJS.Timeout | null>(null);

  // Debounce da busca
  useEffect(() => {
    const handler = setTimeout(() => {
      setDebouncedBusca(busca);
    }, 300);
    return () => clearTimeout(handler);
  }, [busca]);

  const carregar = useCallback(async (silencioso = false) => {
    if (!silencioso) setLoading(true);
    try {
      const q = debouncedBusca.trim();
      const url = `/api/firewall/registro?limit=200${q ? `&q=${encodeURIComponent(q)}` : ''}`;
      const { data } = await client.get<{ entradas: RegistroFW[] }>(url);
      setEntradas(data?.entradas ?? []);
      setErroCarga(false);
    } catch {
      setErroCarga(true);
    } finally {
      setLoading(false);
    }
  }, [debouncedBusca]);

  useEffect(() => {
    carregar();
  }, [carregar]);

  // Atualização periódica a cada 5 segundos
  useEffect(() => {
    timerRef.current = setInterval(() => {
      carregar(true);
    }, 5000);
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [carregar]);

  const formatRuleName = (e: RegistroFW): string => {
    if (e.descricao) return e.descricao;
    if (e.desc_chave) {
      try {
        return t(e.desc_chave as any, e.desc_vars);
      } catch {
        return e.desc_chave;
      }
    }
    return e.chave || '-';
  };

  const renderAcaoBadge = (acao?: string) => {
    if (!acao) return null;
    const isPass = acao === 'accept';
    const isReject = acao === 'reject';
    const isDrop = acao === 'drop';

    const color = isPass
      ? 'bg-green-500/10 text-green-400 border-green-500/30'
      : isReject
      ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
      : 'bg-red-500/10 text-red-400 border-red-500/30';

    const Icon = isPass ? ShieldCheck : isReject ? ShieldAlert : ShieldX;

    return (
      <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 text-[11px] font-mono rounded border ${color}`}>
        <Icon className="w-3 h-3" />
        {acao.toUpperCase()}
      </span>
    );
  };

  return (
    <div className="space-y-4">
      {erroCarga && <LoadError onRetry={() => carregar()} />}
      {/* Nota explicativa */}
      <div className="p-3 bg-gray-900 border border-gray-800 rounded-lg text-xs text-gray-400 flex items-start gap-2">
        <AlertCircle className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
        <span>{t('fwz.registro.nota')}</span>
      </div>

      {/* Barra de controle: busca e atualizar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-gray-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            className="input w-full pl-9 text-xs"
            placeholder={t('fwz.registro.busca')}
            value={busca}
            onChange={(e) => setBusca(e.target.value)}
          />
        </div>
        <button
          onClick={() => carregar()}
          className="btn-secondary flex items-center justify-center gap-1.5 text-xs py-2 px-3"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>{t('fwz.registro.atualizar')}</span>
        </button>
      </div>

      {/* Tabela de logs */}
      <div className="card overflow-x-auto p-0 border border-gray-800">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="border-b border-gray-800 bg-gray-900/60 text-gray-400">
              <th className="py-2.5 px-3 font-medium whitespace-nowrap">{t('fwz.registro.hora')}</th>
              <th className="py-2.5 px-3 font-medium whitespace-nowrap">{t('fwz.registro.regra')}</th>
              <th className="py-2.5 px-3 font-medium whitespace-nowrap">{t('fwz.registro.acao')}</th>
              <th className="py-2.5 px-3 font-medium whitespace-nowrap">{t('fwz.registro.origem')}</th>
              <th className="py-2.5 px-3 font-medium whitespace-nowrap">{t('fwz.registro.destino')}</th>
              <th className="py-2.5 px-3 font-medium whitespace-nowrap">{t('fwz.registro.proto')}</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/60">
            {loading && entradas.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-8 text-center text-gray-500">
                  {t('common.loading')}
                </td>
              </tr>
            ) : entradas.length === 0 && !erroCarga ? (
              <tr>
                <td colSpan={6} className="py-8 text-center text-gray-500">
                  {t('fwz.registro.vazio')}
                </td>
              </tr>
            ) : (
              entradas.map((e, idx) => (
                <tr key={`${e.time}-${e.src}-${e.dst}-${idx}`} className="hover:bg-gray-800/30">
                  <td className="py-2 px-3 font-mono text-gray-400 whitespace-nowrap">{e.time}</td>
                  <td className="py-2 px-3">
                    <div className="flex flex-col gap-0.5">
                      <span className="text-gray-200 font-medium">{formatRuleName(e)}</span>
                      {e.zona && (
                        <span className="text-[10px] text-gray-500 uppercase tracking-wider font-mono">
                          {e.zona}
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="py-2 px-3 whitespace-nowrap">{renderAcaoBadge(e.acao)}</td>
                  <td className="py-2 px-3 font-mono text-gray-300 whitespace-nowrap">
                    {e.src}
                    {e.sport ? `:${e.sport}` : ''}
                  </td>
                  <td className="py-2 px-3 font-mono text-gray-300 whitespace-nowrap">
                    {e.dst}
                    {e.dport ? `:${e.dport}` : ''}
                  </td>
                  <td className="py-2 px-3 font-mono text-gray-400 uppercase whitespace-nowrap">
                    {e.proto || '-'}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
