import { useCallback, useEffect, useState } from 'react';
import { Settings, Shield, Terminal, ShieldAlert, CheckCircle2 } from 'lucide-react';
import client from '../../../api/client';
import { useI18n } from '../../../i18n';
import LoadError from './LoadError';
import { errMsg } from '../../../lib/apiError';
import Panel from '../../ui/Panel';
import type { MsgLevel } from '../../../types';

interface AjustesFW {
  anti_bloqueio?: Record<string, boolean>;
  registrar_bloqueados: boolean;
  registrar_destinos: boolean;
  registrar_padrao: boolean;
  contencao_borda: boolean;
}

interface Contido {
  ip: string;
  expira_em_seg: number;
}

interface Props {
  ruleset: string;
  canWrite: boolean;
  onRefreshGlobal?: () => void;
  onMsg?: (text: string, level?: MsgLevel) => void;
}

export default function AdvancedTab({ ruleset, canWrite, onRefreshGlobal, onMsg }: Props) {
  const { t } = useI18n();

  // Estado dos ajustes
  const [ajustes, setAjustes] = useState<AjustesFW>({
    anti_bloqueio: { vcn: true, vpn: true },
    registrar_bloqueados: false,
    registrar_destinos: false,
    registrar_padrao: false,
    contencao_borda: true,
  });
  const [loadingAjustes, setLoadingAjustes] = useState(true);
  const [erroCarga, setErroCarga] = useState(false);
  const [salvandoAjustes, setSalvandoAjustes] = useState(false);

  // Estado dos contidos
  const [contidos, setContidos] = useState<Contido[]>([]);
  const [loadingContidos, setLoadingContidos] = useState(true);

  const carregarAjustes = useCallback(async () => {
    try {
      const { data } = await client.get<AjustesFW>('/api/firewall/ajustes');
      setAjustes({
        anti_bloqueio: data?.anti_bloqueio ?? { vcn: true, vpn: true },
        registrar_bloqueados: !!data?.registrar_bloqueados,
        registrar_destinos: !!data?.registrar_destinos,
        registrar_padrao: !!data?.registrar_padrao,
        contencao_borda: !!data?.contencao_borda,
      });
      setErroCarga(false);
    } catch {
      setErroCarga(true);
    } finally {
      setLoadingAjustes(false);
    }
  }, []);

  const carregarContidos = useCallback(async () => {
    try {
      const { data } = await client.get<{ contidos: Contido[] }>('/api/nftables/abusers');
      setContidos(data?.contidos ?? []);
    } catch {
      // silencioso
    } finally {
      setLoadingContidos(false);
    }
  }, []);

  useEffect(() => {
    carregarAjustes();
    carregarContidos();
  }, [carregarAjustes, carregarContidos]);

  const handleSalvarAjustes = async () => {
    if (!canWrite || erroCarga) return;
    setSalvandoAjustes(true);
    try {
      await client.put('/api/firewall/ajustes', ajustes);
      onMsg?.(t('fwz.avancado.sucesso'), 'ok');
      onRefreshGlobal?.();
    } catch (err) {
      onMsg?.(errMsg(err, t), 'error');
    } finally {
      setSalvandoAjustes(false);
    }
  };

  const handleLiberarContido = async (ip: string) => {
    if (!canWrite) return;
    try {
      await client.delete('/api/nftables/abusers', { data: { ip } });
      carregarContidos();
      onMsg?.(t('fwz.avancado.contidos.liberado', { ip }), 'ok');
    } catch (err) {
      onMsg?.(errMsg(err, t), 'error');
    }
  };

  return (
    <div className="space-y-6">
      {erroCarga && <LoadError onRetry={() => carregarAjustes()} />}
      {/* 1. Ajustes do Firewall */}
      <Panel
        title={
          <div className="flex items-center gap-2">
            <Settings className="w-5 h-5 text-blue-400" />
            <span className="text-white font-semibold">{t('fwz.avancado.ajustes_titulo')}</span>
          </div>
        }
      >
        {loadingAjustes ? (
          <div className="py-6 text-center text-xs text-gray-500">{t('common.loading')}</div>
        ) : (
          <div className="space-y-6">
            {/* Anti-bloqueio */}
            <div className="space-y-3">
              <h4 className="text-sm font-semibold text-gray-200">{t('fwz.avancado.anti_bloqueio')}</h4>
              <p className="text-xs text-gray-400">{t('fwz.avancado.anti_bloqueio.ajuda')}</p>
              <div className="space-y-2">
                <label className="flex items-center gap-2.5 text-xs text-gray-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={ajustes.anti_bloqueio?.vcn ?? true}
                    onChange={(e) =>
                      setAjustes({
                        ...ajustes,
                        anti_bloqueio: { ...ajustes.anti_bloqueio, vcn: e.target.checked },
                      })
                    }
                    disabled={!canWrite}
                    className="rounded border-gray-700 bg-gray-800 text-blue-500 focus:ring-0"
                  />
                  <span>{t('fwz.avancado.anti_bloqueio.vcn')}</span>
                </label>
                <label className="flex items-center gap-2.5 text-xs text-gray-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={ajustes.anti_bloqueio?.vpn ?? true}
                    onChange={(e) =>
                      setAjustes({
                        ...ajustes,
                        anti_bloqueio: { ...ajustes.anti_bloqueio, vpn: e.target.checked },
                      })
                    }
                    disabled={!canWrite}
                    className="rounded border-gray-700 bg-gray-800 text-blue-500 focus:ring-0"
                  />
                  <span>{t('fwz.avancado.anti_bloqueio.vpn')}</span>
                </label>
              </div>
            </div>

            {/* Contenção de borda */}
            <div className="space-y-2 border-t border-gray-800/80 pt-4">
              <h4 className="text-sm font-semibold text-gray-200">{t('fwz.avancado.contencao')}</h4>
              <p className="text-xs text-gray-400">{t('fwz.avancado.contencao.ajuda')}</p>
              <label className="flex items-center gap-2.5 text-xs text-gray-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={ajustes.contencao_borda}
                  onChange={(e) => setAjustes({ ...ajustes, contencao_borda: e.target.checked })}
                  disabled={!canWrite}
                  className="rounded border-gray-700 bg-gray-800 text-blue-500 focus:ring-0"
                />
                <span>{t('fwz.avancado.contencao')}</span>
              </label>
            </div>

            {/* Registro de descartes padrão */}
            <div className="space-y-2 border-t border-gray-800/80 pt-4">
              <h4 className="text-sm font-semibold text-gray-200">{t('fwz.tab.registro')}</h4>
              <div className="space-y-2">
                <label className="flex items-center gap-2.5 text-xs text-gray-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={ajustes.registrar_padrao}
                    onChange={(e) => setAjustes({ ...ajustes, registrar_padrao: e.target.checked })}
                    disabled={!canWrite}
                    className="rounded border-gray-700 bg-gray-800 text-blue-500 focus:ring-0"
                  />
                  <span>{t('fwz.avancado.registrar_padrao')}</span>
                </label>
                <label className="flex items-center gap-2.5 text-xs text-gray-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={ajustes.registrar_bloqueados}
                    onChange={(e) => setAjustes({ ...ajustes, registrar_bloqueados: e.target.checked })}
                    disabled={!canWrite}
                    className="rounded border-gray-700 bg-gray-800 text-blue-500 focus:ring-0"
                  />
                  <span>{t('fwz.avancado.registrar_bloqueados')}</span>
                </label>
                <label className="flex items-center gap-2.5 text-xs text-gray-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={ajustes.registrar_destinos}
                    onChange={(e) => setAjustes({ ...ajustes, registrar_destinos: e.target.checked })}
                    disabled={!canWrite}
                    className="rounded border-gray-700 bg-gray-800 text-blue-500 focus:ring-0"
                  />
                  <span>{t('fwz.avancado.registrar_destinos')}</span>
                </label>
              </div>
            </div>

            {canWrite && (
              <div className="pt-2">
                <button
                  onClick={handleSalvarAjustes}
                  disabled={salvandoAjustes || erroCarga}
                  className="btn-primary flex items-center gap-2 text-xs py-2 px-4"
                >
                  <CheckCircle2 className="w-4 h-4" />
                  <span>{salvandoAjustes ? t('fwz.avancado.salvando') : t('fwz.avancado.salvar')}</span>
                </button>
                {erroCarga && (
                  <p className="text-xs text-red-300 mt-2">{t('fwz.carga.salvar_bloqueado')}</p>
                )}
              </div>
            )}
          </div>
        )}
      </Panel>

      {/* 2. Cartão de Contidos (Abusers) */}
      <Panel
        title={
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-amber-400" />
            <span className="text-white font-semibold">{t('fwz.avancado.contidos.titulo')}</span>
          </div>
        }
      >
        {loadingContidos ? (
          <div className="py-4 text-center text-xs text-gray-500">{t('common.loading')}</div>
        ) : contidos.length === 0 ? (
          <p className="text-xs text-gray-500 py-2">{t('fwz.avancado.contidos.vazio')}</p>
        ) : (
          <ul className="space-y-2">
            {contidos.map((c) => (
              <li key={c.ip} className="flex items-center justify-between gap-3 text-xs border-b border-gray-800 pb-2">
                <span className="font-mono text-gray-200">{c.ip}</span>
                <span className="flex items-center gap-3">
                  <span className="text-gray-500">
                    {t('fwz.avancado.contidos.expira', { min: Math.max(1, Math.round(c.expira_em_seg / 60)) })}
                  </span>
                  {canWrite && (
                    <button
                      onClick={() => handleLiberarContido(c.ip)}
                      className="text-blue-400 hover:text-blue-300 font-medium"
                    >
                      {t('fwz.avancado.contidos.liberar')}
                    </button>
                  )}
                </span>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      {/* 3. Ruleset Viewer */}
      <Panel
        title={
          <div className="flex items-center gap-2">
            <Terminal className="w-5 h-5 text-gray-400" />
            <span className="text-white font-semibold">{t('fwz.avancado.ruleset.titulo')}</span>
          </div>
        }
      >
        <div className="rounded-lg border border-gray-800 bg-gray-950/80 overflow-hidden">
          <div className="px-3 py-1.5 border-b border-gray-800 bg-gray-900/60 flex items-center gap-2 text-[11px] text-gray-400 font-mono">
            <Terminal className="w-3.5 h-3.5" />
            <span>nft list ruleset</span>
          </div>
          {ruleset?.trim() ? (
            <pre className="p-4 overflow-x-auto text-[11px] font-mono text-gray-300 leading-relaxed whitespace-pre max-h-[500px]">
              {ruleset}
            </pre>
          ) : (
            <p className="p-8 text-center text-gray-600 text-xs">{t('fwz.avancado.ruleset.vazio')}</p>
          )}
        </div>
      </Panel>
    </div>
  );
}
