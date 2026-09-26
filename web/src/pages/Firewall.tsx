import { useEffect, useState, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import { RefreshCw, Shield } from 'lucide-react';
import client from '../api/client';
import { useAuth } from '../context/AuthContext';
import { useI18n } from '../i18n';
import { useConfirmOrRevert } from '../lib/useConfirmOrRevert';
import { useFirewallEstado } from '../lib/useFirewallEstado';
import { ZONAS } from '../lib/fwZonas';
import ConfirmOrRevertBanner from '../components/firewall/ConfirmOrRevertBanner';
import PendingChangesBar from '../components/firewall/zonas/PendingChangesBar';
import ConversionNotice from '../components/firewall/zonas/ConversionNotice';
import RulesTab from '../components/firewall/zonas/RulesTab';
import AliasesTab from '../components/firewall/zonas/AliasesTab';
import SchedulesTab from '../components/firewall/zonas/SchedulesTab';
import NatTab from '../components/firewall/zonas/NatTab';
import DestinosTab from '../components/firewall/zonas/DestinosTab';
import FirewallLog from '../components/firewall/zonas/FirewallLog';
import HistoryTab from '../components/firewall/zonas/HistoryTab';
import AdvancedTab from '../components/firewall/zonas/AdvancedTab';
import DomainTargets from '../components/DomainTargets';
import type { MsgLevel, SystemMetrics } from '../types';
import type { PendenciasFW, Zona } from '../types/firewall';

const TABS = [
  'regras',
  'aliases',
  'agendamentos',
  'nat',
  'destinos',
  'registro',
  'historico',
  'avancado',
] as const;

type Tab = (typeof TABS)[number];

const MSG_STYLES: Record<MsgLevel, string> = {
  ok: 'border-green-500/30 bg-green-500/10 text-green-400',
  warn: 'border-amber-500/40 bg-amber-500/10 text-amber-300',
  error: 'border-red-500/30 bg-red-500/10 text-red-400',
};

function normalizeTab(v: string | null): Tab {
  if (!v) return 'regras';
  if ((TABS as readonly string[]).includes(v)) return v as Tab;
  switch (v) {
    case 'overview':
    case 'posture':
    case 'groups':
      return 'regras';
    case 'hostgroups':
      return 'aliases';
    case 'portforward':
      return 'nat';
    case 'domains':
      return 'destinos';
    case 'blocklog':
      return 'registro';
    case 'ruleset':
    case 'backups':
      return 'avancado';
    default:
      return 'regras';
  }
}

function normalizeZona(v: string | null): Zona {
  if (v && (ZONAS as readonly string[]).includes(v)) return v as Zona;
  return 'internet';
}

export default function Firewall() {
  const { can } = useAuth();
  const { t } = useI18n();
  const canRead = can('firewall.read');
  const canWrite = can('firewall.write');

  const [params, setParams] = useSearchParams();
  const [ifaces, setIfaces] = useState<string[]>([]);
  const [ruleset, setRuleset] = useState('');
  const [pendencias, setPendencias] = useState<PendenciasFW | null>(null);

  const [msg, setMsg] = useState<{ text: string; level: MsgLevel }>({ text: '', level: 'ok' });
  const notify = (text: string, level: MsgLevel = text.startsWith('Erro') ? 'error' : 'ok') =>
    setMsg({ text, level });

  const activeTab: Tab = normalizeTab(params.get('tab'));
  const activeZona: Zona = normalizeZona(params.get('zona'));

  const setActiveTab = (newTab: Tab) => {
    const next = new URLSearchParams(params);
    if (newTab === 'regras') next.delete('tab');
    else next.set('tab', newTab);
    setParams(next, { replace: true });
  };

  const setActiveZona = (newZona: Zona) => {
    const next = new URLSearchParams(params);
    if (newZona === 'internet') next.delete('zona');
    else next.set('zona', newZona);
    setParams(next, { replace: true });
  };

  const { estado, refresh: refreshEstado } = useFirewallEstado();

  const fetchPendencias = useCallback(async () => {
    if (!canRead) return;
    try {
      const { data } = await client.get<PendenciasFW>('/api/firewall/pendencias');
      setPendencias(data);
    } catch {
      setPendencias(null);
    }
  }, [canRead]);

  const fetchAuxData = useCallback(async () => {
    if (!canRead) return;
    try {
      const [sys, rs] = await Promise.all([
        client.get<SystemMetrics>('/api/system/status'),
        client.get<{ ruleset: string }>('/api/nftables/ruleset'),
      ]);
      setIfaces((sys.data?.interfaces ?? []).map((i) => i.name).filter((n) => n && n !== 'lo'));
      setRuleset(rs.data?.ruleset ?? '');
    } catch (e) {
      console.error(e);
    }
  }, [canRead]);

  const refreshAll = useCallback(async () => {
    await Promise.all([refreshEstado(), fetchPendencias(), fetchAuxData()]);
  }, [refreshEstado, fetchPendencias, fetchAuxData]);

  const cor = useConfirmOrRevert(refreshAll, notify);

  useEffect(() => {
    if (canRead) {
      refreshAll();
    }
  }, [canRead, refreshAll]);

  useEffect(() => {
    if (estado?.pendente || (estado?.n_mudancas ?? 0) > 0) {
      fetchPendencias();
    } else {
      setPendencias(null);
    }
  }, [estado?.pendente, estado?.n_mudancas, fetchPendencias]);

  if (!canRead) {
    return (
      <div className="p-6">
        <div className="card text-center py-12 text-gray-500">
          <Shield className="w-12 h-12 text-gray-700 mx-auto mb-3" />
          <p className="text-gray-400 font-medium">{t('shell.nav.accessDenied')}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      {/* Cabeçalho */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-white">{t('fwx.title')}</h1>
          <p className="text-gray-500 text-sm">{t('fwx.subtitle')}</p>
        </div>
        <div className="flex gap-2">
          <button onClick={refreshAll} className="btn-secondary flex items-center gap-2">
            <RefreshCw className="w-4 h-4" /> {t('fwx.btn.refresh')}
          </button>
        </div>
      </div>

      {/* Janela de 90s do confirmar-ou-reverter */}
      {cor.pending && (
        <ConfirmOrRevertBanner cor={cor} canWrite={canWrite} />
      )}

      {/* Barra de Mudanças Pendentes (fixa no topo de todas as abas) */}
      <PendingChangesBar
        pendencias={pendencias}
        cor={cor}
        onRefresh={refreshAll}
        canWrite={canWrite}
      />

      {/* Aviso de Conversão Automática */}
      {estado?.conversao && estado.conversao.length > 0 && (
        <ConversionNotice
          items={estado.conversao}
          onDismiss={refreshAll}
          canWrite={canWrite}
        />
      )}

      {/* Mensagem de notificação */}
      {msg.text && (
        <div className={`card border text-sm ${MSG_STYLES[msg.level]}`}>{msg.text}</div>
      )}

      {/* Navegação entre Abas Principais */}
      <div className="flex gap-2 border-b border-gray-800 overflow-x-auto">
        {TABS.map((id) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors whitespace-nowrap shrink-0 ${
              activeTab === id
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-gray-500 hover:text-gray-300'
            }`}
          >
            {t(`fwz.tab.${id}`)}
          </button>
        ))}
      </div>

      {/* Conteúdo da Aba Ativa */}
      {activeTab === 'regras' ? (
        <RulesTab
          zona={activeZona}
          onZonaChange={setActiveZona}
          canWrite={canWrite}
          editDisabled={cor.editDisabled}
          onRefreshGlobal={refreshAll}
          cor={cor}
        />
      ) : activeTab === 'aliases' ? (
        <AliasesTab canWrite={canWrite} onRefreshGlobal={refreshAll} />
      ) : activeTab === 'agendamentos' ? (
        <SchedulesTab canWrite={canWrite} onRefreshGlobal={refreshAll} />
      ) : activeTab === 'nat' ? (
        <NatTab canWrite={canWrite} onRefreshGlobal={refreshAll} />
      ) : activeTab === 'destinos' ? (
        <DestinosTab canWrite={canWrite}>
          <DomainTargets canEdit={can('firewall.write')} />
        </DestinosTab>
      ) : activeTab === 'registro' ? (
        <FirewallLog canWrite={canWrite} onMsg={notify} />
      ) : activeTab === 'historico' ? (
        <HistoryTab canWrite={canWrite} onRefreshGlobal={refreshAll} onMsg={notify} />
      ) : (
        <AdvancedTab
          ruleset={ruleset}
          canWrite={canWrite}
          onRefreshGlobal={refreshAll}
          onMsg={notify}
        />
      )}
    </div>
  );
}
