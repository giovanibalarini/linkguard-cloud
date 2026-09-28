import { useState, useEffect, useCallback } from 'react';
import { Info, Plus } from 'lucide-react';
import client from '../../../api/client';
import { useI18n } from '../../../i18n';
import { ZONAS } from '../../../lib/fwZonas';
import type { ConfirmOrRevert } from '../../../lib/useConfirmOrRevert';
import type {
  AgendamentoFW,
  AliasFW,
  LinhaFW,
  RegraFW,
  Zona,
} from '../../../types/firewall';
import RuleEditor from './RuleEditor';
import RulesTable from './RulesTable';

interface RulesTabProps {
  zona: Zona;
  onZonaChange: (z: Zona) => void;
  canWrite: boolean;
  editDisabled: boolean;
  onRefreshGlobal: () => Promise<void>;
  cor: ConfirmOrRevert;
}

export default function RulesTab({
  zona,
  onZonaChange,
  canWrite,
  editDisabled,
  onRefreshGlobal,
  cor,
}: RulesTabProps) {
  const { t } = useI18n();

  const [linhas, setLinhas] = useState<LinhaFW[]>([]);
  const [counts, setCounts] = useState<Record<Zona, number>>({
    flutuante: 0,
    internet: 0,
    vcn: 0,
    vpn: 0,
  });
  const [aliases, setAliases] = useState<AliasFW[]>([]);
  const [agendamentos, setAgendamentos] = useState<AgendamentoFW[]>([]);
  const [loading, setLoading] = useState(true);

  const [editorOpen, setEditorOpen] = useState(false);
  const [editingRegra, setEditingRegra] = useState<RegraFW | null>(null);

  const fetchZoneData = useCallback(async (z: Zona) => {
    setLoading(true);
    try {
      const [regrasRes, aliasesRes, agendamentosRes] = await Promise.all([
        client.get<{ zona: Zona; linhas: LinhaFW[] }>(`/api/firewall/regras?zona=${z}`),
        client.get<AliasFW[]>('/api/firewall/aliases'),
        client.get<AgendamentoFW[]>('/api/firewall/agendamentos'),
      ]);

      const currentLinhas = regrasRes.data?.linhas || [];
      setLinhas(currentLinhas);
      setAliases(aliasesRes.data || []);
      setAgendamentos(agendamentosRes.data || []);

      const adminCount = currentLinhas.filter((l) => l.tipo === 'admin').length;
      setCounts((prev) => ({ ...prev, [z]: adminCount }));
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchOtherCounts = useCallback(async (currentZone: Zona) => {
    for (const z of ZONAS) {
      if (z === currentZone) continue;
      try {
        const res = await client.get<{ linhas: LinhaFW[] }>(`/api/firewall/regras?zona=${z}`);
        const c = (res.data?.linhas || []).filter((l) => l.tipo === 'admin').length;
        setCounts((prev) => ({ ...prev, [z]: c }));
      } catch {
        // Ignora erros
      }
    }
  }, []);

  useEffect(() => {
    fetchZoneData(zona);
    fetchOtherCounts(zona);
  }, [zona, fetchZoneData, fetchOtherCounts]);

  const refreshAll = async () => {
    await fetchZoneData(zona);
    await onRefreshGlobal();
  };

  // Toda mutação de regra passa por cor.run: é ele que mostra o erro do backend
  // (a frase e os problemas, traduzidos) na faixa da página e que relê o estado
  // e as pendências. A lista da zona é desta aba, então é relida aqui - também
  // na falha, porque um 404 ou um 409 quase sempre quer dizer que a lista na
  // tela ficou velha.
  const executar = async (fn: () => Promise<unknown>) => {
    await cor.run(fn, '');
    await fetchZoneData(zona);
  };

  const handleToggle = (id: string, ativa: boolean) =>
    executar(() => client.post(`/api/firewall/regras/${id}/ativar`, { ativa }));

  const handleDuplicate = (id: string) =>
    executar(() => client.post(`/api/firewall/regras/${id}/duplicar`));

  const handleDelete = async (id: string, desc: string) => {
    if (!confirm(t('fwz.tabela.apagar.confirm', { desc: desc || id }))) return;
    await executar(() => client.delete(`/api/firewall/regras/${id}`));
  };

  const handleReorder = (ids: string[]) =>
    executar(() => client.post('/api/firewall/regras/ordem', { zona, ids }));

  const openNewRule = () => {
    setEditingRegra(null);
    setEditorOpen(true);
  };

  const openEditRule = (regra: RegraFW) => {
    setEditingRegra(regra);
    setEditorOpen(true);
  };

  return (
    <div className="space-y-4">
      {/* Sub-abas de Zonas */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 pb-2 border-b border-gray-800">
        <div className="flex items-center gap-2 overflow-x-auto">
          {ZONAS.map((z) => {
            const active = zona === z;
            return (
              <button
                key={z}
                type="button"
                onClick={() => onZonaChange(z)}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                  active
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'bg-gray-900/60 text-gray-400 hover:text-white hover:bg-gray-900'
                }`}
              >
                <span>{t(`fwz.zona.${z}`)}</span>
                <span
                  className={`text-[10px] font-mono px-1.5 py-0.2 rounded-full ${
                    active ? 'bg-blue-800 text-blue-100' : 'bg-gray-800 text-gray-400'
                  }`}
                >
                  {counts[z] || 0}
                </span>
              </button>
            );
          })}
        </div>

        {canWrite && (
          <button
            type="button"
            disabled={editDisabled || cor.busy}
            onClick={openNewRule}
            className="btn-primary text-xs flex items-center gap-1.5 py-1.5 px-3 self-start sm:self-auto bg-blue-600 hover:bg-blue-500 disabled:opacity-50"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>{t('fwz.tabela.adicionar')}</span>
          </button>
        )}
      </div>

      {/* Nota da zona atual */}
      <div className="flex items-start gap-2.5 p-3 rounded-lg bg-gray-950/40 border border-gray-800/80 text-xs text-gray-400">
        <Info className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
        <p className="leading-relaxed">{t(`fwz.zona.${zona}.nota`)}</p>
      </div>

      {/* Tabela de Regras */}
      {loading ? (
        <div className="p-8 text-center text-gray-500 text-xs animate-pulse">
          {t('common.loading')}
        </div>
      ) : (
        <RulesTable
          zona={zona}
          linhas={linhas}
          canWrite={canWrite}
          editDisabled={editDisabled}
          onEdit={openEditRule}
          onToggle={handleToggle}
          onDuplicate={handleDuplicate}
          onDelete={handleDelete}
          onReorder={handleReorder}
        />
      )}

      {/* Modal Editor de Regras */}
      <RuleEditor
        open={editorOpen}
        onClose={() => setEditorOpen(false)}
        onSave={refreshAll}
        regra={editingRegra}
        zona={zona}
        aliases={aliases}
        agendamentos={agendamentos}
      />
    </div>
  );
}
