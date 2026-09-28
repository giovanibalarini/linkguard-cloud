import { useState } from 'react';
import Modal from '../../ui/Modal';
import { useI18n } from '../../../i18n';
import { errMsg } from '../../../lib/apiError';
import type { AgendamentoFW } from '../../../types/firewall';

const DIAS = ['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'] as const;
type Dia = (typeof DIAS)[number];

interface Props {
  schedule: AgendamentoFW | null;
  onSave: (data: Partial<AgendamentoFW>) => Promise<void>;
  onClose: () => void;
  canWrite: boolean;
}

export default function ScheduleEditor({ schedule, onSave, onClose, canWrite }: Props) {
  const { t } = useI18n();
  const isEditing = Boolean(schedule);

  const [nome, setNome] = useState(schedule?.nome ?? '');
  const [descricao, setDescricao] = useState(schedule?.descricao ?? '');

  // Dias selecionados
  const initialDias = schedule?.dias ? schedule.dias.split(',').filter(Boolean) as Dia[] : [];
  const [diasSelecionados, setDiasSelecionados] = useState<Dia[]>(initialDias);

  const [inicio, setInicio] = useState(schedule?.inicio ?? '08:00');
  const [fim, setFim] = useState(schedule?.fim ?? '18:00');
  const [salvando, setSalvando] = useState(false);
  const [erro, setErro] = useState('');

  const toggleDia = (dia: Dia) => {
    if (diasSelecionados.includes(dia)) {
      setDiasSelecionados(diasSelecionados.filter((d) => d !== dia));
    } else {
      setDiasSelecionados([...diasSelecionados, dia]);
    }
  };

  const setPreset = (preset: 'todos' | 'uteis' | 'fim_semana') => {
    if (preset === 'todos') {
      setDiasSelecionados([...DIAS]);
    } else if (preset === 'uteis') {
      setDiasSelecionados(['mon', 'tue', 'wed', 'thu', 'fri']);
    } else {
      setDiasSelecionados(['sat', 'sun']);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canWrite || salvando) return;

    setSalvando(true);
    setErro('');

    try {
      await onSave({
        id: schedule?.id,
        nome: nome.trim(),
        descricao: descricao.trim(),
        // Sempre na ordem da semana (seg..dom), não na ordem dos cliques.
        dias: DIAS.filter((d) => diasSelecionados.includes(d)).join(','),
        inicio,
        fim,
      });
      onClose();
    } catch (err) {
      setErro(errMsg(err, t));
    } finally {
      setSalvando(false);
    }
  };

  return (
    <Modal
      open
      onClose={onClose}
      title={isEditing ? t('fwz.agendamentos.editar') : t('fwz.agendamentos.novo')}
    >
      <form onSubmit={handleSubmit} className="space-y-4">
        {erro && (
          <div className="p-3 bg-red-500/10 border border-red-500/30 rounded text-sm text-red-400">
            {erro}
          </div>
        )}

        <div>
          <label className="block text-xs font-medium text-gray-300 mb-1">
            {t('fwz.agendamentos.nome')}
          </label>
          <input
            type="text"
            className="input w-full font-mono text-sm"
            value={nome}
            onChange={(e) => setNome(e.target.value)}
            required
            disabled={!canWrite || salvando}
            placeholder={t('fwz.agendamentos.nome_placeholder')}
          />
        </div>

        <div>
          <label className="block text-xs font-medium text-gray-300 mb-1">
            {t('fwz.agendamentos.descricao')}
          </label>
          <input
            type="text"
            className="input w-full text-sm"
            value={descricao}
            onChange={(e) => setDescricao(e.target.value)}
            disabled={!canWrite || salvando}
            placeholder={t('fwz.agendamentos.descricao_placeholder')}
          />
        </div>

        {/* Seleção de Dias */}
        <div>
          <div className="flex items-center justify-between mb-1.5">
            <label className="block text-xs font-medium text-gray-300">
              {t('fwz.agendamentos.dias')}
            </label>
            <div className="flex gap-2 text-xs">
              <button
                type="button"
                onClick={() => setPreset('uteis')}
                className="text-blue-400 hover:text-blue-300"
              >
                {t('fwz.agendamentos.dias_uteis')}
              </button>
              <span className="text-gray-600">·</span>
              <button
                type="button"
                onClick={() => setPreset('fim_semana')}
                className="text-blue-400 hover:text-blue-300"
              >
                {t('fwz.agendamentos.fim_semana')}
              </button>
              <span className="text-gray-600">·</span>
              <button
                type="button"
                onClick={() => setPreset('todos')}
                className="text-blue-400 hover:text-blue-300"
              >
                {t('fwz.agendamentos.todos_dias')}
              </button>
            </div>
          </div>
          <div className="flex gap-1.5 flex-wrap">
            {DIAS.map((dia) => {
              const ativo = diasSelecionados.includes(dia);
              return (
                <button
                  key={dia}
                  type="button"
                  onClick={() => toggleDia(dia)}
                  disabled={!canWrite || salvando}
                  className={`px-3 py-1.5 rounded text-xs font-medium border transition-colors ${
                    ativo
                      ? 'border-blue-500 bg-blue-500/20 text-blue-300'
                      : 'border-gray-800 bg-gray-900/40 text-gray-400 hover:border-gray-700'
                  }`}
                >
                  {t(`fwz.agendamentos.dia.${dia}`)}
                </button>
              );
            })}
          </div>
        </div>

        {/* Horário Início / Fim */}
        <div>
          <label className="block text-xs font-medium text-gray-300 mb-1.5">
            {t('fwz.agendamentos.horario')}
          </label>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <span className="block text-[11px] text-gray-400 mb-1">
                {t('fwz.agendamentos.inicio')}
              </span>
              <input
                type="time"
                className="input w-full font-mono text-sm"
                value={inicio}
                onChange={(e) => setInicio(e.target.value)}
                required
                disabled={!canWrite || salvando}
              />
            </div>
            <div>
              <span className="block text-[11px] text-gray-400 mb-1">
                {t('fwz.agendamentos.fim')}
              </span>
              <input
                type="time"
                className="input w-full font-mono text-sm"
                value={fim}
                onChange={(e) => setFim(e.target.value)}
                required
                disabled={!canWrite || salvando}
              />
            </div>
          </div>
        </div>

        <div className="flex justify-end gap-2 pt-3 border-t border-gray-800">
          <button
            type="button"
            onClick={onClose}
            disabled={salvando}
            className="btn-secondary"
          >
            {t('fwz.agendamentos.cancelar')}
          </button>
          <button
            type="submit"
            disabled={!canWrite || salvando}
            className="btn-primary"
          >
            {salvando ? t('fwz.editor.salvando') : t('fwz.agendamentos.salvar')}
          </button>
        </div>
      </form>
    </Modal>
  );
}
