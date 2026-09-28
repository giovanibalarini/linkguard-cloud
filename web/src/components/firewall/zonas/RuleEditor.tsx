import { useState, useEffect, useMemo } from 'react';
import { AlertCircle, Code, Shield, Terminal } from 'lucide-react';
import client from '../../../api/client';
import Modal from '../../ui/Modal';
import { useI18n } from '../../../i18n';
import { useUIMode } from '../../../context/UIModeContext';
import { errMsg } from '../../../lib/apiError';
import { validarFormulario } from '../../../lib/fwZonas';
import PontaPicker from './PontaPicker';
import PortaPicker from './PortaPicker';
import type {
  Acao,
  AgendamentoFW,
  AliasFW,
  LinhaNft,
  Ponta,
  Porta,
  ProblemaFW,
  Proto,
  RegraFW,
  Zona,
} from '../../../types/firewall';

interface RuleEditorProps {
  open: boolean;
  onClose: () => void;
  onSave: () => Promise<void>;
  regra?: RegraFW | null;
  zona: Zona;
  aliases: AliasFW[];
  agendamentos: AgendamentoFW[];
}

export default function RuleEditor({
  open,
  onClose,
  onSave,
  regra,
  zona,
  aliases,
  agendamentos,
}: RuleEditorProps) {
  const { t } = useI18n();
  const { isSimple } = useUIMode();

  const [acao, setAcao] = useState<Acao>('accept');
  const [proto, setProto] = useState<Proto>('');
  const [origem, setOrigem] = useState<Ponta>({ kind: 'any' });
  const [destino, setDestino] = useState<Ponta>({ kind: 'any' });
  const [portaDestino, setPortaDestino] = useState<Porta>({ kind: 'any' });
  const [agendamentoId, setAgendamentoId] = useState<string>('');
  const [registrar, setRegistrar] = useState(false);
  const [descricao, setDescricao] = useState('');
  const [ativa, setAtiva] = useState(true);

  const [erros, setErros] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [apiError, setApiError] = useState<string | null>(null);

  const [previa, setPrevia] = useState<LinhaNft[]>([]);
  const [previaProblemas, setPreviaProblemas] = useState<ProblemaFW[]>([]);

  useEffect(() => {
    if (open) {
      if (regra) {
        setAcao(regra.acao);
        setProto(regra.proto);
        setOrigem(regra.origem || { kind: 'any' });
        setDestino(regra.destino || { kind: 'any' });
        setPortaDestino(regra.porta_destino || { kind: 'any' });
        setAgendamentoId(regra.agendamento_id || '');
        setRegistrar(regra.registrar);
        setDescricao(regra.descricao || '');
        setAtiva(regra.ativa);
      } else {
        setAcao('accept');
        setProto('');
        setOrigem({ kind: 'any' });
        setDestino({ kind: 'any' });
        setPortaDestino({ kind: 'any' });
        setAgendamentoId('');
        setRegistrar(false);
        setDescricao('');
        setAtiva(true);
      }
      setErros({});
      setApiError(null);
    }
  }, [open, regra, zona]);

  const draftRegra = useMemo<Partial<RegraFW>>(() => ({
    id: regra?.id,
    zona,
    acao,
    proto,
    origem,
    destino,
    porta_destino: portaDestino,
    agendamento_id: agendamentoId || undefined,
    registrar,
    descricao,
    ativa,
  }), [regra?.id, zona, acao, proto, origem, destino, portaDestino, agendamentoId, registrar, descricao, ativa]);

  useEffect(() => {
    if (!open || isSimple) return;

    let cancelled = false;
    const fetchPrevia = async () => {
      try {
        const { data } = await client.post('/api/firewall/regras/previa', draftRegra);
        if (!cancelled) {
          setPrevia(data.nft || []);
          setPreviaProblemas(data.problemas || []);
        }
      } catch {
        // Ignora erros transitórios na prévia
      }
    };

    const timer = setTimeout(fetchPrevia, 250);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [open, isSimple, draftRegra]);

  const handleSalvar = async () => {
    const errs = validarFormulario(draftRegra);
    if (Object.keys(errs).length > 0) {
      setErros(errs);
      return;
    }

    setBusy(true);
    setApiError(null);
    try {
      if (regra?.id) {
        await client.put(`/api/firewall/regras/${regra.id}`, draftRegra);
      } else {
        await client.post('/api/firewall/regras', draftRegra);
      }
      await onSave();
      onClose();
    } catch (e) {
      setApiError(errMsg(e, t));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-blue-400" />
          <span>{regra ? t('fwz.editor.titulo_editar') : t('fwz.editor.titulo_nova')}</span>
          <span className="text-xs font-mono uppercase bg-gray-800 text-gray-300 px-2 py-0.5 rounded ml-2">
            {t(`fwz.zona.${zona}`)}
          </span>
        </div>
      }
      size="lg"
      className="bg-gray-950 border border-gray-800 rounded-xl"
    >
      <div className="p-6 space-y-4">
        {apiError && (
          <div className="p-3 rounded-lg bg-red-950/40 border border-red-500/30 text-xs text-red-300 flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{apiError}</span>
          </div>
        )}

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-gray-300">
              {t('fwz.editor.acao')}
            </label>
            <div className="grid grid-cols-3 gap-1.5 p-1 bg-gray-900 rounded-lg border border-gray-800">
              {(['accept', 'drop', 'reject'] as const).map((a) => (
                <button
                  key={a}
                  type="button"
                  onClick={() => setAcao(a)}
                  className={`py-1.5 text-xs rounded font-medium transition-colors ${
                    acao === a
                      ? a === 'accept'
                        ? 'bg-emerald-600 text-white'
                        : a === 'drop'
                        ? 'bg-rose-600 text-white'
                        : 'bg-amber-600 text-white'
                      : 'text-gray-400 hover:text-white'
                  }`}
                >
                  {t(`fwz.acao.${a}`)}
                </button>
              ))}
            </div>
            {erros.acao && <p className="text-xs text-red-400">{t(erros.acao)}</p>}
          </div>

          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-gray-300">
              {t('fwz.editor.proto')}
            </label>
            <select
              value={proto}
              onChange={(e) => setProto(e.target.value as Proto)}
              className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-white focus:outline-none focus:border-blue-500"
            >
              <option value="">{t('fwz.editor.proto_qualquer')}</option>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
              <option value="tcp/udp">TCP + UDP</option>
              <option value="icmp">ICMP (Ping)</option>
            </select>
            {erros.proto && <p className="text-xs text-red-400">{t(erros.proto)}</p>}
          </div>
        </div>

        <PontaPicker
          label={t('fwz.editor.origem')}
          value={origem}
          onChange={setOrigem}
          aliases={aliases}
          error={erros.origem ? t(erros.origem) : undefined}
        />

        <PontaPicker
          label={t('fwz.editor.destino')}
          value={destino}
          onChange={setDestino}
          isDestino={true}
          aliases={aliases}
          error={erros.destino ? t(erros.destino) : undefined}
        />

        <PortaPicker
          label={t('fwz.editor.porta_destino')}
          value={portaDestino}
          proto={proto}
          onChange={setPortaDestino}
          aliases={aliases}
          error={erros.porta_destino ? t(erros.porta_destino) : undefined}
        />

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-gray-300">
              {t('fwz.editor.agendamento')}
            </label>
            <select
              value={agendamentoId}
              onChange={(e) => setAgendamentoId(e.target.value)}
              className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-white focus:outline-none focus:border-blue-500"
            >
              <option value="">{t('fwz.editor.agendamento_sempre')}</option>
              {agendamentos.map((ag) => (
                <option key={ag.id} value={ag.id}>
                  {ag.nome} ({ag.inicio} - {ag.fim})
                </option>
              ))}
            </select>
          </div>

          <div className="flex flex-col justify-center space-y-2 pt-4">
            <label className="flex items-center gap-2 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={registrar}
                onChange={(e) => setRegistrar(e.target.checked)}
                className="w-4 h-4 rounded border-gray-700 bg-gray-900 text-blue-600 focus:ring-blue-500"
              />
              <span className="text-sm text-gray-200">{t('fwz.editor.registrar')}</span>
            </label>
            <label className="flex items-center gap-2 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={ativa}
                onChange={(e) => setAtiva(e.target.checked)}
                className="w-4 h-4 rounded border-gray-700 bg-gray-900 text-blue-600 focus:ring-blue-500"
              />
              <span className="text-sm text-gray-200">{t('fwz.editor.ativa')}</span>
            </label>
          </div>
        </div>

        <div className="space-y-1.5">
          <label className="block text-xs font-medium text-gray-300">
            {t('fwz.editor.descricao')}
          </label>
          <input
            type="text"
            value={descricao}
            maxLength={200}
            onChange={(e) => setDescricao(e.target.value)}
            placeholder={t('fwz.editor.descricao_placeholder')}
            className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
          />
          {erros.descricao && <p className="text-xs text-red-400">{t(erros.descricao)}</p>}
        </div>

        {!isSimple && (
          <div className="pt-2 border-t border-gray-800 space-y-2">
            <div className="flex items-center gap-1.5 text-xs text-gray-400">
              <Terminal className="w-3.5 h-3.5" />
              <span>{t('fwz.editor.previa_nft')}</span>
            </div>

            {previaProblemas.length > 0 && (
              <div className="p-2.5 rounded-lg bg-amber-950/20 border border-amber-500/20 text-xs text-amber-300 space-y-1">
                <span className="font-medium">{t('fwz.editor.previa_erro')}</span>
                <ul className="list-disc pl-4 space-y-0.5">
                  {previaProblemas.map((p, idx) => (
                    <li key={idx}>{t(p.chave, p.vars)}</li>
                  ))}
                </ul>
              </div>
            )}

            <div className="rounded-lg border border-gray-800 bg-gray-900/60 p-2.5 font-mono text-[11px] text-gray-300 overflow-x-auto max-h-32">
              {previa.length > 0 ? (
                previa.map((p, idx) => (
                  <div key={idx} className="whitespace-pre">
                    <span className="text-blue-400 font-semibold">{p.chain}:</span> {p.texto}
                  </div>
                ))
              ) : (
                <span className="text-gray-500 italic">—</span>
              )}
            </div>
          </div>
        )}

        <div className="flex items-center justify-end gap-2 pt-3 border-t border-gray-800">
          <button
            type="button"
            disabled={busy}
            onClick={onClose}
            className="btn-secondary text-xs px-4 py-2"
          >
            {t('fwz.editor.cancelar')}
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={handleSalvar}
            className="btn-primary text-xs px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50"
          >
            {busy ? t('fwz.editor.salvando') : t('fwz.editor.salvar')}
          </button>
        </div>
      </div>
    </Modal>
  );
}
