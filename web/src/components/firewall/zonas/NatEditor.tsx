import { useState } from 'react';
import Modal from '../../ui/Modal';
import { useI18n } from '../../../i18n';
import { errMsg } from '../../../lib/apiError';
import type { EncaminhamentoFW } from '../../../types/firewall';

interface Props {
  enc: EncaminhamentoFW | null;
  onSave: (data: Partial<EncaminhamentoFW>) => Promise<void>;
  onClose: () => void;
  canWrite: boolean;
}

export default function NatEditor({ enc, onSave, onClose, canWrite }: Props) {
  const { t } = useI18n();
  const isEditing = Boolean(enc);

  const [nome, setNome] = useState(enc?.nome ?? '');
  const [ativo, setAtivo] = useState(enc?.ativo ?? true);
  const [proto, setProto] = useState(enc?.proto ?? 'tcp');
  const [portaExterna, setPortaExterna] = useState(enc ? String(enc.porta_externa) : '');
  const [ipDestino, setIpDestino] = useState(enc?.ip_destino ?? '');
  const [portaDestino, setPortaDestino] = useState(enc ? String(enc.porta_destino) : '');
  const [salvando, setSalvando] = useState(false);
  const [erro, setErro] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canWrite || salvando) return;

    const pExt = parseInt(portaExterna, 10);
    const pDest = parseInt(portaDestino, 10);

    if (isNaN(pExt) || pExt < 1 || pExt > 65535) {
      setErro(t('fwz.problema.encaminhamentoPortaExternaInvalida', { porta: portaExterna }));
      return;
    }
    if (isNaN(pDest) || pDest < 1 || pDest > 65535) {
      setErro(t('fwz.problema.encaminhamentoPortaDestinoInvalida', { porta: portaDestino }));
      return;
    }

    setSalvando(true);
    setErro('');

    try {
      await onSave({
        id: enc?.id,
        nome: nome.trim(),
        ativo,
        proto,
        porta_externa: pExt,
        ip_destino: ipDestino.trim(),
        porta_destino: pDest,
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
      title={isEditing ? t('fwz.nat.editar') : t('fwz.nat.novo')}
      className="bg-gray-900 border border-gray-800 rounded-xl"
    >
      <form onSubmit={handleSubmit} className="p-6 space-y-4">
        {erro && (
          <div className="p-3 bg-red-500/10 border border-red-500/30 rounded text-sm text-red-400">
            {erro}
          </div>
        )}

        <div>
          <label className="block text-xs font-medium text-gray-300 mb-1">
            {t('fwz.nat.nome')}
          </label>
          <input
            type="text"
            className="input w-full text-sm"
            value={nome}
            onChange={(e) => setNome(e.target.value)}
            required
            disabled={!canWrite || salvando}
            placeholder={t('fwz.nat.nome_placeholder')}
          />
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-xs font-medium text-gray-300 mb-1">
              {t('fwz.nat.proto')}
            </label>
            <select
              className="input w-full text-sm font-mono"
              value={proto}
              onChange={(e) => setProto(e.target.value)}
              disabled={!canWrite || salvando}
            >
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
            </select>
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-300 mb-1">
              {t('fwz.nat.porta_ext')}
            </label>
            <input
              type="number"
              min={1}
              max={65535}
              className="input w-full font-mono text-sm"
              value={portaExterna}
              onChange={(e) => {
                setPortaExterna(e.target.value);
                if (!portaDestino || portaDestino === portaExterna) {
                  setPortaDestino(e.target.value);
                }
              }}
              required
              disabled={!canWrite || salvando}
              placeholder="80, 443, 2222"
            />
          </div>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-xs font-medium text-gray-300 mb-1">
              {t('fwz.nat.ip_dest')}
            </label>
            <input
              type="text"
              className="input w-full font-mono text-sm"
              value={ipDestino}
              onChange={(e) => setIpDestino(e.target.value)}
              required
              disabled={!canWrite || salvando}
              placeholder="10.0.0.5"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-300 mb-1">
              {t('fwz.nat.porta_dest')}
            </label>
            <input
              type="number"
              min={1}
              max={65535}
              className="input w-full font-mono text-sm"
              value={portaDestino}
              onChange={(e) => setPortaDestino(e.target.value)}
              required
              disabled={!canWrite || salvando}
              placeholder="80"
            />
          </div>
        </div>

        <label className="flex items-center gap-2 text-xs text-gray-300 cursor-pointer pt-1">
          <input
            type="checkbox"
            checked={ativo}
            onChange={(e) => setAtivo(e.target.checked)}
            disabled={!canWrite || salvando}
            className="rounded border-gray-700 bg-gray-900 text-blue-500 focus:ring-0"
          />
          <span>{t('fwz.nat.ativo')}</span>
        </label>

        <p className="text-xs text-gray-500 pt-2 border-t border-gray-800">
          {t('fwz.nat.nota')}
        </p>

        <div className="flex justify-end gap-2 pt-3 border-t border-gray-800">
          <button
            type="button"
            onClick={onClose}
            disabled={salvando}
            className="btn-secondary"
          >
            {t('fwz.nat.cancelar')}
          </button>
          <button
            type="submit"
            disabled={!canWrite || salvando}
            className="btn-primary"
          >
            {salvando ? t('fwz.editor.salvando') : t('fwz.nat.salvar')}
          </button>
        </div>
      </form>
    </Modal>
  );
}
