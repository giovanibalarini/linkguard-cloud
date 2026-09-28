import { useState } from 'react';
import Modal from '../../ui/Modal';
import { useI18n } from '../../../i18n';
import { errMsg } from '../../../lib/apiError';
import type { AliasFW, AliasTipo } from '../../../types/firewall';

interface Props {
  alias: AliasFW | null;
  onSave: (data: Partial<AliasFW>) => Promise<void>;
  onClose: () => void;
  canWrite: boolean;
}

export default function AliasEditor({ alias, onSave, onClose, canWrite }: Props) {
  const { t } = useI18n();
  const isEditing = Boolean(alias);

  const [nome, setNome] = useState(alias?.nome ?? '');
  const [tipo, setTipo] = useState<AliasTipo>(alias?.tipo ?? 'enderecos');
  const [descricao, setDescricao] = useState(alias?.descricao ?? '');
  const [itensTexto, setItensTexto] = useState((alias?.itens ?? []).join('\n'));
  const [salvando, setSalvando] = useState(false);
  const [erro, setErro] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canWrite || salvando) return;

    const itens = itensTexto
      .split(/[\n,]+/)
      .map((s) => s.trim())
      .filter(Boolean);

    setSalvando(true);
    setErro('');

    try {
      await onSave({
        id: alias?.id,
        nome: nome.trim(),
        tipo,
        descricao: descricao.trim(),
        itens,
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
      title={isEditing ? t('fwz.aliases.editar') : t('fwz.aliases.novo')}
    >
      <form onSubmit={handleSubmit} className="space-y-4">
        {erro && (
          <div className="p-3 bg-red-500/10 border border-red-500/30 rounded text-sm text-red-400">
            {erro}
          </div>
        )}

        <div>
          <label className="block text-xs font-medium text-gray-300 mb-1">
            {t('fwz.aliases.nome')}
          </label>
          <input
            type="text"
            className="input w-full font-mono text-sm"
            value={nome}
            onChange={(e) => setNome(e.target.value)}
            required
            disabled={!canWrite || salvando}
            placeholder={t('fwz.aliases.nome_placeholder')}
          />
        </div>

        <div>
          <label className="block text-xs font-medium text-gray-300 mb-1">
            {t('fwz.aliases.tipo')}
          </label>
          <select
            className="input w-full text-sm"
            value={tipo}
            onChange={(e) => setTipo(e.target.value as AliasTipo)}
            disabled={!canWrite || salvando || isEditing}
          >
            <option value="enderecos">{t('fwz.aliases.tipo.enderecos')}</option>
            <option value="portas">{t('fwz.aliases.tipo.portas')}</option>
          </select>
        </div>

        <div>
          <label className="block text-xs font-medium text-gray-300 mb-1">
            {t('fwz.aliases.descricao')}
          </label>
          <input
            type="text"
            className="input w-full text-sm"
            value={descricao}
            onChange={(e) => setDescricao(e.target.value)}
            disabled={!canWrite || salvando}
            placeholder={t('fwz.aliases.descricao_placeholder')}
          />
        </div>

        <div>
          <label className="block text-xs font-medium text-gray-300 mb-1">
            {t('fwz.aliases.itens')}
          </label>
          <textarea
            className="input w-full font-mono text-sm"
            rows={5}
            value={itensTexto}
            onChange={(e) => setItensTexto(e.target.value)}
            disabled={!canWrite || salvando}
            placeholder={
              tipo === 'enderecos'
                ? '192.168.1.10\n10.0.0.0/24'
                : '80\n443\n8080-8085'
            }
          />
          <p className="text-xs text-gray-500 mt-1">
            {tipo === 'enderecos'
              ? t('fwz.aliases.itens.ajuda_enderecos')
              : t('fwz.aliases.itens.ajuda_portas')}
          </p>
        </div>

        <div className="flex justify-end gap-2 pt-3 border-t border-gray-800">
          <button
            type="button"
            onClick={onClose}
            disabled={salvando}
            className="btn-secondary"
          >
            {t('fwz.aliases.cancelar')}
          </button>
          <button
            type="submit"
            disabled={!canWrite || salvando}
            className="btn-primary"
          >
            {salvando ? t('fwz.editor.salvando') : t('fwz.aliases.salvar')}
          </button>
        </div>
      </form>
    </Modal>
  );
}
