import { useCallback, useEffect, useState } from 'react';
import {
  Activity, AlertTriangle, ArrowDownCircle, ArrowUpCircle, Ban, Loader2,
  Pencil, Plus, RefreshCw, Trash2,
} from 'lucide-react';
import client from '../api/client';
import { useI18n } from '../i18n';
import { errMsg } from '../lib/apiError';
import {
  emptyDomainTargetForm, normalizeDomainTarget, targetPhase, validateDomainTargetForm,
  type DomainFormError, type DomainRoutingState, type DomainStage,
  type DomainTargetForm, type DomainTargetView,
} from '../lib/domainTargets';
import IconButton from './ui/IconButton';
import Modal from './ui/Modal';
import Panel from './ui/Panel';
import Tag, { type TagVariant } from './ui/Tag';

interface Props {
  canEdit: boolean;
}

const reasonKeys: Record<string, string> = {
  boot_pending: 'fwx.domains.reason.boot',
  blocking_group_missing: 'fwx.domains.reason.blockMissing',
  blocking_group_disabled: 'fwx.domains.reason.blockDisabled',
  invalid_intent: 'fwx.domains.reason.invalidIntent',
};

const validationKeys: Record<DomainFormError, string> = {
  invalid_domain: 'fwx.domains.validation.domain',
  invalid_note: 'fwx.domains.validation.note',
};

function phaseTag(target: DomainTargetView): { variant: TagVariant; key: string } {
  switch (targetPhase(target)) {
    case 'active': return { variant: 'ok', key: 'fwx.domains.phase.active' };
    case 'suspended': return { variant: 'crit', key: 'fwx.domains.phase.suspended' };
    default: return { variant: 'warn', key: 'fwx.domains.phase.trial' };
  }
}

function unixTime(value: number): string {
  if (!value) return '—';
  return new Date(value * 1000).toLocaleString();
}

export default function DomainTargets({ canEdit }: Props) {
  const { t } = useI18n();
  const [state, setState] = useState<DomainRoutingState | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [formError, setFormError] = useState('');
  const [editing, setEditing] = useState<DomainTargetView | null>(null);
  const [form, setForm] = useState<DomainTargetForm | null>(null);
  const [promotionTarget, setPromotionTarget] = useState<DomainTargetView | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<DomainTargetView | null>(null);

  const load = useCallback(async (initial = false) => {
    if (initial) setLoading(true);
    try {
      const { data } = await client.get<DomainRoutingState>('/api/domain-targets');
      setState(data);
      setError('');
    } catch (e) {
      setError(errMsg(e));
    } finally {
      if (initial) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load(true);
    const timer = setInterval(() => void load(false), 15000);
    return () => clearInterval(timer);
  }, [load]);

  const openCreate = () => {
    setEditing(null);
    setForm(emptyDomainTargetForm());
    setFormError('');
  };

  const openEdit = (target: DomainTargetView) => {
    setEditing(target);
    setForm({ domain: target.domain, note: target.note });
    setFormError('');
  };

  const saveTarget = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!form) return;
    const validation = validateDomainTargetForm(form);
    if (validation) {
      setFormError(t(validationKeys[validation]));
      return;
    }
    const payload = {
      domain: normalizeDomainTarget(form.domain)!,
      capability: 'barrar',
      note: form.note.trim(),
    };
    setBusy(true);
    setFormError('');
    try {
      const response = editing
        ? await client.put<DomainRoutingState>(`/api/domain-targets/${editing.id}`, payload)
        : await client.post<DomainRoutingState>('/api/domain-targets', payload);
      setState(response.data);
      setForm(null);
      setEditing(null);
    } catch (e) {
      setFormError(errMsg(e));
    } finally {
      setBusy(false);
    }
  };

  const requestPromotion = (target: DomainTargetView) => {
    setPromotionTarget(target);
    setError('');
  };

  const applyStage = async () => {
    if (!promotionTarget) return;
    const stage: DomainStage = promotionTarget.stage === 'ensaio' ? 'ativo' : 'ensaio';
    setBusy(true);
    try {
      const response = await client.post<DomainRoutingState>(`/api/domain-targets/${promotionTarget.id}/stage`, { stage });
      setState(response.data);
      setPromotionTarget(null);
    } catch (e) {
      setError(errMsg(e));
      setPromotionTarget(null);
    } finally {
      setBusy(false);
    }
  };

  const removeTarget = async () => {
    if (!deleteTarget) return;
    setBusy(true);
    try {
      const response = await client.delete<DomainRoutingState>(`/api/domain-targets/${deleteTarget.id}`);
      setState(response.data);
      setDeleteTarget(null);
    } catch (e) {
      setError(errMsg(e));
      setDeleteTarget(null);
    } finally {
      setBusy(false);
    }
  };

  const runtime = state?.runtime;

  return (
    <>
      <Panel
        title={(
          <span className="flex items-center gap-2">
            <Activity className="w-5 h-5 text-violet-400" />
            <span className="text-white font-semibold">{t('fwx.domains.title')}</span>
          </span>
        )}
        action={(
          <div className="flex items-center gap-2">
            <button onClick={() => void load(false)} className="btn-secondary text-xs flex items-center gap-1.5">
              <RefreshCw className="w-3.5 h-3.5" /> {t('fwx.domains.refresh')}
            </button>
            {canEdit && (
              <button onClick={openCreate} className="btn-primary text-xs flex items-center gap-1.5">
                <Plus className="w-3.5 h-3.5" /> {t('fwx.domains.add')}
              </button>
            )}
          </div>
        )}
        className="mb-1"
      >
        <p className="text-gray-500 text-xs">{t('fwx.domains.subtitle')}</p>

        <div className="mt-3 flex flex-wrap gap-2">
          <Tag variant={state?.ready ? 'ok' : 'warn'} dot>
            {state?.ready ? t('fwx.domains.ready') : t('fwx.domains.notReady')}
          </Tag>
          <Tag variant={runtime?.vivo ? 'ok' : 'crit'}>
            {runtime?.vivo ? t('fwx.domains.runtimeAlive') : t('fwx.domains.runtimeDown')}
          </Tag>
          <Tag variant={runtime?.observando === true ? 'ok' : runtime?.observando === false ? 'crit' : 'warn'}>
            {runtime?.observando === true
              ? t('fwx.domains.observing')
              : runtime?.observando === false
                ? t('fwx.domains.notObserving')
                : t('fwx.domains.observingUnknown')}
          </Tag>
          <Tag variant={runtime?.kernel_lido ? 'ok' : 'warn'}>
            {runtime?.kernel_lido ? t('fwx.domains.kernelRead') : t('fwx.domains.kernelUnknown')}
          </Tag>
          {runtime?.dry_run && <Tag variant="neutral">{t('fwx.domains.dryRun')}</Tag>}
          {!canEdit && <Tag variant="idle">{t('fwx.domains.readOnly')}</Tag>}
        </div>

        {runtime?.observando === false && (
          <div className="mt-3 flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm text-amber-300">
            <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
            <span>{t('fwx.domains.notObservingHelp')}</span>
          </div>
        )}

        {(error || state?.last_error || runtime?.kernel_erro) && (
          <div className="mt-3 flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-400">
            <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
            <span>{error || state?.last_error || runtime?.kernel_erro}</span>
          </div>
        )}

        <div className="mt-4 rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-xs text-amber-100/80">
          <p className="font-medium text-amber-300">{t('fwx.domains.caveat.title')}</p>
          <ul className="mt-2 list-disc space-y-1 pl-4">
            <li>{t('fwx.domains.caveat.cdn')}</li>
            <li>{t('fwx.domains.caveat.encryptedDns')}</li>
            <li>{t('fwx.domains.caveat.vpn')}</li>
            <li>{t('fwx.domains.caveat.fixedIp')}</li>
            <li>{t('fwx.domains.caveat.ipv6')}</li>
          </ul>
        </div>

        {loading ? (
          <div className="py-8 text-center text-gray-500 animate-pulse">{t('common.loading')}</div>
        ) : (state?.targets?.length ?? 0) === 0 ? (
          <div className="py-8 text-center text-sm text-gray-500">{t('fwx.domains.empty')}</div>
        ) : (
          <ul className="mt-4 space-y-3">
            {state!.targets.map((target) => {
              const phase = phaseTag(target);
              const mismatch = runtime?.kernel_lido && target.no_kernel !== null && target.no_kernel !== target.no_index;
              // Rotação e último aprendizado são OBSERVAÇÃO: os dois vêm do
              // dnstap. Com o coletor desligado eles são zero por construção, e
              // mostrar "0" ali afirma que ninguém acessou o nome — que é a
              // conclusão oposta da verdadeira.
              const measuring = runtime?.observando === true;
              return (
                <li key={target.id} className="rounded-xl border border-gray-800 bg-gray-950/35 p-4">
                  <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <Ban className="w-4 h-4 text-red-400" />
                        <span className="font-mono text-sm text-white break-all">{target.domain}</span>
                        <Tag variant={phase.variant}>{t(phase.key)}</Tag>
                        {/* Linha de "direcionar" vinda do linkguard-fw: aparece para ser apagada. */}
                        {target.capability !== 'barrar' && <Tag variant="idle">{t('fwx.domains.cap.route')}</Tag>}
                      </div>
                      {target.suspended && (
                        <p className="mt-2 text-xs text-red-300">
                          {t(reasonKeys[target.suspension_reason || ''] || 'fwx.domains.reason.unknown')}
                        </p>
                      )}
                      {target.note && <p className="mt-1 text-xs text-gray-500">{target.note}</p>}
                    </div>
                    {canEdit && (
                      <div className="flex shrink-0 items-center gap-1">
                        <button onClick={() => requestPromotion(target)}
                          className="btn-secondary text-xs flex items-center gap-1.5">
                          {target.stage === 'ensaio'
                            ? <ArrowUpCircle className="w-3.5 h-3.5" />
                            : <ArrowDownCircle className="w-3.5 h-3.5" />}
                          {target.stage === 'ensaio' ? t('fwx.domains.action.promote') : t('fwx.domains.action.demote')}
                        </button>
                        <IconButton icon={Pencil} onClick={() => openEdit(target)} label={t('fwx.domains.action.edit')} />
                        <IconButton icon={Trash2} onClick={() => setDeleteTarget(target)}
                          label={t('fwx.domains.action.delete')} variant="danger" />
                      </div>
                    )}
                  </div>

                  <dl className="mt-3 grid grid-cols-2 gap-x-5 gap-y-2 text-xs sm:grid-cols-3 lg:grid-cols-6">
                    <Metric label={t('fwx.domains.metric.intent')} value={target.stage} />
                    <Metric label={t('fwx.domains.metric.effective')} value={target.effective_stage} />
                    <Metric label={t('fwx.domains.metric.index')} value={String(target.no_index)} />
                    <Metric label={t('fwx.domains.metric.kernel')}
                      value={target.no_kernel === null ? '?' : String(target.no_kernel)} warn={Boolean(mismatch)} />
                    <Metric label={t('fwx.domains.metric.rotation')}
                      value={measuring
                        ? `${target.rotation}${target.rotation_truncated ? '+' : ''}`
                        : t('fwx.domains.notMeasured')}
                      warn={target.rotation_truncated || !measuring} />
                    <Metric label={t('fwx.domains.metric.lastLearned')}
                      value={measuring ? unixTime(target.last_learned) : t('fwx.domains.notMeasured')}
                      warn={!measuring} />
                  </dl>

                  {(mismatch || target.at_limit || target.overflows > 0 || target.rejected > 0 ||
                    target.rejected_own > 0 || target.no_refcount_slot > 0) && (
                    <div className="mt-3 flex flex-wrap gap-2 text-[11px]">
                      {mismatch && <Tag variant="crit">{t('fwx.domains.warn.mismatch')}</Tag>}
                      {target.at_limit && <Tag variant="warn">{t('fwx.domains.warn.limit', { limit: target.limit })}</Tag>}
                      {target.overflows > 0 && <Tag variant="warn">{t('fwx.domains.warn.overflows', { n: target.overflows })}</Tag>}
                      {target.rejected > 0 && <Tag variant="warn">{t('fwx.domains.warn.rejected', { n: target.rejected })}</Tag>}
                      {target.rejected_own > 0 && <Tag variant="crit">{t('fwx.domains.warn.rejectedOwn', { n: target.rejected_own })}</Tag>}
                      {target.no_refcount_slot > 0 && <Tag variant="warn">{t('fwx.domains.warn.refcount', { n: target.no_refcount_slot })}</Tag>}
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </Panel>

      <Modal open={form !== null} onClose={() => setForm(null)}
        title={editing ? t('fwx.domains.form.editTitle') : t('fwx.domains.form.createTitle')}
        size="md" className="rounded-xl border border-gray-800 bg-gray-900">
        {form && (
          <form onSubmit={saveTarget} className="p-6 space-y-4">
            <div>
              <label className="label">{t('fwx.domains.form.domain')}</label>
              <input className="input w-full font-mono" value={form.domain} placeholder="video.example.com"
                onChange={(event) => setForm({ ...form, domain: event.target.value })} autoFocus />
            </div>
            <div>
              <label className="label">{t('fwx.domains.form.note')}</label>
              <textarea className="input min-h-20 w-full" maxLength={500} value={form.note}
                onChange={(event) => setForm({ ...form, note: event.target.value })} />
            </div>
            <p className="text-xs text-amber-300/80">{t('fwx.domains.form.trialHelp')}</p>
            {formError && (
              <div className="rounded-lg border border-red-500/20 bg-red-500/10 px-3 py-2 text-sm text-red-400">
                {formError}
              </div>
            )}
            <div className="flex gap-3">
              <button type="submit" disabled={busy} className="btn-primary flex-1 disabled:opacity-50">
                {busy ? t('common.saving') : t('common.save')}
              </button>
              <button type="button" onClick={() => setForm(null)} className="btn-secondary flex-1">
                {t('common.cancel')}
              </button>
            </div>
          </form>
        )}
      </Modal>

      <Modal open={promotionTarget !== null} onClose={() => setPromotionTarget(null)}
        title={promotionTarget?.stage === 'ensaio' ? t('fwx.domains.promote.title') : t('fwx.domains.demote.title')}
        size="sm" className="rounded-xl border border-gray-800 bg-gray-900">
        {promotionTarget && (
          <div className="p-6 space-y-4">
            <p className="break-all font-mono text-sm text-white">{promotionTarget.domain}</p>
            <p className="text-sm text-gray-400">
              {promotionTarget.stage === 'ensaio' ? t('fwx.domains.promote.body') : t('fwx.domains.demote.body')}
            </p>
            {promotionTarget.stage === 'ensaio' && promotionTarget.suspended && (
              <p className="text-xs text-amber-300">{t('fwx.domains.promote.suspended')}</p>
            )}
            <div className="flex gap-3">
              <button onClick={() => void applyStage()} disabled={busy} className="btn-primary flex-1 disabled:opacity-50">
                {busy ? <Loader2 className="mx-auto h-4 w-4 animate-spin" /> : t('fwx.domains.promote.confirm')}
              </button>
              <button onClick={() => setPromotionTarget(null)} className="btn-secondary flex-1">
                {t('common.cancel')}
              </button>
            </div>
          </div>
        )}
      </Modal>

      <Modal open={deleteTarget !== null} onClose={() => setDeleteTarget(null)}
        title={t('fwx.domains.delete.title')} size="sm"
        className="rounded-xl border border-gray-800 bg-gray-900">
        {deleteTarget && (
          <div className="p-6 space-y-4">
            <p className="text-sm text-gray-400">{t('fwx.domains.delete.body', { domain: deleteTarget.domain })}</p>
            <div className="flex gap-3">
              <button onClick={() => void removeTarget()} disabled={busy} className="btn-danger flex-1 disabled:opacity-50">
                {t('fwx.domains.delete.confirm')}
              </button>
              <button onClick={() => setDeleteTarget(null)} className="btn-secondary flex-1">
                {t('common.cancel')}
              </button>
            </div>
          </div>
        )}
      </Modal>
    </>
  );
}

function Metric({ label, value, warn = false }: { label: string; value: string; warn?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-gray-600">{label}</dt>
      <dd className={`mt-0.5 truncate font-mono ${warn ? 'text-amber-300' : 'text-gray-300'}`}>{value}</dd>
    </div>
  );
}
