/**
 * BlockEnforcement é a resposta honesta a "este bloqueio está mesmo em
 * vigor?".
 *
 *  - `unknown`     não deu para verificar (sem permissão de firewall, falha ao
 *                  carregar, ou o grupo não aparece na lista). Nunca afirmar
 *                  "em vigor" nem "não está em vigor" a partir daqui.
 *  - `ok`          as linhas estão vivas e nada acima delas pode liberar antes.
 *  - `not_applied` está ligado, mas o firewall não confirma as linhas
 *                  (reconciliação falhou ou ainda não alcançou).
 */
export type BlockEnforcementStatus = 'unknown' | 'ok' | 'not_applied';

export interface BlockEnforcement {
  status: BlockEnforcementStatus;
  /** Chave i18n da frase curta com o motivo; vazia quando status é `ok`. */
  reasonKey: string;
  /** Chave i18n do que fazer para resolver; vazia quando status é `ok`. */
  fixKey: string;
  above?: string[];
}

/**
 * blockEnforcement responde se as regras de bloqueio estão em vigor no firewall.
 * No firewall por zonas, os bloqueios de máquinas e destinos ficam em linhas travadas
 * no topo da aba Flutuantes, avaliadas antes de qualquer regra de zona — portanto não
 * podem mais ser sombreadas por regras de admin nem desligadas individualmente.
 */
export function blockEnforcement(
  bloqueiosAplicados: boolean | null | undefined,
): BlockEnforcement {
  if (bloqueiosAplicados === null || bloqueiosAplicados === undefined) {
    return {
      status: 'unknown',
      reasonKey: 'svc.hosts.enforcement.unknown.reason',
      fixKey: 'svc.hosts.enforcement.unknown.fix',
      above: [],
    };
  }
  if (!bloqueiosAplicados) {
    return {
      status: 'not_applied',
      reasonKey: 'svc.hosts.enforcement.notApplied.reason',
      fixKey: 'svc.hosts.enforcement.notApplied.fix',
      above: [],
    };
  }
  return { status: 'ok', reasonKey: '', fixKey: '', above: [] };
}
