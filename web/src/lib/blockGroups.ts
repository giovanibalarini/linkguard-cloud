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
  /** Frase curta com o motivo; vazia quando status é `ok`. */
  reason: string;
  /** O que fazer para resolver; vazia quando status é `ok`. */
  fix: string;
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
      reason: 'Não foi possível verificar o estado dos bloqueios no firewall.',
      fix: 'Confira as regras em Firewall › Flutuantes.',
      above: [],
    };
  }
  if (!bloqueiosAplicados) {
    return {
      status: 'not_applied',
      reason: 'As regras de bloqueio do firewall ainda não foram aplicadas ou a última aplicação falhou.',
      fix: 'Aplique as pendências em Firewall › Flutuantes.',
      above: [],
    };
  }
  return { status: 'ok', reason: '', fix: '', above: [] };
}
