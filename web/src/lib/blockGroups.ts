import type { FirewallGroup, FirewallGroupKind } from '../types';

// Os dois kinds que o LinkGuard mantém — espelham
// internal/nftables/groups.go (systemGroupForwardRules).
export const KIND_BLOCKED_HOSTS = 'blocked_hosts';
export const KIND_BLOCKLIST = 'blocklist';
export const KIND_WIREGUARD_PEER = 'wireguard_peer';

// isSystemGroup é uma lista fechada dos dois kinds de sistema, nunca
// `kind !== 'admin'`: kind vazio (linhas criadas antes da coluna existir) e
// qualquer kind desconhecido contam como grupo do admin, que é o lado seguro
// — o erro caro seria travar a edição de um grupo que o admin criou. Mesma
// regra do backend.
export function isSystemGroup(kind: string): boolean {
  return kind === KIND_BLOCKED_HOSTS || kind === KIND_BLOCKLIST;
}

// A peer group has a normal chain and editable firewall rules, but its name,
// address, enabled state and lifetime are projections of VPN enrollment.
export function isWireGuardPeerGroup(kind: string): boolean {
  return kind === KIND_WIREGUARD_PEER;
}

/**
 * adminGroupsAbove é a resposta a "quem decide antes deste bloqueio?": os
 * nomes dos grupos do admin LIGADOS que estão antes de `index` na ordem de
 * avaliação (spec §2.2).
 *
 * Só grupo do admin ligado conta. Um grupo desligado não põe linha nenhuma
 * na forward, então não tem como liberar nada antes — avisar por causa dele
 * seria alarme falso. Um grupo do sistema acima de outro também não conta:
 * os dois só descartam, nunca liberam.
 *
 * Vive aqui, e não em cada tela, porque as duas telas que fazem esta
 * pergunta — o aviso de ordem na lista de grupos e o cruzamento da tela de
 * Hosts — têm que dar a MESMA resposta sobre o MESMO bloqueio. Elas já
 * tinham duas implementações separadas, e a de baixo (esta) reordenava por
 * `position` enquanto a da lista confiava na ordem que a API devolveu.
 *
 * `groups` tem que vir na ordem de avaliação (é o que `index` indexa).
 */
export function adminGroupsAbove(groups: FirewallGroup[], index: number): string[] {
  return groups
    .slice(0, Math.max(0, index))
    .filter((g) => !isSystemGroup(g.kind) && g.enabled)
    .map((g) => g.name);
}

/**
 * BlockEnforcement é a resposta honesta a "este bloqueio está mesmo em
 * vigor?".
 *
 * Existe porque, desde que os bloqueios viraram grupos reordenáveis, marcar
 * um host como bloqueado deixou de ser garantia de nada: o grupo pode estar
 * desligado, as linhas de drop podem não estar vivas na forward, ou o admin
 * pode ter arrastado o bloqueio para depois de um grupo dele que faz accept.
 * Nos três casos o painel mostraria "bloqueado" enquanto o tráfego passa —
 * exatamente a confiança falsa que este produto existe para eliminar.
 *
 *  - `unknown`  não deu para verificar (sem permissão de firewall, falha ao
 *               carregar, ou o grupo não aparece na lista). Nunca afirmar
 *               "em vigor" nem "não está em vigor" a partir daqui.
 *  - `ok`       as linhas estão vivas e nada acima delas pode liberar antes.
 *  - `off`      o grupo do sistema está desligado e o firewall confirma que
 *               as linhas não estão lá.
 *  - `not_applied` está ligado, mas o firewall não confirma as linhas na
 *               forward (reconciliação falhou ou ainda não alcançou).
 *  - `off_but_live` está desligado no painel e as linhas continuam vivas no
 *               firewall: o desligar não chegou ao nftables e o tráfego
 *               segue sendo descartado.
 *  - `shadowed` está em vigor, porém depois de grupos do admin ligados, que
 *               podem decidir (accept) antes de o pacote chegar ao bloqueio.
 */
export type BlockEnforcementStatus = 'unknown' | 'ok' | 'not_applied';

export interface BlockEnforcement {
  status: BlockEnforcementStatus;
  /** Frase curta com o motivo; vazia quando status é `ok`. */
  reason: string;
  /** O que fazer para resolver; vazia quando status é `ok`. */
  fix: string;
  above?: string[];
  group?: FirewallGroup;
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

/**
 * groupDisplayNameKey devolve a chave de tradução do nome de um grupo, ou null
 * quando o nome deve ser mostrado como está (issue #106).
 *
 * Só os dois grupos do SISTEMA têm chave. Eles são criados pela migração com o
 * nome em português gravado no banco, são mantidos pelo LinkGuard e o painel
 * não deixa renomeá-los — ou seja, o nome não é escolha de ninguém, e traduzir
 * a EXIBIÇÃO não contradiz nada que o admin tenha escrito.
 *
 * Um grupo criado pelo admin devolve null e mostra o nome dele, exatamente como
 * foi digitado. Essa é a linha que este helper existe para não deixar ninguém
 * cruzar: o casamento é pelo `kind`, NUNCA pelo nome — casar por nome faria um
 * grupo que o admin batizasse de "Hosts bloqueados" ser renomeado na tela dele.
 *
 * E o banco não é tocado. Um UPDATE na migração reescreveria dado de
 * instalações que já existem por causa de uma troca de idioma.
 */
export function groupDisplayNameKey(kind: string | undefined): string | null {
  if (!kind || !isSystemGroup(kind)) return null;
  return `fwx.systemGroup.${kind}`;
}
