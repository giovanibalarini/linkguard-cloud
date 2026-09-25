// Os alvos de rede: o que o LinkGuard JÁ sabe, oferecido pronto no lugar de um
// campo de texto onde se digita CIDR.
//
// POR QUE ISTO EXISTE. Para bloquear uma máquina, o admin precisava
// descobrir o IP por fora (na tela de Máquinas, ou no console da Oracle),
// copiar, voltar e digitar. O produto já conhece essa máquina pelo nome — ela
// aparece na tela de Máquinas, tem apelido —, e mesmo assim pedia o endereço.
//
// Este módulo é só a TRADUÇÃO: recebe o que a tela de Hosts
// devolve e produz uma lista única, agrupada, com o endereço que a regra vai
// usar de verdade. Nada de I/O aqui — quem busca é o componente, e é isso que
// deixa esta parte coberta por asserção.

export type TargetKind = 'host' | 'rede' | 'manual';

export interface Target {
  /** Chave estável para o React e para comparar seleção. */
  id: string;
  kind: TargetKind;
  /** O que a pessoa lê: "notebook-maria". */
  label: string;
  /** A informação de apoio: o endereço. */
  hint: string;
  /** O que vai para a regra — IP, CIDR, ou '' para "qualquer". */
  value: string;
  /** Só para hosts: se ele está na rede agora. */
  online?: boolean;
}

export interface HostLike {
  ip: string; hostname?: string; alias?: string;
  blocked?: boolean; last_seen?: string;
}

/**
 * hostName escolhe como chamar uma máquina.
 *
 * A ordem é apelido → nome da instância → IP. O apelido vem primeiro porque
 * foi o ADMIN quem o escreveu, justamente para reconhecer a máquina; o nome é o
 * que a Oracle (ou a VPN) dá a ela; o IP é o último recurso, e ainda assim
 * melhor do que uma linha em branco.
 */
export function hostName(h: HostLike): string {
  return (h.alias || '').trim() || (h.hostname || '').trim() || h.ip;
}

/** onlineRecently: visto nos últimos 10 minutos conta como "na rede agora". */
export function onlineRecently(lastSeen: string | undefined, agora: number): boolean {
  if (!lastSeen) return false;
  const t = Date.parse(lastSeen);
  if (Number.isNaN(t)) return false;
  return agora - t < 10 * 60 * 1000;
}

/**
 * buildTargets monta a lista oferecida no seletor.
 *
 * Regras de conteúdo, todas com motivo:
 *
 *  - host SEM IP fica de fora: uma regra precisa de endereço, e oferecer um
 *    item que não dá para usar é pior do que não oferecer;
 *  - a LAN inteira entra como rede, porque "bloquear tudo menos X" é um caso
 *    comum e ninguém deveria digitar o CIDR de cabeça.
 */
export function buildTargets(
  hosts: HostLike[],
  lanCidr: string,
  agora: number,
): Target[] {
  const out: Target[] = [];
  for (const h of hosts || []) {
    const ip = (h.ip || '').trim();
    if (!ip) continue;
    out.push({
      id: `host:${ip}`,
      kind: 'host',
      label: hostName(h),
      hint: ip,
      value: ip,
      online: onlineRecently(h.last_seen, agora),
    });
  }

  if ((lanCidr || '').trim()) {
    out.push({
      id: 'rede:lan',
      kind: 'rede',
      label: 'A LAN inteira',
      hint: lanCidr.trim(),
      value: lanCidr.trim(),
    });
  }

  return out;
}

/** Rótulo do grupo na lista, na ordem em que os grupos aparecem. */
export const KIND_LABEL: Record<TargetKind, string> = {
  host: 'Máquinas',
  rede: 'Redes',
  manual: 'Endereço digitado',
};

export const KIND_ORDER: TargetKind[] = ['host', 'rede', 'manual'];

/**
 * searchTargets filtra pela busca, casando por nome E por endereço.
 *
 * Os dois importam: quem lembra do nome digita "maria", quem está olhando um
 * log digita "192.168.3.47". Aparelho ONLINE vem antes do offline dentro do
 * mesmo grupo — na hora de bloquear alguém, é quase sempre alguém que está na
 * rede agora.
 */
export function searchTargets(query: string, alvos: Target[]): Target[] {
  const q = (query || '')
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .trim();

  const fold = (s: string) =>
    (s || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');

  const filtrados = q
    ? alvos.filter((t) => fold(t.label).includes(q) || fold(t.hint).includes(q) || fold(t.value).includes(q))
    : alvos.slice();

  return filtrados.sort((a, b) => {
    const ka = KIND_ORDER.indexOf(a.kind);
    const kb = KIND_ORDER.indexOf(b.kind);
    if (ka !== kb) return ka - kb;
    if (a.kind === 'host' && a.online !== b.online) return a.online ? -1 : 1;
    return 0;
  });
}

/** describeTarget: como a regra pronta se refere a este alvo, em português. */
export function describeTarget(t: Target | null, vazio = 'qualquer origem'): string {
  if (!t || !t.value) return vazio;
  if (t.kind === 'rede') return `${t.label} (${t.value})`;
  if (t.kind === 'manual') return t.value;
  return `${t.label} (${t.value})`;
}
