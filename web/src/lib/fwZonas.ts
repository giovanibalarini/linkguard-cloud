import type { Acao, AliasFW, LinhaFW, MudancaFW, Ponta, Porta, RegraFW, Zona } from '../types/firewall';

export const ZONAS: readonly Zona[] = ['flutuante', 'internet', 'vcn', 'vpn'] as const;

export const ZONA_I18N_KEYS: Record<Zona, string> = {
  flutuante: 'fwz.zona.flutuante',
  internet: 'fwz.zona.internet',
  vcn: 'fwz.zona.vcn',
  vpn: 'fwz.zona.vpn',
};

export const ACAO_I18N_KEYS: Record<Acao, string> = {
  accept: 'fwz.acao.accept',
  drop: 'fwz.acao.drop',
  reject: 'fwz.acao.reject',
};

export function nomePonta(
  p: Ponta | undefined,
  nomeResolvido: string | undefined,
  t: (key: string) => string,
): string {
  if (!p || p.kind === 'any') {
    return t('fwz.ponta.any');
  }
  if (p.kind === 'self') {
    return t('fwz.ponta.self');
  }
  if (nomeResolvido && nomeResolvido.trim()) {
    return nomeResolvido;
  }
  return p.value || '';
}

export function nomePorta(
  p: Porta | undefined,
  nomeResolvido: string | undefined,
  t: (key: string) => string,
): string {
  if (!p || p.kind === 'any') {
    return t('fwz.porta.any');
  }
  if (nomeResolvido && nomeResolvido.trim()) {
    return nomeResolvido;
  }
  return p.value || '';
}

// ---------------------------------------------------------------------------
// Seletores de ponta e de porta
// ---------------------------------------------------------------------------

export type ModoPonta = 'any' | 'self' | 'alias' | 'machine' | 'addr';
export type ModoPorta = 'any' | 'port' | 'alias' | 'service';

/** O modo que quem usa o seletor escolheu, e o valor que a escolha produziu. */
export interface EscolhaDeModo<M> {
  modo: M;
  chave: string;
}

export function chaveDoValor(v: Ponta | Porta): string {
  return `${v.kind}|${v.value ?? ''}`;
}

// O modo (Qualquer, Alias, Máquina...) sai do valor que o editor entrega, para o
// seletor nunca discordar da regra aberta. O valor sozinho não diz duas coisas:
// se um endereço veio da lista de máquinas ou foi digitado, e se uma porta veio
// da lista de serviços ou foi digitada ("8080" passa por "80" enquanto se
// digita). Nesses casos vale a escolha explícita, mas só enquanto o valor for o
// que ela produziu: qualquer outro valor (outra regra aberta) volta a mandar.
export function modoDaPonta(
  v: Ponta,
  enderecosDeMaquinas: readonly string[],
  escolha?: EscolhaDeModo<ModoPonta> | null,
): ModoPonta {
  if (escolha && escolha.chave === chaveDoValor(v)) return escolha.modo;
  if (v.kind === 'addr') {
    return v.value && enderecosDeMaquinas.includes(v.value) ? 'machine' : 'addr';
  }
  return v.kind;
}

export function modoDaPorta(
  v: Porta,
  portasDeServicos: readonly string[],
  escolha?: EscolhaDeModo<ModoPorta> | null,
): ModoPorta {
  if (escolha && escolha.chave === chaveDoValor(v)) return escolha.modo;
  if (v.kind === 'port') {
    return v.value && portasDeServicos.includes(v.value) ? 'service' : 'port';
  }
  return v.kind;
}

/**
 * Opções do seletor de alias, vindas da lista da API: os embutidos (sys:*)
 * primeiro, cada um no seu grupo, e o nome e os itens como o servidor os dá.
 */
export function opcoesDeAlias(
  aliases: readonly AliasFW[],
  tipo: AliasFW['tipo'],
  t: (key: string) => string,
) {
  const doTipo = aliases.filter((a) => a.tipo === tipo);
  return [...doTipo.filter((a) => a.embutido), ...doTipo.filter((a) => !a.embutido)].map((a) => ({
    id: a.id,
    label: a.nome,
    hint: a.itens.join(', '),
    group: t(a.embutido ? 'fwz.picker.alias.embutidos' : 'fwz.picker.alias.seus'),
  }));
}

export function podeArrastar(linha: LinhaFW): boolean {
  return linha.tipo === 'admin';
}

export function idsAposMover(
  linhas: LinhaFW[],
  de: number | string,
  para: number | string,
): string[] {
  const adminIds = linhas.filter((l) => l.tipo === 'admin').map((l) => l.regra.id);
  const fromIdx = typeof de === 'number' ? de : adminIds.indexOf(de);
  const toIdx = typeof para === 'number' ? para : adminIds.indexOf(para);

  if (fromIdx < 0 || fromIdx >= adminIds.length || toIdx < 0 || toIdx >= adminIds.length || fromIdx === toIdx) {
    return adminIds;
  }

  const result = [...adminIds];
  const [removido] = result.splice(fromIdx, 1);
  result.splice(toIdx, 0, removido);
  return result;
}

export function contarMudancas(mudancas?: MudancaFW[] | null): number {
  return mudancas ? mudancas.length : 0;
}

export function isIPv4(s: string): boolean {
  const parts = s.trim().split('.');
  if (parts.length !== 4) return false;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return false;
    const n = parseInt(part, 10);
    if (n < 0 || n > 255) return false;
    if (part.length > 1 && part.startsWith('0')) return false;
  }
  return true;
}

export function isIPv4CIDR(s: string): boolean {
  const parts = s.trim().split('/');
  if (parts.length !== 2) return false;
  if (!isIPv4(parts[0])) return false;
  if (!/^\d+$/.test(parts[1])) return false;
  const mask = parseInt(parts[1], 10);
  return mask >= 0 && mask <= 32;
}

export function isIPv4OrCIDR(s: string): boolean {
  return isIPv4(s) || isIPv4CIDR(s);
}

export function isValidPortOrRange(s: string): boolean {
  const trimmed = s.trim();
  if (!trimmed) return false;
  if (trimmed.includes('-')) {
    const parts = trimmed.split('-');
    if (parts.length !== 2) return false;
    if (!/^\d+$/.test(parts[0]) || !/^\d+$/.test(parts[1])) return false;
    const a = parseInt(parts[0], 10);
    const b = parseInt(parts[1], 10);
    return a >= 1 && b <= 65535 && a < b;
  }
  if (!/^\d+$/.test(trimmed)) return false;
  const p = parseInt(trimmed, 10);
  return p >= 1 && p <= 65535;
}

export interface FormularioErros {
  [campo: string]: string;
}

export function validarFormulario(regra: Partial<RegraFW>): FormularioErros {
  const erros: FormularioErros = {};

  if (!regra.zona || !ZONAS.includes(regra.zona)) {
    erros.zona = 'fwz.problema.zonaInvalida';
  }

  if (!regra.acao || !['accept', 'drop', 'reject'].includes(regra.acao)) {
    erros.acao = 'fwz.problema.acaoInvalida';
  }

  if (regra.proto && !['', 'tcp', 'udp', 'tcp/udp', 'icmp'].includes(regra.proto)) {
    erros.proto = 'fwz.problema.protoInvalido';
  }

  // Origem
  if (!regra.origem) {
    erros.origem = 'fwz.problema.origemTipoInvalido';
  } else if (regra.origem.kind === 'self') {
    erros.origem = 'fwz.problema.origemSelfInvalida';
  } else if (regra.origem.kind === 'addr') {
    if (!regra.origem.value || !isIPv4OrCIDR(regra.origem.value)) {
      erros.origem = 'fwz.problema.origemEnderecoInvalido';
    }
  } else if (regra.origem.kind === 'alias') {
    if (!regra.origem.value || !regra.origem.value.trim()) {
      erros.origem = 'fwz.problema.origemAliasInexistente';
    }
  }

  // Destino
  if (!regra.destino) {
    erros.destino = 'fwz.problema.destinoTipoInvalido';
  } else if (regra.destino.kind === 'addr') {
    if (!regra.destino.value || !isIPv4OrCIDR(regra.destino.value)) {
      erros.destino = 'fwz.problema.destinoEnderecoInvalido';
    }
  } else if (regra.destino.kind === 'alias') {
    if (!regra.destino.value || !regra.destino.value.trim()) {
      erros.destino = 'fwz.problema.destinoAliasInexistente';
    }
  }

  // Porta
  if (regra.porta_destino) {
    if (regra.porta_destino.kind === 'port' || regra.porta_destino.kind === 'alias') {
      const isTcpUdp = regra.proto === 'tcp' || regra.proto === 'udp' || regra.proto === 'tcp/udp';
      if (!isTcpUdp) {
        erros.porta_destino = 'fwz.problema.portaSemProtocoloValido';
      } else if (regra.porta_destino.kind === 'port') {
        if (!regra.porta_destino.value || !isValidPortOrRange(regra.porta_destino.value)) {
          erros.porta_destino = 'fwz.problema.portaValorInvalido';
        }
      } else if (regra.porta_destino.kind === 'alias') {
        if (!regra.porta_destino.value || !regra.porta_destino.value.trim()) {
          erros.porta_destino = 'fwz.problema.portaAliasInexistente';
        }
      }
    }
  }

  // Descrição
  if (regra.descricao && regra.descricao.length > 200) {
    erros.descricao = 'fwz.problema.descricaoMuitoLonga';
  }

  return erros;
}
