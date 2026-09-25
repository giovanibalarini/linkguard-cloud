import type { Acao, LinhaFW, MudancaFW, Ponta, Porta, RegraFW, Zona } from '../types/firewall';

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
  nomeResolvido?: string,
  t?: (key: string) => string,
): string {
  if (!p || p.kind === 'any') {
    return t ? t('fwz.ponta.any') : 'Qualquer';
  }
  if (p.kind === 'self') {
    return t ? t('fwz.ponta.self') : 'Este firewall';
  }
  if (nomeResolvido && nomeResolvido.trim()) {
    return nomeResolvido;
  }
  return p.value || '';
}

export function nomePorta(
  p: Porta | undefined,
  nomeResolvido?: string,
  t?: (key: string) => string,
): string {
  if (!p || p.kind === 'any') {
    return t ? t('fwz.porta.any') : 'Qualquer';
  }
  if (nomeResolvido && nomeResolvido.trim()) {
    return nomeResolvido;
  }
  return p.value || '';
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
