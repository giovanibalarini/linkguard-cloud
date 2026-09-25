import assert from 'node:assert';
import {
  ACAO_I18N_KEYS,
  ZONA_I18N_KEYS,
  ZONAS,
  contarMudancas,
  idsAposMover,
  isIPv4,
  isIPv4CIDR,
  isValidPortOrRange,
  nomePonta,
  nomePorta,
  podeArrastar,
  validarFormulario,
} from './fwZonas.ts';
import type { LinhaFW, MudancaFW, RegraFW } from '../types/firewall.ts';

let n = 0;
const check = (condition: unknown, message: string) => {
  assert.ok(condition, message);
  n++;
};

// 1. ZONAS e chaves
check(ZONAS.length === 4, 'existem 4 zonas');
check(ZONAS.includes('flutuante') && ZONAS.includes('internet') && ZONAS.includes('vcn') && ZONAS.includes('vpn'), 'zonas corretas');
check(ZONA_I18N_KEYS.internet === 'fwz.zona.internet', 'chave i18n internet');
check(ACAO_I18N_KEYS.accept === 'fwz.acao.accept', 'chave i18n acao accept');

// 2. nomePonta e nomePorta
check(nomePonta(undefined) === 'Qualquer', 'ponta indefinida é Qualquer');
check(nomePonta({ kind: 'any' }) === 'Qualquer', 'ponta any é Qualquer');
check(nomePonta({ kind: 'self' }) === 'Este firewall', 'ponta self é Este firewall');
check(nomePonta({ kind: 'alias', value: 'a1' }, 'Servidores') === 'Servidores', 'ponta com nome resolvido');
check(nomePonta({ kind: 'addr', value: '192.168.1.1' }) === '192.168.1.1', 'ponta addr');

check(nomePorta(undefined) === 'Qualquer', 'porta indefinida é Qualquer');
check(nomePorta({ kind: 'any' }) === 'Qualquer', 'porta any é Qualquer');
check(nomePorta({ kind: 'port', value: '443' }) === '443', 'porta número');
check(nomePorta({ kind: 'alias', value: 'p1' }, 'Web') === 'Web', 'porta com nome resolvido');

// 3. podeArrastar
const fakeLinha = (tipo: LinhaFW['tipo'], id: string): LinhaFW => ({
  chave: `r:${id}`,
  tipo,
  zona: 'internet',
  regra: {
    id,
    zona: 'internet',
    posicao: 1,
    ativa: true,
    acao: 'accept',
    proto: 'tcp',
    origem: { kind: 'any' },
    destino: { kind: 'self' },
    porta_destino: { kind: 'port', value: '22' },
    registrar: false,
    descricao: '',
  },
  nomes: { origem: '', destino: '', porta: '', agendamento: '' },
  contador: { pacotes: 0, bytes: 0, medido: false },
});

check(podeArrastar(fakeLinha('admin', '1')), 'admin pode arrastar');
check(!podeArrastar(fakeLinha('travada', '2')), 'travada não pode arrastar');
check(!podeArrastar(fakeLinha('padrao', '3')), 'padrao não pode arrastar');
check(!podeArrastar(fakeLinha('implicita', '4')), 'implicita não pode arrastar');

// 4. idsAposMover
const linhasMistas: LinhaFW[] = [
  fakeLinha('travada', 'lock-1'),
  fakeLinha('admin', 'adm-1'),
  fakeLinha('admin', 'adm-2'),
  fakeLinha('admin', 'adm-3'),
  fakeLinha('padrao', 'def-1'),
];

const reordenado = idsAposMover(linhasMistas, 0, 2);
check(reordenado.length === 3, 'mantém apenas regras do admin');
check(reordenado[0] === 'adm-2' && reordenado[1] === 'adm-3' && reordenado[2] === 'adm-1', 'move item de 0 para 2');

const porId = idsAposMover(linhasMistas, 'adm-3', 'adm-1');
check(porId[0] === 'adm-3' && porId[1] === 'adm-1' && porId[2] === 'adm-2', 'suporta mover por ID');

const fora = idsAposMover(linhasMistas, -1, 5);
check(fora[0] === 'adm-1' && fora[1] === 'adm-2' && fora[2] === 'adm-3', 'índices inválidos mantêm ordem');

// 5. contarMudancas
check(contarMudancas(null) === 0, 'mudanças nulas = 0');
check(contarMudancas([]) === 0, 'mudanças vazias = 0');
const fakeMudancas: MudancaFW[] = [
  { objeto: 'regra', tipo: 'criada', id: '1' },
  { objeto: 'alias', tipo: 'alterada', id: '2' },
];
check(contarMudancas(fakeMudancas) === 2, 'conta mudanças');

// 6. Validadores IPv4 e portas
check(isIPv4('1.2.3.4'), 'IPv4 válido');
check(!isIPv4('1.2.3.256'), 'IPv4 com octeto > 255 inválido');
check(!isIPv4('1.2.3'), 'IPv4 incompleto inválido');
check(isIPv4CIDR('10.0.0.0/8'), 'CIDR válido');
check(!isIPv4CIDR('10.0.0.0/33'), 'CIDR /33 inválido');
check(isValidPortOrRange('80'), 'porta 80 válida');
check(isValidPortOrRange('1-65535'), 'faixa 1-65535 válida');
check(!isValidPortOrRange('65536'), 'porta 65536 inválida');
check(!isValidPortOrRange('443-80'), 'faixa invertida inválida');

// 7. validarFormulario
const regraValida: Partial<RegraFW> = {
  zona: 'internet',
  acao: 'accept',
  proto: 'tcp',
  origem: { kind: 'any' },
  destino: { kind: 'self' },
  porta_destino: { kind: 'port', value: '443' },
  descricao: 'HTTPS',
};
check(Object.keys(validarFormulario(regraValida)).length === 0, 'regra válida sem erros');

const regraOrigemSelf: Partial<RegraFW> = {
  ...regraValida,
  origem: { kind: 'self' },
};
check(validarFormulario(regraOrigemSelf).origem === 'fwz.problema.origemSelfInvalida', 'origem self é rejeitada');

const regraPortaSemProto: Partial<RegraFW> = {
  ...regraValida,
  proto: '',
  porta_destino: { kind: 'port', value: '80' },
};
check(validarFormulario(regraPortaSemProto).porta_destino === 'fwz.problema.portaSemProtocoloValido', 'porta exige tcp/udp');

console.log(`[fwZonas.check.ts] OK (${n} asserções passaram)`);
