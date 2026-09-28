import assert from 'node:assert';
import {
  ACAO_I18N_KEYS,
  ZONA_I18N_KEYS,
  ZONAS,
  chaveDoValor,
  contarMudancas,
  idsAposMover,
  isIPv4,
  isIPv4CIDR,
  isValidPortOrRange,
  modoDaPonta,
  modoDaPorta,
  nomePonta,
  nomePorta,
  opcoesDeAlias,
  podeArrastar,
  validarFormulario,
} from './fwZonas.ts';
import type { AliasFW, LinhaFW, MudancaFW, RegraFW } from '../types/firewall.ts';

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

// 8. Modo do seletor de ponta: sai do valor; a escolha só desempata
const maquinas = ['192.168.1.10', '10.0.0.5'];

check(modoDaPonta({ kind: 'any' }, maquinas) === 'any', 'modo da ponta any');
check(modoDaPonta({ kind: 'self' }, maquinas) === 'self', 'modo da ponta self');
check(modoDaPonta({ kind: 'alias', value: 'sys:vcn' }, maquinas) === 'alias', 'modo da ponta alias');
check(modoDaPonta({ kind: 'addr', value: '10.0.0.5' }, maquinas) === 'machine', 'endereço de máquina conhecida é Máquina');
check(modoDaPonta({ kind: 'addr', value: '172.16.0.0/12' }, maquinas) === 'addr', 'endereço fora da lista é Endereço');
check(modoDaPonta({ kind: 'addr', value: '' }, maquinas) === 'addr', 'endereço vazio sem escolha é Endereço');
check(modoDaPonta({ kind: 'addr', value: '10.0.0.5' }, []) === 'addr', 'sem lista de máquinas o endereço é Endereço');

// o editor abre outra regra com o seletor montado: o modo acompanha o valor novo
const escolhaAntiga = { modo: 'any' as const, chave: chaveDoValor({ kind: 'any' }) };
check(modoDaPonta({ kind: 'addr', value: '172.16.0.1' }, maquinas, escolhaAntiga) === 'addr', 'escolha antiga não segura valor novo (addr)');
check(modoDaPonta({ kind: 'alias', value: 'sys:vpn' }, maquinas, escolhaAntiga) === 'alias', 'escolha antiga não segura valor novo (alias)');

// digitar um endereço que coincide com o de uma máquina não troca o campo por uma lista
const digitando = { modo: 'addr' as const, chave: chaveDoValor({ kind: 'addr', value: '10.0.0.5' }) };
check(modoDaPonta({ kind: 'addr', value: '10.0.0.5' }, maquinas, digitando) === 'addr', 'escolha Endereço vale para o valor em que foi feita');
// Máquina escolhida antes de a lista carregar continua em Máquina
const maquinaVazia = { modo: 'machine' as const, chave: chaveDoValor({ kind: 'addr', value: '' }) };
check(modoDaPonta({ kind: 'addr', value: '' }, [], maquinaVazia) === 'machine', 'Máquina sem máquinas carregadas continua em Máquina');

// 9. Modo do seletor de porta
const servicos = ['22', '80', '443'];

check(modoDaPorta({ kind: 'any' }, servicos) === 'any', 'modo da porta any');
check(modoDaPorta({ kind: 'alias', value: 'sys:gerencia' }, servicos) === 'alias', 'modo da porta alias');
check(modoDaPorta({ kind: 'port', value: '443' }, servicos) === 'service', 'porta de serviço conhecido é Serviço');
check(modoDaPorta({ kind: 'port', value: '8080' }, servicos) === 'port', 'porta fora da lista é Porta');
check(modoDaPorta({ kind: 'port', value: '8000-8080' }, servicos) === 'port', 'faixa é Porta');
check(modoDaPorta({ kind: 'port', value: '' }, servicos) === 'port', 'porta vazia sem escolha é Porta');

// digitar 8080 passa por "80", que é um serviço: o campo não vira lista no meio da digitação
const digitandoPorta = { modo: 'port' as const, chave: chaveDoValor({ kind: 'port', value: '80' }) };
check(modoDaPorta({ kind: 'port', value: '80' }, servicos, digitandoPorta) === 'port', 'escolha Porta vale para o valor em que foi feita');
check(modoDaPorta({ kind: 'port', value: '80' }, servicos, { modo: 'port', chave: 'port|8' }) === 'service', 'escolha de outro valor não segura');

// 10. Opções do seletor de alias: da API, embutidos primeiro, cada grupo no seu rótulo
const aliasApi = (id: string, tipo: AliasFW['tipo'], nome: string, itens: string[], embutido?: boolean): AliasFW => ({
  id,
  nome,
  tipo,
  descricao: '',
  itens,
  embutido,
});
const aliasesApi: AliasFW[] = [
  aliasApi('sys:vcn', 'enderecos', 'VCN', ['10.0.0.0/16', '10.1.0.0/24'], true),
  aliasApi('sys:vpn', 'enderecos', 'VPN', ['10.8.0.0/24'], true),
  aliasApi('sys:gerencia', 'portas', 'Gerência', ['22', '8080'], true),
  aliasApi('u1', 'enderecos', 'Servidores', ['10.0.1.5']),
  aliasApi('u2', 'portas', 'Web', ['80', '443']),
];
const rotulo = (k: string) => `<${k}>`;

const opEnd = opcoesDeAlias(aliasesApi, 'enderecos', rotulo);
check(opEnd.map((o) => o.id).join() === 'sys:vcn,sys:vpn,u1', 'endereços: embutidos e depois os do usuário');
check(opEnd[0].label === 'VCN' && opEnd[0].hint === '10.0.0.0/16, 10.1.0.0/24', 'embutido usa nome e itens da API');
check(opEnd[0].group === '<fwz.picker.alias.embutidos>' && opEnd[2].group === '<fwz.picker.alias.seus>', 'grupos dos aliases');
const opPorta = opcoesDeAlias(aliasesApi, 'portas', rotulo);
check(opPorta.map((o) => o.id).join() === 'sys:gerencia,u2', 'portas: só aliases de portas');
// mesmo que a API mude a ordem, o grupo dos embutidos vem primeiro (um cabeçalho por grupo)
const opInvertido = opcoesDeAlias([...aliasesApi].reverse(), 'enderecos', rotulo);
check(opInvertido[0].group === '<fwz.picker.alias.embutidos>' && opInvertido[2].group === '<fwz.picker.alias.seus>', 'embutidos primeiro em qualquer ordem');
check(opcoesDeAlias([], 'enderecos', rotulo).length === 0, 'sem aliases, sem opções');

console.log(`[fwZonas.check.ts] OK (${n} asserções passaram)`);
