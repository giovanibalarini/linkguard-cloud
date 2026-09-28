export type Zona = 'flutuante' | 'internet' | 'vcn' | 'vpn';

export type Acao = 'accept' | 'drop' | 'reject';

export type Proto = '' | 'tcp' | 'udp' | 'tcp/udp' | 'icmp';

export type PontaTipo = 'any' | 'self' | 'addr' | 'alias';

export interface Ponta {
  kind: PontaTipo;
  value?: string;
}

export type PortaTipo = 'any' | 'port' | 'alias';

export interface Porta {
  kind: PortaTipo;
  value?: string;
}

export interface RegraFW {
  id: string;
  zona: Zona;
  posicao: number;
  ativa: boolean;
  acao: Acao;
  proto: Proto;
  origem: Ponta;
  destino: Ponta;
  porta_destino: Porta;
  agendamento_id?: string;
  registrar: boolean;
  descricao: string;
}

export type AliasTipo = 'enderecos' | 'portas';

export interface AliasFW {
  id: string;
  nome: string;
  tipo: AliasTipo;
  descricao: string;
  itens: string[];
  embutido?: boolean;
  usos?: number;
  usos_lista?: string[];
}

export interface AgendamentoFW {
  id: string;
  nome: string;
  descricao: string;
  dias: string; // 'mon,tue' ou vazio
  inicio: string; // 'HH:MM'
  fim: string; // 'HH:MM'
  usos?: number;
  usos_lista?: string[];
}

export interface EncaminhamentoFW {
  id: string;
  nome: string;
  ativo: boolean;
  proto: string; // 'tcp' | 'udp'
  porta_externa: number;
  ip_destino: string;
  porta_destino: number;
  posicao: number;
}

export interface AjustesFW {
  anti_bloqueio?: Record<string, boolean>;
  redes_vcn_extras?: string[];
  registrar_bloqueados: boolean;
  registrar_destinos: boolean;
  registrar_padrao?: boolean;
  contencao_borda: boolean;
}

export type LinhaTipo = 'admin' | 'travada' | 'padrao' | 'implicita';

export interface LinhaFW {
  chave: string;
  tipo: LinhaTipo;
  zona: Zona;
  regra: RegraFW;
  nomes: {
    origem: string;
    destino: string;
    porta: string;
    agendamento: string;
  };
  editar_em?: string; // 'vpn' | 'nat' | 'maquinas' | 'destinos' | 'ajustes'
  desc_chave?: string;
  desc_vars?: Record<string, string>;
  contador: {
    pacotes: number;
    bytes: number;
    medido: boolean;
  };
  mudanca?: 'nova' | 'alterada' | ''; // só nas linhas do admin com mudança pendente
  nft?: LinhaNft[];
}

export interface LinhaNft {
  chain: string;
  texto: string;
}

export type MudancaTipo = 'criada' | 'removida' | 'alterada' | 'movida';

export interface MudancaFW {
  objeto: 'regra' | 'alias' | 'agendamento' | 'encaminhamento' | 'ajustes';
  tipo: MudancaTipo;
  id: string;
  nome?: string;
  zona?: Zona;
  campos?: string[];
}

export interface ProblemaFW {
  severidade: 'erro' | 'aviso';
  onde: string;
  chave: string;
  vars?: Record<string, string>;
}

export interface PendenciasFW {
  pendente: boolean;
  mudancas: MudancaFW[];
  diff_nft: string;
  precisa_janela: boolean;
  problemas: ProblemaFW[];
}

// Um item do relatório da conversão do legado (GET /api/firewall/estado ->
// conversao). `mensagem` é a frase pronta do backend; `origem` diz de onde ela
// veio: "regra:<id>", "grupo:<id>", "politica:input", "politica:forward", "vpn".
export interface ItemRelatorioConversao {
  tipo: 'flutuante' | 'politica' | 'aviso';
  origem: string;
  mensagem: string;
  detalhes?: string;
}

export interface JanelaFW {
  id: string;
  summary: string;
  applied_by: string;
  expires_at: string;
  seconds_left: number;
  created_at: string;
  reverting: boolean;
  reverting_at?: string;
}

export interface EstadoFW {
  pendente: boolean;
  n_mudancas: number;
  janela: JanelaFW | null;
  aplicado_em: string | null;
  aplicado_por: string;
  ultimo_erro: string;
  conversao: ItemRelatorioConversao[];
  bloqueios_aplicados: boolean;
}

export interface RevisaoFW {
  id: string;
  resumo: string;
  motivo: string;
  aplicado_em: string;
  aplicado_por: string;
}

export interface RegistroFW {
  timestamp: string;
  chave?: string;
  tipo?: string;
  regra_id?: string;
  regra_nome?: string;
  zona?: string;
  in_out?: string;
  prefixo: string;
  acao: string;
  proto: string;
  origem_ip: string;
  origem_porta?: number;
  destino_ip: string;
  destino_porta?: number;
  pacotes?: number;
  bytes?: number;
  razao?: string;
}
