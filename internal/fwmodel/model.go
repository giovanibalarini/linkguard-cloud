package fwmodel

// Zona representa uma das quatro abas/zonas de filtragem do firewall.
type Zona string

const (
	ZonaFlutuante Zona = "flutuante"
	ZonaInternet  Zona = "internet"
	ZonaVCN       Zona = "vcn"
	ZonaVPN       Zona = "vpn"
)

// Zonas lista as zonas na ordem fixa das abas.
var Zonas = []Zona{ZonaFlutuante, ZonaInternet, ZonaVCN, ZonaVPN}

// Acao define o veredito da regra no firewall.
type Acao string

const (
	AcaoAccept Acao = "accept"
	AcaoDrop   Acao = "drop"
	AcaoReject Acao = "reject"
)

// Proto define o protocolo da regra de firewall.
type Proto string

const (
	ProtoQualquer Proto = ""
	ProtoTCP      Proto = "tcp"
	ProtoUDP      Proto = "udp"
	ProtoTCPUDP   Proto = "tcp/udp"
	ProtoICMP     Proto = "icmp"
)

// PontaTipo define o tipo de origem ou destino em uma regra.
type PontaTipo string

const (
	PontaQualquer PontaTipo = "any"
	PontaEste     PontaTipo = "self"  // Válido somente em Destino
	PontaEndereco PontaTipo = "addr"  // IPv4 ou CIDR IPv4
	PontaAlias    PontaTipo = "alias" // ID de alias de endereços (inclusive embutido)
)

// Ponta representa origem ou destino em uma regra de firewall.
type Ponta struct {
	Tipo  PontaTipo `json:"kind"`
	Valor string    `json:"value,omitempty"`
}

// PortaTipo define o tipo de porta de destino da regra.
type PortaTipo string

const (
	PortaQualquer PortaTipo = "any"
	PortaValor    PortaTipo = "port"  // "443" ou "8000-8100"
	PortaAlias    PortaTipo = "alias" // ID de alias de portas
)

// Porta representa a especificação de porta de destino.
type Porta struct {
	Tipo  PortaTipo `json:"kind"`
	Valor string    `json:"value,omitempty"`
}

// Regra representa uma regra de firewall configurada pelo administrador.
type Regra struct {
	ID            string `json:"id"`
	Zona          Zona   `json:"zona"`
	Posicao       int    `json:"posicao"`
	Ativa         bool   `json:"ativa"`
	Acao          Acao   `json:"acao"`
	Proto         Proto  `json:"proto"`
	Origem        Ponta  `json:"origem"`
	Destino       Ponta  `json:"destino"`
	PortaDestino  Porta  `json:"porta_destino"`
	AgendamentoID string `json:"agendamento_id,omitempty"`
	Registrar     bool   `json:"registrar"`
	Descricao     string `json:"descricao"`
}

// AliasTipo define o tipo de itens agrupados pelo alias.
type AliasTipo string

const (
	AliasTipoEnderecos AliasTipo = "enderecos"
	AliasTipoPortas    AliasTipo = "portas"
)

// Alias representa um conjunto nomeado de endereços ou portas.
type Alias struct {
	ID        string    `json:"id"`
	Nome      string    `json:"nome"`
	Tipo      AliasTipo `json:"tipo"`
	Descricao string    `json:"descricao"`
	Itens     []string  `json:"itens"`
}

// Agendamento define uma janela de horário e dias para ativação de regras.
type Agendamento struct {
	ID        string `json:"id"`
	Nome      string `json:"nome"`
	Descricao string `json:"descricao"`
	Dias      string `json:"dias"`   // "mon,tue"; vazio = todos os dias
	Inicio    string `json:"inicio"` // "HH:MM"
	Fim       string `json:"fim"`    // "HH:MM"
}

// Encaminhamento representa uma regra de redirecionamento DNAT (NAT de entrada).
type Encaminhamento struct {
	ID           string `json:"id"`
	Nome         string `json:"nome"`
	Ativo        bool   `json:"ativo"`
	Proto        string `json:"proto"` // "tcp" | "udp"
	PortaExterna int    `json:"porta_externa"`
	IPDestino    string `json:"ip_destino"`
	PortaDestino int    `json:"porta_destino"`
	Posicao      int    `json:"posicao"`
}

// Ajustes guarda parâmetros globais de comportamento do firewall.
type Ajustes struct {
	AntiBloqueio        map[Zona]bool `json:"anti_bloqueio"` // Chaves: "vcn" e "vpn"
	RedesVCNExtras      []string      `json:"redes_vcn_extras"`
	RegistrarBloqueados bool          `json:"registrar_bloqueados"`
	RegistrarDestinos   bool          `json:"registrar_destinos"`
	RegistrarPadrao     bool          `json:"registrar_padrao"`
	ContencaoBorda      bool          `json:"contencao_borda"`
}

// Config é a árvore completa da configuração do firewall por zonas.
type Config struct {
	Formato         int              `json:"formato"` // Sempre 1
	Regras          []Regra          `json:"regras"`
	Aliases         []Alias          `json:"aliases"`
	Agendamentos    []Agendamento    `json:"agendamentos"`
	Encaminhamentos []Encaminhamento `json:"encaminhamentos"`
	Ajustes         Ajustes          `json:"ajustes"`
}

// IDs dos aliases embutidos no sistema.
const (
	AliasVCN        = "sys:vcn"
	AliasVPN        = "sys:vpn"
	AliasGerencia   = "sys:gerencia"
	AliasPessoaPref = "sys:pessoa:" // + user_id
)

// AjustesPadrao devolve a configuração padrão de ajustes do firewall:
// Anti-bloqueio ativo na VCN e inativo na VPN, com as demais opções desligadas.
func AjustesPadrao() Ajustes {
	return Ajustes{
		AntiBloqueio: map[Zona]bool{
			ZonaVCN: true,
			ZonaVPN: false,
		},
		RedesVCNExtras:      []string{},
		RegistrarBloqueados: false,
		RegistrarDestinos:   false,
		RegistrarPadrao:     false,
		ContencaoBorda:      false,
	}
}
