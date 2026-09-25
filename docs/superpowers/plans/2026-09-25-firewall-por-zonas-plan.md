# Firewall por zonas (no jeito do pfSense) — Plano de implementação

> **Para quem vai executar este plano (agente de código):** siga as tarefas na ordem (T1 → T14),
> uma de cada vez. Cada tarefa tem arquivos, passos em checkbox (`- [ ]`), critérios de aceite e os
> comandos que precisam passar. Faça **um commit por tarefa** num ramo próprio. Onde este plano
> disser "decisão fixa", não reabra a discussão: foi escolha do dono do produto. Onde algo não
> estiver dito, prefira o comportamento que já existe no código e anote a dúvida no fim do commit.

**Repositório:** `~/Documentos/Projetos/gbtech/repos/linkguard-cloud` (Go + SQLite + React/Vite).
**Ramo:** crie `feat/firewall-zonas` a partir de `main`. **Nunca** faça push para `main` — o push
em `main` dispara o workflow de release e publica um `.deb`.

**Objetivo:** trocar o modelo atual de regras (grupos de regras ordenados, cada grupo uma chain
`grp_*`, com escopo entrada/passagem, política por chain e grupos de hosts que só a VPN usa) por um
modelo no jeito do pfSense: **uma aba por zona** (Flutuantes, Internet, VCN, VPN), **regras em
tabela lida de cima para baixo**, **aliases** no lugar de endereços soltos, **agendamentos com
nome**, uma caixa **"registrar"** por regra, e um botão **"Aplicar mudanças"** que mostra as
diferenças, testa com `nft -c` e troca tudo de uma vez — mantendo a janela de 90 s de
confirmar-ou-reverter quando a mudança mexe no acesso à própria máquina.

**Arquitetura em um parágrafo:** um pacote folha novo, `internal/fwmodel`, define a configuração do
firewall (regras, aliases, agendamentos, encaminhamentos de porta, ajustes), sua validação, sua
forma canônica em JSON e o cálculo de diferenças. O banco guarda **duas** versões dessa
configuração: a **em edição** (tabelas `fw_*`) e a **aplicada** (`fw_aplicado`, um JSON). O
`internal/nftables` ganha um renderizador puro, `RenderZonas(config, insumos)`, que produz **um
único script** `nft -f` (sets dos aliases, 8 chains de zona, `input` e `forward` como
despachantes, limpeza do legado). O `internal/firewallrules` passa a orquestrar
Aplicar/Descartar/janela/reversão sobre esse script. As regras que outras telas geram (VPN por
pessoa, encaminhamento de porta, bloqueios, WireGuard) **não são guardadas como regras**: são
**linhas travadas derivadas** na hora de renderizar, a partir de "insumos" (perfis da VPN,
encaminhamentos, portas de gerência, redes da VCN).

**Stack:** Go 1.26 (`go.mod`), toolchain local em `~/.local/go/bin/go`, `goimports` em
`~/go/bin/goimports`; React 19 + TypeScript + Vite; i18n em YAML (`web/src/i18n/strings/*.yaml`,
gerado por `npm run i18n:gen`); checagens de lógica do painel em `*.check.ts` (`npm run check`).
**Nenhuma dependência nova** (nem Go nem npm). Arrastar-e-soltar continua com eventos HTML5
nativos, como já é feito em `FirewallGroups.tsx`.

---

## 0. Decisões fixas (checklist marcado pelo dono em 25/09/2026)

| # | Pergunta | Decisão |
|---|---|---|
| 1 | Como separar as abas | **Por zona**: Flutuantes, Internet, VCN, VPN. A zona é descoberta pela **origem** do tráfego. |
| 2 | Quando a regra passa a valer | **Botão "Aplicar mudanças"**: edita várias, vê as diferenças, aplica tudo de uma vez testado com `nft -c`. "Descartar" volta ao que está valendo. |
| 3 | Onde se define o que cada pessoa da VPN alcança | **Continua no perfil da tela da VPN**; as regras aparecem **travadas** na aba VPN e passam pelo mesmo pipeline de aplicar (teste `nft -c`, troca atômica, janela). |
| 4 | Grupos de hosts | **Viram aliases**, usáveis em qualquer regra e nos perfis da VPN. Os grupos existentes são convertidos **com o mesmo nome e o mesmo ID**. |
| 5 | Regras e grupos que já existem | **Converter automaticamente.** Cada regra vai para a aba da sua origem; o que não tiver origem clara vai para **Flutuantes, desativado**, para revisão. |
| 6 | Padrões das zonas | Internet **bloqueia**; VCN **libera para a Internet e bloqueia para a própria máquina**; VPN **bloqueia** (cada pessoa ganha o que o perfil dela diz). |
| 7 | Horários | **Agendamentos com nome**, escolhidos em cada regra. |
| 8 | Registro | **Caixa "registrar" em cada regra**; os registros aparecem no Registro com o nome da regra, com limite de taxa. |

Também decidido na proposta (e portanto dentro do escopo):
- Destino **"Este firewall"** vira regra de **entrada** (chain `zona_<z>_in`); destino **qualquer**
  vale para entrada **e** passagem; outro destino vira regra de **passagem** (`zona_<z>_fwd`).
  Some a escolha de "escopo" que hoje mora no grupo.
- **Hosts bloqueados** e **destinos bloqueados** viram **linhas travadas no topo de Flutuantes**.
- **Encaminhamento de portas** vai para **Firewall › NAT** e cria a regra da aba Internet junto
  (linha travada derivada), como no pfSense.
- Ficam iguais: a tabela `inet linkguard`, o teste com `nft -c`, a auditoria de cada mudança e a
  janela de 90 s.
- **Fica para depois** (não implementar): IPv6 nas regras; NAT de saída manual (o masquerade
  automático continua e aparece só para leitura); separadores e comentários entre regras; regras
  flutuantes por direção; aliases dentro de aliases; porta de origem; negação ("tudo menos");
  vários intervalos por agendamento; UDP nos perfis da VPN.

Defeitos que o desenho novo precisa corrigir (achados no código atual; cada um vira critério de
aceite em alguma tarefa):
1. **Pessoa restrita da VPN alcança SSH e painel** quando a entrada está em "bloquear" (as regras
   de sobrevivência liberam gerência para qualquer origem). → No novo, gerência só entra onde há
   regra (anti-bloqueio por zona escolhida, ou regra do admin).
2. **Quem tem acesso total na VPN perde a Internet** com a passagem em "bloquear". → "Acesso total"
   vira linha travada explícita de **liberar**.
3. **Pessoas da VPN perdem o DNS** com a entrada em "bloquear" (a regra de DNS só aceita as sub-redes
   da VCN). → Linha travada "DNS para quem está na VPN" na aba VPN.
4. **Editar um grupo de hosts não chega ao firewall** (só a VPN reconcilia o banco). → Alias é set
   do nft; o Aplicar troca os elementos.
5. **A VPN grava regras sem `nft -c` e sem janela** (`internal/wireguard/service.go` escreve direto
   em `firewall_groups`/`firewall_rules`). → A VPN deixa de escrever regras; toda mudança de perfil
   passa pelo pipeline de aplicar.
6. **Encaminhamento de porta sem interface sequestra a saída da VCN** (achado ao escrever este
   plano). `dnatRule` (`internal/nftables/service.go:904`) gera `tcp dport 443 dnat ip to …` sem
   `iifname` quando a interface fica vazia — e na nuvem só há uma placa. O gancho `prerouting` vê
   **todo** pacote que entra, inclusive o de uma máquina da VCN indo para a Internet na porta 443:
   ele seria desviado para o destino do encaminhamento. → O DNAT passa a casar só o que é
   endereçado à própria máquina (`fib daddr type local`) e sai no mesmo script atômico do filtro.
   Também deixa de acontecer de o DNAT não ser reaplicado no boot (hoje só volta pelo
   `/etc/nftables.conf`).

---

## 1. Regras de trabalho (valem para todas as tarefas)

- **Comandos que precisam passar ao fim de cada tarefa** (salvo quando a tarefa disser que ainda
  pode haver quebra intermediária — e mesmo aí, no commit final da tarefa, tudo verde):
  ```bash
  cd ~/Documentos/Projetos/gbtech/repos/linkguard-cloud
  ~/.local/go/bin/gofmt -l ./cmd ./internal          # não pode listar nada
  ~/.local/go/bin/go vet ./...
  ~/.local/go/bin/go test ./...
  cd web && npm run check && npm run build            # só nas tarefas que tocam o painel
  ```
- **Textos do painel moram no YAML** (`web/src/i18n/strings/*.yaml`, com `pt` e `en`), **nunca
  cravados no TSX**. O gerador (`scripts/gen-i18n.mjs`) falha com chave repetida entre arquivos,
  idioma faltando ou `{placeholder}` diferente entre idiomas. Palavras-chave do nft (accept, drop,
  chain, nomes de chain) não se traduzem.
- **Comentários em português**, no estilo do código em volta: explicam o **porquê** (o defeito que
  evitam, a medição que os justifica), não o quê.
- **Não mexa** nas migrações 1–102 (`internal/storage/storage.go`). Tabelas novas vão em
  migrações numeradas a partir de **103**. O teste `TestSchemaMigrationsAreOrderedAndUnique`
  (`internal/storage/migration_runner_internal_test.go`) guarda a ordem.
- `internal/nftables` **não pode importar** `internal/storage`. `internal/fwmodel` é **folha**
  (só biblioteca padrão) e pode ser importado por `storage`, `nftables`, `firewallrules`,
  `handlers` e `backup`.
- Cada arquivo de `internal/api/handlers` tem limite de **6 imports internos**
  (`boundary_test.go`, `maxInternalImportsPerFile`). Divida arquivos se precisar.
- **Nada de produção, nada de nuvem.** Não instale em máquina nenhuma, não crie VM, não rode
  Terraform, não toque no repositório `gbtech-oci`. A validação em máquina real (§6) é feita
  depois, por outra pessoa, numa VM descartável da OCI.
- Testes que precisariam do `nft` de verdade (`nft -c` exige netlink/root) devem **pular** quando
  o binário não existir ou não houver permissão (`t.Skip`). A estação de desenvolvimento não tem
  `nft` instalado. A lógica se prova com renderização determinística + goldens + executores
  falsos (os que já existem em `internal/nftables/*_test.go`: `fakeReconcileExec`,
  `execGravador`, `recordExec`).
- Goldens novos seguem o padrão de `internal/nftables/zonas_golden_test.go` (flag `-update`,
  falha vermelha quando reescreve).

---

## 2. O modelo novo

### 2.1 Zonas e como o tráfego é classificado

A máquina tem **uma placa** (ex.: `ens3`, "hairpin") mais a interface WireGuard **`linkguard`**.
A zona é decidida pela **origem**, nesta ordem (a primeira que casar vence):

| Ordem | Zona | Casamento no nft | Observação |
|---|---|---|---|
| 1 | **VPN** | `iifname "linkguard"` | Vem antes da VCN porque a sub-rede da VPN (padrão `10.7.0.0/24`) está dentro de `10.0.0.0/8`, que faz parte do alias VCN. |
| 2 | **VCN** | `ip saddr @fwa_vcn` | Alias embutido "VCN" (§2.3). |
| 3 | **Internet** | (resto) | Tudo que não é VPN nem VCN. IPv6 cai aqui (IPv6 nas regras fica para depois). |

**Flutuantes** não é origem: suas regras são avaliadas **antes** das abas de zona, para todo
tráfego. Regra flutuante que casa decide (liberar/bloquear é final); se nenhuma casar, o pacote
segue para a aba da sua zona.

Fato medido que condiciona o alias VCN: **a OCI não informa o bloco CIDR da VCN** — o IMDS dá só
o `subnetCidrBlock` de cada VNIC (`internal/platform/imds.go`, e o comentário em
`internal/nftables/reconcile.go:156-158`). Por isso o produto já trata como "local", em hairpin,
as sub-redes das VNICs **mais todo o RFC1918** (`redesLocais`, `cmd/linkguard-cloud/platform.go:67`).
O alias VCN é exatamente essa lista **mais** as redes extras que o admin cadastrar (§2.3).

### 2.2 Regra (campos)

| Campo | Valores | Observação |
|---|---|---|
| zona | `flutuante` \| `internet` \| `vcn` \| `vpn` | |
| posição | inteiro, **por zona** | (hoje a posição é global entre grupos; no novo é por zona) |
| ativa | bool | |
| ação | `accept` \| `drop` \| `reject` | tela: liberar / bloquear / rejeitar |
| protocolo | `""` (qualquer) \| `tcp` \| `udp` \| `tcp/udp` \| `icmp` | |
| origem | `{kind: any}` \| `{kind: addr, value: IPv4 ou CIDR}` \| `{kind: alias, value: <id>}` | `self` não vale como origem |
| destino | `{kind: any}` \| `{kind: self}` \| `{kind: addr, value}` \| `{kind: alias, value: <id>}` | `self` = "Este firewall" |
| porta de destino | `{kind: any}` \| `{kind: port, value: "443" ou "8000-8100"}` \| `{kind: alias, value: <id de alias de portas>}` | só com tcp, udp ou tcp/udp |
| agendamento | `""` (sempre) ou id de agendamento | |
| registrar | bool | |
| descrição | texto até 200 caracteres | |

**Para onde a regra vai no nft** (decisão fixa):
- destino `self` → só `zona_<z>_in`;
- destino `any` → `zona_<z>_in` **e** `zona_<z>_fwd` (qualquer destino inclui a própria máquina);
- destino `addr`/`alias` → só `zona_<z>_fwd` (para mirar a própria máquina, use "Este firewall").

Como o despachante aceita `ct state established,related` antes das zonas (§2.7), **toda regra de
zona só vê conexões novas** — o `ct state new` que hoje é opção do grupo deixa de existir.

### 2.3 Aliases

Dois tipos: **`enderecos`** (IPv4 e CIDR misturados) e **`portas`** (porta ou faixa). Cada alias
do usuário vira um **set nomeado** do nft; mudar o alias muda todas as regras que o usam.

| Alias | Tipo | ID fixo | Set no nft | Conteúdo | Editável |
|---|---|---|---|---|---|
| **VCN** | endereços | `sys:vcn` | `fwa_vcn` | `redesLocais(plat)` + `Ajustes.RedesVCNExtras` | só as redes extras |
| **VPN** | endereços | `sys:vpn` | `fwa_vpn` | a rede do túnel (`prefix.Masked()` do endereço do servidor WG); vazio com VPN desligada | não |
| **Gerência** | portas | `sys:gerencia` | `fwp_gerencia` | portas SSH (`system.SSHPorts`, 22 se vazio) + porta do painel (`cfg.Port`) + `cfg.ExtraPorts` | não |
| **pessoa: \<usuário\>** | endereços | `sys:pessoa:<user_id>` | (inline, `/32`) | endereço do peer | não |
| aliases do admin | endereços ou portas | UUID | `fwa_<12 hex>` / `fwp_<12 hex>` | itens digitados | sim |

- Nome do set do usuário: `fwa_` (endereços) ou `fwp_` (portas) + os **12 primeiros hex do UUID
  sem traços**. Se dois aliases colidirem nos 12 hex, o renderizador **devolve erro** (não
  inventa sufixo).
- Itens de endereço são **normalizados** ao salvar: IP solto vira `/32` só na hora de renderizar
  (guardar como o admin digitou, mas **com a máscara aplicada**: `10.0.1.7/24` vira `10.0.1.0/24`
  — hoje `NormalizeHosts` guarda sem mascarar, o que é um dos defeitos achados).
- Ao renderizar, os elementos saem **ordenados** e com **prefixos contidos em outros removidos**
  (ex.: `10.0.0.0/24` some se `10.0.0.0/8` está na lista), para o script ser determinístico e
  para não depender do `auto-merge` do kernel.
- Set vazio é válido (a regra que o usa simplesmente nunca casa); nesse caso **não** emitir
  `add element` (o nft recusa `{ }`).
- Nome do alias: 1 a 64 caracteres, único sem diferenciar maiúsculas; reservados: `VCN`, `VPN`,
  `Gerência`, `Este firewall` e qualquer nome começando com `sys:`.
- Apagar alias em uso (por regra, pelo alias VCN… ou por perfil da VPN) é **recusado** (409) com a
  lista de quem usa.

### 2.4 Agendamentos

Tabela própria, com nome. Campos: nome, descrição, dias (`mon,tue,…`, vazio = todos), início e fim
`HH:MM` (hora local da máquina; faixa que cruza a meia-noite vale). A renderização reaproveita
`nftables.Schedule.Tokens()` (`internal/nftables/schedule.go:107`): `meta day { "Monday", … }` e
`meta hour "08:00"-"18:00"`, no começo da regra. **Mova a validação** (`Schedule.Validate` e
`NormalizeDays`) para `internal/fwmodel` e faça o `nftables` chamar a de lá (o `nftables` importa o
`fwmodel`, nunca o contrário). Apagar agendamento em uso é recusado (409).

### 2.5 Linhas travadas (derivadas) e implícitas — lista completa por zona

As linhas travadas **não são guardadas** como regras: são geradas a cada renderização a partir dos
insumos (§2.8) e dos ajustes. Aparecem na tabela com o selo "travada" e um link para onde se
editam. Cada linha travada tem um **comentário nft estável** (usado para ler contadores e para o
registro). Ordem dentro de cada aba: **travadas no topo** (na ordem abaixo), depois as **regras do
admin** (na posição dele), por último a **regra padrão** da zona.

**Implícitas do despachante** (mostradas num bloco recolhido "Regras implícitas" no topo de
Flutuantes; não têm caixa de registrar):

| Comentário | Onde | Regra |
|---|---|---|
| `s:hosts-bloqueados` | `forward`, **antes** do `established` | `ip saddr @blocked_hosts counter drop` e `ip daddr @blocked_hosts counter drop` |
| `s:destinos-bloqueados` | `forward`, **antes** do `established` | `ip daddr @blocklist`, `ip saddr @blocklist`, `ip daddr @dom_blocked`, `ip6 daddr @dom_blocked6` — cada um `counter drop` |
| `b:estado` | `input` e `forward` | `ct state established,related counter accept` |
| `b:lo` | `input` | `iif "lo" counter accept` |
| `b:nd` | `input` | `icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } counter accept` |
| `b:dhcp` | `input` | `udp sport 67 udp dport 68 counter accept` (a VM da OCI pega endereço por DHCP) |
| `b:dhcp6` | `input` | `udp dport 546 counter accept` |

Os dois bloqueios ficam **antes** do `established` de propósito: bloquear uma máquina tem de
derrubar também as conexões que ela já tinha (é assim hoje, porque a `forward` atual não aceita
`established` antes dos grupos). Como hoje, os bloqueios valem **só para a passagem** — a máquina
bloqueada ainda alcança o próprio firewall (o texto `common.yaml` l.407 já explica isso; manter).
"Hosts bloqueados" e "Destinos bloqueados" aparecem como as duas primeiras linhas travadas de
Flutuantes (com link para Máquinas e para Firewall › Destinos) e **têm caixa "registrar"**
(guardada em `Ajustes.RegistrarBloqueados` e `Ajustes.RegistrarDestinos`).

**Flutuantes:**

| Comentário | Chain | Regra | Quando |
|---|---|---|---|
| `s:ping` | `zona_flut_in` | `icmp type echo-request limit rate 5/second counter accept` | sempre |

**Internet:**

| Comentário | Chain | Regra | Quando |
|---|---|---|---|
| `s:contencao` | `zona_inet_in` | `ip saddr @abusers counter drop` e `tcp dport @fwp_gerencia ct state new limit rate over 10/minute counter add @abusers { ip saddr }` | `Ajustes.ContencaoBorda` (mesmas linhas de `abuseRules`, `internal/nftables/abusers.go:72`) |
| `s:wireguard` | `zona_inet_in` | `udp dport <porta> counter accept` | VPN ligada |
| `s:nat:<id>` | `zona_inet_fwd` | `ct status dnat ip daddr <ip_destino> <tcp\|udp> dport <porta_destino> counter accept` | um por encaminhamento **ativo** |

O encaminhamento em si (a tradução) sai na chain `prerouting_dnat` do **mesmo script**:
`fib daddr type local <tcp|udp> dport <porta_externa> counter dnat ip to <ip_destino>:<porta_destino> comment "s:nat:<id>"`
(defeito 6). A chain é recriada inteira a cada aplicação (`add chain … { type nat hook prerouting
priority dstnat; policy accept; }` + `flush`), então encaminhamento desativado ou apagado some.

**VCN:**

| Comentário | Chain | Regra | Quando |
|---|---|---|---|
| `s:antibloqueio:vcn` | `zona_vcn_in` | `tcp dport @fwp_gerencia counter accept` | `Ajustes.AntiBloqueio["vcn"]` (padrão **ligado**) |

**VPN:**

| Comentário | Chain | Regra | Quando |
|---|---|---|---|
| `s:antibloqueio:vpn` | `zona_vpn_in` | `tcp dport @fwp_gerencia counter accept` | `Ajustes.AntiBloqueio["vpn"]` (padrão **desligado** — defeito 1) |
| `s:dns-vpn` | `zona_vpn_in` | `meta l4proto { tcp, udp } th dport 53 counter accept` | VPN ligada (defeito 3) |
| `s:vpn:<user_id>:total` | `zona_vpn_in` **e** `zona_vpn_fwd` | `ip saddr <peer>/32 counter accept` | pessoa com acesso **total** (defeito 2) |
| `s:vpn:<user_id>:<alias_id>` | `zona_vpn_fwd` | com portas: `ip saddr <peer> ip daddr @fwa_<alias> tcp dport { <portas> } counter accept`; sem portas: `ip saddr <peer> ip daddr @fwa_<alias> counter accept` | pessoa **restrita**, um por alias do perfil |
| `s:vpn:<user_id>:<alias_id>:icmp` | `zona_vpn_fwd` | `ip saddr <peer> ip daddr @fwa_<alias> meta l4proto icmp counter accept` | restrita **com** portas (mesma semântica ZTNA de hoje: TCP + ICMP) |

Ordem das linhas de pessoas: por nome de usuário; dentro da pessoa, por nome do alias. Alias do
perfil que não existe mais é ignorado na renderização e aparece como **aviso** nas pendências.
Pessoa restrita sem nenhum alias válido não ganha linha nenhuma (fica só com DNS e ping).

**Regra padrão de cada zona** (última linha da chain; decisão fixa 6):

| Comentário | Chain | Verdito |
|---|---|---|
| `d:internet:in` | `zona_inet_in` | `counter drop` |
| `d:internet:fwd` | `zona_inet_fwd` | `counter drop` |
| `d:vcn:in` | `zona_vcn_in` | `counter drop` |
| `d:vcn:fwd` | `zona_vcn_fwd` | `counter accept` (a VCN sai para a Internet pelo NAT) |
| `d:vpn:in` | `zona_vpn_in` | `counter drop` |
| `d:vpn:fwd` | `zona_vpn_fwd` | `counter drop` |

As chains `zona_flut_in` e `zona_flut_fwd` **não** têm regra padrão (o pacote volta ao
despachante). Se `Ajustes.RegistrarPadrao` estiver ligado, antes de cada padrão de **drop** sai uma
linha `limit rate 10/second log prefix "lg:d:<zona>:<in|fwd> "`.

### 2.6 Comentários e prefixos de registro

- Toda regra emitida leva `comment "<chave>"`: `r:<uuid>` (regra do admin), `s:<…>` (travada),
  `d:<…>` (padrão), `b:<…>` (implícita). É por esse comentário que o painel lê os contadores
  (`nft -j list table inet linkguard` devolve `comment` e `counter` de cada regra) — some a
  heurística de casar por expressão (`merge_groups.go`, `classify.go`).
- Uma chave pode aparecer em mais de uma regra nft (ex.: acesso total vai em `_in` e `_fwd`; hosts
  bloqueados são duas linhas): os contadores **somam**.
- Registro: quando a regra tem "registrar", sai **uma linha antes** do verdito, com os mesmos
  casamentos e `limit rate 10/second log prefix "<prefixo>"` (sem verdito, sem contador) — o mesmo
  desenho de `comLog` (`internal/nftables/groups.go:214`). Prefixos:
  - regra do admin: `lg:r:<12 hex do uuid> `
  - travada: `lg:s:<chave curta> ` (ex.: `lg:s:hosts `, `lg:s:destinos `)
  - padrão: `lg:d:<zona>:<in|fwd> `
  - o leitor continua aceitando os prefixos antigos `lg:blk:host ` e `lg:blk:dest ` (linhas que já
    estão no journal).

### 2.7 O script gerado (exemplo completo)

Cenário: sub-rede da VNIC `10.0.0.0/24`, hairpin (RFC1918 no alias VCN); VPN ligada em
`10.7.0.1/24`, porta `51820`; gerência `22, 9997`; pessoas `admin` (total, `10.7.0.2`) e `diego`
(restrito, alias `k3s-api` = `10.0.1.20`, portas `6443`); alias do admin `admin-casa` =
`189.1.2.3`; encaminhamento tcp `443` → `10.0.1.30:443`; regra do admin na Internet "SSH e painel
só da minha casa"; regra do admin na VCN "Nada de SMTP direto" (bloquear tcp 25); anti-bloqueio
VCN ligado; nada registrado; contenção desligada. (IDs abreviados como `<…>`.)

```
add table inet linkguard
add set inet linkguard blocklist { type ipv4_addr; flags interval; }
add set inet linkguard blocked_hosts { type ipv4_addr; }
add set inet linkguard dom_blocked { type ipv4_addr; flags timeout; timeout 1h; size 8192; }
add set inet linkguard dom_blocked6 { type ipv6_addr; flags timeout; timeout 1h; size 8192; }
add set inet linkguard abusers { type ipv4_addr; flags dynamic,timeout; timeout 1h; }
add set inet linkguard fwa_vcn { type ipv4_addr; flags interval; }
flush set inet linkguard fwa_vcn
add element inet linkguard fwa_vcn { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }
add set inet linkguard fwa_vpn { type ipv4_addr; flags interval; }
flush set inet linkguard fwa_vpn
add element inet linkguard fwa_vpn { 10.7.0.0/24 }
add set inet linkguard fwp_gerencia { type inet_service; flags interval; }
flush set inet linkguard fwp_gerencia
add element inet linkguard fwp_gerencia { 22, 9997 }
add set inet linkguard fwa_<k3s> { type ipv4_addr; flags interval; }
flush set inet linkguard fwa_<k3s>
add element inet linkguard fwa_<k3s> { 10.0.1.20 }
add set inet linkguard fwa_<casa> { type ipv4_addr; flags interval; }
flush set inet linkguard fwa_<casa>
add element inet linkguard fwa_<casa> { 189.1.2.3 }

add chain inet linkguard zona_flut_in
flush chain inet linkguard zona_flut_in
add rule inet linkguard zona_flut_in icmp type echo-request limit rate 5/second counter accept comment "s:ping"
add chain inet linkguard zona_flut_fwd
flush chain inet linkguard zona_flut_fwd

add chain inet linkguard zona_inet_in
flush chain inet linkguard zona_inet_in
add rule inet linkguard zona_inet_in udp dport 51820 counter accept comment "s:wireguard"
add rule inet linkguard zona_inet_in ip saddr @fwa_<casa> tcp dport @fwp_gerencia counter accept comment "r:<uuid-casa>"
add rule inet linkguard zona_inet_in counter drop comment "d:internet:in"
add chain inet linkguard zona_inet_fwd
flush chain inet linkguard zona_inet_fwd
add rule inet linkguard zona_inet_fwd ct status dnat ip daddr 10.0.1.30 tcp dport 443 counter accept comment "s:nat:<pf>"
add rule inet linkguard zona_inet_fwd counter drop comment "d:internet:fwd"

add chain inet linkguard zona_vcn_in
flush chain inet linkguard zona_vcn_in
add rule inet linkguard zona_vcn_in tcp dport @fwp_gerencia counter accept comment "s:antibloqueio:vcn"
add rule inet linkguard zona_vcn_in tcp dport 25 counter drop comment "r:<uuid-smtp>"
add rule inet linkguard zona_vcn_in counter drop comment "d:vcn:in"
add chain inet linkguard zona_vcn_fwd
flush chain inet linkguard zona_vcn_fwd
add rule inet linkguard zona_vcn_fwd tcp dport 25 counter drop comment "r:<uuid-smtp>"
add rule inet linkguard zona_vcn_fwd counter accept comment "d:vcn:fwd"

add chain inet linkguard zona_vpn_in
flush chain inet linkguard zona_vpn_in
add rule inet linkguard zona_vpn_in meta l4proto { tcp, udp } th dport 53 counter accept comment "s:dns-vpn"
add rule inet linkguard zona_vpn_in ip saddr 10.7.0.2 counter accept comment "s:vpn:<uid-admin>:total"
add rule inet linkguard zona_vpn_in counter drop comment "d:vpn:in"
add chain inet linkguard zona_vpn_fwd
flush chain inet linkguard zona_vpn_fwd
add rule inet linkguard zona_vpn_fwd ip saddr 10.7.0.2 counter accept comment "s:vpn:<uid-admin>:total"
add rule inet linkguard zona_vpn_fwd ip saddr 10.7.0.3 ip daddr @fwa_<k3s> tcp dport { 6443 } counter accept comment "s:vpn:<uid-diego>:<k3s>"
add rule inet linkguard zona_vpn_fwd ip saddr 10.7.0.3 ip daddr @fwa_<k3s> meta l4proto icmp counter accept comment "s:vpn:<uid-diego>:<k3s>:icmp"
add rule inet linkguard zona_vpn_fwd counter drop comment "d:vpn:fwd"

add chain inet linkguard input { type filter hook input priority filter; policy accept; }
flush chain inet linkguard input
add rule inet linkguard input ct state established,related counter accept comment "b:estado"
add rule inet linkguard input iif "lo" counter accept comment "b:lo"
add rule inet linkguard input icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } counter accept comment "b:nd"
add rule inet linkguard input udp sport 67 udp dport 68 counter accept comment "b:dhcp"
add rule inet linkguard input udp dport 546 counter accept comment "b:dhcp6"
add rule inet linkguard input jump zona_flut_in
add rule inet linkguard input iifname "linkguard" jump zona_vpn_in
add rule inet linkguard input ip saddr @fwa_vcn jump zona_vcn_in
add rule inet linkguard input jump zona_inet_in

add chain inet linkguard forward { type filter hook forward priority filter; policy accept; }
flush chain inet linkguard forward
add rule inet linkguard forward ip saddr @blocked_hosts counter drop comment "s:hosts-bloqueados"
add rule inet linkguard forward ip daddr @blocked_hosts counter drop comment "s:hosts-bloqueados"
add rule inet linkguard forward ip daddr @blocklist counter drop comment "s:destinos-bloqueados"
add rule inet linkguard forward ip saddr @blocklist counter drop comment "s:destinos-bloqueados"
add rule inet linkguard forward ip daddr @dom_blocked counter drop comment "s:destinos-bloqueados"
add rule inet linkguard forward ip6 daddr @dom_blocked6 counter drop comment "s:destinos-bloqueados"
add rule inet linkguard forward ct state established,related counter accept comment "b:estado"
add rule inet linkguard forward jump zona_flut_fwd
add rule inet linkguard forward iifname "linkguard" jump zona_vpn_fwd
add rule inet linkguard forward ip saddr @fwa_vcn jump zona_vcn_fwd
add rule inet linkguard forward jump zona_inet_fwd

add chain inet linkguard prerouting_dnat { type nat hook prerouting priority dstnat; policy accept; }
flush chain inet linkguard prerouting_dnat
add rule inet linkguard prerouting_dnat fib daddr type local tcp dport 443 counter dnat ip to 10.0.1.30:443 comment "s:nat:<pf>"

flush chain inet linkguard grp_0a1b2c3d4e5f
delete chain inet linkguard grp_0a1b2c3d4e5f
flush chain inet linkguard user_rules
delete chain inet linkguard user_rules
delete set inet linkguard blocked_macs
```

Regras de construção do script (todas testadas por golden):
- **As políticas das base chains ficam `accept`**; quem decide é a última linha de cada zona. Isso
  mantém compatível o `Restore` (`refuseRestrictiveInputPolicy`, `internal/nftables/service.go:522`,
  recusa snapshot com entrada em `drop`) e evita que uma reconstrução parcial derrube o acesso.
- Sets que outras partes do produto enchem na hora (`blocklist`, `blocked_hosts`, `dom_blocked`,
  `dom_blocked6`, `abusers`) recebem **só `add set`** com a declaração **idêntica** à de hoje
  (`bootstrap.go:95-107`, `abusers.go:50`) — **sem `flush`**, para não apagar elementos. O mapa
  `dom_wan` não é tocado (dívida conhecida: `internal/domtargets` ainda escreve nele e nenhuma
  regra o lê).
- **Limpeza** no fim do mesmo script, depois do `flush` de `input`/`forward` (senão o nft recusa
  apagar chain ainda referenciada): para cada chain existente `grp_*` e `user_rules`, e para cada
  set existente `fwa_*`/`fwp_*` que não está na config, e para `blocked_macs`: `flush` e `delete`
  (o nft só apaga chain vazia). A lista do que existe vem de `nft -j list table inet linkguard`,
  lida **antes** de renderizar e passada ao renderizador (`Insumos.Existentes`).
- `reject`: com protocolo `tcp` sai `reject with tcp reset`; nos outros casos, `reject`.
- Protocolo `tcp/udp` sai `meta l4proto { tcp, udp }` e a porta como `th dport …`; `icmp` sai
  `meta l4proto icmp`; `tcp` ou `udp` com porta saem `tcp dport …`/`udp dport …`, sem porta
  `meta l4proto tcp`.
- Origem VCN numa regra da aba VCN (`ip saddr @fwa_vcn`) é redundante mas correta; o formulário
  sugere "qualquer" como origem padrão (a aba já diz de onde vem).
- **O script sai idêntico** para a mesma entrada (teste de determinismo rodando 50 vezes, como o
  que já existe em `zonas_golden_test.go:629`).

### 2.8 Aplicar, Descartar, janela, VPN

**Duas camadas:**
- **Configuração** (editável, passa pelo Aplicar): regras, aliases, agendamentos,
  encaminhamentos de porta, ajustes. Guardada como **em edição** (tabelas `fw_*`) e **aplicada**
  (`fw_aplicado.config`, JSON canônico).
- **Insumos automáticos** (não passam pelo botão): redes da VCN detectadas, rede e porta da VPN,
  portas de gerência, **perfis das pessoas da VPN** (`wireguard_peers`), chains e sets existentes.

**O que roda no kernel = render(config aplicada, insumos atuais).**

**Pendência** = `canônico(em edição) != fw_aplicado.config`. O painel mostra a barra "A
configuração do firewall mudou" enquanto houver pendência.

**Aplicar** (`POST /api/firewall/aplicar`), em ordem — espelha os estágios de `ApplyGuarded`
(`internal/firewallrules/apply_guarded.go:175`) e reaproveita os tipos `Stage`/`GuardError` para a
API continuar mapeando 400/409/500 do mesmo jeito (`handlers/guarded.go` `writeGuardError`):
1. trava (`s.mu` + o `reconcileMu` do nftables);
2. janela aberta → **409** (`StageLocked`), com a mesma exceção de hoje para janela em reversão já
   assentada;
3. carrega em edição e aplicada; `fwmodel.Validar` → erros **400** (`StageValidate`) com a lista
   de problemas; avisos não bloqueiam;
4. lê os insumos (inclui `nft -j list table` para `Existentes`);
5. `novo := RenderZonas(emEdicao, insumos)`; `atual := RenderZonas(aplicada, insumos)`;
6. `nft -c -f` com `novo.Script` → falha **400** (`StagePreflight`) com a mensagem do nft;
7. **janela** = `novo.HashEntrada != atual.HashEntrada` (hash das linhas de `input`, das chains
   `zona_*_in` e dos elementos dos sets que elas usam). Se precisar, `OpenConfirmWindow` com o
   snapshot **v2** (§ abaixo) tirado **antes** de escrever;
8. `nft -f` com `novo.Script` (atômico). Falha → descarta a janela, **500** (`StageWrite`), nada
   mais muda;
9. numa transação: `fw_aplicado := emEdicao` e grava uma **revisão** (`fw_revisoes`, guarda as 30
   últimas). Falha → reaplica `atual.Script`, descarta a janela, **500**;
10. para cada alias cujos itens mudaram, `db.MarkWireGuardRoutesChangedByHostGroup(aliasID)`
    (a configuração do cliente em túnel dividido fica desatualizada);
11. auditoria `fw.aplicar` com o resumo das mudanças;
12. `Persist` (continua bloqueado enquanto houver janela aberta — `SetPersistGuard` já faz isso) e
    o gancho `saveNftSnapshot`.

**Descartar** (`POST /api/firewall/descartar`): recusado com janela aberta (409); substitui, numa
transação, as tabelas em edição pelo conteúdo de `fw_aplicado.config`. Auditoria `fw.descartar`.

**Edição com janela aberta**: toda escrita na configuração em edição é recusada (409), como hoje
(`guardWindowOpen`); a tela já desabilita edição com `editDisabled`
(`web/src/lib/useConfirmOrRevert.ts`).

**Janela e reversão** (`internal/firewallrules/confirm.go`): mantenha a mecânica (90 s, relógio
monotônico, `WatchPending` a cada 5 s, `RevertPendingOnBoot`, prova de conexão nova para
confirmar, `pending_firewall_change` com uma linha só). Troque o conteúdo do snapshot:

```go
// snapshotV2 é o estado anterior guardado quando a janela abre.
type snapshotV2 struct {
	Formato   int             `json:"formato"` // sempre 2
	Config    fwmodel.Config  `json:"config"`  // a config aplicada ANTES da mudança
	PerfisVPN []perfilVPN     `json:"perfis_vpn"`
}
type perfilVPN struct {
	UserID            string   `json:"user_id"`
	AccessMode        string   `json:"access_mode"`
	AllowedHostGroups []string `json:"allowed_host_groups"` // agora IDs de alias
	AllowedPorts      string   `json:"allowed_ports"`
}
```

Reverter (prazo vencido, "Reverter agora" ou boot): em edição **e** aplicada := `snapshot.Config`;
para cada pessoa que existe hoje: se está em `PerfisVPN`, volta os três campos de acesso; se **não**
está (entrou durante a janela), fica **restrita e sem aliases** (reverter nunca dá acesso a mais);
renderiza com os insumos atuais e aplica; limpa a janela; `Persist`; alerta
`FirewallChangeReverted` como hoje. **O merge de três vias** (`revert_merge.go`) **deixa de
existir**: com edição travada durante a janela, não há edição concorrente para preservar.

Snapshot no formato antigo (sem `formato: 2`) encontrado no boot depois do upgrade: **descarte** a
janela (`ClearPendingChange`) com um `slog.Warn` e uma linha de auditoria — a conversão (§3) roda
logo depois e redefine o estado.

**Mudanças da VPN** (decisão fixa 3): perfil salvo, pessoa cadastrada, chave revogada, usuário
apagado, VPN ligada/desligada ou porta trocada **não** criam pendência — aplicam na hora, pelo
mesmo pipeline:

```go
// AplicarMudancaVPN roda escrever() e reaplica a config APLICADA com os insumos novos.
func (s *Service) AplicarMudancaVPN(ctx context.Context, por, resumo string,
	escrever func() error, desfazer func() error) (*Applied, error)
```
Ordem: trava → janela aberta = 409 → `atual := RenderZonas(aplicada, insumos antes)` e snapshot v2
→ `escrever()` → insumos novos → `novo := RenderZonas(aplicada, insumos novos)` → `nft -c` (falha:
`desfazer()`, 400) → janela se `HashEntrada` mudou → `nft -f` (falha: `desfazer()`, descarta
janela, 500) → auditoria → `Persist`. Pendências do admin (em edição) **não** entram: continuam
pendentes.

**Boot** (`RenderizarNoBoot`): se `fw_aplicado` está vazio (primeira vez depois da conversão ou
instalação nova), `fw_aplicado := em edição` com revisão motivo `conversao`; renderiza aplicada +
insumos; `nft -c`; `nft -f`. Falha: **não** mexe no que está carregado (o `nft -f` é atômico; o que
veio do `/etc/nftables.conf` continua) e levanta alerta. Sem janela no boot.

### 2.9 O que continua imediato (fora do Aplicar)

Elementos de set que são **resposta a incidente** ou dados do dia a dia, e não configuração:
bloquear/desbloquear máquina (`POST /api/hosts/block`), adicionar/tirar destino da lista de bloqueio
por endereço (`/api/nftables/blocklist`), alvos por domínio (`/api/domain-targets`), liberar
contido (`/api/nftables/abusers`). Continuam como hoje: escrevem no set na hora e persistem.

---

## 3. Conversão do que existe (decisão fixa 5)

Duas partes: uma **migração SQL** (dados que não dependem da plataforma) e uma **conversão em Go
no boot** (regras, que precisam saber as redes da VCN e da VPN).

### 3.1 Migração 104 (SQL/Go dentro da transação da migração)
- `host_groups` → `fw_aliases`: **mesmo `id`**, mesmo `nome` (se colidir com nome reservado, vira
  `"<nome> (grupo)"`), `tipo = 'enderecos'`, `descricao`, `itens` = hosts com a máscara aplicada.
  Como o ID é o mesmo, `wireguard_peers.allowed_host_groups` continua válido sem mexer.
- Setting `port_forwards` (JSON no formato de `nftables.PortForward`; decodifique com uma struct
  local, porque `storage` não importa `nftables`) → `fw_encaminhamentos` (o campo
  `interface` é descartado: a nuvem tem uma placa só; se vier preenchido com algo que não seja
  vazio, anote na descrição `"(interface <x> ignorada na conversão)"`).
- **Não apague** `host_groups`, `firewall_groups`, `firewall_rules` nem o setting `port_forwards`
  nesta migração: ficam intocados por uma versão (limpeza numa migração futura, fora deste plano).

### 3.2 Conversão das regras no boot — `ConverterLegadoUmaVez`
Trava por setting `fw_zonas_convertido = "1"` (mesmo padrão de `MigrateRulesIntoDefaultGroup`,
`internal/firewallrules/migrate_groups.go:197`: trava por flag, não por "tabela vazia"; tudo numa
transação). Entradas: `firewall_groups` + `firewall_rules` + settings de postura + fatos
(`RedesVCN`, `RedeVPN`, placa da WAN).

Mapeamento, grupo a grupo na ordem de `position`, regra a regra na ordem de `position`:

| Legado | Novo |
|---|---|
| grupo `blocked_hosts` / `blocklist` | linhas travadas (§2.5); nenhuma regra |
| grupos `wireguard_peer` (passagem e entrada) e suas regras (inclusive `ZTNA:`) | nada — são derivados dos perfis agora |
| grupo do admin (`kind` `""` ou `admin`) | uma regra nova por regra do grupo, mais uma regra de "sobra" se `fallthrough` for `accept`/`drop` |
| grupo desligado | regras convertidas **desativadas** |
| `sched_days/start/end` do grupo | um **agendamento** (deduplicado pela tripla), nome `"Horário de <nome do grupo>"`, preso a cada regra convertida do grupo |
| `conn_state = new` | ignorado (toda regra de zona já só vê conexão nova) |
| `firewall_log_blocks = 1` | `Ajustes.RegistrarBloqueados = RegistrarDestinos = true` |
| `firewall_edge_containment = 1` | `Ajustes.ContencaoBorda = true` |
| `firewall_wan_mgmt_closed` ausente/`0` | regra do admin na **Internet**, **ativa**: liberar tcp, origem qualquer, destino Este firewall, porta alias Gerência, descrição "Gerência (SSH e painel) aberta para a Internet — restrinja a origem" |
| `firewall_wan_mgmt_closed = 1` | a mesma regra, **desativada** |
| `firewall_input_policy`, `firewall_forward_policy` | nada (substituídas pelos padrões das zonas); anotar no relatório se eram `drop` |

**Zona de cada regra do admin** — origem efetiva = `rule.saddr` se preenchida, senão
`group.cond_saddr`; interface efetiva = `rule.iif` ou `group.cond_iif`:
1. interface `linkguard` **ou** origem contida na rede da VPN → **vpn**;
2. origem contida em alguma rede do alias VCN → **vcn**;
3. origem preenchida e fora de todas as redes locais → **internet**;
4. qualquer outro caso (sem origem e sem interface; só interface da WAN, que em hairpin mistura VCN
   e Internet; regra com `oif`; `rule.daddr` e `group.cond_daddr` preenchidos e diferentes) →
   **flutuante, desativada**, descrição começando com `"[revisar] "`.

**Destino** — grupo com escopo `input` → `self`; escopo `forward` → `rule.daddr` (ou
`group.cond_daddr`) como `addr`, ou `any` se vazio. Ação, protocolo, porta e descrição são
copiados. A "sobra" do grupo vira: origem = origem efetiva do grupo, destino conforme o escopo,
protocolo qualquer, ação = o `fallthrough`, descrição `"Sobra do grupo <nome>"`.

**Instalação nova** (sem grupos do admin): cria só a regra de gerência na Internet (ativa, porque
`firewall_wan_mgmt_closed` não existe) e os ajustes padrão (`AntiBloqueio = {vcn: true, vpn: false}`,
resto desligado). O painel precisa continuar alcançável logo depois de instalar
("instalou em VM nova, NAT funciona de primeira; resto pela interface").

**Relatório**: a conversão grava no setting `fw_conversao_relatorio` um JSON com uma linha por
decisão que merece olhar (regra mandada para Flutuantes, política `drop` substituída, interface
ignorada). O painel mostra um aviso no topo do Firewall enquanto o relatório existir, com botão
"Entendi" que apaga o setting (auditado).

**Caminhos preservados** (critério de aceite da conversão, com teste): quem administrava pela
Internet continua (regra de gerência ativa se não estava fechada); de dentro da VCN a gerência
continua (anti-bloqueio VCN); pessoa da VPN com acesso total continua alcançando tudo, inclusive a
caixa. Pessoa restrita perde SSH/painel — é a correção do defeito 1, e vai no relatório.

---
## 4. Tarefas

Ordem pensada para cada commit deixar a árvore compilando e os testes verdes: primeiro se constrói
o novo **ao lado** do velho (T1–T7), depois se troca a ligação no `main.go` e na API (T8–T11),
depois o painel (T12–T13), e só no fim se apaga o legado (T14).

### T1 — Pacote `internal/fwmodel` (tipos, validação, forma canônica, diferenças)

**Arquivos:** criar `internal/fwmodel/{model.go,validar.go,canonico.go,mudancas.go,difftexto.go,agendamento.go}` e os `_test.go` correspondentes.

- [ ] **Tipos** (`model.go`). Só biblioteca padrão. JSON em `snake_case`.

```go
package fwmodel

type Zona string

const (
	ZonaFlutuante Zona = "flutuante"
	ZonaInternet  Zona = "internet"
	ZonaVCN       Zona = "vcn"
	ZonaVPN       Zona = "vpn"
)

// Zonas na ordem das abas.
var Zonas = []Zona{ZonaFlutuante, ZonaInternet, ZonaVCN, ZonaVPN}

type Acao string // "accept" | "drop" | "reject"
type Proto string // "" | "tcp" | "udp" | "tcp/udp" | "icmp"

type PontaTipo string

const (
	PontaQualquer PontaTipo = "any"
	PontaEste     PontaTipo = "self"  // só em Destino
	PontaEndereco PontaTipo = "addr"  // IPv4 ou CIDR
	PontaAlias    PontaTipo = "alias" // ID de alias de endereços (inclusive embutido)
)

type Ponta struct {
	Tipo  PontaTipo `json:"kind"`
	Valor string    `json:"value,omitempty"`
}

type PortaTipo string

const (
	PortaQualquer PortaTipo = "any"
	PortaValor    PortaTipo = "port"  // "443" ou "8000-8100"
	PortaAlias    PortaTipo = "alias" // ID de alias de portas
)

type Porta struct {
	Tipo  PortaTipo `json:"kind"`
	Valor string    `json:"value,omitempty"`
}

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

type AliasTipo string // "enderecos" | "portas"

type Alias struct {
	ID        string    `json:"id"`
	Nome      string    `json:"nome"`
	Tipo      AliasTipo `json:"tipo"`
	Descricao string    `json:"descricao"`
	Itens     []string  `json:"itens"`
}

type Agendamento struct {
	ID        string `json:"id"`
	Nome      string `json:"nome"`
	Descricao string `json:"descricao"`
	Dias      string `json:"dias"`   // "mon,tue"; vazio = todos
	Inicio    string `json:"inicio"` // "HH:MM"
	Fim       string `json:"fim"`    // "HH:MM"
}

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

type Ajustes struct {
	AntiBloqueio        map[Zona]bool `json:"anti_bloqueio"` // só "vcn" e "vpn"
	RedesVCNExtras      []string      `json:"redes_vcn_extras"`
	RegistrarBloqueados bool          `json:"registrar_bloqueados"`
	RegistrarDestinos   bool          `json:"registrar_destinos"`
	RegistrarPadrao     bool          `json:"registrar_padrao"`
	ContencaoBorda      bool          `json:"contencao_borda"`
}

type Config struct {
	Formato         int              `json:"formato"` // 1
	Regras          []Regra          `json:"regras"`
	Aliases         []Alias          `json:"aliases"`
	Agendamentos    []Agendamento    `json:"agendamentos"`
	Encaminhamentos []Encaminhamento `json:"encaminhamentos"`
	Ajustes         Ajustes          `json:"ajustes"`
}

// IDs dos aliases embutidos.
const (
	AliasVCN        = "sys:vcn"
	AliasVPN        = "sys:vpn"
	AliasGerencia   = "sys:gerencia"
	AliasPessoaPref = "sys:pessoa:" // + user_id
)

func AjustesPadrao() Ajustes // AntiBloqueio {vcn: true, vpn: false}; resto desligado
```

- [ ] **Validação** (`validar.go`):
  ```go
  type Problema struct {
      Severidade string `json:"severidade"` // "erro" | "aviso"
      Onde       string `json:"onde"`       // "regra:<id>", "alias:<id>", "agendamento:<id>", "encaminhamento:<id>", "ajustes"
      Chave      string `json:"chave"`      // chave i18n, ex.: "fwz.problema.aliasInexistente"
      Vars       map[string]string `json:"vars,omitempty"`
  }
  // Validar confere a config inteira. pessoas = user_ids das pessoas da VPN (para sys:pessoa:*).
  func Validar(c Config, pessoas []string) []Problema
  func TemErro(ps []Problema) bool
  ```
  Regras mínimas (cada uma com caso de teste):
  - regra: zona conhecida; ação conhecida; proto conhecido; origem não pode ser `self`; `addr`
    precisa ser IPv4 ou CIDR IPv4 válido; `alias` precisa existir **e** ser de endereços (os
    embutidos `sys:vcn`, `sys:vpn` e `sys:pessoa:<id de pessoa existente>` valem); porta só com
    `tcp`/`udp`/`tcp/udp`; porta `port` = número 1–65535 ou faixa `a-b` com `a<b`; porta `alias`
    precisa ser alias de **portas** (inclui `sys:gerencia`); agendamento precisa existir; descrição
    até 200 caracteres; posição sem repetição dentro da zona;
  - aviso (não bloqueia): origem `sys:vcn` numa regra da aba VPN ou `sys:vpn` numa da VCN (nunca
    casa, porque o despachante já separou); regra ativa idêntica a outra da mesma zona;
  - alias: nome 1–64, único sem diferenciar maiúsculas, não reservado (§2.3); tipo conhecido; itens
    válidos para o tipo; no máximo 4096 itens;
  - agendamento: nome único; dias conhecidos (`mon`..`sun`); `HH:MM` válidos; início ≠ fim
    (mova para cá `Schedule.Validate` e `NormalizeDays` de `internal/nftables/schedule.go`,
    deixando lá só `Tokens()`, que passa a chamar as funções daqui);
  - encaminhamento: proto `tcp`/`udp`; portas 1–65535; `IPDestino` IPv4; sem dois **ativos** com o
    mesmo `(proto, porta_externa)`;
  - ajustes: `AntiBloqueio` só com chaves `vcn`/`vpn`; `RedesVCNExtras` CIDR IPv4.
- [ ] **Normalização** (`canonico.go`): `Normalizar(c Config) Config` — máscara nos CIDR, `/32`
  retirado de IP solto (guardar `10.0.1.20`, não `10.0.1.20/32`), dias em ordem canônica,
  regras ordenadas por `(zona na ordem de Zonas, posicao)` com posições renumeradas 0..n-1 por
  zona, aliases/agendamentos/encaminhamentos ordenados por ID, slices nil viram vazias.
  `Canonico(c Config) []byte` = `json.Marshal(Normalizar(c))`. Duas configs são iguais se e só se
  os canônicos são iguais.
- [ ] **Mudanças** (`mudancas.go`): `Mudancas(antes, depois Config) []Mudanca`, com
  `Mudanca{Objeto: "regra"|"alias"|"agendamento"|"encaminhamento"|"ajustes", Tipo: "criada"|"removida"|"alterada"|"movida", ID, Nome, Zona, Campos []string}`.
  Regra "movida" = mesma regra, mudou só a posição ou a zona. Ordem da saída estável.
- [ ] **Diferença de texto** (`difftexto.go`): `DiffLinhas(a, b string) string` — diff unificado
  simples por LCS de linhas (os scripts têm centenas de linhas, não precisa de Myers), com
  prefixos `+`/`-`/` ` e contexto de 3 linhas. Sem dependência externa.
- [ ] **Testes**: tabela de casos de `Validar` (um por regra acima), `Canonico` estável (duas
  configs iguais em ordem diferente dão o mesmo JSON), `Mudancas` (criada/removida/alterada/movida),
  `DiffLinhas` (inserção, remoção, sem diferença = string vazia).

**Aceite:** `go test ./internal/fwmodel/` verde; `go list -deps ./internal/fwmodel` não lista nada
de `github.com/giovanibalarini/linkguard-cloud/...`.

---

### T2 — Banco: migrações 103 e 104, repositório da config

**Arquivos:** `internal/storage/storage.go` (lista `schemaMigrations`), criar
`internal/storage/repo_fwzonas.go` e `internal/storage/repo_fwzonas_test.go`,
`internal/storage/fwzonas_migration_internal_test.go`.

- [ ] **Migração 103 `upFirewallZonas`** — cria as tabelas (use o padrão de sondagem idempotente
  que as outras migrações usam):

```sql
CREATE TABLE IF NOT EXISTS fw_regras (
    id             TEXT PRIMARY KEY,
    zona           TEXT NOT NULL CHECK (zona IN ('flutuante','internet','vcn','vpn')),
    posicao        INTEGER NOT NULL,
    ativa          INTEGER NOT NULL DEFAULT 1,
    acao           TEXT NOT NULL CHECK (acao IN ('accept','drop','reject')),
    proto          TEXT NOT NULL DEFAULT '',
    origem_tipo    TEXT NOT NULL DEFAULT 'any',
    origem_valor   TEXT NOT NULL DEFAULT '',
    destino_tipo   TEXT NOT NULL DEFAULT 'any',
    destino_valor  TEXT NOT NULL DEFAULT '',
    porta_tipo     TEXT NOT NULL DEFAULT 'any',
    porta_valor    TEXT NOT NULL DEFAULT '',
    agendamento_id TEXT NOT NULL DEFAULT '',
    registrar      INTEGER NOT NULL DEFAULT 0,
    descricao      TEXT NOT NULL DEFAULT '',
    criada_em      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    atualizada_em  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_fw_regras_zona ON fw_regras(zona, posicao);

CREATE TABLE IF NOT EXISTS fw_aliases (
    id            TEXT PRIMARY KEY,
    nome          TEXT NOT NULL,
    nome_chave    TEXT NOT NULL UNIQUE,          -- lower(nome), para unicidade sem caixa
    tipo          TEXT NOT NULL CHECK (tipo IN ('enderecos','portas')),
    descricao     TEXT NOT NULL DEFAULT '',
    itens         TEXT NOT NULL DEFAULT '[]',    -- JSON []string
    criado_em     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    atualizado_em DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS fw_agendamentos (
    id            TEXT PRIMARY KEY,
    nome          TEXT NOT NULL,
    nome_chave    TEXT NOT NULL UNIQUE,
    descricao     TEXT NOT NULL DEFAULT '',
    dias          TEXT NOT NULL DEFAULT '',
    inicio        TEXT NOT NULL,
    fim           TEXT NOT NULL,
    criado_em     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    atualizado_em DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS fw_encaminhamentos (
    id            TEXT PRIMARY KEY,
    nome          TEXT NOT NULL DEFAULT '',
    ativo         INTEGER NOT NULL DEFAULT 1,
    proto         TEXT NOT NULL CHECK (proto IN ('tcp','udp')),
    porta_externa INTEGER NOT NULL,
    ip_destino    TEXT NOT NULL,
    porta_destino INTEGER NOT NULL,
    posicao       INTEGER NOT NULL DEFAULT 0,
    criado_em     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    atualizado_em DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS fw_ajustes (
    only_row INTEGER PRIMARY KEY CHECK (only_row = 1),
    ajustes  TEXT NOT NULL                        -- JSON fwmodel.Ajustes
);

CREATE TABLE IF NOT EXISTS fw_aplicado (
    only_row     INTEGER PRIMARY KEY CHECK (only_row = 1),
    config       TEXT NOT NULL,                   -- fwmodel.Canonico
    aplicado_em  INTEGER NOT NULL,                -- unix
    aplicado_por TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS fw_revisoes (
    id           TEXT PRIMARY KEY,
    config       TEXT NOT NULL,
    resumo       TEXT NOT NULL DEFAULT '',
    motivo       TEXT NOT NULL DEFAULT 'aplicar',  -- aplicar | reverter | conversao | restaurar
    aplicado_em  INTEGER NOT NULL,
    aplicado_por TEXT NOT NULL DEFAULT ''
);
```

- [ ] **Migração 104 `upAliasesDosGruposDeHosts`** — dados (§3.1): `host_groups` → `fw_aliases`
  (mesmo id; resolver colisão de nome reservado e de `nome_chave`), setting `port_forwards` →
  `fw_encaminhamentos`. Idempotente: `INSERT OR IGNORE` por id. Não apaga nada.
- [ ] **Repositório** (`repo_fwzonas.go`), usando os tipos de `fwmodel`:
  ```go
  func (db *DB) CarregarConfigEmEdicao() (fwmodel.Config, error)
  func (db *DB) SubstituirConfigEmEdicao(c fwmodel.Config) error            // tx: apaga e regrava as 5 partes
  func (db *DB) CarregarConfigAplicada() (c fwmodel.Config, existe bool, err error)
  func (db *DB) SalvarAplicadaERevisao(c fwmodel.Config, por, resumo, motivo string, agora time.Time) error // tx; poda para 30 revisões
  func (db *DB) ListarRevisoes(limite int) ([]RevisaoFW, error)            // sem o campo config
  func (db *DB) CarregarRevisao(id string) (fwmodel.Config, error)
  // CRUD fino usado pela API (todas escrevem só na config em edição):
  func (db *DB) CriarRegraFW(r *fwmodel.Regra) error                        // posicao = MAX(posicao da zona)+1
  func (db *DB) AtualizarRegraFW(r fwmodel.Regra) error                    // se a zona mudou, vai para o fim da nova zona
  func (db *DB) ApagarRegraFW(id string) error
  func (db *DB) AtivarRegraFW(id string, ativa bool) error
  func (db *DB) ReordenarRegrasFW(zona fwmodel.Zona, ids []string) error   // exige a lista completa da zona
  func (db *DB) CriarAliasFW / AtualizarAliasFW / ApagarAliasFW
  func (db *DB) CriarAgendamentoFW / AtualizarAgendamentoFW / ApagarAgendamentoFW
  func (db *DB) CriarEncaminhamentoFW / AtualizarEncaminhamentoFW / ApagarEncaminhamentoFW
  func (db *DB) SalvarAjustesFW(a fwmodel.Ajustes) error
  func (db *DB) UsosDoAlias(id string) ([]string, error)       // regras, perfis da VPN (wireguard_peers.allowed_host_groups)
  func (db *DB) UsosDoAgendamento(id string) ([]string, error)
  ```
  `fw_ajustes` ausente → `fwmodel.AjustesPadrao()`.
- [ ] **Testes**: migração em banco novo e em banco com `host_groups` e `port_forwards` preenchidos
  (IDs preservados, máscara aplicada, colisão de nome resolvida); ida e volta
  `SubstituirConfigEmEdicao` → `CarregarConfigEmEdicao` com `Canonico` igual; poda de revisões em
  30; `ReordenarRegrasFW` recusa lista incompleta; `UsosDoAlias` acha uso em regra e em perfil.

**Aceite:** testes de `internal/storage` verdes, inclusive `TestSchemaMigrationsAreOrderedAndUnique`.

---

### T3 — Renderizador `RenderZonas` (puro) e goldens

**Arquivos:** criar `internal/nftables/zonas_render.go`, `internal/nftables/zonas_linhas.go`,
`internal/nftables/zonas_render_test.go`, `internal/nftables/testdata/zonas_v2/<cenário>/`.

- [ ] **Insumos e saída:**

```go
// Insumos são os fatos que não passam pelo botão Aplicar (§2.8).
type Insumos struct {
	RedesVCN       []string     // redesLocais(plat); as extras vêm de Config.Ajustes
	RedeVPN        string       // "10.7.0.0/24"; "" com a VPN desligada
	PortaWireGuard int          // 0 = VPN desligada
	InterfaceVPN   string       // "linkguard"
	PortasGerencia []int        // SSH + painel + extras, já ordenadas e sem repetição
	Pessoas        []PessoaVPN
	Existentes     Existentes   // o que já existe na tabela (para a limpeza)
}

type PessoaVPN struct {
	UserID   string
	Usuario  string
	Endereco string   // "10.7.0.3" (sem /32)
	Total    bool     // access_mode == "full"
	Aliases  []string // IDs de alias de endereços
	Portas   string   // CSV, como hoje em allowed_ports
}

type Existentes struct {
	Chains []string
	Sets   []string
}

// Linha é uma linha da tabela que o painel mostra (travada, do admin, padrão ou implícita),
// com o texto nft de cada regra que ela gera. É a MESMA fonte para o script e para a tela.
type Linha struct {
	Chave     string       // comentário nft: "r:<uuid>", "s:...", "d:...", "b:..."
	Zona      fwmodel.Zona
	Tipo      string       // "admin" | "travada" | "padrao" | "implicita"
	Regra     fwmodel.Regra // forma normalizada (para as travadas, sintetizada)
	EditarEm  string       // "" | "vpn" | "nat" | "maquinas" | "destinos" | "ajustes"
	DescChave string       // chave i18n da descrição das travadas/padrões/implícitas
	DescVars  map[string]string
	Nft       []LinhaNft   // cada regra nft que esta linha gera
}

type LinhaNft struct {
	Chain string
	Texto string // tokens juntos por espaço, sem o prefixo "add rule inet linkguard <chain>"
}

type Ruleset struct {
	Script      string                  // o texto para `nft -f`
	Linhas      map[fwmodel.Zona][]Linha // por aba, na ordem da tela; implícitas em Flutuantes
	HashEntrada string                  // sha256 das linhas de input, zona_*_in e sets usados por elas
	Avisos      []fwmodel.Problema      // ex.: alias de perfil da VPN que não existe
}

func RenderZonas(c fwmodel.Config, in Insumos) (Ruleset, error)
```

- [ ] Implementar exatamente as regras do §2.5, §2.6 e §2.7. Construa os tokens com as mesmas
  proteções do renderizador atual (`buildRuleTokens`, `internal/nftables/service.go:1079`:
  validação de interface por `reIface`, endereços IPv4, portas por `validPort`) — nada do que vem
  do banco entra no script sem validação (o `nft -f` junta tudo e parseia; um valor torto vira
  injeção de regra).
- [ ] O script inclui a chain `prerouting_dnat` com os encaminhamentos ativos (§2.5), sempre
  com `fib daddr type local` — há um teste que falha se alguma regra de DNAT sair sem ele
  (defeito 6).
- [ ] `RenderZonas` devolve erro (e não script parcial) quando: colisão de nome de set; regra
  referencia alias/agendamento inexistente; valor inválido que escapou da validação. O chamador
  nunca aplica meio script.
- [ ] **Goldens** em `testdata/zonas_v2/<cenário>/script.nft` e `linhas.json`, com `-update`
  (copie o mecanismo `conferirArquivo` de `zonas_golden_test.go:913`). Cenários mínimos:
  1. `instalacao_nova` — config só com a regra de gerência na Internet, VPN desligada;
  2. `oci_tipico` — o exemplo do §2.7 (o golden tem de bater com o bloco daquela seção);
  3. `registro_e_agenda` — regra com "registrar" e agendamento; padrões registrados;
     bloqueados registrados;
  4. `contencao` — `ContencaoBorda` ligada;
  5. `limpeza_legado` — `Existentes` com `grp_*`, `user_rules`, `blocked_macs` e um `fwa_*` órfão;
  6. `vpn_sem_aliases_validos` — pessoa restrita com alias apagado (sai aviso, não sai linha);
  7. `sem_redes_vcn` — `RedesVCN` vazio (tudo cai em Internet; o set `fwa_vcn` sai sem elementos).
- [ ] **Teste de determinismo**: 50 renderizações do cenário `oci_tipico` com mapas embaralhados
  dão o mesmo `Script` e o mesmo `HashEntrada`.
- [ ] **Teste de janela**: mudar só uma regra de passagem (`zona_vcn_fwd`) **não** muda
  `HashEntrada`; mudar a regra de gerência, o anti-bloqueio, um alias usado em regra de entrada ou
  o perfil de uma pessoa com acesso total **muda**.
- [ ] **Teste de simulação** (reaproveite o simulador de `zone_hairpin_test.go:28-237`, estendido
  para seguir `jump` e comentários): pacotes de exemplo tomam o verdito esperado — pessoa restrita
  → 22 da caixa: `d:vpn:in`; pessoa total → Internet: `s:vpn:…:total`; VCN → Internet: `d:vcn:fwd`
  (aceita); VCN → 9997 da caixa: `s:antibloqueio:vcn`; Internet → 443 encaminhado:
  `s:nat:<id>`; pessoa da VPN → DNS da caixa: `s:dns-vpn`. (Cobre os defeitos 1, 2 e 3.)

**Aceite:** goldens gerados, revisados à mão contra o §2.7, e testes verdes. Nada de `main.go` muda
nesta tarefa.

---

### T4 — Primitivas do nftables: objetos existentes, teste, aplicação, contadores

**Arquivos:** criar `internal/nftables/zonas_aplicar.go` e `zonas_aplicar_test.go`.

- [ ] `func (s *Service) ObjetosExistentes(ctx) (Existentes, error)` — `ExecuteRead nft -j list table inet linkguard`; tabela inexistente = `Existentes{}` sem erro.
- [ ] `func (s *Service) TestarScript(ctx, script string) error` — arquivo temporário +
  `ExecuteRead nft -c -f <arq>` (mesmo caminho de `CheckChainEnsuring`, `reconcile.go:455`);
  dry-run = nil.
- [ ] `func (s *Service) AplicarScript(ctx, script string) error` — arquivo temporário +
  `Execute nft -f <arq>`, depois `Persist` (que já respeita a trava de janela). Pega o
  `reconcileMu`. Dry-run = nil.
- [ ] `func (s *Service) ContadoresPorChave(ctx) (map[string]Contador, error)` — lê
  `nft -j list table inet linkguard`, soma `packets`/`bytes` de cada regra pelo `comment`.
  `Contador{Pacotes, Bytes uint64; Medido bool}` — regra sem contador = `Medido: false` (a tela
  mostra "—", nunca 0; é assim hoje, manter).
- [ ] Testes com executor falso (use o `fakeReconcileExec` de `reconcile_test.go:14`, que já
  captura `checkScripts`/`applyScripts`): o script passado chega inteiro ao `-c -f` e ao `-f`;
  `AplicarScript` chama `Persist` uma vez; parser de contadores com um JSON real de exemplo
  guardado em `testdata/zonas_v2/list_table.json`.

**Aceite:** testes verdes.

---

### T5 — Pipeline em `internal/firewallrules`: Aplicar, Descartar, pendências, janela v2, boot

**Arquivos:** criar `internal/firewallrules/zonas.go`, `zonas_janela.go`, `zonas_test.go`,
`zonas_janela_test.go`; alterar `confirm.go` (formato do snapshot e reversão), `service.go`
(fonte de insumos).

- [ ] Fonte de insumos, ligada no `main.go` na T8:
  ```go
  type FonteInsumos func(ctx context.Context) (nftables.Insumos, error)
  func (s *Service) SetFonteInsumos(f FonteInsumos)
  ```
- [ ] API do serviço:
  ```go
  type Pendencias struct {
      Pendente      bool                `json:"pendente"`
      Mudancas      []fwmodel.Mudanca   `json:"mudancas"`
      DiffNft       string              `json:"diff_nft"`       // fwmodel.DiffLinhas(atual.Script, novo.Script)
      PrecisaJanela bool                `json:"precisa_janela"`
      Problemas     []fwmodel.Problema  `json:"problemas"`
  }
  func (s *Service) EmEdicao() (fwmodel.Config, error)
  func (s *Service) Aplicada() (fwmodel.Config, bool, error)
  func (s *Service) Pendencias(ctx context.Context) (Pendencias, error)
  func (s *Service) Aplicar(ctx context.Context, por string) (*Applied, error)       // §2.8, passos 1–12
  func (s *Service) Descartar(ctx context.Context, por string) error
  func (s *Service) RestaurarRevisao(ctx context.Context, id, por string) error      // em edição := revisão (fica pendente)
  func (s *Service) AplicarMudancaVPN(ctx context.Context, por, resumo string, escrever, desfazer func() error) (*Applied, error)
  func (s *Service) RenderizarNoBoot(ctx context.Context) error
  func (s *Service) Linhas(ctx context.Context, zona fwmodel.Zona) ([]nftables.Linha, error) // render(em edição, insumos) — para a tela
  func (s *Service) RedesVCNExtrasAplicadas() []string                                       // para a ZoneFacts do main
  ```
- [ ] **Todas** as escritas na config em edição (usadas pela API na T9) passam por um único
  método que recusa com janela aberta:
  `func (s *Service) EditarConfig(ctx, por string, f func(db *storage.DB) error) error` →
  `StageLocked`/409 se houver janela; senão roda `f`.
- [ ] Janela v2 (§2.8): `OpenConfirmWindow` passa a gravar `snapshotV2`; `revert` troca o
  `ReplaceFirewallGroupsAndRules` + políticas por: substituir em edição e aplicada pelo
  `snapshot.Config`, restaurar perfis da VPN, renderizar, aplicar, gravar revisão motivo
  `reverter`. `validateSnapshotGroups`, `canonicalState`, `stateMatchesSnapshot` e
  `RevertSettled` passam a comparar `fwmodel.Canonico` (a "reversão assentada" = aplicada atual
  igual ao snapshot). Snapshot sem `formato: 2` → descartar a janela (§2.8).
- [ ] O que sai deste pacote nesta tarefa: nada ainda (o legado ainda é chamado pelo `main.go`
  até a T8). Não quebre `Reconcile`, `ApplyGuarded` etc. agora.
- [ ] **Testes** (executor falso + banco temporário, como `internal/firewallrules/*_test.go` já
  fazem):
  - `Aplicar` sem pendência: não roda `nft -f`, devolve ok;
  - `Aplicar` com erro de validação: 400, nada executado, aplicada inalterada;
  - `Aplicar` com `nft -c` falhando: 400, nenhum `nft -f`, aplicada inalterada;
  - `Aplicar` mudando só passagem: **sem** janela, um `nft -f`, aplicada = em edição, revisão gravada;
  - `Aplicar` mudando entrada: janela aberta com snapshot v2 da aplicada anterior;
  - janela aberta: `Aplicar`, `Descartar`, `EditarConfig` e `AplicarMudancaVPN` devolvem 409;
  - janela vence (`CheckPendingExpired` com relógio falso): em edição e aplicada voltam ao
    snapshot, script anterior reaplicado, revisão `reverter`;
  - reversão com pessoa nova durante a janela: ela fica restrita e sem aliases;
  - `nft -f` falha: janela descartada, aplicada inalterada;
  - `Descartar`: em edição = aplicada;
  - `AplicarMudancaVPN` com `nft -c` falhando chama `desfazer` e não aplica;
  - `RenderizarNoBoot` sem aplicada: aplicada := em edição (revisão `conversao`) e aplica sem janela.

**Aceite:** testes verdes; testes antigos do pacote continuam verdes.

---

### T6 — Conversão do legado (`ConverterLegadoUmaVez`)

**Arquivos:** criar `internal/firewallrules/zonas_conversao.go` e `zonas_conversao_test.go`.

- [ ] `type FatosConversao struct { RedesVCN []string; RedeVPN string; InterfaceVPN string; PlacasWAN []string }`
- [ ] `func (s *Service) ConverterLegadoUmaVez(ctx context.Context, f FatosConversao) error` —
  implementa o §3.2 inteiro, numa transação, com a trava `fw_zonas_convertido`, gravando o
  relatório `fw_conversao_relatorio`. Não chama nft (quem aplica é `RenderizarNoBoot`, logo depois).
- [ ] **Testes** (tabela, um caso por linha do mapeamento do §3.2, mais):
  - regra com `saddr` da VPN → aba VPN; com `iif linkguard` → VPN; com `saddr` 10.0.0.x → VCN;
    com `saddr` público → Internet; sem origem → Flutuantes desativada com `[revisar]`;
  - grupo de entrada vira destino `self`; grupo de passagem com `cond_daddr` vira destino `addr`;
  - `fallthrough drop` gera a regra de sobra no fim;
  - dois grupos com o mesmo horário geram **um** agendamento;
  - grupos `wireguard_peer` e regras `ZTNA:` não geram nada;
  - `firewall_wan_mgmt_closed` ausente → regra de gerência ativa; `= 1` → desativada;
  - rodar duas vezes não duplica (trava);
  - **caminhos preservados** (§3.2): renderizar o resultado da conversão de um banco "como a
    produção" (um grupo por pessoa da VPN, um admin total, um restrito, nenhuma regra do admin,
    políticas `accept`) e simular: gerência pela Internet continua, gerência pela VCN continua,
    pessoa total alcança a caixa e a Internet, pessoa restrita **não** alcança 22/9997.

**Aceite:** testes verdes.

---

### T7 — VPN: parar de escrever regras, perfis por alias, aplicar pelo pipeline

**Arquivos:** `internal/wireguard/service.go`, `internal/storage/repo_wireguard.go`,
`internal/api/handlers/wireguard.go`, `internal/api/handlers/users.go`, testes de cada um.

- [ ] Em `internal/wireguard/service.go`: remova tudo que escreve em `firewall_groups`/
  `firewall_rules` — o grupo por pessoa em `applyEnabled` (l.219-236), em `enroll` (l.473-478) e em
  `SetPeerAccess` (l.681-698); `reconcilePeerZTNARules` (l.707-772); `reconcilePeerInputGroup`,
  `deletePeerInputGroup`, `inputGroupID` (l.1007-1076). `Reconcile` passa a cuidar só do arquivo
  do WireGuard e do serviço.
- [ ] `UpsertWireGuardPeer` deixa de receber e gravar grupo; `EnsureWireGuardPeerGroup`
  (`repo_wireguard.go:477`) é apagada. A coluna `firewall_group_id` fica sem uso, mas é `UNIQUE`:
  **continue gerando um UUID novo para ela** como hoje (gravar `''` em duas pessoas violaria o
  `UNIQUE`). Não crie migração para isso.
- [ ] `resolveRoutes` (l.560-575) e `Mine` (l.1100-1142) passam a ler os itens dos aliases da
  **config aplicada** (`db.CarregarConfigAplicada()`), não de `host_groups`.
- [ ] Perfil: `normalizeAccess` (l.963-1002) valida que cada ID em `AllowedHostGroups` é alias de
  **endereços** existente na config **aplicada** (senão 400 `"alias de endereços inexistente ou
  ainda não aplicado"`). O perfil da VPN só enxerga aliases aplicados: o que aplica o perfil é o
  pipeline da VPN, que renderiza a config aplicada — um alias que só existe em edição não teria set
  no nft.
- [ ] Handler (`handlers/wireguard.go`): `reconcileIntegrations` (l.150-162) é substituído por
  `frSvc.AplicarMudancaVPN(ctx, usuário, resumo, escrever, desfazer)` em `UpdateConfig`,
  `EnrollSelf`, `revoke`, `SetPeerAccess` e `EnrollPeer`. `escrever` é a gravação que cada
  endpoint já faz; `desfazer` regrava o estado lido antes. A recarga do DNS da VPN continua depois
  (`SetDNSReload`). Erro do pipeline **volta ao cliente** (hoje `SetPeerAccess` responde 200 mesmo
  quando a integração falha — l.230-232 — corrija).
- [ ] Apagar usuário (`handlers/users.go:238`) também passa por `AplicarMudancaVPN` quando o usuário
  tinha peer (hoje sobra o grupo de entrada órfão e nada reconcilia).
- [ ] Desligar a VPN: com `PortaWireGuard = 0` e `RedeVPN = ""`, as linhas de pessoas somem da
  renderização (hoje os grupos ficam ativos no nft com a VPN desligada).
- [ ] **Testes**: VPN não escreve mais em `firewall_rules` (conte linhas antes/depois); perfil com
  alias inexistente = 400; `SetPeerAccess` com `nft -c` falhando volta o perfil anterior e responde
  erro; apagar usuário com peer chama o pipeline.

**Aceite:** testes de `internal/wireguard` e `internal/api/handlers` verdes.

---
### T8 — Ligar no `main.go` e na ordem de boot

**Arquivos:** `cmd/linkguard-cloud/main.go`, `cmd/linkguard-cloud/platform.go`,
`internal/nftables/bootstrap.go` (+ goldens), testes em `cmd/linkguard-cloud/*_test.go`.

- [ ] **Fonte de insumos** (`frSvc.SetFonteInsumos`), montada no `buildServices` perto das outras
  fontes (hoje entre as linhas ~538 e ~680):
  - `RedesVCN` = `redesLocais(db, plat)` (`platform.go:67`; corrija o comentário velho que ainda
    cita `netsvc.Config.SubnetCIDR`, que não existe mais);
  - `RedeVPN`/`PortaWireGuard`/`InterfaceVPN` de `wgSvc` (`InputPort()` e `DNSBinding()` já dão
    porta, habilitado e prefixo; `wireguard.InterfaceName`);
  - `PortasGerencia` = SSH (`system.SSHPorts`, 22 se vazio) + `cfg.Port` + `cfg.ExtraPorts`,
    ordenadas e sem repetição (é o que `portasDeGerenciaLista`, `internal/nftables/waninput.go:269`,
    faz hoje — leve a função para o código novo antes de apagar o `waninput.go` na T14);
  - `Pessoas` de `db.ListWireGuardPeers()` (endereço sem `/32`, `access_mode == "full"`,
    `allowed_host_groups`, `allowed_ports`); vazio com a VPN desligada;
  - `Existentes` de `nftSvc.ObjetosExistentes(ctx)`.
- [ ] `SetZoneFactsSource` (main.go:565): `LocalNets` passa a ser `redesLocais(db, plat)` **mais**
  `frSvc.RedesVCNExtrasAplicadas()` — contabilidade, fluxos e MSS usam a mesma noção de "local"
  que o alias VCN.
- [ ] **Nova ordem no `provisionSystem`**:
  1. `frSvc.RevertPendingOnBoot` (continua primeiro; agora entende snapshot v2 e descarta v1);
  2. `routeSvc.EnsureForwarding`;
  3. `wgSvc.Reconcile` (só o WireGuard, depois da T7);
  4. `nftSvc.EnsureTable` + restauração do `nft_live_snapshot` se a tabela foi criada (como hoje);
  5. `nftSvc.RemoverHerancaMultiWAN`;
  6. `server.ReconcileVPNDNS`;
  7. `ReconcileMasquerade`, `EnsureAccounting`, fluxos, `EnsureMSSClamp` (como hoje);
  8. `hostSvc.SincronizaBloqueios`;
  9. `EnsureDomainStructures` + `FlushDomainStructures`;
  10. **`frSvc.ConverterLegadoUmaVez`** (substitui `EnsureSystemGroups`, `ImportOnce` e
      `MigrateRulesIntoDefaultGroup`);
  11. **`frSvc.RenderizarNoBoot`** (substitui `ReconcileInputProtection` e `frSvc.Reconcile`);
  12. `domainRouting.Prepare/Hold`, `trafficSvc.EnsureAccounting`, `unboundSvc.EnsureResolvConf`
      (como hoje);
  13. `go frSvc.WatchPending(ctx, 5*time.Second)`.
  Remova o ramo de erro que chama `nftSvc.ReconcileNTPInput` (main.go:1210-1213) e o
  `ntpInputState` (l.495).
- [ ] **Bootstrap** (`buildBootstrapRuleset`, `bootstrap.go:92`): sem `user_rules`, sem
  `blocked_macs`, sem as linhas de drop e o `jump user_rules` na `forward`; `forward` e `input`
  nascem vazias com política `accept` (o script de zonas as preenche no passo 11). Regrave os
  goldens `testdata/zonas/geradores/*/buildBootstrapRuleset.txt` e
  `testdata/zonas/comandos/*/EnsureTable.txt` com `-update` e revise o diff.
- [ ] **Testes de ligação** (`boot_order_test.go`, `boot_wiring_runtime_test.go`,
  `policy_guard_test.go`, `zone_wiring_test.go`): troque os que travam a ordem antiga por:
  `RevertPendingOnBoot` antes de qualquer render; `ConverterLegadoUmaVez` antes de
  `RenderizarNoBoot`; `SetFonteInsumos` ligada; `SetPersistGuard` continua ligada. Apague os
  testes de NTP (`TestNTPInputIsReconciledAfterTheGroupChainsExist` e afins) e os que exigem as
  fontes de política (`TestMainLigaAsDuasFontesJuntas`, `TestMainNaoLigaPoliticaRestritiva`).
  Esses testes leem o `main.go` com `go/parser` e exigem receptores chamados exatamente `frSvc` e
  `nftSvc` (comentário em main.go:843-849) — mantenha os nomes.

**Aceite:** `go build ./...`, `go vet ./...`, `go test ./...` verdes. Numa execução em dry-run
(`firewall.NewDryRunExecutor`), o boot registra **um** `nft -f` com o script de zonas.

---

### T9 — API nova do firewall

**Arquivos:** criar em `internal/api/handlers/`: `fw_regras.go`, `fw_aliases.go`,
`fw_agendamentos.go`, `fw_nat.go`, `fw_aplicar.go`, `fw_estado.go`, `fw_historico.go` (respeite o
limite de 6 imports internos por arquivo) e testes; registrar em `internal/api/server.go`.

- [ ] Rotas (todas atrás de `authSvc.Middleware`; `R` = `require(auth.PermFirewallRead)`,
  `W` = `require(auth.PermFirewallWrite)`):

| Método | Caminho | Perm | Corpo → resposta |
|---|---|---|---|
| GET | `/api/firewall/estado` | R | → `{pendente, n_mudancas, janela: pendingView\|null, aplicado_em, aplicado_por, ultimo_erro, conversao: [..]\|null, bloqueios_aplicados: bool}` |
| GET | `/api/firewall/regras?zona=` | R | → `{zona, linhas: [LinhaView]}` |
| POST | `/api/firewall/regras` | W | `RegraBody` → 201 regra |
| PUT | `/api/firewall/regras/{id}` | W | `RegraBody` → regra |
| DELETE | `/api/firewall/regras/{id}` | W | → `{status:"ok"}` |
| POST | `/api/firewall/regras/{id}/ativar` | W | `{ativa}` |
| POST | `/api/firewall/regras/{id}/duplicar` | W | → 201 cópia, logo abaixo da original |
| POST | `/api/firewall/regras/ordem` | W | `{zona, ids}` (lista completa das regras do admin daquela zona) |
| POST | `/api/firewall/regras/previa` | R | `RegraBody` → `{nft: [{chain, texto}], problemas}` |
| GET | `/api/firewall/aliases` | R | → `[AliasView]` (inclui os embutidos com `embutido: true` e itens resolvidos; `usos: n`) |
| POST | `/api/firewall/aliases` | W | alias → 201 |
| PUT, DELETE | `/api/firewall/aliases/{id}` | W | DELETE em uso → **409** `{erro, usos: [..]}`; embutido → 400 |
| PUT | `/api/firewall/aliases/sys:vcn/extras` | W | `{redes: []}` → grava `Ajustes.RedesVCNExtras` |
| GET, POST | `/api/firewall/agendamentos` | R / W | |
| PUT, DELETE | `/api/firewall/agendamentos/{id}` | W | DELETE em uso → 409 |
| GET, POST | `/api/firewall/nat` | R / W | encaminhamentos |
| PUT, DELETE | `/api/firewall/nat/{id}` | W | |
| POST | `/api/firewall/nat/{id}/ativar` | W | `{ativo}` |
| GET, PUT | `/api/firewall/ajustes` | R / W | `fwmodel.Ajustes` (sem `RedesVCNExtras`, que tem rota própria) |
| GET | `/api/firewall/pendencias` | R | → `firewallrules.Pendencias` |
| POST | `/api/firewall/aplicar` | W | → `{status:"ok", pending?: pendingView}`; erros pelo `writeGuardError` (400/409/500) |
| POST | `/api/firewall/descartar` | W | |
| GET | `/api/firewall/historico` | R | → revisões (sem a config) |
| POST | `/api/firewall/historico/{id}/restaurar` | W | coloca a revisão em edição (fica pendente) |
| POST | `/api/firewall/conversao/entendi` | W | apaga `fw_conversao_relatorio` |

  Todas as escritas na config em edição passam por `frSvc.EditarConfig` (409 com janela aberta).
  Cada objeto é validado sozinho na escrita (formato dos campos, com as funções de `fwmodel`); a
  validação cruzada completa acontece em `/pendencias` e `/aplicar`.
- [ ] `LinhaView` (o que a tabela da tela consome):
  ```json
  { "chave": "r:<uuid>", "tipo": "admin|travada|padrao|implicita", "zona": "vpn",
    "regra": { ...fwmodel.Regra... },
    "nomes": { "origem": "admin-casa", "destino": "Este firewall", "porta": "Gerência", "agendamento": "" },
    "editar_em": "", "desc_chave": "", "desc_vars": {},
    "contador": { "pacotes": 12, "bytes": 3400, "medido": true },
    "mudanca": "nova|alterada|",
    "nft": [ { "chain": "zona_inet_in", "texto": "ip saddr @fwa_… tcp dport @fwp_gerencia counter accept comment \"r:…\"" } ] }
  ```
  `linhas` vem de `frSvc.Linhas(zona)` (render da config **em edição**), contadores de
  `nftSvc.ContadoresPorChave` (medidos no que está **aplicado**), `mudanca` comparando a regra em
  edição com a aplicada pelo ID.
- [ ] Auditoria (`auditAction`): `fw.regra.criar|alterar|apagar|ativar|desativar|duplicar|ordem`,
  `fw.alias.criar|alterar|apagar`, `fw.vcn.extras`, `fw.agendamento.*`, `fw.nat.*`, `fw.ajustes`,
  `fw.aplicar` (detalhe = resumo das mudanças), `fw.descartar`, `fw.revisao.restaurar`,
  `fw.conversao.entendi`.
- [ ] **Não apague ainda** as rotas antigas (`/api/nftables/groups|rules|policy|…`,
  `/api/hostgroups`, `/api/portforward`): o painel velho ainda as usa até a T13; saem na T14.
- [ ] Testes de handler (use `newTestDB` de `handlers/testdb_test.go`): permissões por rota;
  409 com janela aberta; 409 ao apagar alias em uso; `aplicar` sem pendência; `previa` devolve as
  linhas nft; `regras?zona=vpn` traz DNS e pessoas como travadas e o padrão por último.

**Aceite:** testes verdes; `TestPackageBoundary` verde.

---

### T10 — Registro por regra

**Arquivos:** `internal/blocklog/blocklog.go` (+ teste), `internal/api/handlers/fw_registro.go`.

- [ ] `Parse` reconhece `lg:r:<12hex> `, `lg:s:<chave> `, `lg:d:<zona>:<in|fwd> ` e continua
  aceitando `lg:blk:host `/`lg:blk:dest `. `Entry` ganha `Chave string` e `Tipo string`
  (`regra|travada|padrao|legado`).
- [ ] `GET /api/firewall/registro?limit=200&q=` (R) → `{entradas: [...]}`: para `regra`, o
  handler resolve os 12 hex para a regra da config **aplicada** e devolve `zona`, `acao`,
  `descricao`; para travada/padrão, `desc_chave` i18n. Sem interruptor geral: quem registra é a
  caixa de cada regra (e as de Ajustes).
- [ ] Testes do parser com linhas reais de `journalctl -k -o short-iso` (guarde exemplos em
  `internal/blocklog/testdata/`).

---

### T11 — Backup e restauração

**Arquivos:** `internal/backup/data.go`, `internal/backup/restore.go` (+ testes),
`internal/api/handlers/backup.go`.

- [ ] `BackupData` ganha `Firewall *fwmodel.Config \`json:"firewall,omitempty"\`` com a config
  **aplicada**; suba a versão do formato.
- [ ] Restaurar: se `Firewall` veio, `fwmodel.Validar` (erro → a restauração inteira falha com 400)
  e `SubstituirConfigEmEdicao` — **nunca** direto na aplicada. A resposta ganha
  `firewall_pendente: true` e o painel leva o admin para ver as diferenças e aplicar (com janela,
  se mexer no acesso). Isso fecha o buraco de hoje, em que restaurar `firewall_input_policy=drop`
  valia no próximo reconcile sem janela nenhuma.
- [ ] `fw_zonas_convertido` e `fw_conversao_relatorio` entram em `machineLocalSettingKeys`
  (`restore.go:120`): não se restauram.
- [ ] Teste: backup → restore em banco novo deixa em edição = aplicada do original e aplicada do
  destino intocada; backup com config inválida é recusado.

---

### T12 — Painel, parte 1: dados, página, aba Regras, editor, barra de pendências

**Arquivos:** criar `web/src/types/firewall.ts`, `web/src/lib/fwZonas.ts` +
`web/src/lib/fwZonas.check.ts` (registrar em `package.json` → script `check`),
`web/src/lib/useFirewallEstado.ts`, `web/src/components/firewall/zonas/{PendingChangesBar,DiffModal,RulesTab,RulesTable,RuleEditor,PontaPicker,PortaPicker,ConversionNotice}.tsx`,
`web/src/i18n/strings/firewall-zonas.yaml` (prefixo **`fwz.`**); alterar `web/src/pages/Firewall.tsx`.

- [ ] **Tipos** (`types/firewall.ts`) espelhando a API da T9 (Zona, Ponta, Porta, RegraFW,
  AliasFW, AgendamentoFW, EncaminhamentoFW, AjustesFW, LinhaFW, PendenciasFW, MudancaFW,
  ProblemaFW, EstadoFW, RevisaoFW, RegistroFW).
- [ ] **`lib/fwZonas.ts`** (puro, testado em `fwZonas.check.ts`): ordem e chaves i18n das zonas;
  `nomePonta(p, nomes, t)`; `podeArrastar(linha)` (só `tipo === 'admin'`);
  `idsAposMover(linhas, de, para)` (devolve a lista completa de IDs do admin da zona, ignorando
  travadas e padrão); `contarMudancas(mudancas)`; `validarFormulario(regra)` (as mesmas regras de
  formato do servidor, para avisar antes de salvar).
- [ ] **`useFirewallEstado`**: `GET /api/firewall/estado` a cada 5 s (só com `firewall.read`),
  com pausa quando a aba do navegador está oculta.
- [ ] **`pages/Firewall.tsx`**: abas `regras` (padrão), `aliases`, `agendamentos`, `nat`,
  `destinos`, `registro`, `historico`, `avancado`, pelo `?tab=` (como hoje). Aba de zona pelo
  `?zona=` (padrão `internet`). Redirecione os ids velhos: `overview|posture|groups` → `regras`;
  `hostgroups` → `aliases`; `portforward` → `nat`; `domains` → `destinos`; `blocklog` →
  `registro`; `ruleset|backups` → `avancado`. Proteja o conteúdo com `can('firewall.read')` (hoje
  só o menu esconde). **Mantenha o literal** `<DomainTargets canEdit={can('firewall.write')}`
  dentro de `Firewall.tsx` — `web/src/lib/domainTargets.check.ts:53` confere esse texto.
- [ ] **`PendingChangesBar`** (em todas as abas do Firewall, fixa no topo): "A configuração do
  firewall mudou: {n} mudanças. Aplique para as mudanças valerem." + **Ver diferenças** /
  **Descartar** (com confirmação dentro da própria barra — o visualizador não mostra `confirm()`
  confiável) / **Aplicar mudanças**. Aplicar e Descartar usam `useConfirmOrRevert().run(...)`
  (`lib/useConfirmOrRevert.ts`) para herdar travamento, mensagens e a adoção da janela. Com
  problemas de severidade "erro", o botão Aplicar fica desabilitado e a barra lista os problemas.
- [ ] **`DiffModal`**: mudanças agrupadas por objeto, em frases (`fwz.diff.*`); aviso quando
  `precisa_janela` ("Esta mudança mexe no acesso a esta máquina: depois de aplicar você terá 90
  segundos para confirmar"); botão "Ver em nftables" mostra `diff_nft` num `<pre>` com `+`/`-`
  coloridos (rolagem horizontal própria).
- [ ] **`RulesTab` + `RulesTable`**: sub-abas das 4 zonas com a contagem de regras do admin;
  texto curto de cada zona no topo (`fwz.zona.<z>.nota`, os textos do protótipo); colunas:
  arrastar · # · ação · protocolo · origem · destino · porta · agendamento (ícone) · registrar
  (ícone) · descrição · pacotes · ações.
  - Travadas: fundo sutil, selo "travada", sem arrastar; a ação é um link "Editar em …" conforme
    `editar_em` (`vpn` → `/vpn`; `nat` → `?tab=nat`; `maquinas` → `/hosts`; `destinos` →
    `?tab=destinos`; `ajustes` → `?tab=avancado`).
  - Do admin: arrastar (HTML5 nativo, como `FirewallGroups.tsx:299-309`, incluindo o
    `dataTransfer.setData('text/plain', …)` que o Firefox exige), ligar/desligar, editar, duplicar,
    apagar; selo "nova"/"alterada" quando `mudanca` vier preenchido.
  - Padrão: última linha, sem ações, texto `fwz.padrao.<zona>` (na VCN: "Para a Internet:
    liberar. Para esta máquina: bloquear.").
  - Implícitas: bloco recolhido (`<details>`) no topo de Flutuantes.
  - Contadores: "—" quando `medido` é falso; números com o idioma ativo (hoje há `'pt-BR'`
    cravado em `FirewallGroups.tsx`; não repita).
  - Celular (< `sm`): cartões empilhados, sem arrastar; botões subir/descer (também servem de
    alternativa acessível no desktop).
  - Edição desabilitada enquanto houver janela aberta (`editDisabled`), como hoje.
- [ ] **`RuleEditor`** (modal `ui/Modal`): zona (vem da aba), ação (liberar/bloquear/rejeitar),
  protocolo, origem e destino (`PontaPicker`: Qualquer · Este firewall [só destino] · Alias
  [`ui/Combo` com embutidos e do admin, filtrando por tipo endereços] · Máquina [os alvos de
  `useNetTargets`, que viram `addr`] · Endereço/rede digitado), porta de destino (`PortaPicker`:
  Qualquer · Porta ou faixa · Alias de portas · Serviço conhecido de `lib/services.ts`),
  agendamento (Sempre + lista), "registrar", descrição, ativa. No modo Avançado
  (`useUIMode().isSimple === false`) mostra a prévia `POST /api/firewall/regras/previa`. Salvar
  grava **só em edição** e fecha; a barra de pendências aparece.
- [ ] **`ConversionNotice`**: com `estado.conversao` preenchido, aviso no topo do Firewall com a
  lista do relatório e o botão "Entendi" (`POST /api/firewall/conversao/entendi`).
- [ ] **i18n**: tudo em `firewall-zonas.yaml` (`fwz.*`), `pt` e `en`. Rótulos de ação:
  liberar/bloquear/rejeitar (en: pass/block/reject); zonas: Flutuantes/Internet/VCN/VPN
  (en: Floating/Internet/VCN/VPN).

**Aceite:** `npm run check` e `npm run build` verdes; nenhum texto novo cravado em TSX.

---

### T13 — Painel, parte 2: aliases, agendamentos, NAT, destinos, registro, histórico, avançado, VPN, Máquinas

**Arquivos:** criar `web/src/components/firewall/zonas/{AliasesTab,AliasEditor,SchedulesTab,ScheduleEditor,NatTab,NatEditor,DestinosTab,FirewallLog,HistoryTab,AdvancedTab}.tsx`;
alterar `web/src/pages/Vpn.tsx`, `web/src/components/vpn/{AccessForm,PeerList,PeerAccessModal,MyVpn}.tsx`,
`web/src/pages/Hosts.tsx`, `web/src/lib/blockGroups.ts` (+ check), `web/src/components/Recipes.tsx`,
`web/src/i18n/strings/*.yaml`.

- [ ] **Aliases**: lista com nome, tipo, itens (resumidos), descrição e "usado por N"; os
  embutidos primeiro, travados; VCN mostra as redes detectadas (só leitura) e as **extras**
  (editáveis pela rota própria). Editor: nome, tipo (não muda depois de criado), descrição, itens
  (um por linha ou separados por vírgula). Apagar em uso mostra a lista de usos devolvida no 409.
- [ ] **Agendamentos**: lista e editor (dias como botões, início/fim `<input type="time">`,
  reaproveitando o desenho do bloco de horário de `GroupModal.tsx:140-180`, com os dias vindos do
  YAML — hoje estão cravados em `groupMeta.ts:229-235`).
- [ ] **NAT**: encaminhamentos (nome, protocolo, porta externa, IP e porta de destino, ativo),
  **com edição** (hoje só cria/liga/apaga); nota de que cada um cria a linha travada na aba
  Internet; masquerade automático mostrado só para leitura (texto `fwz.nat.saida`).
- [ ] **Destinos**: painel "Destinos bloqueados por endereço" (lista via `/api/nftables/managed`,
  add/remove via `/api/nftables/blocklist`, imediato) + o `DomainTargets` existente.
- [ ] **Registro**: tabela com hora, regra (descrição, zona, ação), origem, destino, protocolo,
  portas; busca; atualização a cada 5 s; sem interruptor geral — texto explicando que se registra
  marcando "registrar" na regra.
- [ ] **Histórico**: revisões (quando, quem, motivo, resumo) com "Restaurar para edição".
- [ ] **Avançado**: ajustes (anti-bloqueio VCN e VPN, contenção de abuso, registrar os padrões),
  a lista de contidos (leve o `CartaoContidos` de `FirewallPosture.tsx:406`) e o `nft list
  ruleset` só leitura (hoje em `Firewall.tsx:183-186`).
- [ ] **VPN**: `AccessForm` lista aliases de endereços **aplicados**
  (`GET /api/firewall/aliases`, filtrando `tipo=enderecos` e não embutidos) no lugar de
  `/api/hostgroups`; textos "grupos de hosts" → "aliases" (inclusive `vpn.access.noGroups`, que
  hoje manda criar "em Firewall, na aba Grupos de hosts"); tire as notas de "grupo gerenciado pela
  VPN". Depois de salvar perfil, a janela de 90 s (quando abrir) aparece pelo banner global que já
  existe (`PendingWindowBanner`).
- [ ] **Máquinas** (`pages/Hosts.tsx`): troque a leitura de `/api/nftables/groups` (l.85) por
  `/api/firewall/estado` (`bloqueios_aplicados`); simplifique `blockEnforcement`
  (`lib/blockGroups.ts`) para `ok | not_applied | unknown` (o bloqueio agora fica acima de tudo,
  não pode ser "sombreado" nem desligado) e atualize o `blockGroups.check.ts`; os links
  `/firewall?tab=groups` (l.211, 229, 489) viram `/firewall?tab=regras&zona=flutuante`.
- [ ] Textos que citam telas que deixam de existir (levantados no código):
  `fwx.backups.explain.2`, `fw.stage.forward.hint`, `fw.overview.editInGroups`,
  `recipes.yaml:85` ("Firewall → Encaminhamento" → "Firewall › NAT"), `vpn.yaml:163`,
  `svc.hosts.openGroups`, e as frases cravadas em `lib/blockGroups.ts:114-169`.
- [ ] Chaves usadas e inexistentes hoje (`common.filter`, `common.refresh`, `common.edit`,
  `common.delete`): se algum componente que fica ainda as usa, crie-as em `common.yaml`.

**Aceite:** `npm run check` e `npm run build` verdes.

---

### T14 — Apagar o legado

Só depois de T1–T13 verdes. Apague, e rode tudo a cada bloco:

- [ ] **API**: rotas `/api/nftables/{overview,rules*,groups*,policy,wan-management,edge-containment,block-log*,backup,backups,rollback}`,
  `/api/nftables/rules/preview`, `/api/nftables/groups/preview`, `/api/hostgroups*`,
  `/api/portforward`; handlers `groups.go`, `policy.go`, `preview.go`, `hostgroups.go`,
  `portforward.go`, `blocklog.go` (o velho), partes de `nftables.go` (regras, overview, backups,
  rollback) e o `mutation` de `guarded.go` (mantenha `writeGuardError`). **Ficam:**
  `/api/nftables/ruleset` (o cartão de primeiros passos procura `masquerade` nele —
  `GettingStarted.tsx:74`), `/api/nftables/pending*`, `/api/nftables/abusers`,
  `/api/nftables/blocklist`, `/api/nftables/managed` (sem `blocked_macs`).
- [ ] **`internal/nftables`**: `groups.go`, `reconcile_groups.go`, `merge_groups.go`,
  `group_names.go`, `user_rules.go`, `policy.go`, `survival.go`, `waninput.go`, `exposicao.go`,
  `classify.go`, `overview.go` (o `Ruleset()` de `service.go` fica), e de `reconcile.go` as
  funções `inputChainRules`, `reconcileInputChain`, `ReconcileInputProtection`,
  `ReconcileNTPInput`, `forwardChainRules`, `CheckChainEnsuring`, `renderChainScriptEnsuring`,
  `rebuildChain*` (se não sobrar uso). De `service.go`: `SetInputChainSources`,
  `ntpInputSource`, `inputChainGroups`, `ntpInputState`, `BlockedMACSet`, `EnsureBlockedMACSet`,
  `Managed.BlockedMACs`, `UserChain`, `ListUserRules`, `parseRuleFields`, `expressionTokens`,
  `ExpressionMatches`, `ValidateRuleFields`, `buildRuleTokens` (os validadores `reIface`,
  `validPort` e de IPv4 que o renderizador novo usa ficam), `SetBlockLogSource`/`logBlocks`,
  `DeleteUnreferencedChain`, e também `ApplyPortForwards`/`dnatRule`/`PortForward`
  (`service.go:850-930`): o DNAT agora sai do script de zonas (§2.5, defeito 6). Fica:
  `sanitizeNetworks` (usado por `NewZone`), `Zone`, contabilidade, fluxos, MSS, masquerade,
  domínios, abusers (`EnsureAbusersSet`, `Contidos`, `Liberar`), persistência, `Restore`.
- [ ] **`internal/firewallrules`**: `migrate_groups.go`, `ghostiface.go`, `revert_merge.go`,
  `ImportOnce`, `CheckPending*`, `StoredGroups*`, `ToStoredGroup`, `Reconcile`, `ApplyGuarded` e
  `Mutation` (mantenha `Stage`, `GuardError`, `StageOf`, `Applied`, usados pela API), os
  setters de política de `policy.go` (as constantes das chaves ficam na conversão). Os tipos de
  alerta `FirewallSystemGroupsMissing` e `GhostIface` vão para a lista de tipos aposentados de
  `internal/alerts` (a mesma que fecha alertas abertos de tipos que deixaram de existir no boot).
- [ ] **`internal/storage`**: funções de grupo/regra de `repo_firewall.go` (mantenha todas as de
  `PendingChange`), `repo_hostgroups.go`, `FirewallRule` em `models.go`. **Não** apague as
  tabelas (limpeza numa migração futura).
- [ ] **Alvos por domínio**: `DomainRoutingSnapshot` (`internal/storage/repo_domtargets.go:279`)
  lê `firewall_groups WHERE kind = 'blocklist'` para saber se o bloqueio está ligado. No modelo
  novo "Destinos bloqueados" é linha travada sempre ativa: devolva presente/ligado = verdadeiro,
  apague os motivos `ReasonBlockingGroupMissing`/`ReasonBlockingGroupDisabled`
  (`internal/domainrouting/coordinator.go:38-39, 206-208`) e os textos `fwx.domains.*` que falam
  deles. Os handlers que chamavam `domainRouting.Reconcile` depois de ligar/desligar grupo somem
  com eles.
- [ ] **`cmd/linkguard-cloud/main.go`**: setters que ficaram sem uso (`SetInputPolicySource`,
  `SetForwardPolicySource`, `SetWANMgmtClosedSource`, `SetEdgeContainmentSource`,
  `SetAdminAccessSource`, `SetBlockLogSource`, `SetWANInterfacesSource` se não sobrar uso,
  `SetWireGuardInputSource`), o campo `ntpInputState` de `services`.
- [ ] **Painel**: `components/FirewallGroups.tsx`, `FirewallOverview.tsx`, `PortForwarding.tsx`,
  `components/firewall/{GroupList,GroupModal,RuleModal,RuleWizard,NftPreview,FirewallPosture,SystemGroupMembers,HostGroupsTab,BlockLog}.tsx`,
  `groupMeta.ts`, `lib/{groupRules,posture,ruleDesc,ruleWizard,useNftPreview}.ts` e seus
  `.check.ts` (tire-os do script `check` do `package.json`); tipos velhos de
  `types/index.ts` (`FirewallRule`, `FirewallGroup*`, `NftManaged.blocked_macs`, `HostGroup`,
  `PortForward`, `BlockLog*`, `FirewallRulesData`, `FirewallApplyStatus`, `NftChainInfo`, …) que
  ficarem sem uso. Mantenha `netTargets`/`useNetTargets` (o `PontaPicker` usa).
- [ ] **i18n**: remova as chaves que ficaram sem uso — prefixos `fw.group*`, `fw.groups*`,
  `fw.posture*`, `fw.exposure*`, `fw.scope*`, `fw.connState*`, `fw.fallthrough*`,
  `fw.systemKind*`, `fw.sysmembers*`, `fw.overview*`, `fw.stage*`, `fw.wizard*`, `fw.rule*`,
  `fw.pf*`, `fwx.hostgroups*`, `fwx.blocklog*`, `fwx.groups*`, `desc.*`, `fwx.owner.*`
  (e o teste Go `internal/nftables/owner_i18n_test.go`, que as confere). **Antes de apagar cada
  prefixo, confirme com `grep -rn "<prefixo>" web/src --include=*.ts --include=*.tsx` que não há
  uso.**
- [ ] **Documentação**: `FEATURES.md` e o parágrafo do firewall no `README.md`; no topo de
  `docs/superpowers/specs/2026-08-11-firewall-rule-groups-design.md`,
  `2026-08-12-blocks-as-groups-design.md`, `2026-08-11-firewall-page-redesign-design.md` e
  `2026-08-13-grupo-so-conexoes-novas-design.md`, uma linha "Substituído por
  `docs/superpowers/plans/2026-09-25-firewall-por-zonas-plan.md`".
- [ ] `scripts/vm-validate.sh` (script de validação da versão on-prem) **não** é atualizado aqui:
  a validação da nuvem será reescrita à parte (§6).

**Aceite final:** `gofmt -l` vazio, `go vet ./...`, `go test ./...`, `npm run check`,
`npm run build` — tudo verde; `grep -rn "blocked_macs\|user_rules\|grp_\|ReconcileGroups\|hostgroups" internal cmd web/src --include=*.go --include=*.ts --include=*.tsx`
só encontra a limpeza do legado no renderizador, a conversão e a migração 104.

---

## 5. Commits sugeridos

Um por tarefa, mensagem em português no estilo do repositório (verbo no presente, dizendo o que
muda para quem usa):

- T1 `feat(fwmodel): a configuração do firewall ganha um modelo próprio, com validação e diferenças`
- T2 `feat(storage): tabelas do firewall por zonas, e grupos de hosts viram aliases`
- T3 `feat(nftables): o firewall por zonas vira um script só`
- T4 `feat(nftables): testar, aplicar de uma vez e ler contadores pelo comentário`
- T5 `feat(firewall): aplicar, descartar e reverter a configuração por zonas`
- T6 `feat(firewall): as regras de hoje são convertidas para as zonas`
- T7 `fix(vpn): o perfil de cada pessoa passa pelo mesmo aplicar do firewall`
- T8 `feat: o boot aplica o firewall por zonas`
- T9 `feat(api): regras, aliases, agendamentos e NAT por zona`
- T10 `feat(firewall): registro por regra`
- T11 `fix(backup): o firewall restaurado fica pendente até alguém aplicar`
- T12 `feat(painel): regras por zona com aplicar e diferenças`
- T13 `feat(painel): aliases, agendamentos, NAT, registro e histórico`
- T14 `refactor: sai o firewall por grupos`

**Não faça push.** O dono revisa o ramo e decide.

---

## 6. Validação em máquina real (feita depois, fora deste plano de código)

Não execute: fica registrado para quem for provar numa VM descartável da OCI (apagada no fim,
volume de boot incluído). Cenários:

1. Instalação nova: painel alcançável pela Internet logo depois de instalar; NAT da VCN funcionando;
   aba Internet com a regra de gerência ativa.
2. Upgrade a partir da versão publicada, com dados parecidos com os da produção (um admin com VPN
   total, uma pessoa restrita a um alias com porta 6443, um encaminhamento): relatório de
   conversão coerente; gerência pela Internet, pela VCN e pela VPN total continua; a pessoa
   restrita alcança só o alias/porta e o DNS, **não** o 22/9997.
3. Janela: aplicar uma regra que fecha a gerência pela Internet e não confirmar → volta sozinho em
   90 s; confirmar → fica. Reiniciar a máquina com janela aberta → volta no boot.
4. VPN: mudar o próprio perfil de total para restrito → janela; não confirmar → volta.
5. DNS pela VPN com pessoa total e restrita (defeito 3).
6. Bloquear máquina derruba conexão já aberta (o bloqueio fica antes do `established`).
7. Registro: regra com "registrar" aparece no Registro com o nome; limite de 10/s respeitado.
8. Agendamento: regra que só vale num horário.
9. Reboot: tudo volta igual pelo `/etc/nftables.conf` e pelo render do boot; `nft list table inet
   linkguard` sem `grp_*`, `user_rules`, `blocked_macs`.

---

## 7. Armadilhas conhecidas (leia antes de T3, T4 e T8)

- **O nft só apaga chain vazia e sem referência.** No script, `flush` de `input`/`forward` vem
  antes da limpeza, e cada chain legada leva `flush` antes do `delete`.
- **`add set` com declaração diferente da existente falha.** Os sets que outras partes do produto
  enchem (`blocklist`, `blocked_hosts`, `dom_blocked`, `dom_blocked6`, `abusers`) têm de ser
  declarados exatamente como hoje — copie de `bootstrap.go:95-107` e `abusers.go:50`.
- **Elementos sobrepostos em set `interval` dão erro.** Por isso o renderizador remove prefixos
  contidos antes de emitir `add element`.
- **Use `iifname "linkguard"`, nunca `iif`**: `iif` resolve o índice na hora de carregar e falha
  se a interface não existir (VPN desligada).
- **`accept` numa base chain não impede as outras base chains do mesmo gancho** (`acct` em
  `filter + 10`, `flows` em `filter + 15`, `mss_clamp` em `mangle`) — a contabilidade continua
  vendo tudo. `drop` é final.
- **Mudar regra não derruba conexão aberta** (o `established` vem antes das zonas). Diga isso no
  texto de ajuda da aba Regras. Os dois bloqueios travados são a exceção de propósito.
- **Persistência com janela aberta** continua bloqueada (`SetPersistGuard`), para um reboot no meio
  da janela não eternizar uma mudança não confirmada.
- **O `Restore` recusa snapshot com entrada em `drop`** (`service.go:522`): por isso as base chains
  do script novo ficam com `policy accept`. Não mude isso.
- **`meta hour`/`meta day`** são avaliados na hora local da máquina, como o código atual documenta
  em `schedule.go:21-34`; mostre o fuso da máquina no editor de agendamento.
- **A OCI continua filtrando na frente** (security lists/NSG): o firewall não substitui isso, e a
  porta liberada aqui pode continuar fechada lá. Vale uma linha de ajuda na aba Internet.
- **Dívidas que continuam** (não resolver aqui): o mapa `dom_wan` é escrito e ninguém lê; o
  masquerade não qualifica a origem; `Persist` usa `os.WriteFile` e não o executor; os endpoints
  `/api/iptables/*` só leem.
