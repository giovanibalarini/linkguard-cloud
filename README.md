# LinkGuard Cloud

O **LinkGuard Cloud** é o gateway de uma conta de nuvem: NAT de saída para as
instâncias privadas, firewall, VPN WireGuard por pessoa e visibilidade do
tráfego de quem passa, tudo gerenciado por um painel web. Roda numa VM de placa
única (OCI, e o desenho vale para outras nuvens) e é dono da máquina: instalou,
o NAT funciona; o resto se configura pela interface.

Nasceu do [LinkGuard FW](https://github.com/giovanibalarini/linkguard-fw), o
firewall on-prem de múltiplos links, em 24/09/2026. O histórico até ali é o
mesmo; a partir daqui os dois seguem separados, porque quase nada do on-prem
(multi-WAN, failover, Kea, SMART) existe numa VM de nuvem.

### Instalar

```bash
sudo apt install ./linkguard-cloud_<versão>_<arq>.deb
```

Numa máquina que já roda o `linkguard-fw`, o pacote o substitui: copia o estado
de `/var/lib/linkguard-fw` e `/etc/linkguard-fw` para os caminhos novos (o
original fica onde estava), liga o serviço `linkguard-cloud` e mantém as regras
nftables e a VPN de pé durante a troca.

## Project Motivation

**🇧🇷 Português**

Este projeto nasce de uma necessidade real, que acredito que nao seja somente minha, de ter redudancia de link usando uma maquina desktop comum.
Trabalho home office a mais de 10 anos e sempre dependi da estabilidade dos provedores de Internet nao cairem. Quando caiam recorria a rede 3G/4G/5G. 
Após morar com minha esposa e ambos trabalharem remoto dependi ainda mais de links de Internet e ja passei problemas com elas e contratei mais 1 link.

Como resolver para que os links trabalhassem em failover ou em paralelo?
Trabalhei muito tempo com linux e provedores de internet sem uso de appliance e tive a oportunidade de trabalhar e gerenciar firewalls com multiplas interfaces usando iptables com chains (FILTER,NAT,MANGLE), iproute2, isc-dhcp-server, bind9 como soluçoes. Sempre funcionaram muito bem porem dependiam de muitos scripts para funcionar e nao era garantia de funcionar 100%.

Com o uso de IA me permitiu desenvolver em tempo record uma soluçao madura dentro de caso com meu super firewall: um Intel Core i3-3220 de 2012 (2 nucleos / 4 threads a 3.30 GHz), 4 GB de RAM e um HD magnetico de 250 GB a 7200 RPM. Era uma maquina usada de um escritorio e ja passa dos 13 anos de idade. Adicionei 2 placas de rede e dei inicou ao desenvolvimento.

Logo nasce o linkguard, soluçao robusta para redundancia e balanceamento de link e monitoramento proativo.

**🇺🇸 English**

This project was born from a real need, one I believe is not only mine, to have link redundancy using a common desktop machine.
I've worked home office for over 10 years and always depended on Internet providers' stability not going down. When they did, I fell back to the 3G/4G/5G network.
After moving in with my wife, with both of us working remotely, I depended even more on Internet links, and we already had problems with them, so I contracted one more link.

How to solve it so the links would work in failover or in parallel?
I worked for a long time with Linux and Internet providers without using an appliance, and had the opportunity to work with and manage firewalls with multiple interfaces using iptables with chains (FILTER, NAT, MANGLE), iproute2, isc-dhcp-server, bind9 as solutions. They always worked very well, but depended on a lot of scripts to function, and there was no guarantee they would work 100%.

Using AI allowed me to develop a mature solution in record time, as a real case on my super firewall: a 2012 Intel Core i3-3220 (2 cores / 4 threads at 3.30 GHz), 4 GB of RAM and a 250 GB (magnetic) 7200 RPM hard disk. It was a used office machine, and it is already past 13 years old. I added 2 network cards and started development.

Thus LinkGuard was born, a robust solution for link redundancy and balancing, with proactive monitoring.

## Em produção hoje / Running in production today

**🇧🇷** A mesma máquina segue de pé, rodando 24/7 como firewall de borda da
casa. O disco magnético original deu lugar a um SSD, mas o resto do hardware é
o de sempre — a ideia é justamente essa: hardware de 2012 dá conta.

**🇺🇸** The same machine is still standing, running 24/7 as the home's edge
firewall. The original magnetic disk gave way to an SSD, but the rest of the
hardware is the same as always — that is exactly the point: 2012 hardware is
enough.

<table>
<tr>
<td valign="top">

| | |
|---|---|
| CPU | Intel Core i3-3220 @ 3.30 GHz — 2 cores / 4 threads (Ivy Bridge, 2012) |
| RAM | 4 GB |
| Disco / Disk | SSD 512 GB (boot) + HD 250 GB 7200 RPM (o original / the original) |
| Rede / Network | 2 links WAN + LAN, todas gigabit / all gigabit |
| SO / OS | Debian 13 (Trixie), kernel 6.12 |
| LinkGuard | 1.0.102 |

**🇧🇷** Sem rack, sem nobreak, sem sala refrigerada: um desktop de escritório
aposentado, de pé num canto, com duas placas de rede a mais. Os LEDs piscando
são os dois links de Internet passando tráfego de verdade.

**🇺🇸** No rack, no UPS, no cooled room: a retired office desktop standing in a
corner with two extra network cards. The blinking LEDs are the two Internet
links actually passing traffic.

</td>
<td width="360" valign="top">

![O firewall em produção / The firewall in production](docs/images/firewall-em-producao.gif)

</td>
</tr>
</table>

## Telas / Screenshots

**🇧🇷** Painel, tráfego, o firewall por zonas e a janela de confirmação
que evita você se trancar para fora. **🇺🇸** Dashboard, traffic, zone-based
firewall, and the confirmation window that keeps you from locking yourself out.

| Painel / Dashboard | Tráfego / Traffic |
|---|---|
| ![Dashboard](docs/images/dashboard.png) | ![Tráfego](docs/images/traffic.png) |

| Confirmar ou reverter / Confirm or revert | Widgets do painel / Dashboard widgets |
|---|---|
| ![Janela de confirmação](docs/images/confirm-window.png) | ![Catálogo de widgets](docs/images/widget-catalog.png) |

**🇧🇷** Firewall por zonas (Internet, VCN, VPN, Flutuantes) com aliases, agendamentos e aplicação atômica.
**🇺🇸** Zone-based firewall (Internet, VCN, VPN, Floating) with aliases, schedules, and atomic application.

## Futuro do Projeto

**🇧🇷 Português**

Futuramente nascera mais features porem saindo do mundo mais residencial/empresarial de pequeno porte e vamos para a Cloud.
- Substituir o cego NatGateways que existem nas Clouds hoje e traferemos rastreabilidade real e monitoramento de segurança proativo de entrada e saida de dados.
- Soluçao de VPN robusta autenticada e gerenciada via SSO + grupos e perfil.

**🇺🇸 English**

In the future, more features will be born, moving beyond the more residential/small-business world and going into the Cloud.
- Replace the blind NatGateways that exist in Clouds today, and we will bring real traceability and proactive security monitoring of data entering and leaving.
- Robust VPN solution, authenticated and managed via SSO + groups and profile.

## Convite

**🇧🇷 Português**

Para entusiastas que tambem queiram se aventurar e ajudar na evoluçao do projeto sera muito bem vindo. Pessoas e empresas que compartilham desta dor poderam fazer parte desta jornada em resolver de fato essas dores reais.

**🇺🇸 English**

For enthusiasts who also want to venture in and help the evolution of the project, it will be very welcome. People and companies that share this pain will be able to be part of this journey to actually solve these real pains.

**🇧🇷 Transforma uma máquina Debian nua em um appliance de firewall gerenciado — e então passa a ser dono dela.**

**🇺🇸 Turns a bare Debian box into a managed firewall appliance — and then owns it.**

LinkGuard Cloud is the gateway of a cloud account, managed from one web panel:
outbound **NAT** for the private instances behind it, native **nftables**
firewalling, a **WireGuard** VPN with per-person access, a DNS resolver for VPN
users (unbound) with blocklists, and visibility into who is talking to whom
(per-host traffic, flows, packet capture). The uplink comes from the platform
(the VNIC Oracle confirms) or from the kernel's default route; there are no WAN
links to register. You install it on a fresh VM; NAT works right away, and the
rest is configured from the panel.

It is written for the person who would otherwise keep a bastion alive by hand:
an iptables MASQUERADE line, a hand-edited `wg0.conf`, and no idea who is using
the tunnel.

## Installation

**🇧🇷 Português**

**Requisitos:** Debian 13 (Trixie) ou compatível, acesso root. Uma instalação
limpa (sem nada instalado) já é suficiente — você não precisa instalar
nenhuma dependência antes.

```bash
# Instala o pacote — o apt resolve e instala as dependências base
# (nftables, iproute2, iptables, iputils-ping) automaticamente
sudo apt install ./linkguard-cloud_<version>_amd64.deb

# Habilita e inicia o serviço
sudo systemctl enable --now linkguard-cloud

# Verifica o status
sudo systemctl status linkguard-cloud
```

Depois abra o painel web em `http://<ip-da-maquina>:9997`.

- **Usuário:** `admin`
- **Senha:** gerada no primeiro início — leia no log do serviço
  (`sudo journalctl -u linkguard-cloud`) ou em
  `/etc/linkguard-cloud/initial-admin-password` (modo `0600`). Troque-a
  imediatamente após o primeiro login.

**🇺🇸 English**

**Requirements:** Debian 13 (Trixie) or compatible, root access. A bare
install is enough — you do not need to install any dependencies first.

```bash
# Install the package — apt resolves and installs its base dependencies
# (nftables, iproute2, iptables, iputils-ping) automatically
sudo apt install ./linkguard-cloud_<version>_amd64.deb

# Enable and start the service
sudo systemctl enable --now linkguard-cloud

# Check status
sudo systemctl status linkguard-cloud
```

Then open the web panel at `http://<machine-ip>:9997`.

- **User:** `admin`
- **Password:** generated on first run — read it from the service log
  (`sudo journalctl -u linkguard-cloud`) or from
  `/etc/linkguard-cloud/initial-admin-password` (mode `0600`). Change it
  immediately after first login.

## License

MIT
