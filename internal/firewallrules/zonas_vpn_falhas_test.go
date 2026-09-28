package firewallrules

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-cloud/internal/fwmodel"
	"github.com/giovanibalarini/linkguard-cloud/internal/nftables"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

// nftBruto é o que o nft devolve de verdade ao recusar um script: o código de
// saída, o caminho do arquivo temporário e um trecho da própria linguagem.
// Nada disso pode chegar ao operador; tudo precisa ficar na causa (Err), para o log.
var nftBruto = errors.New("exit status 1: /tmp/linkguard-nft-apply-42.conf:7:5-9: Error: syntax error, unexpected drop")

var detalhesTecnicos = []string{
	"/tmp/", "linkguard-nft", "syntax error", "exit status", "no such table",
	"fw_aplicado", "fw_revisoes", "wireguard_peers", "pending_firewall_change", "%!",
}

func semVazamento(t *testing.T, frase string) {
	t.Helper()
	for _, proibido := range detalhesTecnicos {
		if strings.Contains(frase, proibido) {
			t.Errorf("a frase para o operador vaza detalhe técnico (%q): %q", proibido, frase)
		}
	}
}

// exigirEtapa confere que a falha é um GuardError da etapa dada e que a frase
// dele serve a quem lê o painel.
func exigirEtapa(t *testing.T, err error, etapa Stage) *GuardError {
	t.Helper()
	if err == nil {
		t.Fatalf("esperava a falha da etapa %q, não veio erro", etapa)
	}
	g := guardOf(t, err)
	if g.Stage != etapa {
		t.Fatalf("esperava a etapa %q, obteve %q (%s)", etapa, g.Stage, g.Message)
	}
	if strings.TrimSpace(g.Message) == "" {
		t.Fatal("o operador precisa de uma frase: a mensagem veio vazia")
	}
	semVazamento(t, g.Message)
	return g
}

func regraBloqueiaSSH() fwmodel.Regra {
	return fwmodel.Regra{
		ID: "r-entrada", Zona: fwmodel.ZonaVCN, Posicao: 1, Ativa: true,
		Acao: fwmodel.AcaoDrop, Proto: fwmodel.ProtoTCP,
		Origem:       fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
		Destino:      fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
		PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaValor, Valor: "22"},
		Descricao:    "Bloquear SSH",
	}
}

func regraDaPessoa(userID string) fwmodel.Regra {
	return fwmodel.Regra{
		ID: "r-pessoa", Zona: fwmodel.ZonaInternet, Posicao: 1, Ativa: true,
		Acao: fwmodel.AcaoAccept, Proto: fwmodel.ProtoTCP,
		Origem:       fwmodel.Ponta{Tipo: fwmodel.PontaAlias, Valor: fwmodel.AliasPessoaPref + userID},
		Destino:      fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
		PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaValor, Valor: "443"},
		Descricao:    "Acesso da pessoa",
	}
}

// vpnFalhas monta o serviço com uma aplicada vazia e insumos que o teste move:
// mudar a porta do WireGuard muda o hash da entrada, que é o que obriga a abrir
// a janela de confirmação.
type vpnFalhas struct {
	t       *testing.T
	svc     *Service
	db      *storage.DB
	exec    *zonasTestExec
	porta   int
	iface   string
	pessoas []nftables.PessoaVPN
}

func novaVPNFalhas(t *testing.T) *vpnFalhas {
	t.Helper()
	svc, db, exec := newZonasTestService(t)
	f := &vpnFalhas{t: t, svc: svc, db: db, exec: exec, porta: 51820, iface: "linkguard"}
	svc.SetFonteInsumos(func(context.Context) (nftables.Insumos, error) {
		return nftables.Insumos{
			RedesVCN:       []string{"10.0.0.0/16"},
			RedeVPN:        "10.7.0.0/24",
			PortaWireGuard: f.porta,
			InterfaceVPN:   f.iface,
			PortasGerencia: []int{22, 443},
			Pessoas:        f.pessoas,
		}, nil
	})
	f.aplicadaPadrao()
	return f
}

func (f *vpnFalhas) aplicadaPadrao() {
	f.t.Helper()
	f.aplicadaCom(fwmodel.Config{Formato: 1, Ajustes: fwmodel.AjustesPadrao()})
}

func (f *vpnFalhas) aplicadaCom(cfg fwmodel.Config) {
	f.t.Helper()
	if err := f.db.SubstituirConfigEmEdicao(cfg); err != nil {
		f.t.Fatalf("SubstituirConfigEmEdicao: %v", err)
	}
	if err := f.db.SalvarAplicadaERevisao(cfg, "sistema", "inicial", "conversao", time.Now()); err != nil {
		f.t.Fatalf("SalvarAplicadaERevisao: %v", err)
	}
}

// mudaAEntrada é uma escrita que mexe no que abre a caixa (a porta do
// WireGuard entra na regra de entrada): obriga a janela de confirmação.
func (f *vpnFalhas) mudaAEntrada() func() error {
	return func() error {
		f.porta = 51821
		return nil
	}
}

// desfazContando é a volta de mudaAEntrada, e conta quantas vezes rodou.
func (f *vpnFalhas) desfazContando(n *int) func() error {
	return func() error {
		*n++
		f.porta = 51820
		return nil
	}
}

func (f *vpnFalhas) semJanela() {
	f.t.Helper()
	p, err := f.db.GetPendingChange()
	if err != nil {
		f.t.Fatalf("GetPendingChange: %v", err)
	}
	if p != nil {
		f.t.Errorf("não podia haver janela de confirmação aberta, há: %+v", p)
	}
}

func (f *vpnFalhas) quebrar(tabela string) {
	f.t.Helper()
	if _, err := f.db.Conn().Exec("DROP TABLE " + tabela); err != nil {
		f.t.Fatalf("DROP TABLE %s: %v", tabela, err)
	}
}

// --- mudança reversível: escrita + firewall; se o firewall não aceita, desfaz ---

func TestMudancaVPNReversivelComNftFRecusadoDesfazEDizQueNadaMudou(t *testing.T) {
	f := novaVPNFalhas(t)
	f.exec.failApply = nftBruto

	desfeitos := 0
	_, err := f.svc.AplicarMudancaVPN(context.Background(), "admin", "mudar a porta", f.mudaAEntrada(), f.desfazContando(&desfeitos))

	g := exigirEtapa(t, err, StageReconcile)
	if g.Gravada {
		t.Error("a mudança foi desfeita: não pode constar como gravada")
	}
	if !strings.Contains(g.Message, "nada foi alterado") {
		t.Errorf("a frase precisa dizer que nada mudou, veio: %q", g.Message)
	}
	if desfeitos != 1 {
		t.Errorf("o desfazer devia rodar uma vez, rodou %d", desfeitos)
	}
	if f.exec.applies != 1 {
		t.Errorf("esperava um único nft -f (atômico, sem reaplicar o anterior), houve %d", f.exec.applies)
	}
	if !errors.Is(err, nftBruto) {
		t.Error("a causa técnica precisa ficar em Err, para o log")
	}
	f.semJanela()
}

func TestMudancaVPNReversivelComPreVooRecusadoDesfazSemTocarNoKernel(t *testing.T) {
	f := novaVPNFalhas(t)
	f.exec.failCheck = nftBruto

	desfeitos := 0
	_, err := f.svc.AplicarMudancaVPN(context.Background(), "admin", "mudar a porta", f.mudaAEntrada(), f.desfazContando(&desfeitos))

	g := exigirEtapa(t, err, StagePreflight)
	if g.Gravada || !strings.Contains(g.Message, "nada foi alterado") {
		t.Errorf("o pré-voo recusou: nada ficou gravado (Gravada=%v, %q)", g.Gravada, g.Message)
	}
	if desfeitos != 1 {
		t.Errorf("o desfazer devia rodar uma vez, rodou %d", desfeitos)
	}
	if f.exec.applies != 0 {
		t.Errorf("o nft -c recusou: o kernel não podia ser tocado, houve %d nft -f", f.exec.applies)
	}
	if !errors.Is(err, nftBruto) {
		t.Error("a causa técnica precisa ficar em Err, para o log")
	}
}

func TestMudancaVPNQueNaoConsegueDesfazerDizQueFicouPelaMetade(t *testing.T) {
	f := novaVPNFalhas(t)
	f.exec.failApply = nftBruto
	errDesfazer := errors.New("o banco não deixou desfazer")

	_, err := f.svc.AplicarMudancaVPN(context.Background(), "admin", "mudar a porta", f.mudaAEntrada(), func() error { return errDesfazer })

	g := exigirEtapa(t, err, StageStuck)
	if !g.Gravada {
		t.Error("o desfazer falhou: a mudança segue gravada")
	}
	if !strings.Contains(g.Message, "confira") {
		t.Errorf("a frase precisa mandar o operador conferir a VPN e o firewall, veio: %q", g.Message)
	}
	if !errors.Is(err, nftBruto) || !errors.Is(err, errDesfazer) {
		t.Error("as duas causas (a recusa e o desfazer que falhou) precisam ficar em Err")
	}
	f.semJanela()
}

// --- mudança sem volta (revogar, apagar usuário, girar chave): a escrita fica ---

func TestMudancaVPNSemVoltaMantemAEscritaQuandoOFirewallRecusa(t *testing.T) {
	casos := []struct {
		nome string
		usa  func(*vpnFalhas)
	}{
		{"pré-voo recusa", func(f *vpnFalhas) { f.exec.failCheck = nftBruto }},
		{"nft -f recusa", func(f *vpnFalhas) { f.exec.failApply = nftBruto }},
	}
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			f := novaVPNFalhas(t)
			c.usa(f)

			escritas := 0
			_, err := f.svc.AplicarMudancaVPN(context.Background(), "admin", "revogar", func() error {
				escritas++
				return f.mudaAEntrada()()
			}, nil)

			g := exigirEtapa(t, err, StageReconcile)
			if !g.Gravada {
				t.Error("sem volta, a mudança está gravada e a resposta precisa dizer isso")
			}
			if !strings.Contains(g.Message, "gravada") || strings.Contains(g.Message, "nada foi alterado") {
				t.Errorf("a frase precisa dizer que ficou gravada, e não que nada mudou: %q", g.Message)
			}
			if escritas != 1 {
				t.Errorf("a escrita devia rodar uma vez, rodou %d", escritas)
			}
			if !errors.Is(err, nftBruto) {
				t.Error("a causa técnica precisa ficar em Err, para o log")
			}
			f.semJanela()
		})
	}
}

// --- a janela de confirmação não arma ---

func (f *vpnFalhas) escritaQueQuebraAJanela() func() error {
	return func() error {
		f.porta = 51821
		_, err := f.db.Conn().Exec(`DROP TABLE pending_firewall_change`)
		return err
	}
}

func TestMudancaVPNQueNaoArmaAJanelaNaoTocaNoKernel(t *testing.T) {
	t.Run("reversível desfaz e diz que nada mudou", func(t *testing.T) {
		f := novaVPNFalhas(t)
		desfeitos := 0
		_, err := f.svc.AplicarMudancaVPN(context.Background(), "admin", "mudar a porta", f.escritaQueQuebraAJanela(), f.desfazContando(&desfeitos))

		g := exigirEtapa(t, err, StageWindow)
		if g.Gravada || !strings.Contains(g.Message, "nada foi alterado") {
			t.Errorf("Gravada=%v, frase %q", g.Gravada, g.Message)
		}
		if desfeitos != 1 {
			t.Errorf("o desfazer devia rodar uma vez, rodou %d", desfeitos)
		}
		if f.exec.applies != 0 {
			t.Errorf("sem janela armada o kernel não pode ser tocado, houve %d nft -f", f.exec.applies)
		}
	})

	t.Run("sem volta mantém a escrita e diz isso", func(t *testing.T) {
		f := novaVPNFalhas(t)
		_, err := f.svc.AplicarMudancaVPN(context.Background(), "admin", "revogar", f.escritaQueQuebraAJanela(), nil)

		g := exigirEtapa(t, err, StageWindow)
		if !g.Gravada || !strings.Contains(g.Message, "gravada") {
			t.Errorf("Gravada=%v, frase %q", g.Gravada, g.Message)
		}
		if f.exec.applies != 0 {
			t.Errorf("sem janela armada o kernel não pode ser tocado, houve %d nft -f", f.exec.applies)
		}
	})
}

func TestMudancaVPNComJanelaDeOutraMudancaEConflito(t *testing.T) {
	f := novaVPNFalhas(t)
	f.exec.failApply = nil
	// Uma janela já aberta trava a mudança antes de qualquer escrita.
	_ = f.db.CriarRegraFW(func() *fwmodel.Regra { r := regraBloqueiaSSH(); return &r }())
	if _, err := f.svc.Aplicar(context.Background(), "admin"); err != nil {
		t.Fatalf("Aplicar: %v", err)
	}

	escritas := 0
	_, err := f.svc.AplicarMudancaVPN(context.Background(), "admin", "mudar a porta", func() error { escritas++; return nil }, func() error { return nil })
	exigirEtapa(t, err, StageLocked)
	if escritas != 0 {
		t.Errorf("com uma janela aberta a escrita não pode nem começar, rodou %d vezes", escritas)
	}
}

// --- a config aplicada não renderiza mais (ex.: o alias de uma regra sumiu) ---

func TestMudancaVPNComAplicadaQueNaoRenderizaAplicaSemJanela(t *testing.T) {
	for _, reversivel := range []bool{true, false} {
		nome := "sem volta"
		if reversivel {
			nome = "reversível"
		}
		t.Run(nome, func(t *testing.T) {
			f := novaVPNFalhas(t)
			f.iface = "interface inválida!"

			// A escrita conserta o que impedia o render.
			escrever := func() error {
				f.iface = "linkguard"
				return f.mudaAEntrada()()
			}
			var desfazer func() error
			if reversivel {
				desfazer = func() error { return nil }
			}

			applied, err := f.svc.AplicarMudancaVPN(context.Background(), "admin", "entregar VPN", escrever, desfazer)
			if err != nil {
				t.Fatalf("a aplicada que não renderiza não pode travar a mudança da VPN: %v", err)
			}
			if applied == nil || applied.WindowID != "" {
				t.Errorf("sem uma base para reverter não há janela; veio %+v", applied)
			}
			if f.exec.applies != 1 {
				t.Errorf("esperava um nft -f, houve %d", f.exec.applies)
			}
			f.semJanela()
		})
	}
}

// --- a leitura do estado de antes falha ---

func TestMudancaVPNComEstadoAnteriorIlegivel(t *testing.T) {
	t.Run("reversível recusa antes de escrever", func(t *testing.T) {
		f := novaVPNFalhas(t)
		f.quebrar("wireguard_peers")

		escritas := 0
		_, err := f.svc.AplicarMudancaVPN(context.Background(), "admin", "mudar a porta", func() error { escritas++; return nil }, func() error { return nil })

		g := exigirEtapa(t, err, StagePreflight)
		if g.Gravada || !strings.Contains(g.Message, "nada foi alterado") {
			t.Errorf("Gravada=%v, frase %q", g.Gravada, g.Message)
		}
		if escritas != 0 {
			t.Errorf("sem base para desfazer a escrita não pode acontecer, rodou %d vezes", escritas)
		}
		if f.exec.applies != 0 {
			t.Errorf("houve %d nft -f", f.exec.applies)
		}
	})

	t.Run("sem volta escreve e aplica quando a entrada não muda", func(t *testing.T) {
		f := novaVPNFalhas(t)
		f.quebrar("wireguard_peers")

		escritas := 0
		applied, err := f.svc.AplicarMudancaVPN(context.Background(), "admin", "revogar", func() error { escritas++; return nil }, nil)
		if err != nil {
			t.Fatalf("revogar não pode depender de a lista de peers estar legível: %v", err)
		}
		if escritas != 1 || f.exec.applies != 1 {
			t.Errorf("escritas=%d, nft -f=%d", escritas, f.exec.applies)
		}
		if applied == nil || applied.WindowID != "" {
			t.Errorf("sem base não há janela; veio %+v", applied)
		}
	})

	t.Run("sem volta não mexe na entrada sem uma janela que a proteja", func(t *testing.T) {
		f := novaVPNFalhas(t)
		f.quebrar("wireguard_peers")

		_, err := f.svc.AplicarMudancaVPN(context.Background(), "admin", "revogar", f.mudaAEntrada(), nil)

		g := exigirEtapa(t, err, StageWindow)
		if !g.Gravada {
			t.Error("a escrita rodou: precisa constar como gravada")
		}
		if f.exec.applies != 0 {
			t.Errorf("mexer na entrada sem janela pode trancar o operador fora; houve %d nft -f", f.exec.applies)
		}
	})
}

// --- Aplicar ---

func TestAplicarNftFRecusadoNaoVazaOErroDoNft(t *testing.T) {
	f := novaVPNFalhas(t)
	_ = f.db.CriarRegraFW(func() *fwmodel.Regra { r := regraBloqueiaSSH(); return &r }())
	f.exec.failApply = nftBruto

	_, err := f.svc.Aplicar(context.Background(), "admin")

	g := exigirEtapa(t, err, StageReconcile)
	if !errors.Is(err, nftBruto) {
		t.Error("a causa técnica precisa ficar em Err, para o log")
	}
	if f.svc.UltimoErro() != g.Message {
		t.Errorf("UltimoErro vai para a tela e só pode repetir a frase do operador: %q", f.svc.UltimoErro())
	}
	f.semJanela()
	if f.exec.applies != 1 {
		t.Errorf("o nft -f é atômico: recusado, não há o que reaplicar (houve %d)", f.exec.applies)
	}

	f.exec.failApply = nil
	if _, err := f.svc.Aplicar(context.Background(), "admin"); err != nil {
		t.Fatalf("Aplicar de novo: %v", err)
	}
	if f.svc.UltimoErro() != "" {
		t.Errorf("UltimoErro devia limpar depois de uma aplicação boa: %q", f.svc.UltimoErro())
	}
}

func TestAplicarPreVooRecusadoNaoVazaOErroDoNft(t *testing.T) {
	f := novaVPNFalhas(t)
	_ = f.db.CriarRegraFW(func() *fwmodel.Regra { r := regraBloqueiaSSH(); return &r }())
	f.exec.failCheck = nftBruto

	_, err := f.svc.Aplicar(context.Background(), "admin")

	exigirEtapa(t, err, StagePreflight)
	if !errors.Is(err, nftBruto) {
		t.Error("a causa técnica precisa ficar em Err, para o log")
	}
	if f.exec.applies != 0 {
		t.Errorf("o pré-voo recusou: houve %d nft -f", f.exec.applies)
	}
}

func TestAplicarToleraAplicadaQueNaoRenderiza(t *testing.T) {
	f := novaVPNFalhas(t)
	quebrada := regraDaPessoa("x")
	quebrada.Origem = fwmodel.Ponta{Tipo: fwmodel.PontaAlias, Valor: "alias-que-sumiu"}
	f.aplicadaCom(fwmodel.Config{
		Formato: 1, Ajustes: fwmodel.AjustesPadrao(),
		Regras: []fwmodel.Regra{quebrada},
	})
	// A saída é apagar a regra que cita o alias que não existe mais.
	if err := f.db.SubstituirConfigEmEdicao(fwmodel.Config{
		Formato: 1, Ajustes: fwmodel.AjustesPadrao(),
		Regras: []fwmodel.Regra{regraBloqueiaSSH()},
	}); err != nil {
		t.Fatalf("SubstituirConfigEmEdicao: %v", err)
	}

	applied, err := f.svc.Aplicar(context.Background(), "admin")
	if err != nil {
		t.Fatalf("a aplicada quebrada não pode impedir que o operador aplique o conserto: %v", err)
	}
	if applied.WindowID != "" {
		t.Errorf("sem uma aplicada que renderize não há estado anterior para a janela reverter: %+v", applied)
	}
	if f.exec.applies != 1 {
		t.Errorf("esperava um nft -f, houve %d", f.exec.applies)
	}
	aplicada, _, err := f.svc.Aplicada()
	if err != nil || len(aplicada.Regras) != 1 || aplicada.Regras[0].ID != "r-entrada" {
		t.Fatalf("a aplicada devia ser a nova: %+v (%v)", aplicada.Regras, err)
	}
}

func TestAplicarSemAListaDePeersNaoToca(t *testing.T) {
	f := novaVPNFalhas(t)
	_ = f.db.CriarRegraFW(func() *fwmodel.Regra { r := regraBloqueiaSSH(); return &r }())
	f.quebrar("wireguard_peers")

	_, err := f.svc.Aplicar(context.Background(), "admin")

	g := exigirEtapa(t, err, StagePreflight)
	if !strings.Contains(g.Message, "nada foi alterado") {
		t.Errorf("a frase precisa dizer que nada mudou: %q", g.Message)
	}
	if f.exec.applies != 0 {
		t.Errorf("sem os perfis não há como armar a janela: o kernel não pode ser tocado (houve %d nft -f)", f.exec.applies)
	}
}

func TestAplicarQueNaoGravaAAplicadaVoltaOKernel(t *testing.T) {
	f := novaVPNFalhas(t)
	_ = f.db.CriarRegraFW(func() *fwmodel.Regra { r := regraBloqueiaSSH(); return &r }())
	f.quebrar("fw_revisoes")

	ins, err := f.svc.Insumos(context.Background())
	if err != nil {
		t.Fatalf("Insumos: %v", err)
	}
	anterior, err := nftables.RenderZonas(fwmodel.Config{Formato: 1, Ajustes: fwmodel.AjustesPadrao()}, ins)
	if err != nil {
		t.Fatalf("RenderZonas: %v", err)
	}

	_, err = f.svc.Aplicar(context.Background(), "admin")

	g := exigirEtapa(t, err, StageWrite)
	if !strings.Contains(g.Message, "voltou") {
		t.Errorf("a frase precisa dizer que o firewall voltou ao que era: %q", g.Message)
	}
	if f.exec.applies != 2 {
		t.Fatalf("esperava o ruleset novo e a volta ao anterior (2 nft -f), houve %d", f.exec.applies)
	}
	if f.exec.scripts[1] != anterior.Script {
		t.Error("o segundo nft -f devia levar o script da configuração que valia antes")
	}
	f.semJanela()
	aplicada, existe, err := f.svc.Aplicada()
	if err != nil || !existe || len(aplicada.Regras) != 0 {
		t.Errorf("a aplicada no banco não pode ter mudado: %+v (%v)", aplicada.Regras, err)
	}
}

func TestAplicarQueNaoGravaENaoConseguiVoltarDizQueFicouPelaMetade(t *testing.T) {
	f := novaVPNFalhas(t)
	_ = f.db.CriarRegraFW(func() *fwmodel.Regra { r := regraBloqueiaSSH(); return &r }())
	f.quebrar("fw_revisoes")
	f.exec.failApplyAt = 2

	_, err := f.svc.Aplicar(context.Background(), "admin")

	g := exigirEtapa(t, err, StageStuck)
	if !strings.Contains(g.Message, "aplique de novo") {
		t.Errorf("a frase precisa dizer como concluir: %q", g.Message)
	}
	f.semJanela()
}

func TestAplicarEDescartarComBancoQuebradoNaoVazamOErroDoBanco(t *testing.T) {
	casos := map[string]func(*vpnFalhas) error{
		"Aplicar": func(f *vpnFalhas) error {
			_ = f.db.CriarRegraFW(func() *fwmodel.Regra { r := regraBloqueiaSSH(); return &r }())
			_, err := f.svc.Aplicar(context.Background(), "admin")
			return err
		},
		"Descartar": func(f *vpnFalhas) error {
			return f.svc.Descartar(context.Background(), "admin")
		},
	}
	for nome, opera := range casos {
		t.Run(nome, func(t *testing.T) {
			f := novaVPNFalhas(t)
			f.quebrar("fw_aplicado")

			err := opera(f)

			g := exigirEtapa(t, err, StageWrite)
			if g.Err == nil {
				t.Error("a causa técnica precisa ficar em Err, para o log")
			}
		})
	}
}

// --- boot ---

func TestRenderizarNoBootRecusadoNaoVazaOErroParaUltimoErro(t *testing.T) {
	casos := []struct {
		nome  string
		usa   func(*zonasTestExec)
		etapa Stage
	}{
		{"nft -c recusa", func(e *zonasTestExec) { e.failCheck = nftBruto }, StagePreflight},
		{"nft -f recusa", func(e *zonasTestExec) { e.failApply = nftBruto }, StageReconcile},
	}
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			f := novaVPNFalhas(t)
			c.usa(f.exec)

			err := f.svc.RenderizarNoBoot(context.Background())

			g := exigirEtapa(t, err, c.etapa)
			if !errors.Is(err, nftBruto) {
				t.Error("a causa técnica precisa ficar em Err, para o log")
			}
			if f.svc.UltimoErro() != g.Message {
				t.Errorf("UltimoErro vai para a tela e só pode repetir a frase do operador: %q", f.svc.UltimoErro())
			}
		})
	}
}

// Reverter para um snapshot em que uma regra cita quem já não tem VPN é
// possível: a regra órfã não entra no render nem barra a reversão.
func TestSnapshotComRegraDePessoaRemovidaPodeReverter(t *testing.T) {
	snap := snapshotV2{Formato: 2, Config: fwmodel.Config{
		Formato: 1, Ajustes: fwmodel.AjustesPadrao(),
		Regras: []fwmodel.Regra{regraDaPessoa("fantasma")},
	}}
	if err := validateSnapshotV2(snap); err != nil {
		t.Fatalf("o snapshot devia ser válido: %v", err)
	}
}
