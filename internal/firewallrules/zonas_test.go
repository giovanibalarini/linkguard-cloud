package firewallrules

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-cloud/internal/fwmodel"
	"github.com/giovanibalarini/linkguard-cloud/internal/nftables"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

type zonasTestExec struct {
	executed  [][]string
	failCheck error
	failApply error
	readMap   map[string]string
}

func (z *zonasTestExec) Execute(_ context.Context, cmd string, args ...string) (string, error) {
	z.executed = append(z.executed, append([]string{cmd}, args...))
	if z.failApply != nil && cmd == "nft" && len(args) > 0 && args[0] == "-f" {
		return "", z.failApply
	}
	return "", nil
}

func (z *zonasTestExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	joined := strings.Join(args, " ")
	if z.failCheck != nil && strings.Contains(joined, "-c") && strings.Contains(joined, "-f") {
		return "", z.failCheck
	}
	if z.readMap != nil {
		if val, ok := z.readMap[cmd+" "+joined]; ok {
			return val, nil
		}
	}
	if strings.Contains(joined, "-j") {
		return `{"nftables": []}`, nil
	}
	return "table inet linkguard {\n}\n", nil
}

func (z *zonasTestExec) IsDryRun() bool                              { return false }
func (_ *zonasTestExec) WriteFile(string, []byte, os.FileMode) error { return nil }

func newZonasTestService(t *testing.T) (*Service, *storage.DB, *zonasTestExec) {
	t.Helper()
	db := newTestDB(t)
	exec := &zonasTestExec{}
	nftSvc := nftables.NewService(exec)
	svc := NewService(db, nftSvc)
	svc.SetFonteInsumos(func(ctx context.Context) (nftables.Insumos, error) {
		return nftables.Insumos{
			RedesVCN:       []string{"10.0.0.0/16"},
			RedeVPN:        "10.7.0.0/24",
			PortaWireGuard: 51820,
			InterfaceVPN:   "linkguard",
			PortasGerencia: []int{22, 443},
		}, nil
	})
	return svc, db, exec
}

func TestAplicarSemPendencia(t *testing.T) {
	svc, db, exec := newZonasTestService(t)
	ctx := context.Background()

	cfg := fwmodel.Config{
		Formato: 1,
		Ajustes: fwmodel.AjustesPadrao(),
		Regras: []fwmodel.Regra{
			{
				ID:           "r-1",
				Zona:         fwmodel.ZonaInternet,
				Posicao:      1,
				Ativa:        true,
				Acao:         fwmodel.AcaoAccept,
				Proto:        fwmodel.ProtoTCP,
				Origem:       fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
				Destino:      fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
				PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaQualquer},
				Descricao:    "Regra inicial",
			},
		},
	}
	if err := db.SubstituirConfigEmEdicao(cfg); err != nil {
		t.Fatalf("SubstituirConfigEmEdicao: %v", err)
	}
	if err := db.SalvarAplicadaERevisao(cfg, "sistema", "inicial", "conversao", time.Now()); err != nil {
		t.Fatalf("SalvarAplicadaERevisao: %v", err)
	}

	exec.executed = nil

	applied, err := svc.Aplicar(ctx, "admin")
	if err != nil {
		t.Fatalf("Aplicar sem pendência não deveria dar erro: %v", err)
	}
	if applied == nil {
		t.Fatal("applied não pode ser nil")
	}

	for _, cmd := range exec.executed {
		if len(cmd) > 1 && cmd[1] == "-f" {
			t.Fatalf("não deveria rodar nft -f sem pendência, executou: %v", cmd)
		}
	}
}

func TestAplicarErroValidacao(t *testing.T) {
	svc, db, exec := newZonasTestService(t)
	ctx := context.Background()

	cfg := fwmodel.Config{
		Formato: 1,
		Ajustes: fwmodel.AjustesPadrao(),
	}
	if err := db.SubstituirConfigEmEdicao(cfg); err != nil {
		t.Fatalf("SubstituirConfigEmEdicao: %v", err)
	}
	if err := db.SalvarAplicadaERevisao(cfg, "sistema", "inicial", "conversao", time.Now()); err != nil {
		t.Fatalf("SalvarAplicadaERevisao: %v", err)
	}

	// Insere uma regra com IP inválido diretamente no banco
	err := db.CriarRegraFW(&fwmodel.Regra{
		ID:           "r-invalida",
		Zona:         fwmodel.ZonaInternet,
		Posicao:      1,
		Ativa:        true,
		Acao:         fwmodel.AcaoAccept,
		Proto:        fwmodel.ProtoTCP,
		Origem:       fwmodel.Ponta{Tipo: fwmodel.PontaEndereco, Valor: "999.999.999.999"},
		Destino:      fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
		PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaQualquer},
		Descricao:    "IP Inválido",
	})
	if err != nil {
		t.Fatalf("CriarRegraFW: %v", err)
	}

	exec.executed = nil

	applied, err := svc.Aplicar(ctx, "admin")
	if err == nil {
		t.Fatal("esperava erro de validação (400), obteve nil")
	}
	stage, ok := StageOf(err)
	if !ok || stage != StageValidate {
		t.Fatalf("esperava StageValidate, obteve: %v", err)
	}
	if applied != nil {
		t.Fatalf("applied deveria ser nil em caso de erro")
	}

	// Nenhuma execução de nft
	if len(exec.executed) > 0 {
		t.Fatalf("não deveria ter executado nenhum comando no nftables, emitiu: %v", exec.executed)
	}

	// Configuração aplicada deve estar inalterada
	aplicada, existe, err := svc.Aplicada()
	if err != nil || !existe {
		t.Fatalf("aplicada deveria existir: %v", err)
	}
	if len(aplicada.Regras) != 0 {
		t.Fatalf("aplicada deveria permanecer inalterada com 0 regras, tem: %d", len(aplicada.Regras))
	}
}

func TestAplicarNftCFalhando(t *testing.T) {
	svc, db, exec := newZonasTestService(t)
	ctx := context.Background()

	cfg := fwmodel.Config{
		Formato: 1,
		Ajustes: fwmodel.AjustesPadrao(),
	}
	_ = db.SubstituirConfigEmEdicao(cfg)
	_ = db.SalvarAplicadaERevisao(cfg, "sistema", "inicial", "conversao", time.Now())

	_ = db.CriarRegraFW(&fwmodel.Regra{
		ID:           "r-2",
		Zona:         fwmodel.ZonaInternet,
		Posicao:      1,
		Ativa:        true,
		Acao:         fwmodel.AcaoAccept,
		Proto:        fwmodel.ProtoTCP,
		Origem:       fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
		Destino:      fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
		PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaQualquer},
		Descricao:    "Regra válida",
	})

	exec.failCheck = errors.New("simulated nft -c failure")
	exec.executed = nil

	_, err := svc.Aplicar(ctx, "admin")
	if err == nil {
		t.Fatal("esperava erro de pré-voo StagePreflight (400)")
	}
	stage, ok := StageOf(err)
	if !ok || stage != StagePreflight {
		t.Fatalf("esperava StagePreflight, obteve: %v", err)
	}

	for _, cmd := range exec.executed {
		if len(cmd) > 1 && cmd[1] == "-f" {
			t.Fatalf("nenhum nft -f deveria ter sido executado quando nft -c falha: %v", cmd)
		}
	}
}

func TestAplicarMudandoPassagemSemJanela(t *testing.T) {
	svc, db, exec := newZonasTestService(t)
	ctx := context.Background()

	cfg := fwmodel.Config{
		Formato: 1,
		Ajustes: fwmodel.AjustesPadrao(),
	}
	_ = db.SubstituirConfigEmEdicao(cfg)
	_ = db.SalvarAplicadaERevisao(cfg, "sistema", "inicial", "conversao", time.Now())

	// Regra na zona Internet (passagem/forward, não altera entrada na própria caixa)
	_ = db.CriarRegraFW(&fwmodel.Regra{
		ID:           "r-passagem",
		Zona:         fwmodel.ZonaInternet,
		Posicao:      1,
		Ativa:        true,
		Acao:         fwmodel.AcaoAccept,
		Proto:        fwmodel.ProtoTCP,
		Origem:       fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
		Destino:      fwmodel.Ponta{Tipo: fwmodel.PontaEndereco, Valor: "10.0.1.50"},
		PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaValor, Valor: "80"},
		Descricao:    "Permitir HTTP Internet",
	})

	exec.executed = nil

	applied, err := svc.Aplicar(ctx, "admin")
	if err != nil {
		t.Fatalf("Aplicar: %v", err)
	}
	if applied.WindowID != "" {
		t.Fatalf("mudança apenas em passagem NÃO deve abrir janela, abriu: %s", applied.WindowID)
	}

	var nftFCount int
	for _, cmd := range exec.executed {
		if len(cmd) > 1 && cmd[1] == "-f" {
			nftFCount++
		}
	}
	if nftFCount != 1 {
		t.Fatalf("esperava exatamente um nft -f, obteve: %d", nftFCount)
	}

	aplicada, existe, err := svc.Aplicada()
	if err != nil || !existe {
		t.Fatalf("carregar aplicada: %v", err)
	}
	if len(aplicada.Regras) != 1 || aplicada.Regras[0].ID != "r-passagem" {
		t.Fatalf("aplicada não foi atualizada para emEdicao: %+v", aplicada)
	}

	revisoes, err := db.ListarRevisoes(10)
	if err != nil || len(revisoes) == 0 {
		t.Fatalf("revisão deveria ter sido gravada: %v", err)
	}
	if revisoes[0].Motivo != "aplicar" {
		t.Errorf("motivo da revisão deveria ser 'aplicar', obtido: %s", revisoes[0].Motivo)
	}
}

func TestAplicarMudandoEntradaAbreJanela(t *testing.T) {
	svc, db, _ := newZonasTestService(t)
	ctx := context.Background()

	cfg := fwmodel.Config{
		Formato: 1,
		Ajustes: fwmodel.AjustesPadrao(),
	}
	_ = db.SubstituirConfigEmEdicao(cfg)
	_ = db.SalvarAplicadaERevisao(cfg, "sistema", "inicial", "conversao", time.Now())

	// Regra na zona VCN destinada à gerência (porta 22), toca input
	_ = db.CriarRegraFW(&fwmodel.Regra{
		ID:           "r-entrada",
		Zona:         fwmodel.ZonaVCN,
		Posicao:      1,
		Ativa:        true,
		Acao:         fwmodel.AcaoDrop,
		Proto:        fwmodel.ProtoTCP,
		Origem:       fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
		Destino:      fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
		PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaValor, Valor: "22"},
		Descricao:    "Bloquear SSH",
	})

	applied, err := svc.Aplicar(ctx, "admin")
	if err != nil {
		t.Fatalf("Aplicar: %v", err)
	}
	if applied.WindowID == "" {
		t.Fatal("mudança de entrada DEVE abrir janela de confirmação de 90s")
	}
	if applied.Pending == nil {
		t.Fatal("pending não pode ser nil quando janela é aberta")
	}

	var snap snapshotV2
	if err := json.Unmarshal([]byte(applied.Pending.Snapshot), &snap); err != nil {
		t.Fatalf("deserializar snapshot v2: %v", err)
	}
	if snap.Formato != 2 {
		t.Errorf("formato do snapshot v2 deveria ser 2, obtido: %d", snap.Formato)
	}
	if len(snap.Config.Regras) != 0 {
		t.Errorf("o snapshot deve conter a configuração ANTERIOR (0 regras), tem: %d", len(snap.Config.Regras))
	}
}

// O nft -f passou (o ruleset já vale no kernel) mas o arquivo de boot não pode ser gravado:
// a aplicação segue de pé, a aplicada é gravada e a janela de 90 s continua aberta.
func TestAplicarFalhaNoArquivoDeBootMantemJanela(t *testing.T) {
	svc, db, _ := newZonasTestService(t)
	svc.nft.SetConfPath(filepath.Join(t.TempDir(), "nao-existe", "nftables.conf"))
	ctx := context.Background()

	cfg := fwmodel.Config{Formato: 1, Ajustes: fwmodel.AjustesPadrao()}
	_ = db.SubstituirConfigEmEdicao(cfg)
	_ = db.SalvarAplicadaERevisao(cfg, "sistema", "inicial", "conversao", time.Now())

	_ = db.CriarRegraFW(&fwmodel.Regra{
		ID:           "r-entrada",
		Zona:         fwmodel.ZonaVCN,
		Posicao:      1,
		Ativa:        true,
		Acao:         fwmodel.AcaoDrop,
		Proto:        fwmodel.ProtoTCP,
		Origem:       fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
		Destino:      fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
		PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaValor, Valor: "22"},
		Descricao:    "Bloquear SSH",
	})

	applied, err := svc.Aplicar(ctx, "admin")
	if err != nil {
		t.Fatalf("o nft -f passou: Aplicar não podia falhar por causa do arquivo de boot: %v", err)
	}
	if applied.WindowID == "" {
		t.Fatal("a janela de confirmação tinha de continuar aberta")
	}
	if pend, err := db.GetPendingChange(); err != nil || pend == nil {
		t.Fatalf("a mudança pendente tinha de continuar gravada: pend=%v err=%v", pend, err)
	}
	aplicada, existe, err := svc.Aplicada()
	if err != nil || !existe {
		t.Fatalf("carregar aplicada: existe=%v err=%v", existe, err)
	}
	if len(aplicada.Regras) != 1 || aplicada.Regras[0].ID != "r-entrada" {
		t.Fatalf("a aplicada tinha de refletir o que entrou no kernel: %+v", aplicada.Regras)
	}
}

func TestAplicarMudancaVPNFalhaNoArquivoDeBoot(t *testing.T) {
	svc, db, _ := newZonasTestService(t)
	svc.nft.SetConfPath(filepath.Join(t.TempDir(), "nao-existe", "nftables.conf"))
	ctx := context.Background()

	cfg := fwmodel.Config{Formato: 1, Ajustes: fwmodel.AjustesPadrao()}
	_ = db.SubstituirConfigEmEdicao(cfg)
	_ = db.SalvarAplicadaERevisao(cfg, "sistema", "inicial", "conversao", time.Now())

	var desfeito bool
	_, err := svc.AplicarMudancaVPN(ctx, "admin", "adicionar peer", func() error {
		createTestPeer(t, db, "user-vpn", "valdo", "10.7.0.5", "full", nil, "")
		return nil
	}, func() error {
		desfeito = true
		return nil
	})
	if err != nil {
		t.Fatalf("o nft -f passou: a mudança da VPN não podia falhar por causa do arquivo de boot: %v", err)
	}
	if desfeito {
		t.Fatal("o desfazer não podia rodar: o ruleset novo já vale no kernel")
	}
}

func TestJanelaAbertaRecusaMutacoes409(t *testing.T) {
	svc, db, _ := newZonasTestService(t)
	ctx := context.Background()

	cfg := fwmodel.Config{
		Formato: 1,
		Ajustes: fwmodel.AjustesPadrao(),
	}
	_ = db.SubstituirConfigEmEdicao(cfg)
	_ = db.SalvarAplicadaERevisao(cfg, "sistema", "inicial", "conversao", time.Now())

	// Abre a janela simulando uma mudança
	_ = db.CriarRegraFW(&fwmodel.Regra{
		ID:           "r-entrada",
		Zona:         fwmodel.ZonaVCN,
		Posicao:      1,
		Ativa:        true,
		Acao:         fwmodel.AcaoDrop,
		Proto:        fwmodel.ProtoTCP,
		Origem:       fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
		Destino:      fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
		PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaValor, Valor: "22"},
		Descricao:    "Bloquear SSH",
	})
	applied, err := svc.Aplicar(ctx, "admin")
	if err != nil || applied.WindowID == "" {
		t.Fatalf("abrir janela via Aplicar: %v", err)
	}

	// 1. Aplicar recusa com 409 (StageLocked)
	_, err = svc.Aplicar(ctx, "outro")
	if stage, ok := StageOf(err); !ok || stage != StageLocked {
		t.Errorf("Aplicar deveria recusar com StageLocked (409), obteve: %v", err)
	}

	// 2. Descartar recusa com 409 (StageLocked)
	err = svc.Descartar(ctx, "outro")
	if stage, ok := StageOf(err); !ok || stage != StageLocked {
		t.Errorf("Descartar deveria recusar com StageLocked (409), obteve: %v", err)
	}

	// 3. EditarConfigValidando recusa com 409 (StageLocked)
	err = svc.EditarConfigValidando(ctx, "outro", func(db *storage.DB) error {
		return nil
	})
	if stage, ok := StageOf(err); !ok || stage != StageLocked {
		t.Errorf("EditarConfigValidando deveria recusar com StageLocked (409), obteve: %v", err)
	}

	// 4. AplicarMudancaVPN recusa com 409 (StageLocked)
	_, err = svc.AplicarMudancaVPN(ctx, "outro", "vpn", func() error { return nil }, nil)
	if stage, ok := StageOf(err); !ok || stage != StageLocked {
		t.Errorf("AplicarMudancaVPN deveria recusar com StageLocked (409), obteve: %v", err)
	}
}

func TestAplicarNftFFalhaDescartaJanela(t *testing.T) {
	svc, db, exec := newZonasTestService(t)
	ctx := context.Background()

	cfg := fwmodel.Config{
		Formato: 1,
		Ajustes: fwmodel.AjustesPadrao(),
	}
	_ = db.SubstituirConfigEmEdicao(cfg)
	_ = db.SalvarAplicadaERevisao(cfg, "sistema", "inicial", "conversao", time.Now())

	_ = db.CriarRegraFW(&fwmodel.Regra{
		ID:           "r-entrada",
		Zona:         fwmodel.ZonaVCN,
		Posicao:      1,
		Ativa:        true,
		Acao:         fwmodel.AcaoDrop,
		Proto:        fwmodel.ProtoTCP,
		Origem:       fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
		Destino:      fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
		PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaValor, Valor: "22"},
		Descricao:    "Bloquear SSH",
	})

	exec.failApply = errors.New("falha na execução de nft -f")

	_, err := svc.Aplicar(ctx, "admin")
	if err == nil {
		t.Fatal("esperava erro de execução StageWrite (500)")
	}
	stage, ok := StageOf(err)
	if !ok || stage != StageWrite {
		t.Fatalf("esperava StageWrite, obteve: %v", err)
	}

	// Janela deve ter sido descartada
	pending, err := db.GetPendingChange()
	if err != nil {
		t.Fatalf("GetPendingChange: %v", err)
	}
	if pending != nil {
		t.Errorf("janela deveria ter sido descartada após falha de nft -f, ainda há: %+v", pending)
	}

	// Aplicada deve permanecer inalterada
	aplicada, existe, err := svc.Aplicada()
	if err != nil || !existe {
		t.Fatalf("aplicada: %v", err)
	}
	if len(aplicada.Regras) != 0 {
		t.Fatalf("aplicada não pode ter mudado, tem %d regras", len(aplicada.Regras))
	}
}

func TestDescartarRestauraEmEdicao(t *testing.T) {
	svc, db, _ := newZonasTestService(t)
	ctx := context.Background()

	cfg := fwmodel.Config{
		Formato: 1,
		Ajustes: fwmodel.AjustesPadrao(),
		Regras: []fwmodel.Regra{
			{
				ID:           "r-base",
				Zona:         fwmodel.ZonaInternet,
				Posicao:      1,
				Ativa:        true,
				Acao:         fwmodel.AcaoAccept,
				Proto:        fwmodel.ProtoTCP,
				Origem:       fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
				Destino:      fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
				PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaQualquer},
				Descricao:    "Base",
			},
		},
	}
	_ = db.SubstituirConfigEmEdicao(cfg)
	_ = db.SalvarAplicadaERevisao(cfg, "sistema", "inicial", "conversao", time.Now())

	// Edita adicionando uma regra nova
	_ = db.CriarRegraFW(&fwmodel.Regra{
		ID:           "r-nova",
		Zona:         fwmodel.ZonaVCN,
		Posicao:      2,
		Ativa:        true,
		Acao:         fwmodel.AcaoAccept,
		Proto:        fwmodel.ProtoTCP,
		Origem:       fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
		Destino:      fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
		PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaQualquer},
		Descricao:    "Nova",
	})

	pend, err := svc.Pendencias(ctx)
	if err != nil || !pend.Pendente {
		t.Fatalf("deveria haver pendência antes de descartar: %+v", pend)
	}

	if err := svc.Descartar(ctx, "admin"); err != nil {
		t.Fatalf("Descartar: %v", err)
	}

	emEdicao, err := svc.EmEdicao()
	if err != nil {
		t.Fatalf("EmEdicao: %v", err)
	}
	if len(emEdicao.Regras) != 1 || emEdicao.Regras[0].ID != "r-base" {
		t.Fatalf("emEdicao deveria ter voltado para a aplicada (1 regra), tem: %+v", emEdicao.Regras)
	}

	pendDepois, err := svc.Pendencias(ctx)
	if err != nil || pendDepois.Pendente {
		t.Fatalf("após descartar não pode haver pendências: %+v", pendDepois)
	}
}

func TestRenderizarNoBootSemAplicada(t *testing.T) {
	svc, db, exec := newZonasTestService(t)
	ctx := context.Background()

	cfg := fwmodel.Config{
		Formato: 1,
		Ajustes: fwmodel.AjustesPadrao(),
		Regras: []fwmodel.Regra{
			{
				ID:           "r-boot",
				Zona:         fwmodel.ZonaInternet,
				Posicao:      1,
				Ativa:        true,
				Acao:         fwmodel.AcaoAccept,
				Proto:        fwmodel.ProtoTCP,
				Origem:       fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
				Destino:      fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
				PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaQualquer},
				Descricao:    "Regra no boot",
			},
		},
	}
	if err := db.SubstituirConfigEmEdicao(cfg); err != nil {
		t.Fatalf("SubstituirConfigEmEdicao: %v", err)
	}

	// fw_aplicado está vazio
	_, existe, err := svc.Aplicada()
	if err != nil || existe {
		t.Fatalf("fw_aplicado deveria estar vazio no início deste teste")
	}

	exec.executed = nil

	if err := svc.RenderizarNoBoot(ctx); err != nil {
		t.Fatalf("RenderizarNoBoot: %v", err)
	}

	aplicada, existe, err := svc.Aplicada()
	if err != nil || !existe {
		t.Fatalf("RenderizarNoBoot deveria ter criado fw_aplicado")
	}
	if len(aplicada.Regras) != 1 || aplicada.Regras[0].ID != "r-boot" {
		t.Fatalf("fw_aplicado deveria espelhar emEdicao: %+v", aplicada)
	}

	revisoes, err := db.ListarRevisoes(10)
	if err != nil || len(revisoes) == 0 {
		t.Fatalf("deveria ter registrado revisão no boot: %v", err)
	}
	if revisoes[0].Motivo != "conversao" {
		t.Errorf("motivo da revisão deveria ser 'conversao', obtido: %s", revisoes[0].Motivo)
	}

	pending, _ := db.GetPendingChange()
	if pending != nil {
		t.Errorf("RenderizarNoBoot não deve abrir janela de confirmação")
	}
}

func TestPendenciasEDiff(t *testing.T) {
	svc, db, _ := newZonasTestService(t)
	ctx := context.Background()

	cfg := fwmodel.Config{
		Formato: 1,
		Ajustes: fwmodel.AjustesPadrao(),
	}
	_ = db.SubstituirConfigEmEdicao(cfg)
	_ = db.SalvarAplicadaERevisao(cfg, "sistema", "inicial", "conversao", time.Now())

	_ = db.CriarRegraFW(&fwmodel.Regra{
		ID:           "r-diff",
		Zona:         fwmodel.ZonaInternet,
		Posicao:      1,
		Ativa:        true,
		Acao:         fwmodel.AcaoAccept,
		Proto:        fwmodel.ProtoTCP,
		Origem:       fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
		Destino:      fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
		PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaQualquer},
		Descricao:    "Permitir geral",
	})

	pend, err := svc.Pendencias(ctx)
	if err != nil {
		t.Fatalf("Pendencias: %v", err)
	}
	if !pend.Pendente {
		t.Errorf("esperava Pendente == true")
	}
	if len(pend.Mudancas) != 1 {
		t.Errorf("esperava 1 mudança, obteve %d", len(pend.Mudancas))
	}
	if pend.DiffNft == "" {
		t.Errorf("esperava diff de nft não vazio")
	}

	linhas, err := svc.Linhas(ctx, fwmodel.ZonaInternet)
	if err != nil {
		t.Fatalf("Linhas: %v", err)
	}
	if len(linhas) == 0 {
		t.Errorf("esperava linhas na zona internet")
	}

	extras := svc.RedesVCNExtrasAplicadas()
	if len(extras) != 0 {
		t.Errorf("esperava 0 redes VCN extras inicialmente")
	}
}

func TestRestaurarRevisao(t *testing.T) {
	svc, db, _ := newZonasTestService(t)
	ctx := context.Background()

	cfg1 := fwmodel.Config{
		Formato: 1,
		Ajustes: fwmodel.AjustesPadrao(),
		Regras: []fwmodel.Regra{
			{
				ID:           "r-rev1",
				Zona:         fwmodel.ZonaInternet,
				Posicao:      1,
				Ativa:        true,
				Acao:         fwmodel.AcaoAccept,
				Proto:        fwmodel.ProtoTCP,
				Origem:       fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
				Destino:      fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
				PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaQualquer},
				Descricao:    "Rev 1",
			},
		},
	}
	_ = db.SubstituirConfigEmEdicao(cfg1)
	_ = db.SalvarAplicadaERevisao(cfg1, "admin", "versao 1", "aplicar", time.Now())

	revisoes, err := db.ListarRevisoes(1)
	if err != nil || len(revisoes) == 0 {
		t.Fatalf("listar revisões: %v", err)
	}
	rev1ID := revisoes[0].ID

	cfg2 := fwmodel.Config{
		Formato: 1,
		Ajustes: fwmodel.AjustesPadrao(),
	}
	_ = db.SubstituirConfigEmEdicao(cfg2)
	_ = db.SalvarAplicadaERevisao(cfg2, "admin", "versao 2", "aplicar", time.Now())

	// Restaura a revisão 1
	if err := svc.RestaurarRevisao(ctx, rev1ID, "admin"); err != nil {
		t.Fatalf("RestaurarRevisao: %v", err)
	}

	emEdicao, err := svc.EmEdicao()
	if err != nil {
		t.Fatalf("EmEdicao: %v", err)
	}
	if len(emEdicao.Regras) != 1 || emEdicao.Regras[0].ID != "r-rev1" {
		t.Fatalf("emEdicao deveria ter sido restaurada com a regra de rev1: %+v", emEdicao.Regras)
	}

	// Configuração aplicada ainda é cfg2 (fica pendente para aplicar)
	aplicada, _, _ := svc.Aplicada()
	if len(aplicada.Regras) != 0 {
		t.Fatalf("aplicada não deve mudar ao restaurar revisão para edição")
	}
}
