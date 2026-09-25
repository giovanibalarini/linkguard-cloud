package hostquota

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

func newTestDB(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// alerterFalso registra o que teria sido alertado.
type alerterFalso struct {
	criados    []string // "tipo|ip"
	resolvidos []string
	mensagens  []string // corpo do alerta, para conferir o texto que o admin lê
	titulos    []string
}

func (a *alerterFalso) Create(alertType, _, title, message, key string) error {
	a.criados = append(a.criados, alertType+"|"+key)
	a.titulos = append(a.titulos, title)
	a.mensagens = append(a.mensagens, message)
	return nil
}
func (a *alerterFalso) AutoResolve(alertType, key string) {
	a.resolvidos = append(a.resolvidos, alertType+"|"+key)
}
func (a *alerterFalso) temCriado(s string) bool { return contem(a.criados, s) }
func (a *alerterFalso) temResolvido(s string) bool {
	return contem(a.resolvidos, s)
}

func contem(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

const ipA = "192.168.3.50"

func aparelho(t *testing.T, db *storage.DB, ip, alias string) {
	t.Helper()
	if err := db.UpsertHostSightings([]string{ip}); err != nil {
		t.Fatalf("UpsertHostSightings: %v", err)
	}
	if alias != "" {
		if err := db.SetHostAlias(ip, alias); err != nil {
			t.Fatalf("SetHostAlias: %v", err)
		}
	}
}

// ─── ciclo ───────────────────────────────────────────────────────────────────

func TestCycleStartDiarioEhMeiaNoiteLocal(t *testing.T) {
	loc := time.FixedZone("BRT", -3*3600)
	agora := time.Date(2026, 8, 25, 23, 59, 59, 0, loc)
	got := CycleStart(agora, storage.HostPeriodDaily, 17)
	want := time.Date(2026, 8, 25, 0, 0, 0, 0, loc)
	if !got.Equal(want) {
		t.Errorf("CycleStart diário = %v, queria %v", got, want)
	}
	// O dia de fechamento é ignorado no diário: se ele contasse, o ciclo viraria
	// no dia 17 e a cota "de hoje" duraria um mês.
	if fim := CycleEnd(got, storage.HostPeriodDaily); fim.Sub(got) != 24*time.Hour {
		t.Errorf("ciclo diário durou %v, queria 24h", fim.Sub(got))
	}
}

func TestCycleStartMensalFechaNoDiaEscolhido(t *testing.T) {
	loc := time.UTC
	agora := time.Date(2026, 8, 5, 12, 0, 0, 0, loc)
	got := CycleStart(agora, storage.HostPeriodMonthly, 10)
	want := time.Date(2026, 7, 10, 0, 0, 0, 0, loc)
	if !got.Equal(want) {
		t.Errorf("CycleStart mensal = %v, queria %v", got, want)
	}
	if fim := CycleEnd(got, storage.HostPeriodMonthly); !fim.Equal(time.Date(2026, 8, 10, 0, 0, 0, 0, loc)) {
		t.Errorf("CycleEnd mensal = %v", fim)
	}
}

func TestPeriodoVazioCaiNoMensal(t *testing.T) {
	loc := time.UTC
	agora := time.Date(2026, 8, 25, 12, 0, 0, 0, loc)
	// Aparelho sem cota declarada: o Snapshot e o Flush usam Period "" e dia 0.
	got := CycleStart(agora, "", 0)
	want := time.Date(2026, 8, 1, 0, 0, 0, 0, loc)
	if !got.Equal(want) {
		t.Errorf("CycleStart sem cota = %v, queria %v", got, want)
	}
}

// ─── validação ───────────────────────────────────────────────────────────────

func TestSaveRecusaOQueNaoExiste(t *testing.T) {
	svc := NewService(newTestDB(t), nil)
	casos := []struct {
		nome string
		q    storage.HostQuota
	}{
		{"IP vazio", storage.HostQuota{IP: "", LimitGB: 1, Period: "monthly", CycleDay: 1, AlertPct: 80}},
		{"IP malformado", storage.HostQuota{IP: "não-é-ip", LimitGB: 1, Period: "monthly", CycleDay: 1, AlertPct: 80}},
		// O contador do nft é por IPv4: uma cota num IPv6 ou numa faixa nunca
		// casaria com o consumo medido. Recusar aqui devolve 400 na hora.
		{"IPv6", storage.HostQuota{IP: "fd00::50", LimitGB: 1, Period: "monthly", CycleDay: 1, AlertPct: 80}},
		{"faixa em vez de máquina", storage.HostQuota{IP: "192.168.3.0/24", LimitGB: 1, Period: "monthly", CycleDay: 1, AlertPct: 80}},
		{"dia 31 não existe em fevereiro", storage.HostQuota{IP: ipA, LimitGB: 1, Period: "monthly", CycleDay: 31, AlertPct: 80}},
		{"aviso em 150%", storage.HostQuota{IP: ipA, LimitGB: 1, Period: "monthly", CycleDay: 1, AlertPct: 150}},
		{"aviso em 0%", storage.HostQuota{IP: ipA, LimitGB: 1, Period: "monthly", CycleDay: 1, AlertPct: 0}},
		{"período inventado", storage.HostQuota{IP: ipA, LimitGB: 1, Period: "semanal", CycleDay: 1, AlertPct: 80}},
		{"cota negativa", storage.HostQuota{IP: ipA, LimitGB: -1, Period: "monthly", CycleDay: 1, AlertPct: 80}},
	}
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			if err := svc.Save(c.q); err == nil {
				t.Error("aceitou o que deveria recusar")
			}
		})
	}
}

func TestSaveNormalizaOEndereco(t *testing.T) {
	db := newTestDB(t)
	svc := NewService(db, nil)
	// A grafia IPv4-mapeada e os espaços viram o IPv4 puro, que é a grafia que o
	// contador do nft entrega e o inventário grava. Sem isso, a cota nasceria
	// numa chave e o consumo medido noutra — a barra da tela nunca encheria.
	if err := svc.Save(storage.HostQuota{IP: " ::ffff:192.168.3.50 ", LimitGB: 1, Period: "monthly", CycleDay: 1, AlertPct: 80}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	quotas, err := db.GetHostQuotas()
	if err != nil {
		t.Fatalf("GetHostQuotas: %v", err)
	}
	if _, ok := quotas[ipA]; !ok {
		t.Fatalf("a cota não foi gravada na grafia canônica: %+v", quotas)
	}
}

func TestSaveDiarioZeraODiaDeFechamento(t *testing.T) {
	db := newTestDB(t)
	svc := NewService(db, nil)
	if err := svc.Save(storage.HostQuota{IP: ipA, LimitGB: 1, Period: storage.HostPeriodDaily, CycleDay: 17, AlertPct: 80}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	quotas, _ := db.GetHostQuotas()
	if got := quotas[ipA].CycleDay; got != 1 {
		t.Errorf("cycle_day gravado = %d, queria 1 no período diário", got)
	}
}

// ─── acumulação e alerta ─────────────────────────────────────────────────────

func TestFlushAcumulaEMedeQuemNaoDeclarouCota(t *testing.T) {
	db := newTestDB(t)
	al := &alerterFalso{}
	svc := NewService(db, al)
	aparelho(t, db, ipA, "tablet da sala")

	medir(svc, ipA, 3_000_000, 1_000_000)
	svc.Flush()

	st, err := svc.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(st) != 1 {
		t.Fatalf("Snapshot devolveu %d linhas, queria 1", len(st))
	}
	if st[0].UsedBytes != 4_000_000 {
		t.Errorf("used_bytes = %d, queria 4000000", st[0].UsedBytes)
	}
	if st[0].Configured {
		t.Error("apareceu como configurado sem cota declarada")
	}
	// Sem cota declarada não pode nascer alerta nenhum, por mais que consuma.
	if len(al.criados) != 0 {
		t.Errorf("alertou sem cota declarada: %v", al.criados)
	}
}

func TestOSinkIgnoraORotuloDeOutros(t *testing.T) {
	db := newTestDB(t)
	svc := NewService(db, nil)
	// "outros" é rótulo de gráfico. Se ele virasse linha de consumo, apareceria
	// na tela como um aparelho que ninguém consegue nomear nem remover.
	medir(svc, "", 1_000_000, 0)
	svc.Flush()
	st, _ := svc.Snapshot()
	if len(st) != 0 {
		t.Errorf("Snapshot criou linha para IP vazio: %+v", st)
	}
}

func TestAlertaDeAvisoEDeEstouroComUnidadeLegivel(t *testing.T) {
	db := newTestDB(t)
	al := &alerterFalso{}
	svc := NewService(db, al)
	aparelho(t, db, ipA, "tablet da sala")
	// 1 MB de cota: é o tamanho que se declara para uma câmera, e é onde a
	// formatação em "%.1f GB" produzia "0.0 GB de 0 GB".
	if err := svc.Save(storage.HostQuota{IP: ipA, LimitGB: 0.001, Period: storage.HostPeriodMonthly, CycleDay: 1, AlertPct: 80, AlertEnabled: true}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	medir(svc, ipA, 900_000, 0) // 90%
	svc.Flush()
	if !al.temCriado(TypeQuotaWarning + "|" + ipA) {
		t.Fatalf("não avisou em 90%%: %v", al.criados)
	}
	aviso := al.mensagens[0]
	if strings.Contains(aviso, "0.0 GB") {
		t.Errorf("o aviso saiu ilegível: %q", aviso)
	}
	if !strings.Contains(aviso, "tablet da sala") {
		t.Errorf("o aviso não nomeia o aparelho pelo apelido: %q", aviso)
	}
	if strings.Contains(aviso, ipA) {
		t.Errorf("o aviso usou o IP cru tendo apelido: %q", aviso)
	}

	medir(svc, ipA, 200_000, 0) // passa de 100%
	svc.Flush()
	if !al.temCriado(TypeQuotaExceeded + "|" + ipA) {
		t.Fatalf("não alertou o estouro: %v", al.criados)
	}
	// O aviso de "chegando lá" tem de FECHAR quando o crítico abre, senão a
	// tela mostra dois alertas do mesmo aparelho dizendo coisas diferentes.
	if !al.temResolvido(TypeQuotaWarning + "|" + ipA) {
		t.Errorf("o aviso de 80%% ficou aberto ao lado do crítico: %v", al.resolvidos)
	}
	critico := al.mensagens[len(al.mensagens)-1]
	if !strings.Contains(critico, "NÃO corta") {
		t.Errorf("o alerta crítico não diz que o produto não corta: %q", critico)
	}
}

func TestViradaDeCicloDiarioResolveOsAlertasDeOntem(t *testing.T) {
	db := newTestDB(t)
	al := &alerterFalso{}
	svc := NewService(db, al)
	aparelho(t, db, ipA, "notebook")
	if err := svc.Save(storage.HostQuota{IP: ipA, LimitGB: 0.001, Period: storage.HostPeriodDaily, CycleDay: 1, AlertPct: 80, AlertEnabled: true}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loc := time.UTC
	hoje := time.Date(2026, 8, 25, 20, 0, 0, 0, loc)
	svc.nowFn = func() time.Time { return hoje }
	medir(svc, ipA, 2_000_000, 0)
	svc.Flush()
	if !al.temCriado(TypeQuotaExceeded + "|" + ipA) {
		t.Fatalf("não estourou hoje: %v", al.criados)
	}

	// AMANHÃ. Sem o AutoResolve na virada, o alerta de ontem continuaria aberto,
	// o alerts.Service deduplicaria por (tipo, aparelho) e a cota ficaria MUDA a
	// partir do segundo dia — com a suíte verde.
	amanha := hoje.AddDate(0, 0, 1)
	svc.nowFn = func() time.Time { return amanha }
	al.resolvidos = nil
	svc.Flush()
	if !al.temResolvido(TypeQuotaExceeded + "|" + ipA) {
		t.Errorf("a virada do dia não resolveu o estouro de ontem: %v", al.resolvidos)
	}
	if !al.temResolvido(TypeQuotaWarning + "|" + ipA) {
		t.Errorf("a virada do dia não resolveu o aviso de ontem: %v", al.resolvidos)
	}

	// E o ciclo novo nasce zerado: o consumo de ontem continua no banco, mas não
	// conta para hoje.
	st, err := svc.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if st[0].UsedBytes != 0 {
		t.Errorf("o ciclo de hoje nasceu com %d bytes", st[0].UsedBytes)
	}
	hist, err := svc.History(ipA, 12)
	if err != nil {
		t.Fatalf("History: %v", err)
	}
	if len(hist) != 1 || hist[0].RxBytes != 2_000_000 {
		t.Errorf("o consumo de ontem sumiu do histórico: %+v", hist)
	}
}

func TestRemoverACotaNaoEscondeOConsumoJaMedido(t *testing.T) {
	db := newTestDB(t)
	al := &alerterFalso{}
	svc := NewService(db, al)
	aparelho(t, db, ipA, "câmera")
	// Fechamento no dia 28: é o caso em que apagar a linha mudaria o ciclo lido
	// e o consumo sumiria da tela — o defeito medido em 2026-08-20 na metade de
	// link.
	if err := svc.Save(storage.HostQuota{IP: ipA, LimitGB: 10, Period: storage.HostPeriodMonthly, CycleDay: 28, AlertPct: 80, AlertEnabled: true}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	medir(svc, ipA, 2_600_000, 0)
	svc.Flush()

	antes, _ := svc.Snapshot()
	if antes[0].UsedBytes == 0 {
		t.Fatal("nada foi medido antes da remoção")
	}

	if err := svc.Delete(ipA); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	depois, _ := svc.Snapshot()
	if depois[0].Configured {
		t.Error("continuou configurado depois do Delete")
	}
	if depois[0].UsedBytes != antes[0].UsedBytes {
		t.Errorf("o consumo mudou de %d para %d ao remover a cota", antes[0].UsedBytes, depois[0].UsedBytes)
	}
	if depois[0].CycleStart != antes[0].CycleStart {
		t.Errorf("o ciclo mudou ao remover a cota: %d para %d", antes[0].CycleStart, depois[0].CycleStart)
	}
	if !al.temResolvido(TypeQuotaExceeded + "|" + ipA) {
		t.Errorf("remover a cota deixou alerta aberto: %v", al.resolvidos)
	}
}

func TestCotaDeAparelhoQueSumiuContinuaVisivelEMuda(t *testing.T) {
	db := newTestDB(t)
	al := &alerterFalso{}
	svc := NewService(db, al)
	// Máquina destruída, ou cota gravada antes de a máquina subir: nunca foi
	// avistada, então não está em host_info.
	if err := svc.Save(storage.HostQuota{IP: ipA, LimitGB: 1, Period: storage.HostPeriodMonthly, CycleDay: 1, AlertPct: 80, AlertEnabled: true}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	svc.Flush()

	st, err := svc.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(st) != 1 {
		t.Fatalf("a cota órfã sumiu da tela: %+v", st)
	}
	if st[0].Present {
		t.Error("a cota órfã se apresentou como aparelho presente")
	}
	if st[0].Name != ipA {
		t.Errorf("nome da máquina ausente = %q, queria o IP", st[0].Name)
	}
	// Sem consumo, ela é muda: cota fantasma não pode gerar alerta.
	if len(al.criados) != 0 {
		t.Errorf("a cota órfã alertou sozinha: %v", al.criados)
	}
}

func TestCadaAparelhoTemOSeuAlerta(t *testing.T) {
	const ipB = "192.168.3.51"
	db := newTestDB(t)
	al := &alerterFalso{}
	svc := NewService(db, al)
	aparelho(t, db, ipA, "tablet")
	aparelho(t, db, ipB, "tv")
	for _, m := range []string{ipA, ipB} {
		if err := svc.Save(storage.HostQuota{IP: m, LimitGB: 0.001, Period: storage.HostPeriodMonthly, CycleDay: 1, AlertPct: 80, AlertEnabled: true}); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}
	medir(svc, ipA, 2_000_000, 0)
	medir(svc, ipB, 2_000_000, 0)
	svc.Flush()

	// A chave do alerta é o aparelho. Se fosse "" ou compartilhada, o segundo
	// estouro seria engolido pelo dedupe do alerts.Service e resolver um
	// fecharia o do outro.
	if !al.temCriado(TypeQuotaExceeded+"|"+ipA) || !al.temCriado(TypeQuotaExceeded+"|"+ipB) {
		t.Errorf("os dois aparelhos não ganharam alerta próprio: %v", al.criados)
	}
}

func TestSnapshotOrdenaPorConsumo(t *testing.T) {
	const ipB = "192.168.3.51"
	db := newTestDB(t)
	svc := NewService(db, nil)
	aparelho(t, db, ipA, "pouco")
	aparelho(t, db, ipB, "muito")
	medir(svc, ipA, 1_000, 0)
	medir(svc, ipB, 9_000_000, 0)
	svc.Flush()
	st, _ := svc.Snapshot()
	if len(st) != 2 || st[0].IP != ipB {
		t.Errorf("a tela não começa por quem mais gastou: %+v", st)
	}
}

// medir entrega bytes ao acumulador com o instante que o próprio serviço
// considera "agora" — que é o que o amostrador faz em produção. Os testes
// que mexem o relógio (svc.nowFn) ganham de graça o comportamento certo: o byte
// medido às 23h59 pertence ao ciclo de hoje, mesmo que o flush só aconteça
// depois da meia-noite.
func medir(s *Service, ip string, rx, tx uint64) {
	s.AddHostBytes(ip, s.nowFn().Unix(), rx, tx)
}
