package backup_test

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/giovanibalarini/linkguard-cloud/internal/backup"
	"github.com/giovanibalarini/linkguard-cloud/internal/backupcrypt"
	"github.com/giovanibalarini/linkguard-cloud/internal/fwmodel"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

// encryptForTest produz o mesmo formato de arquivo que EncryptSnapshot grava,
// mas a partir de um BackupData montado à mão — os testes da trava precisam de
// um .lgbak cuja senha eles conhecem, sem depender de um banco populado.
func encryptForTest(t *testing.T, data backup.BackupData, passphrase string) []byte {
	t.Helper()
	plaintext, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal BackupData: %v", err)
	}
	ciphertext, err := backupcrypt.Encrypt(plaintext, passphrase)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return ciphertext
}

func newRestoreDB(t *testing.T) *storage.DB {
	t.Helper()
	db, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// validNetsvcConfigJSON é um netsvc_config limpo e inteiramente válido — a
// linha de base que todo teste de "restauração recusada não grava nada"
// restaura antes, para haver estado bom conhecido a provar intacto.
const validNetsvcConfigJSON = `{"upstreams":["1.1.1.1","9.9.9.9"],"log_queries":false,"dnstap_enabled":false}`

func backupWith(settings map[string]string) backup.BackupData {
	return backup.BackupData{Version: "test-version", Kind: "linkguard-fw-backup", Settings: settings}
}

// ─── Críticos 2 e 3: estado local da máquina não viaja no backup ────────────
//
// Esta guarda mora no domínio (internal/backup) e é provada aqui, e não só
// através de um httptest do handler: um backup de OUTRA máquina não pode
// redefinir esta. nft_live_snapshot é lido no bootstrap
// (cmd/linkguard-cloud/main.go) e entregue a `nft -f` como root, com um "flush
// ruleset" na frente — restaurá-lo significaria deixar um arquivo controlar o
// firewall inteiro da máquina de destino, inclusive numa instalação nova (o
// cenário documentado de restauração). firewall_rules_imported é a trava da
// importação única: gravada no destino sem trazer regra nenhuma (BackupData
// não tem campo para regras de firewall), faz o próximo boot pular o
// ImportOnce e o Reconcile esvaziar a chain user_rules viva contra um banco
// vazio. firewall_rules_apply e netsvc_last_apply são resultados de um apply
// que aconteceu na máquina de origem. platform_snapshot é a plataforma
// detectada no boot (nuvem ou não, região, shape, limite de VNICs) e as
// capacidades derivadas dela: restaurado, um backup tirado numa OCI de uma
// VNIC só diria a esta caixa que ela não tem multi-WAN. Nenhuma das cinco é
// configuração: são estado daquela máquina.
func TestApplySkipsMachineLocalStateKeys(t *testing.T) {
	db := newRestoreDB(t)

	data := backupWith(map[string]string{
		"netsvc_config":           validNetsvcConfigJSON,
		"nft_live_snapshot":       "flush ruleset\ntable inet evil { chain c { type filter hook input priority 0; policy accept; } }\n",
		"firewall_rules_imported": "true",
		"firewall_rules_apply":    `{"ok":true,"at":1}`,
		"netsvc_last_apply":       `{"ok":true,"at":1}`,
		"platform_snapshot":       `{"format":1,"facts":{"kind":"oci","fingerprint":"outramaquina00"},"capabilities":{"multi_wan":false}}`,
		"fw_zonas_convertido":     "1",
		"fw_conversao_relatorio":  `{"convertidas":1}`,
	})

	res, err := backup.Apply(db, data)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}

	for _, k := range []string{"nft_live_snapshot", "firewall_rules_imported", "firewall_rules_apply", "netsvc_last_apply", "platform_snapshot", "fw_zonas_convertido", "fw_conversao_relatorio"} {
		if v, _ := db.GetSetting(k); v != "" {
			t.Errorf("%q é estado local da máquina e não pode ser restaurado, mas foi gravado: %q", k, v)
		}
	}
	if v, _ := db.GetSetting("netsvc_config"); v != validNetsvcConfigJSON {
		t.Errorf("a configuração de verdade tinha que ser restaurada normalmente, obtive %q", v)
	}
	if res.Settings != 1 {
		t.Errorf("a contagem de settings restauradas não pode incluir as chaves puladas, obtive %d", res.Settings)
	}
	if res.SkippedLocal != 7 {
		t.Errorf("SkippedLocal = %d, esperava 7", res.SkippedLocal)
	}
}

// TestApplyNeverOverwritesAnExistingLiveSnapshot: a guarda vale também quando
// a máquina de destino já tem um ruleset gravado — restaurar não pode trocar
// o firewall desta caixa pelo da caixa de origem.
func TestApplyNeverOverwritesAnExistingLiveSnapshot(t *testing.T) {
	db := newRestoreDB(t)
	const meu = "table inet linkguard { chain input { type filter hook input priority 0; policy drop; } }\n"
	if err := db.SetSetting("nft_live_snapshot", meu); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}

	if _, err := backup.Apply(db, backupWith(map[string]string{
		"nft_live_snapshot": "flush ruleset\ntable inet outra_maquina { chain c { type filter hook input priority 0; policy accept; } }\n",
	})); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	got, _ := db.GetSetting("nft_live_snapshot")
	if got != meu {
		t.Fatalf("o ruleset vivo desta máquina foi substituído pelo do backup:\ngot=%q", got)
	}
}

// ─── Validação: nada é gravado quando o arquivo é recusado ──────────────────

func TestApplyRejectsAndWritesNothing(t *testing.T) {
	cases := []struct {
		name string
		data backup.BackupData
	}{
		{"upstream que não é IP", backupWith(map[string]string{
			// O upstream cai no forward-zone do unbound.conf por concatenação
			// de string; o que não for IP puro tem de ser recusado.
			"netsvc_config": `{"upstreams":["1.1.1.1\nforward-addr: 6.6.6.6"],"log_queries":false}`,
		})},
		{"monitoring com formato errado", backupWith(map[string]string{
			"monitoring": `{"services":{"nao":"e uma lista"}}`,
		})},
		{"domínio de bloqueio com injeção", backup.BackupData{
			Version: "test-version", Kind: "linkguard-fw-backup",
			Blocklist: []string{"good.example.com", "evil.com\ninclude: \"/etc/passwd"},
		}},
		{"firewall com regra inválida", backup.BackupData{
			Version: "test-version", Kind: "linkguard-fw-backup",
			Firewall: &fwmodel.Config{
				Regras: []fwmodel.Regra{
					{ID: "invalida", Zona: "invalida", Acao: "invalida"},
				},
			},
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := newRestoreDB(t)
			// Linha de base boa: é ela que tem de sobreviver intacta.
			if _, err := backup.Apply(db, backup.BackupData{
				Version: "test-version", Kind: "linkguard-fw-backup",
				Settings:  map[string]string{"netsvc_config": validNetsvcConfigJSON},
				Blocklist: []string{"good.example.com"},
			}); err != nil {
				t.Fatalf("linha de base: %v", err)
			}
			before := snapshotState(t, db)

			_, err := backup.Apply(db, tc.data)
			var invalid *backup.ValidationError
			if !errors.As(err, &invalid) {
				t.Fatalf("esperava *backup.ValidationError, obtive %v", err)
			}

			after := snapshotState(t, db)
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("o banco mudou depois de uma restauração que devia ter sido recusada:\nantes=%v\ndepois=%v", before, after)
			}
		})
	}
}

// snapshotState lê as coleções que uma restauração grava, para provar
// que uma recusa não deixou rastro.
func snapshotState(t *testing.T, db *storage.DB) map[string]any {
	t.Helper()
	settings, err := db.ExportSettings()
	if err != nil {
		t.Fatalf("ExportSettings: %v", err)
	}
	bl, err := db.ListDNSBlocklist()
	if err != nil {
		t.Fatalf("ListDNSBlocklist: %v", err)
	}
	emEdicao, err := db.CarregarConfigEmEdicao()
	if err != nil {
		t.Fatalf("CarregarConfigEmEdicao: %v", err)
	}
	aplicada, existe, err := db.CarregarConfigAplicada()
	if err != nil {
		t.Fatalf("CarregarConfigAplicada: %v", err)
	}
	return map[string]any{
		"settings":        settings,
		"blocklist":       bl,
		"em_edicao":       emEdicao,
		"aplicada":        aplicada,
		"aplicada_existe": existe,
	}
}

// TestApplyCleanBackupRestoresEverything prova que a validação não recusa
// conteúdo legítimo: config e blocklist entram como vieram (os domínios
// normalizados para minúsculas, como o handler sempre fez).
func TestApplyCleanBackupRestoresEverything(t *testing.T) {
	db := newRestoreDB(t)
	res, err := backup.Apply(db, backup.BackupData{
		Version:   "test-version",
		Kind:      "linkguard-fw-backup",
		Settings:  map[string]string{"netsvc_config": validNetsvcConfigJSON},
		Blocklist: []string{"ads.example.com", " Tracker.Example.NET "},
	})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if res.Settings != 1 || res.Blocklist != 2 {
		t.Fatalf("contagens = %+v, esperava 1 setting e 2 domínios", res)
	}
	if v, _ := db.GetSetting("netsvc_config"); v != validNetsvcConfigJSON {
		t.Errorf("netsvc_config = %q", v)
	}
	bl, _ := db.ListDNSBlocklist()
	if !reflect.DeepEqual(bl, []string{"ads.example.com", "tracker.example.net"}) {
		t.Errorf("blocklist = %v, esperava normalizada para minúsculas e sem espaços", bl)
	}
}

// TestApplyRestoresUnknownSettingsKeysAsIs: chaves fora do mapa de
// validadores continuam sendo gravadas como vêm — decisão deliberada, não
// esquecimento (ver o doc de Apply).
func TestApplyRestoresUnknownSettingsKeysAsIs(t *testing.T) {
	db := newRestoreDB(t)
	if _, err := backup.Apply(db, backupWith(map[string]string{"balancer_mode": "failover"})); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if v, _ := db.GetSetting("balancer_mode"); v != "failover" {
		t.Fatalf("balancer_mode = %q, esperava failover", v)
	}
}

// ─── Trava por tentativas ───────────────────────────────────────────────────

func TestRestoreLocksOutAfterRepeatedWrongPassphrase(t *testing.T) {
	db := newRestoreDB(t)
	lim := backup.NewRestoreLimiter()
	ciphertext := encryptForTest(t, backupWith(map[string]string{"balancer_mode": "failover"}), "senha-certa-123456")

	var lastErr error
	for i := 0; i < backup.MaxRestoreAttempts+1; i++ {
		_, lastErr = backup.Restore(db, lim, "u1", ciphertext, "senha-errada-123456")
	}
	if !errors.Is(lastErr, backup.ErrLockedOut) {
		t.Fatalf("esperava ErrLockedOut depois de %d tentativas erradas, obtive %v", backup.MaxRestoreAttempts+1, lastErr)
	}

	// A trava é por usuário: outro usuário não é punido pelas tentativas deste.
	if _, err := backup.Restore(db, lim, "u2", ciphertext, "senha-errada-123456"); !errors.Is(err, backup.ErrBadPassphrase) {
		t.Fatalf("outro usuário deveria receber ErrBadPassphrase, obtive %v", err)
	}
}

func TestRestoreSuccessResetsAttempts(t *testing.T) {
	db := newRestoreDB(t)
	lim := backup.NewRestoreLimiter()
	const senha = "senha-certa-123456"
	ciphertext := encryptForTest(t, backupWith(map[string]string{"balancer_mode": "failover"}), senha)

	for i := 0; i < backup.MaxRestoreAttempts-1; i++ {
		if _, err := backup.Restore(db, lim, "u1", ciphertext, "errada-123456"); !errors.Is(err, backup.ErrBadPassphrase) {
			t.Fatalf("tentativa %d: %v", i, err)
		}
	}
	if _, err := backup.Restore(db, lim, "u1", ciphertext, senha); err != nil {
		t.Fatalf("restauração com a senha certa: %v", err)
	}
	// Contador zerado: mais uma errada não pode trancar.
	if _, err := backup.Restore(db, lim, "u1", ciphertext, "errada-123456"); !errors.Is(err, backup.ErrBadPassphrase) {
		t.Fatalf("esperava ErrBadPassphrase (contador zerado pelo acerto), obtive %v", err)
	}
}

func TestRestoreFirewallLeavesAppliedUntouchedAndDraftUpdated(t *testing.T) {
	dbOrig := newRestoreDB(t)
	cfgOriginal := fwmodel.Config{
		Ajustes: fwmodel.Ajustes{RegistrarPadrao: true},
		Aliases: []fwmodel.Alias{
			{ID: "al-1", Nome: "web_servers", Tipo: fwmodel.AliasTipoEnderecos, Itens: []string{"192.168.1.10"}},
		},
		Regras: []fwmodel.Regra{
			{
				ID: "r-1", Zona: fwmodel.ZonaInternet, Posicao: 1, Ativa: true,
				Acao: fwmodel.AcaoAccept, Proto: fwmodel.ProtoTCP,
				Origem: fwmodel.Ponta{Tipo: fwmodel.PontaQualquer},
				Destino: fwmodel.Ponta{Tipo: fwmodel.PontaEste},
				PortaDestino: fwmodel.Porta{Tipo: fwmodel.PortaValor, Valor: "443"},
			},
		},
	}
	if err := dbOrig.SalvarAplicadaERevisao(cfgOriginal, "admin", "teste", "teste", time.Now()); err != nil {
		t.Fatalf("SalvarAplicadaERevisao dbOrig: %v", err)
	}

	snap, err := backup.Snapshot(dbOrig, "v2-test")
	if err != nil {
		t.Fatalf("Snapshot dbOrig: %v", err)
	}
	if snap.Format != 2 {
		t.Fatalf("Snapshot Format = %d, want 2", snap.Format)
	}
	if snap.Firewall == nil {
		t.Fatalf("Snapshot Firewall is nil, want populated config")
	}

	// Banco de destino novo
	dbDest := newRestoreDB(t)
	// Garante que o destino não tem aplicada
	_, existeAntes, err := dbDest.CarregarConfigAplicada()
	if err != nil {
		t.Fatalf("CarregarConfigAplicada dbDest antes: %v", err)
	}
	if existeAntes {
		t.Fatalf("dbDest já tinha configuração aplicada!")
	}

	res, err := backup.Apply(dbDest, snap)
	if err != nil {
		t.Fatalf("Apply no dbDest: %v", err)
	}
	if !res.FirewallPendente {
		t.Fatalf("res.FirewallPendente = false, want true")
	}

	// 1. fw_aplicado no destino permanece intocado (não existe)
	_, existeDepois, err := dbDest.CarregarConfigAplicada()
	if err != nil {
		t.Fatalf("CarregarConfigAplicada dbDest depois: %v", err)
	}
	if existeDepois {
		t.Fatalf("fw_aplicado no destino foi escrito pelo restore! Deveria ter ficado intocado.")
	}

	// 2. em_edicao no destino recebeu as regras e aliases do snapshot
	emEdicao, err := dbDest.CarregarConfigEmEdicao()
	if err != nil {
		t.Fatalf("CarregarConfigEmEdicao dbDest: %v", err)
	}
	if len(emEdicao.Aliases) != 1 || emEdicao.Aliases[0].Nome != "web_servers" {
		t.Errorf("Aliases em edição = %+v, want web_servers", emEdicao.Aliases)
	}
	if len(emEdicao.Regras) != 1 || emEdicao.Regras[0].ID != "r-1" {
		t.Errorf("Regras em edição = %+v, want r-1", emEdicao.Regras)
	}
}
