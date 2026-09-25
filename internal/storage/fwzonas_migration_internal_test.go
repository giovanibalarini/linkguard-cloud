package storage

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestMigracao103E104BancoComDados(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "legacy.db")

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	// Simula estado antes de 103/104:
	// Remove registro de 103 e 104 de schema_migrations
	if _, err := db.conn.Exec(`DELETE FROM schema_migrations WHERE version >= 103`); err != nil {
		t.Fatalf("delete schema_migrations: %v", err)
	}
	// Dropa tabelas criadas pela 103 para simular o banco anterior
	for _, tbl := range []string{"fw_regras", "fw_aliases", "fw_agendamentos", "fw_encaminhamentos", "fw_ajustes", "fw_aplicado", "fw_revisoes"} {
		if _, err := db.conn.Exec("DROP TABLE IF EXISTS " + tbl); err != nil {
			t.Fatalf("drop table %s: %v", tbl, err)
		}
	}

	// Insere dados legados em host_groups e settings (port_forwards)
	// 1. host_groups com nome reservado ("VCN") e com colisão de caixa ("Servidores" e "servidores")
	hostsJSON1 := `["10.0.1.7/24", "10.0.2.20/32", "192.168.1.1"]`
	hostsJSON2 := `["10.0.3.0/24"]`
	hostsJSON3 := `["10.0.4.0/24"]`
	if _, err := db.conn.Exec(`
		INSERT INTO host_groups (id, name, description, hosts) VALUES
		('hg-vcn', 'VCN', 'Grupo VCN', ?),
		('hg-srv1', 'Servidores', 'Srv 1', ?),
		('hg-srv2', 'SERVIDORES', 'Srv 2', ?)`,
		hostsJSON1, hostsJSON2, hostsJSON3,
	); err != nil {
		t.Fatalf("inserir host_groups legados: %v", err)
	}

	// 2. port_forwards em settings
	type legacyPF struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Enabled   bool   `json:"enabled"`
		Proto     string `json:"proto"`
		Interface string `json:"interface"`
		ExtPort   int    `json:"ext_port"`
		DestIP    string `json:"dest_ip"`
		DestPort  int    `json:"dest_port"`
	}
	pfs := []legacyPF{
		{
			ID:        "pf-1",
			Name:      "Web Server",
			Enabled:   true,
			Proto:     "TCP",
			Interface: "eth0",
			ExtPort:   8080,
			DestIP:    "10.0.1.20/32",
			DestPort:  80,
		},
		{
			ID:        "pf-2",
			Name:      "",
			Enabled:   false,
			Proto:     "udp",
			Interface: "",
			ExtPort:   5353,
			DestIP:    "10.0.1.53",
			DestPort:  53,
		},
	}
	pfBytes, _ := json.Marshal(pfs)
	if _, err := db.conn.Exec(`INSERT OR REPLACE INTO settings (key, value) VALUES ('port_forwards', ?)`, string(pfBytes)); err != nil {
		t.Fatalf("inserir port_forwards legados: %v", err)
	}

	// Agora executa as migrações 103 e 104
	var migs103e104 []migration
	for _, m := range schemaMigrations {
		if m.version >= 103 && m.version <= 104 {
			migs103e104 = append(migs103e104, m)
		}
	}
	if err := db.runMigrations(migs103e104); err != nil {
		t.Fatalf("rodar migrações 103 e 104: %v", err)
	}

	// Verifica aliases migrados
	var nomeVCN, chaveVCN, itensVCN string
	if err := db.conn.QueryRow(`SELECT nome, nome_chave, itens FROM fw_aliases WHERE id = 'hg-vcn'`).Scan(&nomeVCN, &chaveVCN, &itensVCN); err != nil {
		t.Fatalf("alias hg-vcn não encontrado: %v", err)
	}
	if nomeVCN != "VCN (grupo)" {
		t.Errorf("nome reservado 'VCN' deveria ter virado 'VCN (grupo)', virou %q", nomeVCN)
	}
	// Verifica aplicação de máscara
	if itensVCN != `["10.0.1.0/24","10.0.2.20","192.168.1.1"]` {
		t.Errorf("itens do alias não foram normalizados com máscara: %s", itensVCN)
	}

	// Verifica resolução de colisão de nome entre hg-srv1 e hg-srv2
	var nomeSrv1, nomeSrv2 string
	_ = db.conn.QueryRow(`SELECT nome FROM fw_aliases WHERE id = 'hg-srv1'`).Scan(&nomeSrv1)
	_ = db.conn.QueryRow(`SELECT nome FROM fw_aliases WHERE id = 'hg-srv2'`).Scan(&nomeSrv2)
	if nomeSrv1 == nomeSrv2 {
		t.Errorf("nomes colidiram após migração: srv1=%q, srv2=%q", nomeSrv1, nomeSrv2)
	}

	// Verifica encaminhamentos migrados
	var countEnc int
	if err := db.conn.QueryRow(`SELECT COUNT(*) FROM fw_encaminhamentos`).Scan(&countEnc); err != nil {
		t.Fatalf("contar encaminhamentos: %v", err)
	}
	if countEnc != 2 {
		t.Errorf("esperava 2 encaminhamentos migrados, obteve %d", countEnc)
	}

	var nomePF1, ipPF1 string
	var ativoPF1, portaExtPF1 int
	if err := db.conn.QueryRow(`
		SELECT nome, ativo, porta_externa, ip_destino
		FROM fw_encaminhamentos
		WHERE id = 'pf-1'`).Scan(&nomePF1, &ativoPF1, &portaExtPF1, &ipPF1); err != nil {
		t.Fatalf("encaminhamento pf-1 não encontrado: %v", err)
	}
	if ativoPF1 != 1 || portaExtPF1 != 8080 || ipPF1 != "10.0.1.20" {
		t.Errorf("campos inesperados em pf-1: ativo=%d, porta=%d, ip=%q", ativoPF1, portaExtPF1, ipPF1)
	}
	if nomePF1 != "Web Server (interface eth0 ignorada na conversão)" {
		t.Errorf("anotação de interface ignorada inesperada: %q", nomePF1)
	}

	// Idempotência: rodar novamente não pode falhar
	if err := db.runMigrations(migs103e104); err != nil {
		t.Fatalf("segunda execução de 103 e 104 falhou: %v", err)
	}
}
