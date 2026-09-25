package storage

import "time"

// ─── Máquinas (host_info, por IP) ────────────────────────────────────────────

// UpsertHostSightings grava que estes IPs foram vistos agora, numa transação
// só: uma escrita por máquina a cada abertura da tela fazia um fsync por linha.
// Os campos do admin (apelido, bloqueio) e o nome resolvido são preservados.
func (db *DB) UpsertHostSightings(ips []string) error {
	if len(ips) == 0 {
		return nil
	}
	now := time.Now()
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`
		INSERT INTO host_info (ip, first_seen, last_seen)
		VALUES (?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET last_seen = excluded.last_seen`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, ip := range ips {
		if _, err := stmt.Exec(ip, now, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListHostInfo devolve todas as máquinas conhecidas.
func (db *DB) ListHostInfo() ([]HostInfo, error) {
	rows, err := db.conn.Query(`
		SELECT ip, hostname, alias, blocked, first_seen, last_seen
		FROM host_info`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []HostInfo
	for rows.Next() {
		var h HostInfo
		var blocked int
		if err := rows.Scan(&h.IP, &h.Hostname, &h.Alias, &blocked, &h.FirstSeen, &h.LastSeen); err != nil {
			return nil, err
		}
		h.Blocked = blocked != 0
		list = append(list, h)
	}
	return list, rows.Err()
}

// SetHostAlias dá um apelido à máquina (criando a linha se preciso).
func (db *DB) SetHostAlias(ip, alias string) error {
	now := time.Now()
	_, err := db.conn.Exec(`
		INSERT INTO host_info (ip, alias, first_seen, last_seen)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET alias = excluded.alias`,
		ip, alias, now, now)
	return err
}

// SetHostBlocked liga ou desliga o bloqueio da máquina (criando a linha se
// preciso).
func (db *DB) SetHostBlocked(ip string, blocked bool) error {
	now := time.Now()
	_, err := db.conn.Exec(`
		INSERT INTO host_info (ip, blocked, first_seen, last_seen)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET blocked = excluded.blocked`,
		ip, boolToInt(blocked), now, now)
	return err
}

// SetHostnames grava os nomes resolvidos (DNS reverso da VCN) de várias
// máquinas numa transação. Só atualiza linhas que existem: nome sem máquina
// vista não é informação.
func (db *DB) SetHostnames(nomes map[string]string) error {
	if len(nomes) == 0 {
		return nil
	}
	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`UPDATE host_info SET hostname = ? WHERE ip = ?`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for ip, nome := range nomes {
		if _, err := stmt.Exec(nome, ip); err != nil {
			return err
		}
	}
	return tx.Commit()
}
