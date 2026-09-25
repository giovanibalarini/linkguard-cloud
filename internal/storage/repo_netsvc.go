package storage

// ─── DNS repository ──────────────────────────────────────────────────────────

// ListDNSBlocklist returns all blocked domains ordered alphabetically.
func (db *DB) ListDNSBlocklist() ([]string, error) {
	rows, err := db.conn.Query(`SELECT domain FROM dns_blocklist ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// AddDNSBlocklist adds a domain to the DNS blocklist.
func (db *DB) AddDNSBlocklist(domain string) error {
	_, err := db.conn.Exec(`INSERT OR IGNORE INTO dns_blocklist (domain) VALUES (?)`, domain)
	return err
}

// DeleteDNSBlocklist removes a domain from the DNS blocklist.
func (db *DB) DeleteDNSBlocklist(domain string) error {
	_, err := db.conn.Exec(`DELETE FROM dns_blocklist WHERE domain = ?`, domain)
	return err
}
