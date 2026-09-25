package storage

import (
	"time"

	"github.com/google/uuid"
)

// ─── iptables backups repository ─────────────────────────────────────────────

// CreateIptablesBackup stores an iptables rules snapshot.
func (db *DB) CreateIptablesBackup(b *IptablesBackup) error {
	if b.ID == "" {
		b.ID = uuid.NewString()
	}
	b.CreatedAt = time.Now()
	_, err := db.conn.Exec(`
		INSERT INTO iptables_backups (id, label, rules, created_at) VALUES (?, ?, ?, ?)`,
		b.ID, b.Label, b.Rules, b.CreatedAt)
	return err
}

// GetIptablesBackups returns backup history.
func (db *DB) GetIptablesBackups(limit int) ([]IptablesBackup, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := db.conn.Query(`
		SELECT id, label, rules, created_at
		FROM iptables_backups ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var backups []IptablesBackup
	for rows.Next() {
		var b IptablesBackup
		if err := rows.Scan(&b.ID, &b.Label, &b.Rules, &b.CreatedAt); err != nil {
			return nil, err
		}
		backups = append(backups, b)
	}
	return backups, rows.Err()
}
