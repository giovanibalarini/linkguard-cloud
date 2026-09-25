package monitoring

import (
	"encoding/json"

	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

const configKey = "monitoring"

// Config is the persisted monitoring/alerting configuration. Absence of the
// settings key means "all defaults" — monitoring is ON out of the box.
type Config struct {
	Enabled                   bool     `json:"enabled"`
	Services                  []string `json:"services"`
	DiskThresholdPct          int      `json:"disk_threshold_pct"`
	JournalVerifyIntervalDays int      `json:"journal_verify_interval_days"`
	UpdatesCheckIntervalHours int      `json:"updates_check_interval_hours"`
}

func defaults() Config {
	return Config{
		Enabled:                   true,
		Services:                  []string{"kea-dhcp4-server", "unbound", "nftables"},
		DiskThresholdPct:          90,
		JournalVerifyIntervalDays: 7,
		UpdatesCheckIntervalHours: 6,
	}
}

// LoadConfig returns the persisted config, or zero-config defaults if unset.
func LoadConfig(db *storage.DB) Config {
	raw, err := db.GetSetting(configKey)
	if err != nil || raw == "" {
		return defaults()
	}
	c := defaults()
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return defaults()
	}
	if c.DiskThresholdPct <= 0 || c.DiskThresholdPct > 100 {
		c.DiskThresholdPct = 90
	}
	if c.JournalVerifyIntervalDays <= 0 {
		c.JournalVerifyIntervalDays = 7
	}
	if c.UpdatesCheckIntervalHours <= 0 {
		c.UpdatesCheckIntervalHours = 1
	}
	return c
}

// SaveConfig persists the config.
func SaveConfig(db *storage.DB, c Config) error {
	out, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return db.SetSetting(configKey, string(out))
}
