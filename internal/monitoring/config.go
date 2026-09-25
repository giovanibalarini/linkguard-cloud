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
		Services:                  []string{"unbound", "nftables"},
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
	c.Services = semServicosAposentados(c.Services)
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

// servicosAposentados são unidades que o produto já vigiou e não tem mais.
//
// A caixa que veio do linkguard-fw traz a lista gravada com o
// kea-dhcp4-server, e a migração para o pacote cloud PARA o kea (a versão
// cloud não serve DHCP: quem entrega endereço na VCN é a Oracle). Sem este
// filtro, o vigia olharia uma unidade instalada e parada e diria "Serviço
// offline: kea-dhcp4-server" — um alerta de queda para um serviço que foi
// desligado de propósito.
var servicosAposentados = map[string]bool{"kea-dhcp4-server": true}

func semServicosAposentados(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !servicosAposentados[s] {
			out = append(out, s)
		}
	}
	return out
}

// SaveConfig persists the config.
func SaveConfig(db *storage.DB, c Config) error {
	out, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return db.SetSetting(configKey, string(out))
}
