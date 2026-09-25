package fwmodel

import (
	"testing"
)

func TestNormalizeDays(t *testing.T) {
	casos := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"sun,mon,tue", "mon,tue,sun"},
		{"MON, tue, mon", "mon,tue"},
		{"seg,ter,qua", ""},
		{"sun,sat,fri,thu,wed,tue,mon", "mon,tue,wed,thu,fri,sat,sun"},
	}
	for _, tc := range casos {
		got := NormalizeDays(tc.in)
		if got != tc.want {
			t.Errorf("NormalizeDays(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestValidarJanela(t *testing.T) {
	casos := []struct {
		nome    string
		dias    string
		inicio  string
		fim     string
		wantErr bool
	}{
		{"vazio", "", "", "", false},
		{"dias e horario validos", "mon,wed,fri", "08:00", "18:00", false},
		{"só dias", "sat,sun", "", "", false},
		{"atravessa meia-noite", "", "22:00", "06:00", false},
		{"dia desconhecido", "seg", "08:00", "18:00", true},
		{"inicio sem fim", "", "08:00", "", true},
		{"fim sem inicio", "", "", "18:00", true},
		{"horario invalido", "", "25:00", "18:00", true},
		{"minuto invalido", "", "08:60", "18:00", true},
		{"inicio igual a fim", "", "10:00", "10:00", true},
	}
	for _, tc := range casos {
		t.Run(tc.nome, func(t *testing.T) {
			err := ValidarJanela(tc.dias, tc.inicio, tc.fim)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidarJanela(%q, %q, %q) err = %v, wantErr %v", tc.dias, tc.inicio, tc.fim, err, tc.wantErr)
			}
		})
	}
}
