package main

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/giovanibalarini/linkguard-cloud/internal/api/handlers"
	"github.com/giovanibalarini/linkguard-cloud/internal/platform"
)

// instantaneoDaOCI é a VM real: UMA VNIC, IMDS confirmado, a placa anunciando
// 9000 e o caminho externo aceitando 1500. Os números vieram de uma instância de
// verdade — ver internal/platform/detect.go.
func instantaneoDaOCI() platform.Snapshot {
	fatos := platform.Facts{
		Kind:       platform.KindOCI,
		Confidence: platform.ConfidenceAuthoritative,
		Net: platform.NetFacts{
			PrimaryInterface: "ens3",
			LinkMTU:          9000,
			PathMTU:          1500,
			PathMTUSource:    platform.PathMTUSourcePlatform,
		},
		OCI: &platform.OCIFacts{
			MaxVNICAttachments: 1,
			VNICs:              []platform.OCIVNIC{{SubnetCIDR: "10.0.0.0/24"}},
		},
	}
	return platform.Snapshot{
		Format:       platform.SnapshotFormat,
		Facts:        fatos,
		Capabilities: platform.DeriveCapabilities(fatos),
	}
}

// rotaExec responde `ip -j route show default` com o JSON dado, ou com erro.
// Qualquer outro comando é erro: o uplink só lê a rota default.
type rotaExec struct {
	saida    string
	falha    error
	chamadas int
}

func (e *rotaExec) Execute(context.Context, string, ...string) (string, error) {
	return "", errors.New("o uplink não escreve nada")
}
func (e *rotaExec) ExecuteRead(_ context.Context, cmd string, args ...string) (string, error) {
	e.chamadas++
	if cmd != "ip" {
		return "", errors.New("comando inesperado: " + cmd)
	}
	if e.falha != nil {
		return "", e.falha
	}
	return e.saida, nil
}
func (e *rotaExec) IsDryRun() bool                              { return false }
func (e *rotaExec) WriteFile(string, []byte, os.FileMode) error { return nil }

const rotaDefaultOCI = `[{"dst":"default","gateway":"10.0.0.1","dev":"ens3","protocol":"dhcp","prefsrc":"10.0.0.47","metric":100,"flags":[]}]`

// A VM de nuvem recém-criada: a plataforma responde, e o kernel nem é
// consultado. A MTU do caminho vem junto, e é ela que alimenta a mss_clamp.
func TestNaOCIOUplinkSaiDaPlataforma(t *testing.T) {
	e := &rotaExec{falha: errors.New("não devia ter perguntado ao kernel")}
	u, err := uplinkEfetivo(context.Background(), e, instantaneoDaOCI())
	if err != nil {
		t.Fatalf("uplinkEfetivo: %v", err)
	}
	if u.Interface != "ens3" || u.PathMTU != 1500 || u.Origem != handlers.UplinkOrigemPlataforma {
		t.Fatalf("uplink = %+v, quero ens3/1500/platform", u)
	}
	if e.chamadas != 0 {
		t.Errorf("perguntou ao kernel %d vez(es) com a plataforma respondendo", e.chamadas)
	}
	wans, err := wansEfetivas(context.Background(), e, instantaneoDaOCI())
	if err != nil || len(wans) != 1 || wans[0] != "ens3" {
		t.Fatalf("wansEfetivas = %v, %v; quero [ens3]", wans, err)
	}
}

// Com mais de uma VNIC a resposta continua sendo a primária: é nela que a VCN
// põe a rota default, e não há cadastro de WAN que pudesse escolher outra.
func TestComMaisDeUmaVNICOUplinkEAPrimaria(t *testing.T) {
	s := instantaneoDaOCI()
	oci := *s.Facts.OCI
	oci.MaxVNICAttachments = 2
	s.Facts.OCI = &oci
	s.Capabilities = platform.DeriveCapabilities(s.Facts)

	u, err := uplinkEfetivo(context.Background(), &rotaExec{}, s)
	if err != nil || u.Interface != "ens3" {
		t.Fatalf("uplink = %+v, %v; quero a VNIC primária", u, err)
	}
}

// O boot em que o IMDS não respondeu (cache invalidado, metadata fora do ar).
// Sem a rota default como reserva a lista de WANs sairia vazia, e com ela a
// mss_clamp e a proteção de entrada da WAN nasceriam vazias e seriam
// persistidas assim.
func TestSemAPlataformaOUplinkEAPlacaDaRotaDefault(t *testing.T) {
	casos := map[string]platform.Snapshot{
		"o IMDS não confirmou": func() platform.Snapshot {
			s := instantaneoDaOCI()
			s.Facts.Confidence = platform.ConfidenceLocal
			return s
		}(),
		"plataforma desconhecida": platform.UnknownSnapshot(),
		"instantâneo zero":        {},
	}
	for nome, snap := range casos {
		t.Run(nome, func(t *testing.T) {
			u, err := uplinkEfetivo(context.Background(), &rotaExec{saida: rotaDefaultOCI}, snap)
			if err != nil {
				t.Fatalf("uplinkEfetivo: %v", err)
			}
			if u.Interface != "ens3" || u.Origem != handlers.UplinkOrigemKernel {
				t.Fatalf("uplink = %+v, quero ens3 vindo do kernel", u)
			}
			// Sem a plataforma a MTU do caminho é desconhecida: chutar a da
			// placa (9000 na OCI) seria um ajuste de MSS que parece feito.
			if u.PathMTU != 0 {
				t.Errorf("PathMTU = %d sem a plataforma; tinha de ser 0 (desconhecida)", u.PathMTU)
			}
		})
	}
}

// Duas rotas default: vale a de menor métrica, que é a que o kernel usa.
func TestARotaDefaultDeMenorMetricaVence(t *testing.T) {
	e := &rotaExec{saida: `[{"dst":"default","dev":"ens5","metric":200},{"dst":"default","dev":"ens3","metric":100}]`}
	u, err := uplinkEfetivo(context.Background(), e, platform.UnknownSnapshot())
	if err != nil || u.Interface != "ens3" {
		t.Fatalf("uplink = %+v, %v; quero ens3 (métrica 100)", u, err)
	}
}

// Nenhuma fonte respondeu: lista VAZIA e sem erro. É a lista vazia que mantém
// ReconcileMasquerade se recusando a tocar na chain de NAT.
func TestSemRotaDefaultALIstaDeWANsEVazia(t *testing.T) {
	for nome, saida := range map[string]string{"sem rota": `[]`, "rota sem placa": `[{"dst":"default","type":"blackhole"}]`} {
		t.Run(nome, func(t *testing.T) {
			wans, err := wansEfetivas(context.Background(), &rotaExec{saida: saida}, platform.UnknownSnapshot())
			if err != nil {
				t.Fatalf("wansEfetivas: %v", err)
			}
			if len(wans) != 0 {
				t.Fatalf("wans = %v, quero vazia", wans)
			}
		})
	}
}

// ERRO DE LEITURA PROPAGA E NÃO VIRA LISTA VAZIA: obedecer a uma lista vazia
// que na verdade é um `ip route` que falhou apagaria a proteção de entrada de
// uma caixa que a tem.
func TestErroAoLerARotaDefaultPropaga(t *testing.T) {
	_, err := wansEfetivas(context.Background(), &rotaExec{falha: errors.New("ip: comando não encontrado")}, platform.UnknownSnapshot())
	if err == nil {
		t.Fatal("o erro de leitura virou lista vazia")
	}
}

// A tela diz de onde o uplink veio: da plataforma, do kernel, ou de lugar
// nenhum — e só no último o operador tem trabalho a fazer.
func TestATelaDizDeOndeVeioOUplink(t *testing.T) {
	ctx := context.Background()
	if v := uplinkParaTela(ctx, &rotaExec{}, instantaneoDaOCI()); v.Origem != "platform" || v.Interface != "ens3" || v.PathMTU != 1500 || v.Plataforma != "oci" {
		t.Errorf("OCI: %+v", v)
	}
	if v := uplinkParaTela(ctx, &rotaExec{saida: rotaDefaultOCI}, platform.UnknownSnapshot()); v.Origem != "kernel" || v.Interface != "ens3" {
		t.Errorf("kernel: %+v", v)
	}
	if v := uplinkParaTela(ctx, &rotaExec{saida: `[]`}, platform.UnknownSnapshot()); v.Origem != "none" || v.Interface != "" {
		t.Errorf("nenhum: %+v", v)
	}
	if v := uplinkParaTela(ctx, &rotaExec{falha: errors.New("x")}, platform.UnknownSnapshot()); v.Origem != "none" || v.Interface != "" {
		t.Errorf("erro de leitura tinha de virar \"none\" honesto: %+v", v)
	}
}
