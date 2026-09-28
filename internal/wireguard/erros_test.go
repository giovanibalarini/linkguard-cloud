package wireguard

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/giovanibalarini/linkguard-cloud/internal/secrets"
	"github.com/giovanibalarini/linkguard-cloud/internal/storage"
)

// execQueRecusa falha os comandos que `recusar` escolher e repassa o resto ao
// executor de teste.
type execQueRecusa struct {
	*serviceExec
	recusar func(cmd string, args []string) bool
}

func (e *execQueRecusa) Execute(ctx context.Context, cmd string, args ...string) (string, error) {
	if e.recusar != nil && e.recusar(cmd, args) {
		return "", errors.New("recusado pelo teste: stderr com /caminho/interno")
	}
	return e.serviceExec.Execute(ctx, cmd, args...)
}

func recusaHabilitar(cmd string, args []string) bool {
	return cmd == "systemctl" && len(args) > 0 && args[0] == "enable"
}

// cofreQueNaoApaga guarda os segredos normalmente e falha só ao apagá-los.
type cofreQueNaoApaga struct{ secrets.Secrets }

func (cofreQueNaoApaga) Delete(string) error { return errors.New("cofre indisponível") }

func confDoServidor(t *testing.T, svc *Service) string {
	t.Helper()
	conteudo, err := os.ReadFile(svc.configPath)
	if err != nil {
		t.Fatalf("ler a config do servidor: %v", err)
	}
	return string(conteudo)
}

func TestRevogarReconciliaMesmoSemALinhaDoPeer(t *testing.T) {
	svc, db, _, exec := newServiceTest(t)
	userID, enrollment := enrolaUsuario(t, svc, db, "ana")
	chave := enrollment.Peer.PublicKey
	if !strings.Contains(confDoServidor(t, svc), chave) {
		t.Fatal("o peer deveria estar na config do servidor depois de enrolar")
	}

	// A primeira revogação apaga a linha do banco, mas o wg-quick recusa a
	// config nova: o peer segue no arquivo que o kernel usa.
	exec.failStrip = true
	err := svc.Revoke(context.Background(), userID)
	var falha *FalhaDeReconciliacao
	if !errors.As(err, &falha) {
		t.Fatalf("Revoke = %v, queria FalhaDeReconciliacao", err)
	}
	if peer, _ := db.GetWireGuardPeer(userID); peer != nil {
		t.Fatal("a linha do peer deveria ter saído do banco")
	}
	if !strings.Contains(confDoServidor(t, svc), chave) {
		t.Fatal("com o validador recusando, o arquivo vivo não devia mudar")
	}

	// Tentar de novo tem de consertar o arquivo, mesmo já não havendo linha:
	// senão a revogação fica presa para sempre no estado "meio feito".
	exec.failStrip = false
	if err := svc.Revoke(context.Background(), userID); err != nil {
		t.Fatalf("segunda revogação: %v", err)
	}
	if strings.Contains(confDoServidor(t, svc), chave) {
		t.Fatal("o peer revogado continua na config do servidor")
	}
}

func TestRevogarNaoFalhaPorCausaDoCofre(t *testing.T) {
	svc, db, sec, _ := newServiceTest(t)
	userID, enrollment := enrolaUsuario(t, svc, db, "beto")
	svc.secrets = cofreQueNaoApaga{Secrets: sec}

	if err := svc.Revoke(context.Background(), userID); err != nil {
		t.Fatalf("Revoke = %v: um segredo órfão não pode desfazer a revogação", err)
	}
	if strings.Contains(confDoServidor(t, svc), enrollment.Peer.PublicKey) {
		t.Fatal("o peer revogado continua na config do servidor")
	}
}

func TestFalhaDoSistemaChegaTipadaEComAMudancaGravada(t *testing.T) {
	svc, db, _, exec := newServiceTest(t)
	userID, _ := enrolaUsuario(t, svc, db, "carla")
	svc.exec = &execQueRecusa{serviceExec: exec, recusar: recusaHabilitar}

	t.Run("perfil do peer", func(t *testing.T) {
		err := svc.SetPeerAccess(context.Background(), userID, PeerAccess{AccessMode: "full", TunnelMode: TunnelSplit})
		var falha *FalhaDeReconciliacao
		if !errors.As(err, &falha) {
			t.Fatalf("SetPeerAccess = %v, queria FalhaDeReconciliacao", err)
		}
		peer, _ := db.GetWireGuardPeer(userID)
		if peer == nil || peer.TunnelMode != TunnelSplit {
			t.Fatalf("a mudança deveria estar gravada: %+v", peer)
		}
	})

	t.Run("config da VPN", func(t *testing.T) {
		c := DefaultConfig()
		c.Enabled = true
		c.EndpointHost = "outro.example.net"
		err := svc.UpdateConfig(context.Background(), c)
		var falha *FalhaDeReconciliacao
		if !errors.As(err, &falha) {
			t.Fatalf("UpdateConfig = %v, queria FalhaDeReconciliacao", err)
		}
		gravada, _ := svc.Config()
		if gravada.EndpointHost != "outro.example.net" {
			t.Fatalf("a mudança deveria estar gravada: %+v", gravada)
		}
		var recusa *Recusa
		if errors.As(err, &recusa) {
			t.Fatal("uma falha do sistema não é uma recusa ao pedido")
		}
	})

	t.Run("a próxima leitura conta a verdade", func(t *testing.T) {
		visao, err := svc.Overview(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if visao.LastApplyOK || visao.LastApplyError == "" {
			t.Fatalf("Overview deveria acusar a última aplicação falha: %+v", visao)
		}
	})
}

func exigirRecusa(t *testing.T, err error, motivo Motivo) {
	t.Helper()
	var r *Recusa
	if !errors.As(err, &r) {
		t.Fatalf("erro = %v, queria uma Recusa", err)
	}
	if r.Motivo != motivo {
		t.Fatalf("motivo = %d, queria %d (%q)", r.Motivo, motivo, r.Msg)
	}
	if strings.TrimSpace(r.Msg) == "" {
		t.Fatal("a recusa precisa de uma mensagem legível")
	}
	var falha *FalhaDeReconciliacao
	if errors.As(err, &falha) {
		t.Fatalf("uma recusa ao pedido não é falha do sistema: %v", err)
	}
}

func TestRecusasDoServicoCarregamOMotivo(t *testing.T) {
	svc, db, _, _ := newServiceTest(t)
	ctx := context.Background()
	pessoa := &storage.User{Username: "sem-vpn"}
	if err := db.CreateUser(pessoa, "hash", nil); err != nil {
		t.Fatal(err)
	}

	t.Run("config inválida", func(t *testing.T) {
		c := DefaultConfig()
		c.Address = "10.7.0.1/8"
		exigirRecusa(t, svc.UpdateConfig(ctx, c), PedidoInvalido)
	})
	t.Run("enrolar com a VPN desligada", func(t *testing.T) {
		_, err := svc.Enroll(ctx, pessoa.ID)
		exigirRecusa(t, err, EstadoImpede)
	})
	t.Run("perfil inválido", func(t *testing.T) {
		_, err := svc.EnrollFor(ctx, pessoa.ID, PeerAccess{AccessMode: "quase"})
		exigirRecusa(t, err, PedidoInvalido)
	})
	t.Run("perfil de peer que não existe", func(t *testing.T) {
		exigirRecusa(t, svc.SetPeerAccess(ctx, pessoa.ID, PeerAccess{AccessMode: "full"}), NaoEncontrado)
	})
	t.Run("perfil com rota inválida", func(t *testing.T) {
		exigirRecusa(t, svc.SetPeerAccess(ctx, pessoa.ID, PeerAccess{AccessMode: "full", ExtraRoutes: []string{"não é rota"}}), PedidoInvalido)
	})
	t.Run("perfil com MTU impraticável", func(t *testing.T) {
		exigirRecusa(t, svc.SetPeerAccess(ctx, pessoa.ID, PeerAccess{AccessMode: "full", MTU: 42}), PedidoInvalido)
	})

	c := DefaultConfig()
	c.Enabled = true
	c.EndpointHost = "vpn.example.net"
	if err := svc.UpdateConfig(ctx, c); err != nil {
		t.Fatal(err)
	}

	t.Run("reemitir sem identidade", func(t *testing.T) {
		_, err := svc.ClientConfig(ctx, pessoa.ID)
		exigirRecusa(t, err, NaoEncontrado)
	})
	t.Run("usuário que não existe", func(t *testing.T) {
		_, err := svc.Enroll(ctx, "u-que-nao-existe")
		exigirRecusa(t, err, NaoEncontrado)
	})
	t.Run("sem endereço público", func(t *testing.T) {
		row, _ := db.GetWireGuardConfig()
		semEndereco := *row
		semEndereco.EndpointHost = ""
		if err := db.SaveWireGuardConfig(&semEndereco); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = db.SaveWireGuardConfig(row) }()
		_, err := svc.Enroll(ctx, pessoa.ID)
		exigirRecusa(t, err, EstadoImpede)
	})
	t.Run("config gravada corrompida", func(t *testing.T) {
		row, _ := db.GetWireGuardConfig()
		corrompida := *row
		corrompida.Address = "10.7.0.1/24\nPostUp = pwn"
		if err := db.SaveWireGuardConfig(&corrompida); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = db.SaveWireGuardConfig(row) }()
		_, err := svc.Enroll(ctx, pessoa.ID)
		exigirRecusa(t, err, EstadoImpede)
		_, err = svc.ClientConfig(ctx, pessoa.ID)
		exigirRecusa(t, err, EstadoImpede)
	})
}

func TestReconciliarConfigCorrompidaEFalhaDoSistemaNaoRecusa(t *testing.T) {
	svc, db, _, _ := newServiceTest(t)
	ruim := &storage.WireGuardConfig{Enabled: true, ListenPort: 51820, Address: "10.7.0.1/24\nPostUp = pwn", EndpointHost: "vpn.example.net"}
	if err := db.SaveWireGuardConfig(ruim); err != nil {
		t.Fatal(err)
	}

	err := svc.Reconcile(context.Background())
	var falha *FalhaDeReconciliacao
	if !errors.As(err, &falha) {
		t.Fatalf("Reconcile = %v, queria FalhaDeReconciliacao", err)
	}
	var r *Recusa
	if errors.As(err, &r) {
		t.Fatalf("quem chama não pode ter de adivinhar pela ordem dos testes: %v é falha do sistema E recusa", err)
	}
}

func TestErroDeInfraestruturaNaoViraRecusa(t *testing.T) {
	svc, db, _, _ := newServiceTest(t)
	userID, _ := enrolaUsuario(t, svc, db, "dora")
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	err := svc.SetPeerAccess(context.Background(), userID, PeerAccess{AccessMode: "full"})
	if err == nil {
		t.Fatal("com o banco fechado o serviço deveria falhar")
	}
	var r *Recusa
	if errors.As(err, &r) {
		t.Fatalf("erro de banco não é uma recusa que possa ir à tela: %v", err)
	}
}
