package facts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

// NOTA DE MÉTODO: a primeira versão destes casos tinha blobs base64
// INVENTADOS, e o parser os rejeitou com razão — fingerprint vazio. Dado
// codificado não se escreve à mão: gera-se. O mesmo erro tinha acabado de
// acontecer no teste do apk, e o teste que passa com dado inválido não protege
// o caminho que importa.
//
// authorized_keys é o acesso permanente mais comum que existe, e o parsing dele
// é onde a chave do invasor se esconde: o bloco de OPÇÕES vem antes do tipo, e
// aceita aspas com espaço dentro. Errar o limite entre opção e chave faz o
// `command=` sumir do relatório — que é justamente a parte que diz o que aquela
// chave EXECUTA quando alguém entra com ela.
func TestParseAuthorizedKey(t *testing.T) {
	casos := []struct {
		nome                  string
		linha                 string
		tipo, opcoes, comment string
		querFingerprint       bool
	}{
		{
			nome:            "chave simples",
			linha:           "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= deploy@ci",
			tipo:            "ssh-ed25519",
			comment:         "deploy@ci",
			querFingerprint: true,
		},
		{
			// A FORMA QUE IMPORTA: forced command. A chave entra e executa
			// aquilo, e o comando tem ESPAÇO dentro das aspas.
			nome:            "com forced command entre aspas",
			linha:           `command="/bin/bash -i",no-pty ssh-rsa AAAAB3NzaC1yc2EBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB backup`,
			tipo:            "ssh-rsa",
			opcoes:          `command="/bin/bash -i",no-pty`,
			comment:         "backup",
			querFingerprint: true,
		},
		{
			nome:            "opções sem aspas",
			linha:           "no-port-forwarding,no-agent-forwarding ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= chave",
			tipo:            "ssh-ed25519",
			opcoes:          "no-port-forwarding,no-agent-forwarding",
			comment:         "chave",
			querFingerprint: true,
		},
		{
			nome:            "chave de token físico",
			linha:           "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI= yubikey",
			tipo:            "sk-ssh-ed25519@openssh.com",
			comment:         "yubikey",
			querFingerprint: true,
		},
		{
			nome:  "sem comentário",
			linha: "ssh-rsa AAAAB3NzaC1yc2EBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB",
			tipo:  "ssh-rsa", querFingerprint: true,
		},
		{nome: "linha vazia", linha: ""},
		{nome: "lixo", linha: "isto-nao-e-chave"},
	}

	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			k := ParseAuthorizedKeyParaTeste(c.linha)
			if k.Type != c.tipo {
				t.Errorf("tipo = %q, queria %q", k.Type, c.tipo)
			}
			if k.Options != c.opcoes {
				t.Errorf("opções = %q, queria %q", k.Options, c.opcoes)
			}
			if k.Comment != c.comment {
				t.Errorf("comentário = %q, queria %q", k.Comment, c.comment)
			}
			if c.querFingerprint && k.Fingerprint == "" {
				t.Error("sem fingerprint a chave não serve de IOC de frota: " +
					"a MESMA chave em vários hosts é a mesma pessoa")
			}
		})
	}
}

// O limite do bloco de opções respeita aspas. Sem isso, `command="/bin/bash -i"`
// seria cortado no espaço do meio e o resto da linha viraria a chave.
func TestFimDasOpcoesRespeitaAspas(t *testing.T) {
	casos := []struct {
		ln   string
		quer int
	}{
		{`command="a b" ssh-rsa X`, 13},
		{`no-pty ssh-rsa X`, 6},
		{`sozinho`, -1},
		{``, -1},
	}
	for _, c := range casos {
		if got := fimDasOpcoes(c.ln); got != c.quer {
			t.Errorf("fimDasOpcoes(%q) = %d, queria %d", c.ln, got, c.quer)
		}
	}
}

// O fingerprint é o SHA-256 no formato que o ssh-keygen imprime, porque é assim
// que o operador vai comparar com o que ele tem em mãos.
func TestFingerprintNoFormatoDoSshKeygen(t *testing.T) {
	fp := FingerprintSSH("AAAAC3NzaC1lZDI1NTE5AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if !strings.HasPrefix(fp, "SHA256:") {
		t.Errorf("o ssh-keygen imprime com prefixo SHA256:, e saiu %q", fp)
	}
	// O mesmo blob dá o mesmo fingerprint — é o que torna a comparação entre
	// hosts possível.
	if fp != FingerprintSSH("AAAAC3NzaC1lZDI1NTE5AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=") {
		t.Error("o fingerprint não é estável")
	}
	if FingerprintSSH("") != "" {
		t.Error("sem blob não há fingerprint a inventar")
	}
}

func TestPareceTipoDeChave(t *testing.T) {
	for _, s := range []string{"ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256", "sk-ssh-ed25519@openssh.com"} {
		if !pareceTipoDeChave(s) {
			t.Errorf("%q é tipo de chave", s)
		}
	}
	for _, s := range []string{"command=\"x\"", "no-pty", "", "restrict"} {
		if pareceTipoDeChave(s) {
			t.Errorf("%q é opção, não tipo de chave", s)
		}
	}
}

// sshd_config ilegível não pode virar "host sem SSH".
//
// O arquivo é 0600 root em host endurecido. Sem root, a leitura falha, c.Files
// fica vazio — e vazio era o mesmo estado de uma máquina que não tem servidor
// SSH nenhum. O check de PermitRootLogin voltava mudo sobre um host que aceita
// login de root pela rede.
func TestSshdConfigIlegivelNaoViraHostSemSSH(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root lê tudo")
	}
	raiz := t.TempDir()
	if err := os.MkdirAll(filepath.Join(raiz, "etc/ssh"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(raiz, "etc/ssh/sshd_config")
	if err := os.WriteFile(cfg, []byte("PermitRootLogin yes\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	e := env.Probe(env.Options{Root: raiz})
	t.Cleanup(func() { e.Close() })
	f := Collect(e)

	if len(f.SSH.Files) != 0 {
		t.Fatalf("o arquivo é ilegível: não podia ter sido lido — %v", f.SSH.Files)
	}
	if len(f.PersistDenied["ssh"]) == 0 {
		t.Error("config ilegível saiu igual a config ausente: a diferença entre " +
			"'esta máquina não tem sshd' e 'não consegui ler quem entra nela'")
	}
}

// O parser do config de cliente: a diretiva certa vira comando, e o que NÃO
// executa (ProxyCommand none, LocalCommand sem PermitLocalCommand) fica de fora.
func TestParseClientConfig(t *testing.T) {
	cfg := "" +
		"Host bom\n" +
		"    ProxyCommand ssh -W %h:%p bastion\n" +
		"Host ruim\n" +
		"    ProxyCommand /tmp/.beacon %h\n" +
		"Host desligado\n" +
		"    ProxyCommand none\n" +
		"Host local-inerte\n" +
		"    LocalCommand /tmp/x\n" + // sem PermitLocalCommand: não executa
		"Host local-vivo\n" +
		"    PermitLocalCommand yes\n" +
		"    LocalCommand /tmp/y\n" +
		"Match exec \"/tmp/decide.sh %h\"\n"

	got := AnalisaConfigClienteParaTeste("/root/.ssh/config", "root", []byte(cfg))

	quer := map[string]string{
		"ProxyCommand": "ssh -W %h:%p bastion", // o primeiro ProxyCommand achado
		"LocalCommand": "/tmp/y",               // só o que tem a permissão
		"Match exec":   "/tmp/decide.sh %h",    // desaspado
	}
	viu := map[string]int{}
	for _, d := range got {
		viu[d.Directive]++
	}
	// ProxyCommand aparece 2x (ssh e /tmp/.beacon), nunca o `none`.
	if viu["ProxyCommand"] != 2 {
		t.Errorf("ProxyCommand: quer 2 (o `none` não conta), viu %d", viu["ProxyCommand"])
	}
	if viu["LocalCommand"] != 1 {
		t.Errorf("LocalCommand: quer 1 (o inerte sem PermitLocalCommand fica fora), viu %d", viu["LocalCommand"])
	}
	if viu["Match exec"] != 1 {
		t.Errorf("Match exec: quer 1, viu %d", viu["Match exec"])
	}
	// a desaspagem do Match exec
	for _, d := range got {
		if d.Directive == "Match exec" && d.Command != quer["Match exec"] {
			t.Errorf("Match exec desaspado: quer %q, viu %q", quer["Match exec"], d.Command)
		}
	}
}

// matchExec pega o comando depois de `exec`, com e sem aspas.
func TestMatchExec(t *testing.T) {
	casos := []struct {
		in, quer string
		ok       bool
	}{
		{`host bastion exec "/opt/gate %h"`, "/opt/gate %h", true},
		{`exec /usr/bin/decide`, "/usr/bin/decide", true},
		{`host foo`, "", false}, // sem exec
	}
	for _, c := range casos {
		got, ok := matchExec(c.in)
		if ok != c.ok || (ok && got != c.quer) {
			t.Errorf("matchExec(%q) = (%q,%v), quer (%q,%v)", c.in, got, ok, c.quer, c.ok)
		}
	}
}
