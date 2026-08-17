package facts

import (
	"strings"
	"testing"
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
