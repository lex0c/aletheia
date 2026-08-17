package facts

import "testing"

// OS QUATRO FORMATOS, e cada um responde "pede senha?" de um jeito diferente.
//
// O cenário exercita só o OpenSSH novo. Os outros três existem em servidor
// antigo e em chave gerada por ferramenta de nuvem, e uma resposta errada aqui
// é pior que nenhuma: dizer que uma chave protegida está aberta faz o operador
// rotacionar à toa; o contrário deixa uma credencial exposta sem aviso.
func TestFormatosDeChavePrivada(t *testing.T) {
	casos := []struct {
		nome    string
		tipo    string
		texto   string
		cifrada bool
	}{
		{
			nome: "PEM clássico SEM senha", tipo: "rsa", cifrada: false,
			texto: "-----BEGIN RSA PRIVATE KEY-----\n" +
				"MIIEowIBAAKCAQEAuEDJiI7lFJ6e9qN1SgLvaXJbBIDAcVCFOOQtIo8wN/KxEaA7\n" +
				"-----END RSA PRIVATE KEY-----\n",
		},
		{
			// O par `Proc-Type` + `DEK-Info` é como o OpenSSL marca cifragem no
			// formato antigo. É o que ssh-keygen -m PEM escreve.
			nome: "PEM clássico COM senha", tipo: "rsa", cifrada: true,
			texto: "-----BEGIN RSA PRIVATE KEY-----\n" +
				"Proc-Type: 4,ENCRYPTED\n" +
				"DEK-Info: AES-128-CBC,EFAF496112AB1D64CF47E516F7F3F8C4\n\n" +
				"MIIEowIBAAKCAQEAuEDJiI7lFJ6e9qN1SgLvaXJbBIDAcVCFOOQtIo8wN/KxEaA7\n" +
				"-----END RSA PRIVATE KEY-----\n",
		},
		{
			nome: "PKCS#8 cifrada", tipo: "pkcs8-cifrada", cifrada: true,
			texto: "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n" +
				"-----END ENCRYPTED PRIVATE KEY-----\n",
		},
		{
			// Gerada por ssh-keygen -t ed25519 -N '' — o corpo declara a cifra
			// `none`, e é preciso decodificar para descobrir.
			nome: "OpenSSH novo SEM senha", tipo: "openssh", cifrada: false,
			texto: "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
				"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n" +
				"QyNTUxOQAAACAKlbMkWN+4WnJuLfhyXdl5i1VnqO7eVL2ylTZYW5SomwAAAIjyYC208mAt\n" +
				"-----END OPENSSH PRIVATE KEY-----\n",
		},
		{
			// A mesma forma com `aes256-ctr` no lugar de `none`.
			nome: "OpenSSH novo COM senha", tipo: "openssh", cifrada: true,
			texto: "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
				"b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABBwe+jSOr\n" +
				"-----END OPENSSH PRIVATE KEY-----\n",
		},
		{
			// Corpo ilegível: a leitura CONSERVADORA é "cifrada". Errar para o
			// lado de calar um achado é melhor que acusar uma chave que pede
			// senha e mandar o time rotacionar à toa.
			nome: "OpenSSH ilegível", tipo: "openssh", cifrada: true,
			texto: "-----BEGIN OPENSSH PRIVATE KEY-----\n!!!nao-eh-base64!!!\n" +
				"-----END OPENSSH PRIVATE KEY-----\n",
		},
	}

	for _, c := range casos {
		if got := chaveCifrada(c.texto, c.tipo); got != c.cifrada {
			t.Errorf("%s: chaveCifrada = %v, quer %v", c.nome, got, c.cifrada)
		}
	}
}

// O `known_hosts` embaralhado não devolve o destino, e a ferramenta precisa
// dizer isso em vez de fingir lista completa — a contagem continua valendo.
func TestKnownHostsEmbaralhado(t *testing.T) {
	f := &Facts{}
	lerKnownHostsTexto(f, "/root/.ssh/known_hosts",
		"bastion.interno ssh-ed25519 AAAA\n"+
			"|1|salt=|hash= ssh-ed25519 AAAA\n"+
			"# comentário\n\n")

	if len(f.Destinos) != 2 {
		t.Fatalf("destinos = %v", f.Destinos)
	}
	if f.Destinos[0].Host != "bastion.interno" || f.Destinos[0].Hasheado {
		t.Error("entrada em texto claro precisa manter o nome")
	}
	if f.Destinos[1].Host != "" || !f.Destinos[1].Hasheado {
		t.Error("entrada embaralhada não tem destino recuperável, e precisa dizer")
	}
}
