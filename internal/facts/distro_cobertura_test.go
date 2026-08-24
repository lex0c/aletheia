package facts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// As tabelas de caminho são a superfície onde "esta distro não é entendida"
// vira, sozinha, "esta distro está limpa".
//
// Um caminho que falta numa tabela não produz erro, não produz lacuna e não
// produz achado: o arquivo simplesmente não existe naquele host, então nem o
// ramo negativo do lookup é tomado. É a falha mais silenciosa que esta base
// pode ter, e foi assim que a família RHEL inteira ficou sem o /etc/bashrc —
// enquanto o vigia.go, dez arquivos ao lado, já listava o caminho.
//
// Esta trava não sabe julgar se uma tabela está COMPLETA. Ela fixa o que a
// revisão de compatibilidade já pagou para descobrir, para que a próxima
// edição não desfaça em silêncio.
func TestTabelasCobremAsFamiliasDeDistro(t *testing.T) {
	sistema := map[string]bool{}
	for _, g := range gatilhosDeSistema {
		sistema[g.path] = true
	}
	diretorio := map[string]bool{}
	for _, g := range gatilhosDeDiretorio {
		diretorio[g.dir] = true
	}

	casos := []struct {
		caminho string
		tabela  map[string]bool
		porque  string
	}{
		// Família RHEL: Rocky, Alma, CentOS, Fedora. O /etc/profile chama o
		// /etc/bashrc, e uma linha ali roda em todo login SSH de todo usuário.
		{"/etc/bashrc", sistema, "o bash.bashrc da família RHEL"},
		{"/etc/zshenv", sistema, "o zshenv da família RHEL — roda SEMPRE, até em zsh não interativo"},
		{"/etc/zprofile", sistema, "o zsh de login da família RHEL"},
		{"/etc/zshrc", sistema, "o zsh interativo da família RHEL"},
		// Debian/Ubuntu/SUSE: a metade que já estava lá, fixada para o
		// conserto de uma família não apagar a outra.
		{"/etc/bash.bashrc", sistema, "o bashrc de Debian, Ubuntu e SUSE"},
		{"/etc/zsh/zshenv", sistema, "o zshenv de Debian e Ubuntu"},
		// O principal do dracut, ao lado dos fragmentos: num Rocky 9 de fábrica
		// o conf.d vem vazio e o principal existe.
		{"/etc/rc.local", sistema, "o rc.local clássico"},
		// OpenRC: Alpine e Gentoo. Sem systemd, um script aqui não é Unit,
		// não é Cron, e era Trigger de ninguém.
		{"/etc/local.d", diretorio, "o rc.local do OpenRC (Alpine, Gentoo)"},
		// busybox run-parts: os cinco, não três. Os dois que faltavam eram
		// inventariados como entrada de cron e tinham o conteúdo nunca lido.
		{"/etc/periodic/15min", diretorio, "run-parts do busybox"},
		{"/etc/periodic/hourly", diretorio, "run-parts do busybox"},
		{"/etc/periodic/daily", diretorio, "run-parts do busybox"},
		{"/etc/periodic/weekly", diretorio, "run-parts do busybox"},
		{"/etc/periodic/monthly", diretorio, "run-parts do busybox"},
		// E os equivalentes Debian/RHEL, para a simetria não se perder.
		{"/etc/cron.weekly", diretorio, "o cron.weekly de Debian e RHEL"},
		{"/etc/cron.monthly", diretorio, "o cron.monthly de Debian e RHEL"},
	}
	for _, c := range casos {
		if !c.tabela[c.caminho] {
			t.Errorf("%s saiu da tabela de gatilhos.\n"+
				"É %s. Um caminho ausente aqui não gera erro nem lacuna — o arquivo "+
				"só não existe naquele host, e o relatório sai com cobertura COMPLETA "+
				"sobre um mecanismo de persistência que ninguém olhou.", c.caminho, c.porque)
		}
	}
}

// O /etc/dracut.conf é lido ALÉM dos drop-ins, e a asserção é sobre o fonte
// porque o coletor não expõe a lista.
//
// Num Rocky 9 de fábrica o /etc/dracut.conf.d vem VAZIO e o /etc/dracut.conf
// existe: o único lugar que se edita normalmente era o único que não era lido.
// É a mesma forma que o /etc/apt/apt.conf já tinha ganhado ao lado do
// apt.conf.d, com o mesmo comentário explicando por quê.
func TestDracutLeOArquivoPrincipalEnaoSoOsFragmentos(t *testing.T) {
	src := lerFonte(t, "initramfs.go")
	if !strings.Contains(src, `"/etc/dracut.conf"`) {
		t.Error("/etc/dracut.conf não é lido: um install_items ali embute o " +
			"arquivo na imagem e ele roda como root antes do pivot da raiz, sem " +
			"aparecer em hook nenhum — e sem lacuna declarada")
	}
}

func lerFonte(t *testing.T, nome string) string {
	t.Helper()
	b, err := os.ReadFile(nome)
	if err != nil {
		t.Fatalf("ler %s: %v", nome, err)
	}
	return string(b)
}

// A chave de lacuna do homeDirs precisa ser a do COLETOR que pergunta.
//
// homeDirs declara a lacuna quando o /etc/passwd não abre, e a chave decide
// QUAL check degrada. Passar a chave errada não quebra nada de forma visível —
// a catraca de lacunas continua satisfeita, porque a chave errada também é uma
// chave consumida por alguém — e o relatório passa a dizer que o check errado
// não cobriu o que devia. É o mesmo defeito que o comentário do rodarColetor
// descreve: "o coletor caiu" sem dizer qual manda o operador procurar no lugar
// errado.
//
// Este teste existe porque o erro aconteceu: um `sed` com vários `-e` aplica
// TODOS os scripts a TODOS os arquivos, e onze chamadas ficaram com a chave
// "segredo" — inclusive as de codigo, ssh, trust, startup e persist. Nenhum
// teste reclamou.
func TestHomeDirsDeclaraSobAChaveDoColetorQuePergunta(t *testing.T) {
	esperado := map[string]string{
		"codigo.go":     "codigo",
		"credencial.go": "credencial",
		"persist.go":    "persist",
		"segredo.go":    "segredo",
		"ssh.go":        "ssh",
		"startup.go":    "startup",
		"trust.go":      "trust",
	}
	total := 0
	for arquivo, chave := range esperado {
		src := lerFonte(t, arquivo)
		n := strings.Count(src, `homeDirs(f, e, "`)
		if n == 0 {
			t.Errorf("%s não chama mais homeDirs: a tabela deste teste envelheceu", arquivo)
			continue
		}
		total += n
		certas := strings.Count(src, `homeDirs(f, e, "`+chave+`")`)
		if certas != n {
			t.Errorf("%s: %d de %d chamadas a homeDirs usam chave diferente de %q.\n"+
				"A chave decide qual check degrada quando o /etc/passwd não abre — "+
				"com a chave do vizinho, o relatório aponta o check errado como "+
				"aquele que não cobriu o que devia.", arquivo, n-certas, n, chave)
		}
	}
	// Se alguém acrescentar um chamador num arquivo fora da tabela, o total para
	// de bater e este teste manda incluí-lo em vez de deixar passar.
	nomes, _ := filepath.Glob("*.go")
	global := 0
	for _, n := range nomes {
		if strings.HasSuffix(n, "_test.go") {
			continue
		}
		global += strings.Count(lerFonte(t, n), `homeDirs(f, e, "`)
	}
	if global != total {
		t.Errorf("há %d chamadas a homeDirs no pacote e a tabela deste teste cobre %d: "+
			"o chamador novo precisa entrar aqui com a chave do coletor dele", global, total)
	}
}
