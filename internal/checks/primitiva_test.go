package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

func regra(texto string) *facts.Facts {
	return &facts.Facts{Sudoers: []facts.SudoRule{
		{File: "/etc/sudoers.d/x", Line: 1, Text: texto},
	}}
}

// A ESCADA INTEIRA numa tabela, porque cada degrau dela custou uma afirmação
// falsa no relatório antes de existir.
func TestEscadaDaPrimitivaNoSudo(t *testing.T) {
	casos := []struct {
		regra string
		sev   check.Severity
		diz   string
		porqu string
	}{
		{"web ALL=(root) NOPASSWD: /bin/bash", check.SevCritical,
			"é um interpretador",
			"shell como root sem senha é root irrestrito"},
		{"web ALL=(root) NOPASSWD: /usr/bin/find", check.SevCritical,
			"executa comando arbitrário",
			"`find . -exec /bin/sh` é um passo, não uma exploração"},
		{"web ALL=(root) NOPASSWD: /usr/bin/tar", check.SevCritical,
			"NÃO fixa argumento",
			"regra sem argumento aceita QUALQUER argumento: é a forma mais ampla"},
		{"web ALL=(root) NOPASSWD: /usr/bin/tar *", check.SevCritical,
			"curinga",
			"o `*` na ÚLTIMA posição devolve o que o argumento fixo tinha tirado"},
		// O CURINGA NO MEIO, e esta linha já esteve travada ao contrário.
		//
		// A versão anterior dizia WARN aqui, com a evidência afirmando que "o
		// literal que vem depois dele fecha o que ele abriu". É falso, e o
		// sudoers(5) avisa exatamente sobre isto: os argumentos são comparados
		// como UMA string concatenada e o `*` casa até espaço. Contra o padrão
		// `/var/log -name *.gz -delete`, isto casa:
		//
		//	sudo find /var/log -name '*' -exec /bin/sh \; -name x.gz -delete
		//
		// O literal `.gz -delete` continua no fim e o curinga absorveu um
		// `-exec` no meio. Confinamento não provado volta a ser o que era.
		{"web ALL=(root) NOPASSWD: /usr/bin/find /var/log -name *.gz -delete", check.SevCritical,
			"em QUALQUER posição",
			"o curinga do sudoers atravessa a fronteira entre argumentos, e literal " +
				"depois dele não fecha nada"},
		// O CAMINHO que não nomeia binário. `primitivaDoBinario` lia o basename,
		// achava um binário chamado `*` e a tabela não o reconhecia — a regra
		// que entrega /usr/bin/bash saía com "esta ferramenta NÃO reconhece".
		{"ops ALL=(root) NOPASSWD: /usr/bin/*", check.SevCritical,
			"diretório de ferramentas do sistema",
			"o padrão alcança bash, find e python juntos: é ALL escrito de outra forma"},
		{"ops ALL=(root) NOPASSWD: /usr/bin/", check.SevCritical,
			"é um diretório",
			"caminho terminado em barra concede todo comando daquele diretório"},
		// E o outro lado do curinga: `?` e `[...]` casam UM caractere cada.
		// Tratá-los como o `*` tornaria crítica a regra de webhook que qualquer
		// produção tem — eles entram como nota, não como severidade.
		{"ops ALL=(root) NOPASSWD: /usr/bin/curl https://api.x/?token=y", check.SevWarn,
			"casa UM caractere",
			"um caractere não é onde cabe uma opção injetada"},
		{"ops ALL=(root) NOPASSWD: /opt/app/bin/*", check.SevWarn,
			"NÃO enumera o diretório",
			"fora dos diretórios de sistema o alcance é desconhecido, e desconhecido " +
				"não vira crítico nem absolvição"},
		// O `ALL` que é ARGUMENTO. Produzia um CRITICAL determinístico falso.
		{"ops ALL=(root) NOPASSWD: /usr/bin/printf ALL", check.SevWarn,
			"restrita a comando nomeado",
			"o ALL aqui é argumento do printf, e lê-lo como especificação de comando " +
				"gasta o crítico que faz a frota parar"},
		// O RUNAS na posição SINTÁTICA dele. O parêntese do regex de argumento
		// (sudoers 1.9.10+) fazia a regra de root sair "e não como root".
		{"web ALL=NOPASSWD: /usr/bin/vim ^(/etc/motd|/etc/issue)$", check.SevCritical,
			"como root",
			"sem runas declarado é root, e o parêntese do regex não é runas"},
		// A TAG que engolia o comando seguinte.
		{"ops ALL=(root) NOPASSWD: SETENV: /usr/bin/find", check.SevCritical,
			"executa comando arbitrário",
			"`SETENV:` é tag, não binário — lê-la como comando escondia o find"},
		// E a tag que de fato restringe, que antes caía em "não reconheço".
		{"ops ALL=(root) NOPASSWD: NOEXEC: /usr/bin/vim", check.SevWarn,
			"tag `NOEXEC:`",
			"o sudo intercepta a família exec, e é por ali que o escape passa"},
		{"web ALL=(root) NOPASSWD: /usr/bin/tar czf /b.tgz /srv", check.SevWarn,
			"SÓ isso que a segura",
			"argumento fixado prende a primitiva do tar — e o relatório precisa " +
				"dizer que o freio é uma string"},
		{"web ALL=(root) NOPASSWD: /usr/bin/vim /etc/motd", check.SevCritical,
			"modo interativo",
			"fixar o arquivo que o vim edita não tira o `:!sh` dele"},
		// O SHELL COM ARGUMENTO FIXADO é o contrário, e é o desenho de delegação
		// mais comum que existe: o sudo casa a linha inteira, então quem usa a
		// regra não troca o script nem acrescenta `-c`. Chamar isto de root
		// irrestrito encheria de crítico toda frota que faz deploy assim.
		{"web ALL=(root) NOPASSWD: /bin/bash /opt/deploy/restart.sh", check.SevWarn,
			"SÓ isso que a segura",
			"a rota volta se o script for gravável por quem tem a regra, e essa " +
				"pergunta é do priv.root_runs_writable"},
		{"web ALL=(root) NOPASSWD: /usr/bin/dd", check.SevCritical,
			"escreve conteúdo arbitrário",
			"escrever onde quiser como root é uma linha em /etc/sudoers"},
		{"web ALL=(root) NOPASSWD: /bin/cat", check.SevWarn,
			"lê arquivo arbitrário",
			"leitura entrega o shadow e ainda exige quebrar o hash: aviso, não root"},
		{"web ALL=(root) NOPASSWD: /usr/sbin/nginx", check.SevWarn,
			"NÃO reconhece",
			"o que a ferramenta não examinou precisa ser DITO, não virar absolvição"},
		{"web ALL=(root) NOPASSWD: PGCTL", check.SevWarn,
			"não resolve alias",
			"alias não é binário: o que ele expande está em outra linha"},
	}
	for _, c := range casos {
		r := sudoSemSenha.Run(sudoSemSenha, regra(c.regra), testEnv())
		if len(r.Findings) != 1 {
			t.Errorf("%s: achados = %d", c.regra, len(r.Findings))
			continue
		}
		fd := r.Findings[0]
		if fd.Sev != c.sev {
			t.Errorf("%s\n  severidade=%v, queria %v — %s", c.regra, fd.Sev, c.sev, c.porqu)
		}
		if ev := strings.Join(fd.Evidence, " "); !strings.Contains(ev, c.diz) {
			t.Errorf("%s\n  a evidência precisa conter %q — %s\n  saiu: %s",
				c.regra, c.diz, c.porqu, ev)
		}
	}
}

// Uma spec pode listar VÁRIOS comandos separados por vírgula, e a leitura
// anterior era `Fields(spec)[0]`: o `/bin/bash` depois da vírgula — o caso
// crítico que já estava implementado — sumia porque não era o primeiro campo.
func TestSpecComVirgulaOlhaTodosOsComandos(t *testing.T) {
	r := sudoSemSenha.Run(sudoSemSenha,
		regra("web ALL=(root) NOPASSWD: /usr/bin/id, /bin/bash"), testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("o shell depois da vírgula concede igual: %+v", r.Findings)
	}
}

// O `!` nega em vez de conceder, e `ALL` não é binário: nenhum dos dois tem
// primitiva, e tratá-los como caminho produziria conclusão inventada.
func TestNegacaoEAllNaoViramPrimitiva(t *testing.T) {
	for _, spec := range []string{"ALL, !/bin/bash", "!/usr/bin/find"} {
		cs := comandosDaSpec(spec)
		for _, c := range cs {
			if c.Classe != primNenhuma {
				t.Errorf("%q: %q não devia ter primitiva", spec, c.Bin)
			}
		}
	}
}

// A TERCEIRA PORTA do suid: bit setuid num binário que TEM dono de pacote e
// cujo conteúdo confere. `chmod u+s /usr/bin/find` não altera conteúdo, não
// altera dono, e não aparece em verificação de hash nenhuma — era silêncio.
func TestSuidComPrimitivaEDonoDePacoteDispara(t *testing.T) {
	f := &facts.Facts{
		Suid:      []facts.SuidFile{{Path: "/usr/bin/find", Setuid: true, UID: 0, DirModo: 0o755}},
		Ownership: []facts.Ownership{{Path: "/usr/bin/find", Owned: true, Pacote: "findutils"}},
	}
	r := suidInesperado.Run(suidInesperado, f, imgEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("setuid num binário com primitiva é achado mesmo com dono: %+v", r.Findings)
	}
	ev := strings.Join(r.Findings[0].Evidence, " ")
	for _, quer := range []string{"mudou o MODO", "distribuição NENHUMA entrega"} {
		if !strings.Contains(ev, quer) {
			t.Errorf("a evidência precisa explicar por que o achado existe apesar "+
				"da origem em ordem (%q):\n%s", quer, ev)
		}
	}
}

// E o outro lado: o conjunto legítimo de setuid vem TODO de pacote e nenhum
// deles tem primitiva de execução. `sudo`, `su`, `passwd`, `mount` e `ping` com
// o bit são o estado de fábrica de qualquer distribuição, e acusá-los tornaria
// o check inútil em todo host do mundo.
func TestSuidLegitimoDePacoteContinuaCalado(t *testing.T) {
	var suid []facts.SuidFile
	var own []facts.Ownership
	for _, p := range []string{
		"/usr/bin/sudo", "/bin/su", "/usr/bin/passwd", "/bin/mount",
		"/bin/umount", "/bin/ping", "/usr/bin/chsh", "/usr/bin/chfn",
		"/usr/bin/gpasswd", "/usr/bin/newgrp", "/usr/bin/pkexec",
	} {
		suid = append(suid, facts.SuidFile{Path: p, Setuid: true, UID: 0, DirModo: 0o755})
		own = append(own, facts.Ownership{Path: p, Owned: true, Pacote: "base"})
	}
	f := &facts.Facts{Suid: suid, Ownership: own}
	if r := suidInesperado.Run(suidInesperado, f, imgEnv()); len(r.Findings) != 0 {
		t.Fatalf("o conjunto de fábrica não pode virar achado: %+v", r.Findings)
	}
}

// A EXCEÇÃO NÃO PODE SER AMPLA DEMAIS, e a fronteira dela veio de um host real.
//
// O `crontab` do Arch é setuid ROOT; o do Debian é setgid crontab. Uma lista
// escrita olhando só para o Debian acusa todo desktop Arch do mundo — foi o que
// aconteceu na primeira execução contra uma máquina limpa.
//
// A resposta certa não foi alargar a exceção, foi corrigir o MODELO: o poder do
// `crontab` é primitiva de SUDO (`sudo crontab -e` abre um editor como root) e
// não de SETUID (com o bit, ele larga o privilégio antes de chamar o editor).
// Ele saiu da lista do bit, e por isso não dispara em nenhuma das duas
// distribuições.
func TestCrontabNaoDisparaEmNenhumaDistribuicao(t *testing.T) {
	f := func(setuid, setgid bool) *facts.Facts {
		return &facts.Facts{
			Suid:      []facts.SuidFile{{Path: "/usr/bin/crontab", Setuid: setuid, Setgid: setgid, UID: 0, DirModo: 0o755}},
			Ownership: []facts.Ownership{{Path: "/usr/bin/crontab", Owned: true, Pacote: "cronie"}},
		}
	}
	if r := suidInesperado.Run(suidInesperado, f(true, false), imgEnv()); len(r.Findings) != 0 {
		t.Errorf("setuid root é o crontab do Arch (cronie): %+v", r.Findings)
	}
	if r := suidInesperado.Run(suidInesperado, f(false, true), imgEnv()); len(r.Findings) != 0 {
		t.Errorf("setgid é o crontab do Debian: %+v", r.Findings)
	}
}

// E o outro lado da MESMA distinção: `sudo systemctl` sem argumento continua
// crítico, porque ali o poder vem de quem invoca. O mesmo nome, duas respostas,
// e é isso que separar os contextos comprou.
func TestMesmoBinarioRespostasDiferentesPorContexto(t *testing.T) {
	r := sudoSemSenha.Run(sudoSemSenha,
		regra("ops ALL=(root) NOPASSWD: /usr/bin/crontab"), testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("via sudo o crontab abre um editor como root: %+v", r.Findings)
	}
	f := &facts.Facts{
		Suid:      []facts.SuidFile{{Path: "/usr/bin/crontab", Setuid: true, UID: 0, DirModo: 0o755}},
		Ownership: []facts.Ownership{{Path: "/usr/bin/crontab", Owned: true, Pacote: "cronie"}},
	}
	if r := suidInesperado.Run(suidInesperado, f, imgEnv()); len(r.Findings) != 0 {
		t.Fatalf("via setuid ele larga o privilégio antes do editor: %+v", r.Findings)
	}
}

// SETGID SEM SETUID escala para o GRUPO, e o ramo faltava no switch de
// severidade: antes da terceira porta ele era inalcançável (arquivo com dono de
// pacote nunca chegava lá), e com ela um `chmod g+s` caía no `default` — que
// fala de DONO e imprimia "o dono não é root" sobre um arquivo root:root,
// contradizendo a linha seguinte que o marcava como crítico.
func TestSetgidTemRamoProprioNaSeveridade(t *testing.T) {
	f := func(gid int) *facts.Facts {
		return &facts.Facts{
			Suid:      []facts.SuidFile{{Path: "/usr/bin/find", Setgid: true, UID: 0, GID: gid, DirModo: 0o755}},
			Ownership: []facts.Ownership{{Path: "/usr/bin/find", Owned: true, Pacote: "findutils"}},
		}
	}
	r := suidInesperado.Run(suidInesperado, f(0), imgEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("%+v", r.Findings)
	}
	ev := strings.Join(r.Findings[0].Evidence, " ")
	if strings.Contains(ev, "o dono não é root") {
		t.Errorf("o arquivo é root:root — a evidência se contradizia:\n%s", ev)
	}
	if r.Findings[0].Sev != check.SevCritical || !strings.Contains(ev, "GRUPO root") {
		t.Errorf("setgid de grupo root é crítico e precisa dizer por quê:\n%s", ev)
	}

	r = suidInesperado.Run(suidInesperado, f(1000), imgEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevWarn {
		t.Fatalf("setgid de grupo comum pesa menos: %+v", r.Findings)
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "grupo 1000") {
		t.Error("a evidência precisa nomear o grupo, não o dono")
	}
}
