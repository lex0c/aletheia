package facts

import (
	"strings"
	"testing"
)

// O alvo de `sh -c` era o primeiro token cru, e isso produzia alvos que não são
// programa: "X=1", "exec", "cd". Não é erro neutro — o unit_unowned pergunta a
// propriedade DESSE nome, não acha nada em diretório de pacote e cala. Um
// binário órfão em /bin escapava por um prefixo `exec`, que ainda por cima é
// idioma legítimo de wrapper.
func TestAlvoDeShellNaoDevolveTokenFalso(t *testing.T) {
	casos := []struct {
		cmd   string
		alvo  string
		indet bool
	}{
		// Os quatro que estavam quebrados, medidos antes do conserto.
		{`/bin/sh -c 'X=1 /bin/shellserver'`, "/bin/shellserver", false},
		{`/bin/sh -c 'exec /bin/shellserver'`, "/bin/shellserver", false},
		{`/bin/sh -c 'command /bin/shellserver'`, "/bin/shellserver", false},
		{`/bin/sh -c 'cd /tmp && /bin/shellserver'`, "/bin/shellserver", false},
		// O caso simples nunca esteve quebrado e não pode quebrar agora.
		{`/bin/sh -c '/bin/shellserver'`, "/bin/shellserver", false},
		{`/bin/sh -c '/bin/shellserver --flag'`, "/bin/shellserver", false},
		// Combinações do mesmo tema.
		{`/bin/sh -c 'A=1 B=2 exec /bin/shellserver'`, "/bin/shellserver", false},
		{`/bin/sh -c 'umask 077; /bin/shellserver'`, "/bin/shellserver", false},
		{`/bin/sh -c 'export X=1 && exec /bin/shellserver'`, "/bin/shellserver", false},
		// Pipe: o primeiro programa RODA, e apontar para ele é verdade.
		// DOIS programas: a fachada singular é fail-closed na cardinalidade.
		// Este caso fixava a evasão — exigia "/bin/cat" para uma linha em que
		// /tmp/y TAMBÉM executa, e com AlvoIndeterminado=false o /tmp/y sumia
		// da pergunta de propriedade. Quem quer os dois chama o plural.
		{`/bin/sh -c '/bin/cat /etc/x | /tmp/y'`, "", true},

		// INDETERMINADO: o alvo depende de execução, e afirmar seria inventar.
		{"/bin/sh -c '$(/tmp/resolve)'", "", true},
		{"/bin/sh -c '`/tmp/resolve`'", "", true},
		{`/bin/sh -c '(/tmp/x)'`, "", true},
		{`/bin/sh -c 'eval "$CMD"'`, "", true},
		// Só builtin: não há programa que este parser saiba nomear.
		{`/bin/sh -c 'cd /tmp'`, "", true},
		{`/bin/sh -c 'X=1'`, "", true},

		// Sem shell, nada muda.
		{`/usr/bin/env /bin/.backdoor`, "/bin/.backdoor", false},
		{`/usr/local/sbin/agent --daemon`, "/usr/local/sbin/agent", false},
	}
	for _, c := range casos {
		alvo, indet := AlvoEfetivoDeExec(c.cmd)
		if alvo != c.alvo || indet != c.indet {
			t.Errorf("%-45s -> (%q, %v), queria (%q, %v)", c.cmd, alvo, indet, c.alvo, c.indet)
		}
	}
}

// Sair pelo TETO de wrappers é indeterminado, e indeterminado se DECLARA.
//
// O laço para em oito passos, e quem cai fora dele não resolveu o alvo. O
// retorno era `("", false)` — vazio, e o `false` do AlvoIndeterminado significa
// "alvo PROVADO". A ferramenta afirmava ter provado que a linha não executa
// nada, sobre uma linha que executa.
//
// O estrago é dos dois lados e silencioso nos dois: `add("")` é descartado pelo
// guarda de prefixo "/" em pkg.go, então candidatosDePropriedade nunca pergunta
// quem entregou o binário; e o ramo `if ex.AlvoIndeterminado` de
// checks/systemd.go, que existe para transformar isso em lacuna, não é tomado.
// persist.unit_unowned é CRITICAL e nunca chega a avaliar o alvo.
func TestTetoDeWrappersDeclaraIndeterminadoENaoAlvoVazio(t *testing.T) {
	casos := []struct {
		nome string
		cmd  string
	}{
		{"oito wrappers encadeados",
			"/usr/bin/env /usr/bin/env /usr/bin/env /usr/bin/env " +
				"/usr/bin/env /usr/bin/env /usr/bin/env /usr/bin/env /usr/lib/systemd/.upd"},
		{"wrapper que consome todos os tokens", "/usr/bin/sudo -u root"},
	}
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			alvo, indet := AlvoEfetivoDeExec(c.cmd)
			if alvo != "" {
				t.Fatalf("alvo = %q — o caso mudou, o teste não vale mais", alvo)
			}
			if !indet {
				t.Errorf("alvo vazio marcado como PROVADO: a linha executa algo e a "+
					"ferramenta não soube dizer o quê, mas afirma ter provado que não "+
					"há alvo. O binário sai da pergunta de propriedade sem lacuna. (%s)", c.cmd)
			}
		})
	}
	// Sete wrappers ainda resolvem: o teto é o limite, não o comportamento.
	alvo, indet := AlvoEfetivoDeExec(
		"/usr/bin/env /usr/bin/env /usr/bin/env /usr/bin/env " +
			"/usr/bin/env /usr/bin/env /usr/bin/env /usr/lib/.backdoor")
	if alvo != "/usr/lib/.backdoor" || indet {
		t.Errorf("sete wrappers deviam resolver: alvo=%q indet=%v", alvo, indet)
	}
}

// Sintaxe de CONTROLE do shell não pode virar "alvo resolvido".
//
// O `default` do parser devolvia o primeiro token não tratado como alvo
// provado, e palavra reservada cai ali. O resultado era a MESMA classe de
// defeito que este arquivo existe para não cometer — o binário real fora da
// pergunta de propriedade, sem lacuna — só que alcançada com sintaxe de shell
// perfeitamente normal:
//
//	ExecStart=sh -c 'if test -e /tmp/a; then exec /usr/lib/.backdoor; fi'
//	  -> alvo "if", AlvoIndeterminado=false
//	  -> /usr/lib/.backdoor nunca entra em candidatosDePropriedade
//	  -> persist.unit_unowned não avalia, e não declara nada
//
// A resposta certa não é escrever um shell: é dizer "não sei". O sistema já
// sabe tratar indeterminado.
func TestSintaxeDeControleDoShellViraIndeterminado(t *testing.T) {
	casos := []string{
		`/bin/sh -c 'if test -e /tmp/a; then exec /usr/lib/systemd/.backdoor; fi'`,
		`/bin/sh -c 'for i in 1 2; do /usr/lib/.x; done'`,
		`/bin/sh -c 'while true; do /usr/lib/.x; done'`,
		`/bin/sh -c 'until false; do /usr/lib/.x; done'`,
		`/bin/sh -c 'case $x in a) /usr/lib/.x ;; esac'`,
		`/bin/sh -c '{ /usr/lib/.x; }'`,
	}
	for _, c := range casos {
		alvo, indet := AlvoEfetivoDeExec(c)
		if !indet {
			t.Errorf("alvo=%q RESOLVIDO para uma linha com estrutura de shell: %s\n"+
				"O programa real está adiante, e afirmar o token de controle tira "+
				"o binário da pergunta de propriedade sem deixar lacuna.", alvo, c)
		}
	}
}

// Texto DENTRO DE ASPAS nunca vira executável.
//
// separaOperadoresDeShell punha espaço em volta de `;` sem olhar aspas, e o
// comentário apostava que isso "no máximo leva a indeterminado". Medido, não
// levava: o `;` forjado dentro da string encerrava o consumo do builtin e o
// resto do TEXTO virava programa afirmado.
func TestSeparadorDentroDeAspasNaoFabricaPrograma(t *testing.T) {
	casos := []string{
		`/bin/sh -c 'echo "texto; /bin/nao-roda"'`,
		`/bin/sh -c 'echo "a | /bin/nao-roda"'`,
		`/bin/sh -c 'logger "falha && /bin/nao-roda"'`,
	}
	for _, c := range casos {
		alvo, _ := AlvoEfetivoDeExec(c)
		if strings.Contains(alvo, "nao-roda") {
			t.Errorf("alvo=%q saiu de dentro de uma string: %s\n"+
				"Aquele caminho nunca executa — é uma pergunta de propriedade "+
				"sobre texto, e o programa real sumiu do lugar dele.", alvo, c)
		}
	}
}

// O parser é FAIL-CLOSED: o que ele não sabe seguir vira "não sei".
//
// A rodada anterior fechou a estrutura de controle (if/for/while/case), e
// sobraram quatro famílias que produziam a MESMA mentira — alvo afirmado sobre
// uma linha que executa outra coisa.
//
// A pior delas era `!`: o TrimLeft de "-@+!:" o reduzia a string VAZIA com
// AlvoIndeterminado=false, e aí o chamador caía no `return toks[0]` e afirmava
// o PRÓPRIO INTERPRETADOR (/bin/sh) como alvo provado da unit. O TrimLeft
// existe para os prefixos de ExecStart do systemd, que só valem no primeiro
// token de uma linha de unit — dentro de `sh -c` um traço à frente é opção.
//
// As outras três: teste condicional (`test`, `[`), execução de código que este
// parser não segue (`eval`, `source`, `.`, `trap` — os quatro estavam listados
// como builtin "que não executa arquivo", o que é falso), e OPÇÃO virando alvo
// (`command -v foo` devolvia "v"; `exec -a nome` devolvia "a").
func TestParserDeShellEhFailClosed(t *testing.T) {
	casos := []struct{ cmd, porque string }{
		{`/bin/sh -c '! /usr/lib/systemd/.backdoor'`,
			"negação: o TrimLeft esvaziava o token e o chamador afirmava o próprio /bin/sh"},
		{`/bin/sh -c 'test -e /tmp/enable && /usr/lib/systemd/.backdoor'`,
			"teste condicional: o programa está atrás do &&"},
		{`/bin/sh -c '[ -e /tmp/x ] && /usr/lib/.backdoor'`,
			"idem, na forma de colchete"},
		{`/bin/sh -c 'source /usr/lib/.backdoor; /bin/true'`,
			"source EXECUTA o arquivo, e o alvo resolvido saía /bin/true"},
		{`/bin/sh -c '. /usr/lib/.backdoor; /bin/true'`, "idem, forma curta"},
		{`/bin/sh -c 'eval "$PAYLOAD"; /bin/true'`,
			"eval executa o que ninguém consegue ler daqui"},
		{`/bin/sh -c 'trap "/usr/lib/.backdoor" EXIT; /bin/true'`,
			"trap executa na saída, e o alvo resolvido saía /bin/true"},
		{`/bin/sh -c 'command -v foo && /usr/lib/.backdoor'`,
			"opção virando alvo: devolvia \"v\""},
		{`/bin/sh -c 'exec -a nome /usr/lib/.backdoor'`,
			"opção virando alvo: devolvia \"a\""},
	}
	for _, c := range casos {
		alvo, indet := AlvoEfetivoDeExec(c.cmd)
		if !indet {
			t.Errorf("alvo=%q RESOLVIDO — %s\n  %s\n"+
				"Interpretação desconhecida virando alvo conhecido é exatamente o "+
				"invariante que este arquivo existe para sustentar.", alvo, c.porque, c.cmd)
		}
	}
}

// E o outro lado, que não pode ser perdido junto: as formas que o parser SABE
// desembrulhar continuam resolvendo. Um parser que responde "não sei" para tudo
// é tão inútil quanto um que mente.
func TestParserDeShellNaoDesistiuDoQueSabeResolver(t *testing.T) {
	casos := []struct{ cmd, quer string }{
		{`/bin/sh -c 'cd /tmp && /bin/shellserver'`, "/bin/shellserver"},
		{`/bin/sh -c 'exec /bin/shellserver'`, "/bin/shellserver"},
		{`/bin/sh -c 'X=1 /bin/shellserver'`, "/bin/shellserver"},
		{`/bin/sh -c '/usr/bin/legitimo --flag'`, "/usr/bin/legitimo"},
		{`/usr/bin/env /usr/local/bin/app`, "/usr/local/bin/app"},
		// `time` mede o comando SEGUINTE: resolver o que vem depois é mais
		// informação que desistir da linha.
		{`/bin/sh -c 'time /usr/lib/.x'`, "/usr/lib/.x"},
	}
	for _, c := range casos {
		alvo, indet := AlvoEfetivoDeExec(c.cmd)
		if indet || alvo != c.quer {
			t.Errorf("alvo=%q indet=%v, queria %q: %s\n"+
				"O fail-closed não pode virar 'não sei' para tudo — aí a cobertura "+
				"cai em todo host e a lacuna deixa de ser lida.", alvo, indet, c.quer, c.cmd)
		}
	}
}

// Uma linha de shell pode ter N alvos, e o fato precisa carregar os N.
//
// Este é o defeito que duas rodadas de conserto NÃO pegaram, porque as duas o
// trataram como lista de palavras faltando na peneira. Não era: era a
// CARDINALIDADE do fato. `ExecLine` tinha `Target string`, o resolvedor
// devolvia o primeiro programa e parava, e o segundo desaparecia da pergunta de
// propriedade com AlvoIndeterminado=false — sem depender de test, de source, de
// eval nem de sintaxe complicada nenhuma. Bastava um `&&`.
//
// O grau de enraizamento: um teste desta mesma suíte FIXAVA a evasão, exigindo
// "/bin/cat" para `/bin/cat /etc/x | /tmp/y`, onde /tmp/y também executa.
func TestLinhaDeShellComVariosProgramasDevolveTodos(t *testing.T) {
	casos := []struct {
		cmd   string
		quer  []string
		indet bool
	}{
		{`/bin/sh -c '/usr/bin/true && /usr/lib/systemd/.backdoor'`,
			[]string{"/usr/bin/true", "/usr/lib/systemd/.backdoor"}, false},
		{`/bin/sh -c '/bin/cat /etc/x | /tmp/y'`,
			[]string{"/bin/cat", "/tmp/y"}, false},
		{`/bin/sh -c '/usr/bin/legit; /usr/lib/.backdoor'`,
			[]string{"/usr/bin/legit", "/usr/lib/.backdoor"}, false},
		{`/bin/sh -c '/usr/bin/legit || /usr/lib/.backdoor'`,
			[]string{"/usr/bin/legit", "/usr/lib/.backdoor"}, false},
		// A LACUNA NÃO APAGA O OBSERVADO: antes, `indet` fazia return vazio e
		// jogava fora o alvo já provado.
		{`/bin/sh -c '/usr/bin/legit; eval "$CMD"'`,
			[]string{"/usr/bin/legit"}, true},
		{`/bin/sh -c '/usr/bin/legit && $(curl x)'`,
			[]string{"/usr/bin/legit"}, true},
		// E o que já funcionava continua: builtin não vira alvo, wrapper é
		// desembrulhado, atribuição é pulada.
		{`/bin/sh -c 'cd /tmp && /usr/lib/.backdoor'`,
			[]string{"/usr/lib/.backdoor"}, false},
		{`/bin/sh -c 'X=1 /bin/x'`, []string{"/bin/x"}, false},
		{`/usr/bin/env /usr/local/bin/app`, []string{"/usr/local/bin/app"}, false},
	}
	for _, c := range casos {
		alvos, indet := AlvosEfetivosDeExec(c.cmd)
		if indet != c.indet || !mesmaLista(alvos, c.quer) {
			t.Errorf("AlvosEfetivosDeExec(%s)\n  = (%q, %v)\n  queria (%q, %v)",
				c.cmd, alvos, indet, c.quer, c.indet)
		}
	}
}

// E a fachada singular precisa ser FAIL-CLOSED na cardinalidade: quem só sabe
// lidar com um alvo não pode receber "o primeiro de dois" como se fosse o alvo.
func TestFachadaSingularRecusaLinhaComVariosAlvos(t *testing.T) {
	alvo, indet := AlvoEfetivoDeExec(`/bin/sh -c '/usr/bin/true && /usr/lib/.backdoor'`)
	if alvo != "" || !indet {
		t.Errorf("AlvoEfetivoDeExec devolveu (%q, %v) para uma linha com DOIS "+
			"programas: devolver o primeiro é exatamente a evasão que o plural "+
			"existe para fechar", alvo, indet)
	}
	// Com um alvo só, ela continua respondendo.
	if a, i := AlvoEfetivoDeExec(`/usr/bin/env /usr/local/bin/app`); a != "/usr/local/bin/app" || i {
		t.Errorf("a fachada parou de resolver o caso de um alvo: (%q, %v)", a, i)
	}
}

func mesmaLista(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
