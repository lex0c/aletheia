package facts

import "testing"

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
		{`/bin/sh -c '/bin/cat /etc/x | /tmp/y'`, "/bin/cat", false},

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
