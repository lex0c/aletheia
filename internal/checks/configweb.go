package checks

import (
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() { check.Register(configWebExecuta) }

// configWebExecuta — runbook §7.12 ("Módulo e hook do servidor web").
//
// A pergunta é uma só, e ela não é sobre o conteúdo do docroot:
//
//	alguém mudou, POR DIRETÓRIO, o que este servidor EXECUTA?
//
// O `persist.web_prepend` já responde pela diretiva que roda um arquivo antes
// de cada requisição. Esta responde pela família ao redor dela, que é onde mora
// a forma mais econômica de webshell que existe:
//
//	AddType application/x-httpd-php .htaccess
//	# <?php system($_GET['cmd']); ?>
//
// Duas linhas, um arquivo, nenhum `.php` no docroot. A primeira faz o Apache
// servir o próprio `.htaccess` como PHP; a segunda é comentário para o Apache e
// código para o interpretador. E o arquivo passava por baixo dos dois lados
// desta ferramenta ao mesmo tempo: o coletor de gatilhos só olhava /etc/php*, e
// a varredura de código seleciona por EXTENSÃO — `.htaccess` não tem nenhuma.
//
// # Por que a configuração pesa mais que o código aqui
//
// Um `.php` estranho no docroot é achado por qualquer varredura, inclusive a
// desta ferramenta. Um `.htaccess` não: ele está em toda aplicação PHP do
// mundo, ninguém o lê, e o `ls` do docroot continua com a cara de sempre. O que
// esta ferramenta pode afirmar com precisão é estreito e forte — este arquivo
// de configuração muda o que EXECUTA, e essa mudança tem uma classe conhecida.
var configWebExecuta = check.Check{
	ID:       "app.web_config_exec",
	Ref:      "7.12",
	Title:    "configuração por diretório muda o que o servidor web executa",
	Group:    "app",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"MAPEAR .php PARA O PHP é o uso normal e mais comum do .htaccess: " +
			"hospedagem compartilhada escreve `AddType application/x-httpd-php " +
			".php` para escolher a versão do interpretador. Mapeamento cujas " +
			"extensões são todas da família php NÃO vira achado — o sinal é " +
			"mapear o que não é php",
		"`Options +ExecCGI` e `AddHandler cgi-script .cgi` são a configuração " +
			"legítima de qualquer aplicação CGI, e ainda existem: painel antigo, " +
			"webmail, script de relatório. Saem como AVISO, e o que decide é o " +
			"time reconhecer o diretório",
		"DIRETIVA DE PROTEÇÃO do PHP escrita num arquivo por diretório quase " +
			"nunca é afrouxamento efetivo: `disable_functions`, `disable_classes` " +
			"e `allow_url_*` são PHP_INI_SYSTEM e o PHP as IGNORA vindas de " +
			"`.user.ini`/`.htaccess`; `open_basedir` vale, mas só ESTREITA. As " +
			"duas famílias saem como INFO — o achado diz o que alguém TENTOU, e " +
			"não o estado do host. O afrouxamento de verdade mora no php.ini, no " +
			"pool do PHP-FPM ou no vhost",
		"a varredura destes arquivos herda os LIMITES da varredura de código: as " +
			"mesmas raízes, os mesmos tetos, a mesma poda de node_modules e " +
			"vendor, e a mesma cegueira sobre docroot fora da lista de raízes " +
			"(um Alias de Apache apontando para /home/cliente/app). O que ficou " +
			"de fora é declarado pela cobertura de `codigo`",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for i := range f.ConfigWeb {
			cw := &f.ConfigWeb[i]
			for _, ln := range cw.Linhas {
				sev, ev, ok := pesoDaLinhaWeb(cw, ln)
				if !ok {
					continue
				}
				ev = append(ev, cw.Path+":"+strconv.Itoa(ln.N))
				if cw.ModUTC != "" {
					ev = append(ev, "modificado em "+cw.ModUTC+
						" — compare com a janela do incidente")
				}
				fd := self.F(sev, cw.Path, "", ev...)
				fd.Quando, fd.QuandoFonte = cw.ModUTC, "mtime do arquivo de configuração"
				// O sujeito é o ARQUIVO, e o mesmo arquivo produz mais de uma
				// linha: sem discriminador, a segunda herdaria a presença da
				// primeira na baseline e sairia sem a marca ✳NOVO. O motivo
				// mais o texto é estável entre execuções; o número da linha não.
				fd.Chave = ln.Motivo + "|" + ln.Text
				fd.NextSteps = passosDaLinhaWeb(cw, ln)
				r.Findings = append(r.Findings, fd)
			}
		}
		r.Partial = append(r.Partial, f.PersistDenied["codigo"]...)
		return r
	},
}

// pesoDaLinhaWeb traduz a classe da linha em severidade e evidência. Devolve
// ok=false para o que é configuração normal — o mapeamento de `.php` para o PHP,
// que é o uso para o qual a diretiva existe.
func pesoDaLinhaWeb(cw *facts.ConfigWeb, ln facts.LinhaConfigWeb) (check.Severity, []string, bool) {
	switch ln.Motivo {
	case "prepend":
		// Já é o achado do persist.web_prepend, e emitir de novo aqui daria
		// duas linhas para o mesmo fato. A divisão é deliberada: aquele check
		// responde "o que roda antes de toda requisição", este responde "o que
		// este diretório passou a executar".
		return 0, nil, false

	case "codigo":
		return check.SevCritical, []string{
			ln.Text,
			"há CÓDIGO PHP dentro de um arquivo de CONFIGURAÇÃO — e isso não tem " +
				"forma inocente: configuração de servidor não contém `<?php`",
			"a tag costuma vir depois de um `#`, e o `#` é o ponto: ele faz o " +
				"servidor IGNORAR a linha ao ler a configuração, e o interpretador " +
				"não sabe nada de `#` quando o mesmo arquivo é servido como PHP",
			"procure, no MESMO arquivo, a linha que o torna executável — um " +
				"`AddType`/`SetHandler`; sem ela o código está plantado e ainda " +
				"não alcançável, o que é uma diferença de urgência e não de fato",
		}, true

	case "expoe":
		return check.SevCritical, []string{
			ln.Text,
			"a configuração REVERTE a negação de fábrica dos arquivos `.ht*`: o " +
				"servidor nega esses arquivos desde o Apache 2.4, e desligar essa " +
				"negação DENTRO de um deles não tem uso legítimo",
			"é o passo de que o webshell-no-próprio-.htaccess precisa para ser " +
				"alcançável pela URL — sem ele o código está lá e responde 403",
		}, true

	case "handler":
		naoPHP := extensoesNaoPHP(ln.Alvo)
		if ln.Alvo != "(o diretório inteiro)" && len(naoPHP) == 0 {
			// Mapear `.php` para o PHP é para isso que a diretiva serve.
			return 0, nil, false
		}
		ev := []string{
			ln.Text,
			"este mapeamento faz o servidor EXECUTAR o que ele entregaria como " +
				"arquivo — o conteúdo deixa de ser dado e passa a ser código",
		}
		if ln.Alvo == "(o diretório inteiro)" {
			ev = append(ev, "e o alvo é o diretório INTEIRO (`SetHandler`), não uma "+
				"extensão: todo arquivo aqui dentro passa a ser executado, "+
				"independente do nome")
			if dentroDeUpload(cw.Path) {
				return check.SevCritical, append(ev,
					"e este diretório é árvore de UPLOAD: qualquer coisa que um "+
						"usuário enviar vira código executado pelo servidor"), true
			}
			return check.SevWarn, ev, true
		}
		ev = append(ev, "e as extensões mapeadas NÃO são da família php: "+
			strings.Join(naoPHP, " ")+" — o interpretador passa a rodar o que "+
			"nenhuma varredura de webshell procura")
		if temExtensaoDeConfig(naoPHP) {
			ev = append(ev, "e uma delas é o PRÓPRIO arquivo de configuração: é a "+
				"forma em que o webshell inteiro cabe no .htaccess, sem deixar um "+
				"único .php no docroot")
		}
		return check.SevCritical, ev, true

	case "afrouxa":
		return pesoDaDiretivaPHP(cw, ln)

	case "cgi":
		return check.SevWarn, []string{
			ln.Text,
			"execução de CGI/SSI é habilitada neste diretório: um arquivo aqui " +
				"deixa de ser conteúdo e passa a ser programa",
			"tem uso legítimo e antigo — painel, webmail, script de relatório. O " +
				"que decide é o time reconhecer ESTE diretório",
		}, true
	}
	return 0, nil, false
}

// # ARQUIVO ENCONTRADO NÃO É CONFIGURAÇÃO EFETIVA
//
// É a regra arquitetural desta ferramenta, e esta função existe porque a
// primeira versão do check a quebrou justamente aqui.
//
// Ela dizia "uma proteção do PHP é desligada NESTE diretório" para qualquer uma
// de cinco diretivas, em qualquer dos dois tipos de arquivo, com qualquer valor
// — e subia para CRÍTICO quando encontrava:
//
//	.user.ini:
//	disable_functions =
//
// O PHP IGNORA essa linha. `disable_functions` é PHP_INI_SYSTEM, e um
// `.user.ini` só honra o que é PHP_INI_ALL, PHP_INI_PERDIR ou PHP_INI_USER; o
// `.htaccess` está no mesmo caso, porque `php_value` não seta diretiva de
// sistema e `php_admin_value` não é permitido em `.htaccess`. Ou seja: a
// ferramenta gritava CRÍTICO sobre uma configuração sem efeito nenhum.
//
// A leitura passou a ter quatro eixos, e o que muda a conclusão são os dois
// primeiros:
//
//	diretiva      qual é
//	origem        de que tipo de arquivo ela veio
//	mudabilidade  o PHP aceita mudá-la DALI?
//	direção       o valor afrouxa, ou aperta?
//
// A decisão mora no CHECK e não no coletor de propósito: o fato guardado
// continua sendo a linha, e um dump gravado antes desta correção é reanalisado
// com ela.
//
// phpPorDiretorio responde o terceiro eixo.
var phpPorDiretorio = map[string]bool{
	// PHP_INI_SYSTEM: só php.ini ou `php_admin_value` na configuração do
	// servidor. Escritas num arquivo por diretório, são IGNORADAS pelo PHP.
	"disable_functions": false,
	"disable_classes":   false,
	"allow_url_fopen":   false,
	// PHP_INI_SYSTEM também, e ainda por cima removida no PHP 8.
	"allow_url_include": false,

	// PHP_INI_ALL e PHP_INI_PERDIR: estas VALEM daqui.
	"open_basedir":      true,
	"auto_prepend_file": true,
	"auto_append_file":  true,
}

// diretivaDaLinhaWeb devolve o NOME da diretiva. A sintaxe é diferente nos dois
// arquivos, e é por isso que a origem entra na conta:
//
//	.user.ini    disable_functions =
//	.htaccess    php_value disable_functions ""
func diretivaDaLinhaWeb(cw *facts.ConfigWeb, texto string) string {
	t := strings.TrimSpace(texto)
	if cw.Tipo == "user.ini" {
		nome, _, _ := strings.Cut(t, "=")
		return strings.ToLower(strings.TrimSpace(nome))
	}
	campos := strings.Fields(t)
	if len(campos) >= 2 && strings.HasPrefix(strings.ToLower(campos[0]), "php_") {
		return strings.ToLower(campos[1])
	}
	return ""
}

func nomeDoArquivoWeb(cw *facts.ConfigWeb) string {
	if cw.Tipo == "user.ini" {
		return "`.user.ini`"
	}
	return "`.htaccess`"
}

func pesoDaDiretivaPHP(cw *facts.ConfigWeb, ln facts.LinhaConfigWeb) (check.Severity, []string, bool) {
	dir := diretivaDaLinhaWeb(cw, ln.Text)
	vale, conhecida := phpPorDiretorio[dir]
	arq := nomeDoArquivoWeb(cw)
	switch {
	case !conhecida:
		// Não saber qual diretiva é não vira absolvição nem crítico: sai como
		// aviso dizendo o que não foi lido.
		return check.SevWarn, []string{
			ln.Text,
			"esta linha mexe numa diretiva de proteção do PHP, e o nome dela NÃO " +
				"foi lido desta linha — o que ela muda de fato depende da " +
				"mudabilidade da diretiva (`PHP_INI_*`), e é uma conferência que " +
				"sobra",
		}, true

	case !vale:
		// O achado NÃO some: a linha continua sendo sinal de intenção, e num
		// diretório de upload ela é sinal de quem a escreveu. Some é o que a
		// ferramenta não pode fazer com um fato que leu. O que muda é a
		// AFIRMAÇÃO — de "a proteção foi desligada" para "isto não desliga".
		return check.SevInfo, []string{
			ln.Text,
			"`" + dir + "` é PHP_INI_SYSTEM: o PHP só a aceita do php.ini ou de " +
				"`php_admin_value` na configuração do servidor. Escrita num " + arq +
				", ela é IGNORADA — a proteção NÃO foi desligada aqui",
			"o que a linha diz é sobre QUEM a escreveu, não sobre o estado do " +
				"host: alguém tentou afrouxar o PHP a partir de um arquivo que o " +
				"PHP não obedece. O ctime do arquivo data a tentativa",
			"o afrouxamento de verdade estaria no php.ini, no pool do PHP-FPM ou " +
				"no vhost — e é ali que vale conferir",
		}, true

	case dir == "open_basedir":
		// A diretiva VALE daqui (PHP_INI_ALL), mas a direção é a contrária:
		// depois da inicialização o PHP rejeita um valor que AMPLIE o que já
		// valia. Um `open_basedir` por diretório aperta, e a versão anterior
		// chamava isso de "proteção desligada" — sobre a linha que endurece.
		return check.SevInfo, []string{
			ln.Text,
			"`open_basedir` num arquivo por diretório só ESTREITA: passada a " +
				"inicialização, o PHP recusa valor que amplie o alcance anterior",
			"esta linha LIMITA o que o PHP alcança neste diretório — é " +
				"endurecimento, e chamá-la de afrouxamento invertia o fato",
		}, true

	default:
		return check.SevWarn, []string{
			ln.Text,
			"`" + dir + "` vale a partir de um " + arq + " (é PHP_INI_PERDIR ou " +
				"PHP_INI_ALL), e esta linha muda o comportamento do PHP NESTE " +
				"diretório — por configuração que não exige root",
		}, true
	}
}

func passosDaLinhaWeb(cw *facts.ConfigWeb, ln facts.LinhaConfigWeb) []string {
	base := []string{
		"leia o arquivo INTEIRO: `" + cw.Path + "` — a linha citada raramente " +
			"está sozinha",
		"o ctime do arquivo data a inserção mesmo que o conteúdo pareça antigo",
	}
	if ln.Motivo == "codigo" || ln.Motivo == "expoe" {
		return append([]string{
			"copie o arquivo antes de qualquer coisa: ele É a amostra",
		}, base...)
	}
	return append(base,
		"os irmãos dele: `find <docroot> -name .htaccess -o -name .user.ini` — "+
			"quem escreve um costuma escrever mais de um")
}

// extensoesPHP são as extensões cujo mapeamento para o interpretador é o uso
// NORMAL da diretiva. Fora desta lista, mapear é fazer executar o que não
// executava.
var extensoesPHP = map[string]bool{
	".php": true, ".php3": true, ".php4": true, ".php5": true,
	".php7": true, ".php8": true, ".phtml": true, ".phps": true,
	".inc": true, ".module": true,
}

// extensoesNaoPHP devolve as extensões do mapeamento que NÃO são da família
// php. A diretiva pode citar várias na mesma linha.
func extensoesNaoPHP(alvo string) []string {
	var out []string
	for _, campo := range strings.Fields(alvo) {
		campo = strings.Trim(campo, `"'`)
		if campo == "" {
			continue
		}
		if !strings.HasPrefix(campo, ".") {
			campo = "." + campo
		}
		if !extensoesPHP[strings.ToLower(campo)] {
			out = append(out, campo)
		}
	}
	return out
}

// temExtensaoDeConfig diz se o mapeamento inclui o próprio arquivo de
// configuração — a forma em que o webshell não precisa de um segundo arquivo.
func temExtensaoDeConfig(exts []string) bool {
	for _, e := range exts {
		low := strings.ToLower(e)
		if strings.Contains(low, "htaccess") || strings.Contains(low, "user.ini") {
			return true
		}
	}
	return false
}
