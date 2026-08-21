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
		"AFROUXAR `disable_functions` ou `open_basedir` é feito de propósito por " +
			"aplicação que precisa de `exec` (conversor de imagem, gerador de " +
			"PDF, integração com binário externo). Continua valendo perguntar " +
			"quem afrouxou e quando — o ctime do arquivo responde a segunda",
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
		ev := []string{
			ln.Text,
			"uma proteção do PHP é desligada NESTE diretório, e por configuração " +
				"que não exige root",
		}
		if strings.Contains(strings.ToLower(ln.Text), "disable_functions") &&
			strings.TrimSpace(ln.Alvo) == "" {
			return check.SevCritical, append(ev,
				"e o valor está VAZIO: a lista de funções proibidas foi zerada, o "+
					"que devolve `system`, `exec` e `passthru` a um host que os "+
					"tinha tirado — é o pré-requisito de todo webshell"), true
		}
		return check.SevWarn, ev, true

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
