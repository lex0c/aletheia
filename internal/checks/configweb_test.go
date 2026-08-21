package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

func fConfigWeb(cs ...facts.ConfigWeb) *facts.Facts { return &facts.Facts{ConfigWeb: cs} }

func evidenciaDe(fds []check.Finding) string {
	var b strings.Builder
	for _, fd := range fds {
		b.WriteString(strings.Join(fd.Evidence, " "))
	}
	return b.String()
}

// Mapear `.php` para o PHP é o uso NORMAL da diretiva, e é o que hospedagem
// compartilhada escreve. Se isto virasse achado, todo host com PHP sairia
// vermelho e ninguém leria mais a saída.
func TestHandlerDePHPNaoEhAchado(t *testing.T) {
	f := fConfigWeb(facts.ConfigWeb{
		Path: "/var/www/app/.htaccess", Tipo: "htaccess",
		Linhas: []facts.LinhaConfigWeb{{
			N: 1, Motivo: "handler", Alvo: ".php .phtml",
			Text: "AddHandler application/x-httpd-php74 .php .phtml",
		}},
	})
	if r := configWebExecuta.Run(configWebExecuta, f, imgEnv()); len(r.Findings) != 0 {
		t.Fatalf("mapear .php para o PHP é o uso normal: %+v", r.Findings)
	}
}

// Mapear o PRÓPRIO arquivo de configuração é a forma em que o webshell inteiro
// cabe no .htaccess, sem deixar um único .php no docroot.
func TestHandlerDoProprioHtaccessEhCritico(t *testing.T) {
	f := fConfigWeb(facts.ConfigWeb{
		Path: "/var/www/.htaccess", Tipo: "htaccess",
		Linhas: []facts.LinhaConfigWeb{{
			N: 7, Motivo: "handler", Alvo: ".htaccess",
			Text: "AddType application/x-httpd-php .htaccess",
		}},
	})
	r := configWebExecuta.Run(configWebExecuta, f, imgEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("%+v", r.Findings)
	}
	if !strings.Contains(evidenciaDe(r.Findings), "PRÓPRIO arquivo de configuração") {
		t.Error("a evidência precisa nomear a forma")
	}
}

// Código PHP dentro de configuração não tem forma inocente.
func TestCodigoDentroDeConfigEhCritico(t *testing.T) {
	f := fConfigWeb(facts.ConfigWeb{
		Path: "/srv/.htaccess", Tipo: "htaccess",
		Linhas: []facts.LinhaConfigWeb{{
			N: 9, Motivo: "codigo", Text: "# <?php system($_GET['cmd']); ?>",
		}},
	})
	r := configWebExecuta.Run(configWebExecuta, f, imgEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("%+v", r.Findings)
	}
	if r.Findings[0].NextSteps[0] != "copie o arquivo antes de qualquer coisa: ele É a amostra" {
		t.Error("o arquivo É a amostra: preservar vem antes")
	}
}

// `Options +ExecCGI` tem uso legítimo e antigo: AVISO, não crítico.
func TestExecCGIEhAviso(t *testing.T) {
	f := fConfigWeb(facts.ConfigWeb{
		Path: "/var/www/cgi/.htaccess", Tipo: "htaccess",
		Linhas: []facts.LinhaConfigWeb{{N: 1, Motivo: "cgi", Text: "Options +ExecCGI"}},
	})
	r := configWebExecuta.Run(configWebExecuta, f, imgEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevWarn {
		t.Fatalf("%+v", r.Findings)
	}
}

// ARQUIVO ENCONTRADO NÃO É CONFIGURAÇÃO EFETIVA — e este teste trava o lado do
// PHP dessa regra, porque a primeira versão do check a quebrou aqui.
//
// `disable_functions =` num `.user.ini` parece o pré-requisito de todo webshell
// e sai CRÍTICO em qualquer leitura ingênua. Só que o PHP IGNORA a linha:
// `disable_functions` é PHP_INI_SYSTEM, e um `.user.ini` só honra
// PHP_INI_ALL/PERDIR/USER. Gritar crítico ali é gritar sobre configuração sem
// efeito nenhum.
//
// O achado não some — a linha diz algo sobre QUEM a escreveu —, mas a
// AFIRMAÇÃO muda: de "a proteção foi desligada" para "isto não desliga".
func TestDiretivaDeSistemaNoUserIniNaoEhAfrouxamento(t *testing.T) {
	f := fConfigWeb(facts.ConfigWeb{
		Path: "/var/www/uploads/.user.ini", Tipo: "user.ini",
		Linhas: []facts.LinhaConfigWeb{
			{N: 1, Motivo: "afrouxa", Text: "disable_functions =", Alvo: ""},
			{N: 2, Motivo: "afrouxa", Text: "open_basedir = /var/www", Alvo: "/var/www"},
		},
	})
	r := configWebExecuta.Run(configWebExecuta, f, imgEnv())
	if len(r.Findings) != 2 {
		t.Fatalf("as duas linhas continuam no relatório: %+v", r.Findings)
	}
	for _, fd := range r.Findings {
		if fd.Sev != check.SevInfo {
			t.Errorf("nenhuma das duas afrouxa nada a partir de um .user.ini: %v — %v",
				fd.Sev, fd.Evidence)
		}
		if ev := strings.Join(fd.Evidence, " "); strings.Contains(ev, "é desligada") {
			t.Errorf("a evidência não pode afirmar desligamento:\n%s", ev)
		}
	}
	if ev := strings.Join(r.Findings[0].Evidence, " "); !strings.Contains(ev, "IGNORADA") {
		t.Errorf("a evidência precisa dizer POR QUE não vale:\n%s", ev)
	}
	// E a segunda inverte o sinal: `open_basedir` por diretório só ESTREITA.
	if ev := strings.Join(r.Findings[1].Evidence, " "); !strings.Contains(ev, "endurecimento") {
		t.Errorf("open_basedir com valor é restrição, não afrouxamento:\n%s", ev)
	}
}

// E o outro lado da MESMA tabela: o que ela não conhece não vira absolvição.
//
// Sem esta trava, a correção acima teria um jeito silencioso de errar — bastaria
// uma diretiva fora do mapa para o check devolver INFO sobre algo que ele não
// examinou.
func TestDiretivaDesconhecidaNaoViraAbsolvicao(t *testing.T) {
	f := fConfigWeb(facts.ConfigWeb{
		Path: "/var/www/uploads/.user.ini", Tipo: "user.ini",
		Linhas: []facts.LinhaConfigWeb{
			{N: 1, Motivo: "afrouxa", Text: "diretiva_que_nao_existe = x", Alvo: "x"},
		},
	})
	r := configWebExecuta.Run(configWebExecuta, f, imgEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevWarn {
		t.Fatalf("o que a tabela não conhece continua com peso: %+v", r.Findings)
	}
	if ev := strings.Join(r.Findings[0].Evidence, " "); !strings.Contains(ev, "NÃO") {
		t.Errorf("e precisa DIZER que não leu:\n%s", ev)
	}
}

// O prepend é do persist.web_prepend e sai deste check de propósito: duas
// linhas para o mesmo fato é o que a divisão evita.
func TestPrependNaoDuplicaNesteCheck(t *testing.T) {
	f := fConfigWeb(facts.ConfigWeb{
		Path: "/var/www/uploads/.user.ini", Tipo: "user.ini",
		Linhas: []facts.LinhaConfigWeb{
			{N: 1, Motivo: "prepend", Text: "auto_prepend_file = /var/www/uploads/.i.php",
				Alvo: "/var/www/uploads/.i.php"},
		},
	})
	if r := configWebExecuta.Run(configWebExecuta, f, imgEnv()); len(r.Findings) != 0 {
		t.Fatalf("%+v", r.Findings)
	}
}

// SetHandler vale para o diretório INTEIRO. Numa árvore de upload isso é
// qualquer arquivo enviado virando código.
func TestSetHandlerEmUploadEhCritico(t *testing.T) {
	linha := facts.LinhaConfigWeb{
		N: 1, Motivo: "handler", Alvo: "(o diretório inteiro)",
		Text: "SetHandler application/x-httpd-php",
	}
	fora := fConfigWeb(facts.ConfigWeb{Path: "/var/www/app/.htaccess", Tipo: "htaccess", Linhas: []facts.LinhaConfigWeb{linha}})
	dentro := fConfigWeb(facts.ConfigWeb{Path: "/var/www/uploads/.htaccess", Tipo: "htaccess", Linhas: []facts.LinhaConfigWeb{linha}})

	if r := configWebExecuta.Run(configWebExecuta, fora, imgEnv()); len(r.Findings) != 1 || r.Findings[0].Sev != check.SevWarn {
		t.Errorf("fora de upload é aviso: %+v", r.Findings)
	}
	if r := configWebExecuta.Run(configWebExecuta, dentro, imgEnv()); len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Errorf("em árvore de upload é crítico: %+v", r.Findings)
	}
}

// O prepend é do persist.web_prepend, e emitir aqui daria DUAS linhas para o
// mesmo fato.
func TestPrependNaoDuplicaComWebPrepend(t *testing.T) {
	f := fConfigWeb(facts.ConfigWeb{
		Path: "/var/www/uploads/.user.ini", Tipo: "user.ini",
		Linhas: []facts.LinhaConfigWeb{{
			N: 1, Motivo: "prepend", Alvo: "/var/www/uploads/.i.php",
			Text: "auto_prepend_file = /var/www/uploads/.i.php",
		}},
	})
	if r := configWebExecuta.Run(configWebExecuta, f, imgEnv()); len(r.Findings) != 0 {
		t.Fatalf("o prepend é do outro check: %+v", r.Findings)
	}
	r := webPrepend.Run(webPrepend, f, imgEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("prepend apontando para dentro de upload é crítico: %+v", r.Findings)
	}
	if !strings.Contains(evidenciaDe(r.Findings), "não exige root") {
		t.Error("a diferença para o php.ini é justamente essa, e precisa ser dita")
	}
}

// A árvore de upload é reconhecida por SEGMENTO, não por substring: o achado
// que sai dali vai direto para CRÍTICO, e casar "/img/" em qualquer posição do
// caminho escalava por acidente.
func TestArvoreDeUploadEhPorSegmento(t *testing.T) {
	dentro := []string{
		"/var/www/html/uploads/.i.php",
		"/srv/app/public/upload/x.php",
		"/var/www/wp-content/uploads/2026/a.php",
		"/tmp/.i.php",
		"/var/www/images/x.php",
	}
	for _, p := range dentro {
		if !dentroDeUpload(p) {
			t.Errorf("%s é árvore de upload", p)
		}
	}
	fora := []string{
		"/srv/media-api/bootstrap.php", // "media" é PREFIXO do segmento, não o segmento
		"/opt/imgproc/boot.php",        // idem para "img"
		"/var/www/app/vendor/autoload.php",
		"/etc/php/8.2/fpm/prepend.php",
		"/usr/share/uploader-tool/boot.php",
	}
	for _, p := range fora {
		if dentroDeUpload(p) {
			t.Errorf("%s NÃO é árvore de upload — casar por substring escalava "+
				"isto para crítico por acidente", p)
		}
	}
}
