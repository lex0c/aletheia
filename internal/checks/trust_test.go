package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

// Uma CA raiz do atacante faz o host confiar em QUALQUER certificado que ele
// emitir — update de pacote inclusive. O achado é a instalação, não o conteúdo.
func TestCAPlantada(t *testing.T) {
	f := &facts.Facts{CACerts: []facts.CACert{{
		File:    "/usr/local/share/ca-certificates/corp.crt",
		Subject: "CN=Corp Proxy CA,O=Corp", Issuer: "CN=Corp Proxy CA,O=Corp",
		AutoAssinado: true, NotAfter: "2035-01-01T00:00:00Z",
		ModUTC: "2026-08-16T03:00:00Z",
	}}}
	r := caPlantada.Run(caPlantada, f, imgEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %d", len(r.Findings))
	}
	ev := strings.Join(r.Findings[0].Evidence, " ")
	for _, quer := range []string{"AUTO-ASSINADA", "MITM completo", "Corp Proxy CA"} {
		if !strings.Contains(ev, quer) {
			t.Errorf("falta %q:\n%s", quer, ev)
		}
	}
}

// Certificado que não decodifica continua sendo achado: a PRESENÇA no
// diretório de âncoras é o fato, e "não consegui ler" não é "não existe".
func TestCAIlegivelAindaEhAchado(t *testing.T) {
	f := &facts.Facts{CACerts: []facts.CACert{
		{File: "/etc/pki/ca-trust/source/anchors/x.crt", Erro: "não é PEM"}}}
	r := caPlantada.Run(caPlantada, f, imgEnv())
	if len(r.Findings) != 1 {
		t.Fatal("presença no diretório de âncoras já é o fato")
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "PRESENÇA") {
		t.Error("a evidência precisa dizer por que ainda vale")
	}
}

func TestHostsOverrideSeparaInternoDePublico(t *testing.T) {
	f := &facts.Facts{Hosts: []facts.HostEntry{
		{IP: "127.0.0.1", Names: []string{"localhost"}, Line: 1, Scope: facts.ScopeLoopback},
		{IP: "10.0.0.9", Names: []string{"registry.interno.corp"}, Line: 2, Scope: facts.ScopePrivate},
		{IP: "198.51.100.7", Names: []string{"api.parceiro.com"}, Line: 3, Scope: facts.ScopePublic},
		{IP: "192.168.0.9", Names: []string{"deb.debian.org"}, Line: 4, Scope: facts.ScopePrivate},
		{IP: "10.0.0.1", Names: []string{"gateway"}, Line: 5, Scope: facts.ScopePrivate}, // sem ponto: apelido
	}}
	r := hostsOverride.Run(hostsOverride, f, imgEnv())
	sev := map[string]check.Severity{}
	for _, fd := range r.Findings {
		sev[fd.Subject] = fd.Sev
	}
	if len(r.Findings) != 3 {
		t.Fatalf("achados = %v", sev)
	}
	if sev["registry.interno.corp"] != check.SevWarn {
		t.Error("destino interno é comum em espelho de pacote: aviso")
	}
	if sev["api.parceiro.com"] != check.SevCritical {
		t.Error("nome público apontando para IP público é redirecionamento")
	}
	// Domínio de ATUALIZAÇÃO sobe mesmo com destino interno: quem controla
	// para onde ele aponta controla o que o host instala.
	if sev["deb.debian.org"] != check.SevCritical {
		t.Errorf("domínio de pacote = %s, quer CRITICAL", sev["deb.debian.org"])
	}
}

// O metadata da nuvem é o único ponto de persistência que NÃO está em disco.
// Reportar ausência como "nada encontrado" seria a mentira exata que a
// ferramenta existe para não contar — por isso o achado é a PERGUNTA.
func TestCloudMetadataEhPerguntaManual(t *testing.T) {
	f := &facts.Facts{
		Host:  facts.Host{Virt: "gce"},
		Units: []facts.Unit{{Name: "google-startup-scripts.service", Kind: "service"}},
	}
	r := cloudMetadata.Run(cloudMetadata, f, imgEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevManual {
		t.Fatalf("achados = %v", r.Findings)
	}
	passos := strings.Join(r.Findings[0].NextSteps, " ")
	if !strings.Contains(passos, "169.254.169.254") {
		t.Error("o achado precisa entregar o comando: é a única forma de olhar")
	}
}

// Host sem nuvem nenhuma não deve receber a pergunta.
func TestCloudMetadataNaoPerguntaEmHostFisico(t *testing.T) {
	if r := cloudMetadata.Run(cloudMetadata, &facts.Facts{}, imgEnv()); len(r.Findings) != 0 {
		t.Error("sem agente e sem virtualização, não há metadata para conferir")
	}
}

// auto_prepend_file põe código no caminho de TODA requisição. Aqui o sinal é a
// DIRETIVA: o caminho apontado pode parecer normal.
func TestWebPrependDisparaMesmoComCaminhoNormal(t *testing.T) {
	f := &facts.Facts{Triggers: []facts.Trigger{{
		File: "/etc/php/8.2/fpm/php.ini", Kind: "php",
		When: "antes de CADA requisição, em qualquer rota",
		Lines: []facts.TriggerLine{
			{N: 10, Text: "auto_prepend_file = /var/www/html/.init.php"},
			{N: 11, Text: "auto_append_file = none"},
			{N: 12, Text: "memory_limit = 128M"},
		},
	}}}
	r := webPrepend.Run(webPrepend, f, imgEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %d, quer 1 (none e memory_limit não contam)", len(r.Findings))
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "webshell não acha") {
		t.Error("o achado precisa dizer por que o grep de webshell não acha nada")
	}
}

// Uma linha |"comando" no aliases faz o MTA executar aquilo a cada e-mail.
// Sem extrair o comando, o classificador veria o nome do alias.
func TestPipeDeMailViraComando(t *testing.T) {
	casos := map[string]string{
		`suporte: |"/tmp/.x"`:     "/tmp/.x",
		`backup: |/usr/bin/legit`: "/usr/bin/legit",
		`admin: root`:             "admin: root",
	}
	for ln, quer := range casos {
		if got := linhaExecutavel(ln); got != quer {
			t.Errorf("linhaExecutavel(%q) = %q, quer %q", ln, got, quer)
		}
	}
}
