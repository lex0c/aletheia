package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

func alvo(a facts.AlvoDeRoot) *facts.Facts {
	return &facts.Facts{AlvosDeRoot: []facts.AlvoDeRoot{a}}
}

// A escada do §36.4. A forma que mais aparece em host real não é a óbvia: é o
// DONO não-root, não o "gravável por todos".
func TestQuemPodeReescreverOQueRootExecuta(t *testing.T) {
	casos := []struct {
		nome   string
		a      facts.AlvoDeRoot
		quero  check.Severity
		trecho string
	}{
		{
			nome: "dono não é root",
			a: facts.AlvoDeRoot{Caminho: "/opt/app/job.sh", Origem: "cron", Onde: "/etc/cron.d/app",
				Existe: true, UID: 1000, GID: 1000, Modo: 0o755, DirUID: 0, DirModo: 0o755},
			quero: check.SevWarn, trecho: "o dono do arquivo (uid 1000) não é root",
		},
		{
			// Qualquer um escreve: não precisa de conta nenhuma antes, e o
			// próximo minuto do cron já executa o que foi escrito.
			nome: "gravável por todos",
			a: facts.AlvoDeRoot{Caminho: "/usr/local/bin/rotate.sh", Origem: "unit", Onde: "/etc/systemd/system/x.service",
				Existe: true, UID: 0, GID: 0, Modo: 0o777, DirUID: 0, DirModo: 0o755},
			quero: check.SevCritical, trecho: "gravável por QUALQUER usuário",
		},
		{
			nome: "grupo que não é o do root",
			a: facts.AlvoDeRoot{Caminho: "/opt/x.sh", Origem: "cron", Onde: "/etc/crontab",
				Existe: true, UID: 0, GID: 1500, Modo: 0o775, DirUID: 0, DirModo: 0o755},
			quero: check.SevWarn, trecho: "grupo 1500",
		},
		{
			// A mais silenciosa: a vaga está aberta e nada no host reclama.
			nome: "não existe, e o diretório é gravável",
			a: facts.AlvoDeRoot{Caminho: "/opt/deploy/pre.sh", Origem: "unit", Onde: "/etc/systemd/system/y.service",
				Existe: false, UID: -1, GID: -1, DirUID: 1000, DirModo: 0o755},
			quero: check.SevWarn, trecho: "quem criá-lo",
		},
	}
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			r := rootExecutaGravavel.Run(rootExecutaGravavel, alvo(c.a), testEnv())
			if len(r.Findings) != 1 {
				t.Fatalf("achados = %v", r.Findings)
			}
			fd := r.Findings[0]
			if fd.Sev != c.quero {
				t.Errorf("sev = %v, queria %v", fd.Sev, c.quero)
			}
			if !strings.Contains(strings.Join(fd.Evidence, " "), c.trecho) {
				t.Errorf("a evidência não explica o caso (%q): %v", c.trecho, fd.Evidence)
			}
			if fd.Subject != c.a.Caminho {
				t.Errorf("subject = %q, queria o caminho", fd.Subject)
			}
		})
	}
}

// O host de referência: tudo root:root 755. Zero achados — e é isso que decide
// se o check é usável, porque um servidor tem centenas de alvos assim.
func TestOQueSoRootEscreveNaoDispara(t *testing.T) {
	f := &facts.Facts{AlvosDeRoot: []facts.AlvoDeRoot{
		{Caminho: "/usr/bin/systemd-tmpfiles", Existe: true, UID: 0, GID: 0, Modo: 0o755, DirModo: 0o755},
		{Caminho: "/usr/sbin/logrotate", Existe: true, UID: 0, GID: 0, Modo: 0o755, DirModo: 0o755},
		// Grupo root grava: continua sendo só root, porque estar no grupo 0 já
		// é ser root para efeito prático.
		{Caminho: "/usr/local/sbin/x", Existe: true, UID: 0, GID: 0, Modo: 0o775, DirModo: 0o755},
	}}
	if r := rootExecutaGravavel.Run(rootExecutaGravavel, f, testEnv()); len(r.Findings) != 0 {
		t.Errorf("root:root não é achado: %v", r.Findings)
	}
}

// O sticky bit muda o que dá para fazer: em /tmp qualquer um cria, e ninguém
// substitui o arquivo do outro. Dizer isso é a diferença entre um achado que se
// investiga e um que se descarta.
func TestStickyBitEhDito(t *testing.T) {
	f := alvo(facts.AlvoDeRoot{
		Caminho: "/tmp/job.sh", Origem: "cron", Onde: "/etc/cron.d/x",
		Existe: true, UID: 0, GID: 0, Modo: 0o777, DirUID: 0, DirModo: 0o777, DirSticky: true,
	})
	r := rootExecutaGravavel.Run(rootExecutaGravavel, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %v", r.Findings)
	}
	if r.Findings[0].Sev != check.SevWarn {
		t.Errorf("sev = %v: com sticky bit o arquivo alheio não é substituível, "+
			"e a severidade precisa refletir isso", r.Findings[0].Sev)
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "sticky") {
		t.Errorf("o sticky bit precisa ser dito: %v", r.Findings[0].Evidence)
	}
}

// A propriedade que se lê nem sempre é a do alvo: um rootfs extraído por
// usuário comum fica INTEIRO com o uid de quem extraiu, e ali `/bin/sh` aparece
// como dono 1000. As três fixtures de servidor de referência produziram 89, 91 e
// 112 achados assim — todos falsos, todos convincentes.
//
// O coletor recusa a pergunta nesse caso; o check precisa REPASSAR a lacuna, ou
// o silêncio dele vira "nada encontrado".
func TestSemPropriedadeConfiavelALacunaEhRepassada(t *testing.T) {
	f := &facts.Facts{
		Partial: map[string][]string{"gravavel": {
			"a propriedade dos arquivos desta árvore não é a do sistema de origem"}},
	}
	r := rootExecutaGravavel.Run(rootExecutaGravavel, f, testEnv())
	if len(r.Findings) != 0 {
		t.Errorf("sem propriedade confiável não há acusação: %v", r.Findings)
	}
	if len(r.Partial) == 0 || !strings.Contains(r.Partial[0], "propriedade") {
		t.Errorf("e a lacuna precisa ser declarada: %v", r.Partial)
	}
}
