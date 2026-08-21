package checks

import (
	"os"
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

// A LINHA DO CHECK, e ela e uma so: caractere de FORMATACAO invisivel e de
// controle disparam; letra de outra lingua nao.
//
// Sem essa distincao o check acusaria `relatorio-2026.php` e `\u6587\u6863.py`, que sao
// nomes legitimos — e um check que acusa o mundo e desligado na primeira semana.
func TestInvisivelSeparaFormatacaoDeLingua(t *testing.T) {
	invisiveis := []rune{0x200b, 0x200c, 0x200d, 0x200e, 0x202e, 0xfeff, 0x00ad, '\n', '\t', 0x7f}
	for _, r := range invisiveis {
		if !invisivel(r) {
			t.Errorf("U+%04X devia ser invisivel", r)
		}
	}
	legitimos := []rune{'a', 'ç', 'ã', 'é', 0x4e2d, 0x1f600, '-', '_', '.', ' '}
	for _, r := range legitimos {
		if invisivel(r) {
			t.Errorf("U+%04X e caractere legitimo de nome de arquivo", r)
		}
	}
}

// O GEMEO e o que separa "esquisito" de "disfarce": um nome invisivel sozinho e
// aviso; ao lado do arquivo com o nome limpo, e o disfarce montado, e quem
// remover "o suspeito" tem metade de chance de remover o legitimo.
func TestNomeInvisivelComGemeoEhCritico(t *testing.T) {
	dir := t.TempDir()
	limpo := dir + "/update"
	if err := os.WriteFile(limpo, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	impostor := dir + "/upd\u200date"

	f := &facts.Facts{Suid: []facts.SuidFile{{Path: impostor, Setuid: true}}}
	r := textoOculto.Run(textoOculto, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %+v", r.Findings)
	}
	if r.Findings[0].Sev != check.SevCritical {
		t.Errorf("com o gemeo ao lado e disfarce montado: %v", r.Findings[0].Sev)
	}
	ev := strings.Join(r.Findings[0].Evidence, " ")
	if !strings.Contains(ev, "nome limpo ao lado") {
		t.Errorf("a evidencia precisa nomear o gemeo:\n%s", ev)
	}
	// O SUJEITO precisa ser estavel e comparavel: a baseline compara strings, e
	// um sujeito com byte invisivel casa consigo mesmo e com mais nada.
	if !strings.Contains(r.Findings[0].Subject, "<U+200D>") {
		t.Errorf("sujeito = %q, precisa vir escapado", r.Findings[0].Subject)
	}
}

// Sem gemeo o nome continua sendo dito — e como aviso, porque a intencao nao
// esta provada.
func TestNomeInvisivelSemGemeoEhAviso(t *testing.T) {
	f := &facts.Facts{Suid: []facts.SuidFile{{Path: "/opt/app/serv\u200bico", Setuid: true}}}
	r := textoOculto.Run(textoOculto, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevWarn {
		t.Fatalf("%+v", r.Findings)
	}
}

// Nome normal nao pode virar achado, e nome com acento tambem nao.
func TestNomesLegitimosNaoViramAchado(t *testing.T) {
	f := &facts.Facts{Suid: []facts.SuidFile{
		{Path: "/usr/bin/sudo"},
		{Path: "/srv/app/relatório-2026.php"},
		{Path: "/opt/\u6587\u6863/run.py"},
	}}
	if r := textoOculto.Run(textoOculto, f, testEnv()); len(r.Findings) != 0 {
		t.Fatalf("%+v", r.Findings)
	}
}

// O escape de terminal e campo PROPRIO do gatilho porque ele mora numa linha de
// COMENTARIO — que a coleta de linhas executaveis descarta.
func TestEscapeDeTerminalEmGatilhoEhCritico(t *testing.T) {
	f := &facts.Facts{Triggers: []facts.Trigger{{
		File: "/root/.bashrc", Kind: "shell", When: "a cada shell interativo",
		EscapeN: 2,
	}}}
	r := textoOculto.Run(textoOculto, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("%+v", r.Findings)
	}
	if !r.Findings[0].Irreversible {
		t.Error("o arquivo e a amostra: preservar vem antes")
	}
}

// Gatilho sem escape nao diz nada.
func TestGatilhoLimpoNaoDispara(t *testing.T) {
	f := &facts.Facts{Triggers: []facts.Trigger{{File: "/etc/profile", Kind: "shell"}}}
	if r := textoOculto.Run(textoOculto, f, testEnv()); len(r.Findings) != 0 {
		t.Fatalf("%+v", r.Findings)
	}
}
