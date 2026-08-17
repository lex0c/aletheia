package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

// Configuração é entregue para ser EDITADA: divergir ali é o trabalho normal do
// administrador. O que devolve o peso é o arquivo EXECUTAR alguma coisa.
func TestHashSeparaConfigDeBinario(t *testing.T) {
	f := &facts.Facts{HashDiff: []facts.HashDivergente{
		{Path: "/usr/bin/wc", Pacote: "coreutils", Algo: "md5", Esperado: "a", Obtido: "b"},
		{Path: "/etc/adduser.conf", Pacote: "adduser", Algo: "md5", Esperado: "a", Obtido: "b", Config: true},
		{Path: "/etc/init.d/ssh", Pacote: "openssh", Algo: "md5", Esperado: "a", Obtido: "b", Config: true},
	}}
	r := arquivoDePacoteAlterado.Run(arquivoDePacoteAlterado, f, testEnv())
	if len(r.Findings) != 3 {
		t.Fatalf("achados = %d", len(r.Findings))
	}
	sev := map[string]check.Severity{}
	for _, fd := range r.Findings {
		sev[fd.Subject] = fd.Sev
	}
	if sev["/usr/bin/wc"] != check.SevCritical {
		t.Error("binário de pacote alterado é substituição")
	}
	if sev["/etc/adduser.conf"] != check.SevWarn {
		t.Error("config editada é o trabalho normal do administrador")
	}
	if sev["/etc/init.d/ssh"] != check.SevCritical {
		t.Error("config que EXECUTA é persistência que mantém o dono de pacote")
	}
}

// Trocar biblioteca é pior que trocar binário: o código do invasor entra em
// todo processo que linkar contra ela, sem nenhum processo novo aparecer.
func TestHashDestacaBiblioteca(t *testing.T) {
	f := &facts.Facts{HashDiff: []facts.HashDivergente{
		{Path: "/lib/x86_64-linux-gnu/libkeyutils.so.1", Pacote: "libkeyutils1",
			Algo: "md5", Esperado: "a", Obtido: "b"},
	}}
	r := arquivoDePacoteAlterado.Run(arquivoDePacoteAlterado, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %v", r.Findings)
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "BIBLIOTECA") {
		t.Error("a evidência precisa explicar por que biblioteca é pior")
	}
}

// A diferença de datas sozinha descreve extração de tarball, restauração de
// backup e camada de contêiner. Só vira achado no arquivo que FAZ TRABALHO.
func TestTimestompSoReportaOQueFazTrabalho(t *testing.T) {
	base := []facts.Timestomp{
		{Path: "/opt/app/lib.so", ModUTC: "2020-01-01T00:00:00Z", MetaUTC: "2026-01-01T00:00:00Z", DeltaH: 52000},
		{Path: "/usr/local/sbin/impl", ModUTC: "2020-01-01T00:00:00Z", MetaUTC: "2026-01-01T00:00:00Z", DeltaH: 52000},
	}

	// Sem nada apontando para eles: silêncio.
	f := &facts.Facts{Timestomps: base}
	if r := dataFalsificada.Run(dataFalsificada, f, testEnv()); len(r.Findings) != 0 {
		t.Fatalf("extração de tarball tem esta forma: %v", r.Findings)
	}

	// Com uma unit executando um deles: achado, e só ele.
	f = &facts.Facts{
		Timestomps: base,
		Units: []facts.Unit{{Name: "x.service", Exec: []facts.ExecLine{
			{Key: "ExecStart", Cmd: "/usr/local/sbin/impl sleep 1"}}}},
	}
	r := dataFalsificada.Run(dataFalsificada, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Subject != "/usr/local/sbin/impl" {
		t.Fatalf("achados = %v", r.Findings)
	}
	if r.Findings[0].Sev != check.SevCritical {
		t.Error("data mexida num alvo de persistência é deliberada")
	}
}
