package facts

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

// O TETO DO INVENTÁRIO AGE ANTES DA ALOCAÇÃO, E DECLARA.
//
// `maxLogDirs = 200` era o único teto estrutural da caminhada, e duzentos
// diretórios sem teto de arquivo é ilimitado: a lista de /var/log é escrita por
// quem tem root no alvo, e é esse o threat model do coletor — alvosDeLog já
// cita `touch /var/log/auth.log.{1..3000}` como caso medido.
//
// Medido com 200 mil arquivos vazios, antes e depois:
//
//	                 antes      depois
//	inventariados   200.000     20.000
//	tempo             2,83 s     0,16 s
//	alocado          316 MiB      22 MiB
//	lacuna            NENHUMA    declarada
//
// A lacuna é a metade que importa. O corte existia — alvosDeLog cortava em 500
// lá adiante —, mas o inventário não dizia nada sobre ter parado, e um teto que
// corta calado é indistinguível de um host que não tinha mais nada ali.
func TestInventarioDeLogTemTetoQueDeclara(t *testing.T) {
	raiz := t.TempDir()
	dir := filepath.Join(raiz, "var/log")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Acima do teto, e o bastante para o corte ser inequívoco.
	n := maxLogArquivosInventario + 5_000
	for i := 0; i < n; i++ {
		if err := os.WriteFile(filepath.Join(dir, "auth.log."+strconv.Itoa(i)), nil, 0o600); err != nil {
			t.Skipf("sem espaço para o cenário: %v", err)
		}
	}

	f := &Facts{}
	collectLogs(f, env.Probe(env.Options{Root: raiz, Version: "test"}))

	if len(f.Logs) > maxLogArquivosInventario {
		t.Errorf("inventariou %d arquivos com teto de %d: o teto está agindo "+
			"depois da alocação que ele existe para impedir",
			len(f.Logs), maxLogArquivosInventario)
	}
	if len(f.Logs) == 0 {
		t.Fatal("não inventariou nada: o teto virou recusa")
	}
	if !temLacuna(f, "logs", "parou em "+strconv.Itoa(maxLogArquivosInventario)) {
		t.Errorf("o inventário parou e não disse: %v\n"+
			"Um teto que corta calado é indistinguível de um host que não tinha "+
			"mais nada ali — e é sobre este inventário que o buraco de rotação "+
			"afirma ausência.", f.Partial["logs"])
	}
}

// E UM HOST NORMAL NÃO PERDE NADA.
//
// Sem isto, um teto apertado demais passaria no teste acima e mutilaria o
// inventário de todo host real.
func TestInventarioDeLogNaoCortaHostNormal(t *testing.T) {
	raiz := t.TempDir()
	dir := filepath.Join(raiz, "var/log")
	if err := os.MkdirAll(filepath.Join(dir, "audit"), 0o755); err != nil {
		t.Fatal(err)
	}
	nomes := []string{
		"auth.log", "auth.log.1", "auth.log.2.gz", "syslog", "syslog.1",
		"kern.log", "wtmp", "btmp", "lastlog", "messages", "secure-20260801",
	}
	for _, n := range nomes {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "audit/audit.log"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	f := &Facts{}
	collectLogs(f, env.Probe(env.Options{Root: raiz, Version: "test"}))

	if len(f.Logs) != len(nomes)+1 {
		t.Errorf("inventariou %d de %d arquivos", len(f.Logs), len(nomes)+1)
	}
	if len(f.Partial["logs"]) != 0 {
		t.Errorf("um /var/log comum produziu lacuna: %v\n"+
			"Lacuna que aparece em host saudável deixa de ser lida.", f.Partial["logs"])
	}
	// A subárvore tem de continuar sendo descida: /var/log/audit é 0700 na
	// prática, e sumir dela é o defeito que o coletor inteiro combate.
	achouAudit := false
	for _, l := range f.Logs {
		if strings.HasSuffix(l.Path, "/audit/audit.log") {
			achouAudit = true
		}
	}
	if !achouAudit {
		t.Error("a recursão em subdiretório se perdeu na conversão para lotes")
	}
}

func temLacuna(f *Facts, chave, trecho string) bool {
	for _, m := range f.Partial[chave] {
		if strings.Contains(m, trecho) {
			return true
		}
	}
	return false
}

// A ORDEM DE SELEÇÃO É UMA ORDEM.
//
// A versão anterior comparava a DATA quando os dois lados eram datados e o
// CAMINHO quando só um era, o que não é ordem total: três elementos fecham
// ciclo. O sort do Go tolera isso — não entra em laço nem corrompe — e devolve
// uma permutação arbitrária, e aí a promessa de que "o corte fica com as
// gerações MAIS NOVAS" deixa de valer justamente no host onde há mais o que
// cortar.
//
// O caso não é exótico: ele aparece quando alguém troca a configuração do
// logrotate de contador para `dateext` e os arquivos velhos ficam.
func TestOrdemDeSelecaoEhTotal(t *testing.T) {
	out := []alvoDeLog{
		{path: "/var/log/secure-20260820", base: "/var/log/secure", geracao: 1, dataRot: "20260820"},
		{path: "/var/log/messages-20260101", base: "/var/log/messages", geracao: 1, dataRot: "20260101"},
		{path: "/var/log/messages.1", base: "/var/log/messages", geracao: 1},
		{path: "/var/log/secure-20260801", base: "/var/log/secure", geracao: 1, dataRot: "20260801"},
		{path: "/var/log/secure", base: "/var/log/secure", geracao: 0},
	}
	rankearNaSerie(out)
	menor := func(a, b alvoDeLog) bool {
		if a.geracao != b.geracao {
			return a.geracao < b.geracao
		}
		if a.rank != b.rank {
			return a.rank < b.rank
		}
		if a.base != b.base {
			return a.base < b.base
		}
		return a.path < b.path
	}
	// IRREFLEXIVA, ASSIMÉTRICA e TRANSITIVA sobre todos os trios: é a definição
	// de ordem estrita, e é o que o sort exige para o resultado significar algo.
	for i := range out {
		if menor(out[i], out[i]) {
			t.Fatalf("%s é menor que si mesmo", out[i].path)
		}
		for j := range out {
			if i == j {
				continue
			}
			if menor(out[i], out[j]) && menor(out[j], out[i]) {
				t.Fatalf("%s e %s são menores um que o outro", out[i].path, out[j].path)
			}
			for k := range out {
				if menor(out[i], out[j]) && menor(out[j], out[k]) && !menor(out[i], out[k]) {
					t.Fatalf("CICLO: %s < %s < %s, e %s não é menor que %s",
						out[i].path, out[j].path, out[k].path, out[i].path, out[k].path)
				}
			}
		}
	}
}

// E O CORTE FICA COM AS GERAÇÕES MAIS NOVAS DE CADA SÉRIE.
//
// É a promessa escrita no comentário do teto rígido, e ela não valia para
// rotação datada: toda geração 1, ordenada por caminho, punha
// `secure-20260801` ANTES de `secure-20260820` — o orçamento era gasto com as
// velhas, no padrão de fábrica da família RHEL.
//
// O rank por SÉRIE é o que faz a promessa ser verdade, e faz mais: ele
// INTERCALA as séries. Com um rank global, o orçamento acabaria dentro da série
// que tem mais rotações, e a série ao lado ficaria de fora com a geração mais
// recente dela ainda por examinar.
func TestCorteFicaComAsMaisNovasDeCadaSerie(t *testing.T) {
	var out []alvoDeLog
	for _, d := range []string{"20260801", "20260810", "20260820"} {
		out = append(out, alvoDeLog{
			path: "/var/log/secure-" + d, base: "/var/log/secure", geracao: 1, dataRot: d,
		})
	}
	for _, d := range []string{"20260701", "20260702"} {
		out = append(out, alvoDeLog{
			path: "/var/log/messages-" + d, base: "/var/log/messages", geracao: 1, dataRot: d,
		})
	}
	rankearNaSerie(out)
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.geracao != b.geracao {
			return a.geracao < b.geracao
		}
		if a.rank != b.rank {
			return a.rank < b.rank
		}
		if a.base != b.base {
			return a.base < b.base
		}
		return a.path < b.path
	})

	// As duas primeiras têm de ser a MAIS NOVA de cada série — não as duas mais
	// novas de uma série só.
	primeiras := map[string]bool{out[0].path: true, out[1].path: true}
	for _, quer := range []string{"/var/log/secure-20260820", "/var/log/messages-20260702"} {
		if !primeiras[quer] {
			t.Errorf("%s não está entre as duas primeiras: %s, %s\n"+
				"O corte precisa intercalar as séries pela recência de cada uma.",
				quer, out[0].path, out[1].path)
		}
	}
	if out[len(out)-1].path != "/var/log/secure-20260801" {
		t.Errorf("a última é %s, queria a mais antiga da série mais longa",
			out[len(out)-1].path)
	}
}

// O INVENTÁRIO SAI NA MESMA ORDEM TODA VEZ.
//
// A leitura em LOTES entrega na ordem do readdir, que muda a cada arquivo
// criado no diretório — e (base, geração) NÃO é ordem total, porque toda
// rotação datada é geração 1. Com sort.Slice, que não é estável, o desempate
// passava a variar entre execuções.
//
// Isso vaza para fora: antiforense.log_rotation_gap monta a evidência
// "presentes: ..." percorrendo f.Logs, e uma evidência que muda de ordem
// sozinha faz o drift acusar mudança sobre um host que ninguém tocou.
func TestInventarioDeLogTemOrdemEstavel(t *testing.T) {
	raiz := t.TempDir()
	dir := filepath.Join(raiz, "var/log")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Empate nas duas chaves antigas: mesma base, todos geração 1.
	nomes := []string{
		"secure-20260801", "secure-20260810", "secure-20260820",
		"secure-20260805", "secure-20260815", "secure",
		"messages-20260701", "messages-20260702", "messages",
	}
	for _, n := range nomes {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	inventariar := func() []string {
		f := &Facts{}
		collectLogs(f, env.Probe(env.Options{Root: raiz, Version: "test"}))
		var out []string
		for _, l := range f.Logs {
			out = append(out, l.Path)
		}
		return out
	}

	ref := inventariar()
	if len(ref) != len(nomes) {
		t.Fatalf("inventariou %d de %d", len(ref), len(nomes))
	}
	// Mexer no diretório muda a ordem do readdir em ext4 e afins. A ordem do
	// FATO não pode mudar com isso.
	for i := 0; i < 3; i++ {
		tmp := filepath.Join(dir, "ruido"+strconv.Itoa(i))
		if err := os.WriteFile(tmp, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(tmp); err != nil {
			t.Fatal(err)
		}
		got := inventariar()
		for j := range ref {
			if got[j] != ref[j] {
				t.Fatalf("a ordem mudou entre execuções na posição %d:\n"+
					"  antes: %v\n  agora: %v", j, ref, got)
			}
		}
	}
}
