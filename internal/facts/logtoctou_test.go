package facts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lex0c/aletheia/internal/env"
)

// escreveLog grava n linhas numeradas e devolve o caminho e o tamanho real.
func escreveLog(t *testing.T, dir, nome string, n int) (string, int64) {
	t.Helper()
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString("Aug 24 10:00:00 host prog: linha-")
		b.WriteString(strings.Repeat("x", 8))
		b.WriteString("-")
		b.WriteString(itoaLog(i))
		b.WriteString("\n")
	}
	p := filepath.Join(dir, nome)
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return p, fi.Size()
}

func itoaLog(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	return string(d)
}

// A METADATA DA DECISÃO VEM DO DESCRITOR, NÃO DO Lstat ANTERIOR.
//
// `a.tam` sai do Lstat que alvosDeLog fez, e entre aquele Lstat e o open cabe o
// arquivo crescer — um auth.log VIVO cresce por definição. Os dois ramos
// mentiam de formas diferentes:
//
//	cabe inteiro   lia até o teto sem testar o byte seguinte e devolvia
//	               FonteLida. Os bytes além do teto não foram observados, e a
//	               fonte saía declarando completude
//	cauda          o seek ia para `a.tam - teto`, que num arquivo maior é o
//	               MIOLO — a fonte dizia "só a CAUDA foi lida" sobre bytes do
//	               meio
//
// O teste passa um `a.tam` deliberadamente MENTIROSO. Se a função ainda o
// consultasse, ela escolheria o ramo errado e leria a região errada.
func TestLeituraDeLogIgnoraTamanhoAnterior(t *testing.T) {
	dir := t.TempDir()
	_, real := escreveLog(t, dir, "auth.log", 300)
	e := env.Probe(env.Options{Root: dir, Version: "test"})
	rel := "/auth.log"

	t.Run("cresceu acima do teto", func(t *testing.T) {
		// O Lstat viu 50 bytes; o arquivo tem `real`. Com teto de 100, a
		// verdade manda para o ramo da CAUDA.
		orc := &orcamento{bytes: 100, eventos: maxEventosLog, estourou: map[string]bool{}}
		var fonte FonteDeLog
		cab, corpo, obs, err := abreConteudoDeLog(e, alvoDeLog{path: rel, tam: 50}, orc, &fonte)
		if err != nil {
			t.Fatal(err)
		}
		if obs.tam != real {
			t.Errorf("o descritor devia dizer %d, disse %d", real, obs.tam)
		}
		if fonte.Estado != FonteTruncada {
			t.Errorf("estado = %q; um arquivo maior que o teto NÃO foi lido "+
				"inteiro, e declarar completude sobre ele é a mentira que este "+
				"conserto existe para impedir", fonte.Estado)
		}
		// E o que veio é o FIM do arquivo, não o miolo: a última linha do
		// arquivo tem de estar no corpo.
		if !strings.Contains(corpo, "-299\n") {
			t.Errorf("a cauda não contém a última linha do arquivo.\n"+
				"corpo termina em: %q", ultimos(corpo, 60))
		}
		if cab == "" {
			t.Error("a cabeça, que data a rotação, não foi lida")
		}
	})

	t.Run("teto cobre o arquivo inteiro", func(t *testing.T) {
		// Agora o Lstat mente para MAIS: 10 MB num arquivo de poucos KB. Se a
		// função confiasse nele, iria para o ramo da cauda e faria um seek
		// muito além do fim.
		orc := &orcamento{bytes: maxLogBytesTotal, eventos: maxEventosLog, estourou: map[string]bool{}}
		var fonte FonteDeLog
		_, corpo, _, err := abreConteudoDeLog(e, alvoDeLog{path: rel, tam: 10 << 20}, orc, &fonte)
		if err != nil {
			t.Fatal(err)
		}
		if fonte.Estado == FonteTruncada {
			t.Errorf("um arquivo de %d bytes sob teto de %d MB foi declarado "+
				"truncado", real, maxLogBytesTotal>>20)
		}
		if int64(len(corpo)) != real {
			t.Errorf("leu %d de %d bytes", len(corpo), real)
		}
		if !strings.Contains(corpo, "-0\n") || !strings.Contains(corpo, "-299\n") {
			t.Error("o arquivo cabia inteiro e não veio inteiro")
		}
	})
}

// A ÂNCORA DO ANO TAMBÉM VEM DO DESCRITOR.
//
// Ela é o mtime do arquivo ROTACIONADO, e é de onde o ano das linhas do syslog
// tradicional é inferido — o formato não carrega ano. Ancorar num mtime que
// descreve outro inode desloca o ano de todas as linhas daquele arquivo, e um
// ano a menos empurra o achado para fora de `--since 7d`.
func TestAncoraDoAnoVemDoDescritor(t *testing.T) {
	dir := t.TempDir()
	p, _ := escreveLog(t, dir, "auth.log.1", 3)
	real := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	if err := os.Chtimes(p, real, real); err != nil {
		t.Fatal(err)
	}
	e := env.Probe(env.Options{Root: dir, Version: "test"})

	orc := &orcamento{bytes: maxLogBytesTotal, eventos: maxEventosLog, estourou: map[string]bool{}}
	var fonte FonteDeLog
	_, _, obs, err := abreConteudoDeLog(e, alvoDeLog{path: "/auth.log.1"}, orc, &fonte)
	if err != nil {
		t.Fatal(err)
	}
	if !obs.mod.Equal(real) {
		t.Errorf("o mtime do descritor é %v, queria %v", obs.mod, real)
	}
}

func ultimos(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// UM ARQUIVO MENOR QUE A CABEÇA E MAIOR QUE O TETO NÃO É "LIDO".
//
// A cabeça tem 64 KiB e existe só para DATAR a rotação — ela não é parseada
// para evento nenhum. Quem vira cobertura é o corpo. Num arquivo de 12 KB com
// orçamento de 100 bytes, a cabeça lê tudo e o corpo lê a cauda: concluir daí
// que não há miolo por observar declararia completude sobre um arquivo cujos
// eventos iniciais ninguém examinou.
//
// Foi um furo que a primeira versão deste conserto introduziu, ao trocar
// `inicio > 0` por "a cabeça alcançou a cauda".
func TestCabecaQueCobreOArquivoNaoEhCobertura(t *testing.T) {
	dir := t.TempDir()
	_, real := escreveLog(t, dir, "auth.log", 300)
	if real >= cabecaDeLog {
		t.Fatalf("o cenário exige arquivo menor que a cabeça (%d): tem %d",
			cabecaDeLog, real)
	}
	e := env.Probe(env.Options{Root: dir, Version: "test"})

	orc := &orcamento{bytes: 100, eventos: maxEventosLog, estourou: map[string]bool{}}
	fonte := FonteDeLog{Estado: FonteLida}
	_, corpo, _, err := abreConteudoDeLog(e, alvoDeLog{path: "/auth.log"}, orc, &fonte)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(corpo)) >= real {
		t.Fatalf("o cenário não truncou o corpo: %d de %d bytes", len(corpo), real)
	}
	if fonte.Estado != FonteTruncada {
		t.Errorf("estado = %q; o corpo pegou %d de %d bytes", fonte.Estado, len(corpo), real)
	}
	if !fonte.LeituraDescontinua {
		t.Error("LeituraDescontinua falso: sem ele, CoberturaLog junta PrimeiroAt " +
			"com CobertoAte e afirma um intervalo contínuo sobre um buraco")
	}
}
