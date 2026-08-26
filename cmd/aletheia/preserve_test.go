package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
	"github.com/lex0c/aletheia/internal/pcap"
	"github.com/lex0c/aletheia/internal/preserve"
)

// As recusas de invocação vêm ANTES de qualquer leitura. Este é o único comando
// que escreve: um `--out` esquecido não pode virar uma coleta no diretório
// corrente, e um comando sem alvo não pode sair 0 dizendo que preservou nada.
func TestPreserveRecusaInvocacaoAmbigua(t *testing.T) {
	dir := t.TempDir()
	casos := []struct {
		nome string
		args []string
	}{
		{"sem --out", []string{"--pid", "1"}},
		{"sem alvo", []string{"--out", dir}},
		{"--out inexistente", []string{"--out", filepath.Join(dir, "nao-existe"), "--pid", "1"}},
		{"--pid que não é número", []string{"--out", dir, "--pid", "init"}},
		{"--bpf que não é id", []string{"--out", dir, "--bpf", "x"}},
		{"--mem-max sem sentido", []string{"--out", dir, "--file", "/etc/hostname", "--mem-max", "muito"}},
	}
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			if code := semSaida(t, func() int { return runPreserve(c.args) }); code != 3 {
				t.Errorf("exit = %d, queria 3 (ERROR de invocação)", code)
			}
		})
	}
	// E nada foi escrito por causa das tentativas recusadas.
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 0 {
		t.Errorf("uma invocação recusada escreveu no destino: %v", ents)
	}
}

// O caminho feliz, ponta a ponta: manifesto humano, JSONL, amostra no disco e
// o registro de execução — que é o que liga esta coleta às outras do incidente.
func TestPreservePontaAPonta(t *testing.T) {
	dir := t.TempDir()
	origem := filepath.Join(t.TempDir(), "implante.sh")
	if err := os.WriteFile(origem, []byte("#!/bin/sh\n:(){ :|:& };:\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	jsonl := filepath.Join(t.TempDir(), "manifesto.jsonl")

	code := semSaida(t, func() int {
		return runPreserve([]string{"--out", dir, "--file", origem, "--json", jsonl})
	})
	if code != 0 {
		t.Fatalf("exit = %d, queria 0", code)
	}

	linhas := jsonlDe(t, jsonl)
	if len(linhas) != 1 {
		t.Fatalf("manifesto com %d linha(s), queria 1", len(linhas))
	}
	if linhas[0]["id"] != "preserve" || linhas[0]["sha256_source"] == "" {
		t.Errorf("linha do manifesto sem custódia: %v", linhas[0])
	}
	if linhas[0]["sha256_source"] != linhas[0]["sha256_copy"] {
		t.Errorf("origem e cópia divergiram sem ninguém mexer no arquivo: %v", linhas[0])
	}

	dest := filepath.Join(dir, linhas[0]["out"])
	if b, err := os.ReadFile(dest); err != nil || !strings.Contains(string(b), ":(){") {
		t.Errorf("a amostra em %s não é o arquivo de origem (%v)", dest, err)
	}

	// O run log é append e fica DENTRO do diretório de incidente: ele é a
	// ordem das coletas, que faz parte da história do caso.
	runs := jsonlDe(t, filepath.Join(dir, "aletheia-runs.jsonl"))
	if len(runs) != 1 || runs[0]["cmd"] != "preserve" || runs[0]["argv"] == "" {
		t.Fatalf("registro de execução = %v", runs)
	}
}

// O diretório de evidência precisa se explicar SOZINHO. Sem isto a cadeia de
// custódia moraria no terminal: o operador leva as amostras para a análise e os
// hashes ficam na tela que ele fechou.
func TestManifestoFicaNoDiretorioMesmoSemJSON(t *testing.T) {
	dir := t.TempDir()
	origem := filepath.Join(t.TempDir(), "implante")
	if err := os.WriteFile(origem, []byte("carga"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Sem --json: é assim que o comando sai do NextSteps de um achado.
	code := semSaida(t, func() int {
		return runPreserve([]string{"--out", dir, "--file", origem, "--file", "/nao/existe"})
	})
	if code != 1 {
		t.Fatalf("exit = %d, queria 1 — uma peça ficou de fora", code)
	}

	linhas := jsonlDe(t, filepath.Join(dir, "aletheia-manifest.jsonl"))
	if len(linhas) != 2 {
		t.Fatalf("manifesto com %d linha(s), queria 2 (a peça e a lacuna): %v",
			len(linhas), linhas)
	}
	if linhas[0]["sha256_source"] == "" || linhas[0]["sha256_copy"] == "" {
		t.Errorf("a peça foi anotada sem custódia: %v", linhas[0])
	}
	// A lacuna vai no MESMO arquivo: quem ler o diretório meses depois precisa
	// ver o que NÃO está ali.
	if linhas[1]["id"] != "preserve_failed" || !strings.Contains(linhas[1]["target"], "/nao/existe") {
		t.Errorf("a lacuna não está no manifesto: %v", linhas[1])
	}

	// Segunda coleta no mesmo diretório: o manifesto ACUMULA, como o run log.
	outra := filepath.Join(t.TempDir(), "outro")
	if err := os.WriteFile(outra, []byte("mais"), 0o600); err != nil {
		t.Fatal(err)
	}
	semSaida(t, func() int { return runPreserve([]string{"--out", dir, "--file", outra}) })
	if n := len(jsonlDe(t, filepath.Join(dir, "aletheia-manifest.jsonl"))); n != 3 {
		t.Errorf("manifesto com %d linhas depois da segunda coleta, queria 3 — "+
			"sobrescrever apagaria a custódia da primeira", n)
	}
}

// Segunda coleta no mesmo diretório: o run log ACUMULA (senão a primeira some),
// mas a amostra NÃO é sobrescrita — e isso sai como exit 1, não em silêncio.
func TestPreserveSegundaColetaNaoApagaAPrimeira(t *testing.T) {
	dir := t.TempDir()
	origem := filepath.Join(t.TempDir(), "x")
	if err := os.WriteFile(origem, []byte("primeira"), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"--out", dir, "--file", origem}
	if code := semSaida(t, func() int { return runPreserve(args) }); code != 0 {
		t.Fatalf("primeira coleta: exit = %d", code)
	}

	if err := os.WriteFile(origem, []byte("segunda"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := semSaida(t, func() int { return runPreserve(args) }); code != 1 {
		t.Errorf("segunda coleta: exit = %d, queria 1 (peça NÃO preservada)", code)
	}

	if runs := jsonlDe(t, filepath.Join(dir, "aletheia-runs.jsonl")); len(runs) != 2 {
		t.Errorf("o run log tem %d linha(s), queria 2 — ele é append", len(runs))
	}
	b, err := os.ReadFile(filepath.Join(dir, "file-"+nomeArquivo(origem)))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "primeira" {
		t.Errorf("a amostra virou %q: a primeira cópia foi perdida", b)
	}
}

// O laço que fecha: a linha que o CHECK imprime tem que ser um comando que
// ESTE build entende.
//
// A regra nasceu do erro: uma versão prometia `aletheia preserve` quando o
// subcomando não existia. O operador colava a linha, recebia "comando
// desconhecido", e podia seguir para matar o processo — destruindo a única
// cópia do binário. Testar a existência por substring do lado do check não
// resolve: só o parser de verdade sabe se as flags existem.
//
// Por isso o teste não escreve o comando: ele PEGA a instrução do check e a
// entrega ao runPreserve.
func TestInstrucaoDePreservacaoRodaNesteBuild(t *testing.T) {
	c := checkPorID(t, "proc.maps_rwx_anon") // o que recomenda --mem
	res := c.Run(c, &facts.Facts{Processes: []facts.Process{{
		PID: 8812, Comm: "nginx", Exe: "/usr/sbin/nginx",
		MapsRWX: []string{"7f00-7f01 rwxp (anônimo)"},
	}}}, &env.Env{})
	if len(res.Findings) != 1 {
		t.Fatalf("esperava 1 achado, veio %d", len(res.Findings))
	}

	var testadas int
	for _, ns := range res.Findings[0].NextSteps {
		if !strings.Contains(ns, "preserve") {
			continue
		}
		args := argsDaInstrucao(t, ns, t.TempDir())
		if code := semSaida(t, func() int { return runPreserve(args) }); code == 3 {
			t.Errorf("a instrução que o check imprime não é aceita por este build: "+
				"%q\nargs: %v", ns, args)
		}
		testadas++
	}
	if testadas == 0 {
		t.Fatalf("nenhum passo de preservação em %v — o check parou de recomendar "+
			"a coleta, e o achado mais irreversível ficou sem primeiro passo",
			res.Findings[0].NextSteps)
	}
}

// argsDaInstrucao transforma a linha impressa nos argumentos do subcomando:
// tira o `sudo`, o caminho do binário e o nome do subcomando, resolve o `$IR`
// para um diretório de verdade e remove as aspas que existem para o shell.
func argsDaInstrucao(t *testing.T, linha, ir string) []string {
	t.Helper()
	campos := strings.Fields(linha)
	if len(campos) < 3 || campos[0] != "sudo" || campos[2] != "preserve" {
		t.Fatalf("instrução em formato inesperado: %q", linha)
	}
	var out []string
	for _, c := range campos[3:] {
		c = strings.ReplaceAll(c, `"$IR"`, ir)
		out = append(out, strings.Trim(c, `"`))
	}
	return out
}

func checkPorID(t *testing.T, id string) check.Check {
	t.Helper()
	for _, c := range check.All() {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("check %s não existe", id)
	return check.Check{}
}

func TestTamanhoLeOsSufixos(t *testing.T) {
	casos := map[string]int64{
		"512M": 512 << 20, "2G": 2 << 30, "64k": 64 << 10, "1048576": 1048576,
	}
	for s, quer := range casos {
		if n, ok := tamanho(s); !ok || n != quer {
			t.Errorf("tamanho(%q) = %d,%v — queria %d", s, n, ok, quer)
		}
	}
	// Recusar é melhor que adivinhar: um teto entendido errado corta o dump no
	// lugar errado, e ninguém percebe.
	for _, s := range []string{"", "muito", "-1M", "0", "0G", "1.5G", "M"} {
		if n, ok := tamanho(s); ok {
			t.Errorf("tamanho(%q) = %d, deveria ser recusado", s, n)
		}
	}
}

// semSaida executa o comando com stdout e stderr desviados: o teste mede o
// contrato (exit code, arquivos), não o texto na tela.
func semSaida(t *testing.T, f func() int) int {
	t.Helper()
	nulo, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer nulo.Close()
	out, errOut := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = nulo, nulo
	defer func() { os.Stdout, os.Stderr = out, errOut }()
	return f()
}

func jsonlDe(t *testing.T, p string) []map[string]string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("lendo %s: %v", p, err)
	}
	var out []map[string]string
	for _, ln := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if ln == "" {
			continue
		}
		var bruto map[string]any
		if err := json.Unmarshal([]byte(ln), &bruto); err != nil {
			t.Fatalf("%s: linha não é JSON: %v", p, err)
		}
		m := map[string]string{}
		for k, v := range bruto {
			if s, ok := v.(string); ok {
				m[k] = s
			}
		}
		out = append(out, m)
	}
	return out
}

// nomeArquivo repete a regra de nomeação do pacote preserve — de propósito: se
// ela mudar, este teste falha e o operador descobre pelo teste, não no meio de
// um incidente procurando um arquivo que trocou de nome.
func nomeArquivo(p string) string {
	s := strings.TrimPrefix(p, "/")
	s = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '.', r == '-', r == '_':
			return r
		}
		return '_'
	}, s)
	return s + ".bin"
}

// As recusas da captura. Cada uma protege contra um arquivo que ninguém
// conseguiria interpretar depois — ou que ninguém deveria ter gravado.
func TestCapturaRecusaPedidoAmbiguo(t *testing.T) {
	casos := []struct {
		nome string
		f    func() (*pcap.Opcoes, int)
	}{
		{"--pcap sem --iface", func() (*pcap.Opcoes, int) {
			return montarCaptura(true, "", "", 0, "", true, time.Second, 0, "256M")
		}},
		{"--iface sem --pcap", func() (*pcap.Opcoes, int) {
			return montarCaptura(false, "lo", "", 0, "", false, time.Second, 0, "256M")
		}},
		{"sem filtro e sem --all", func() (*pcap.Opcoes, int) {
			return montarCaptura(true, "lo", "", 0, "", false, time.Second, 0, "256M")
		}},
		{"--all junto com filtro", func() (*pcap.Opcoes, int) {
			return montarCaptura(true, "lo", "", 443, "", true, time.Second, 0, "256M")
		}},
		{"protocolo que não sei decidir", func() (*pcap.Opcoes, int) {
			return montarCaptura(true, "lo", "", 0, "sctp", false, time.Second, 0, "256M")
		}},
		{"nome no lugar de endereço", func() (*pcap.Opcoes, int) {
			return montarCaptura(true, "lo", "evil.example.com", 0, "", false, time.Second, 0, "256M")
		}},
		{"porta fora da faixa", func() (*pcap.Opcoes, int) {
			return montarCaptura(true, "lo", "", 70000, "", false, time.Second, 0, "256M")
		}},
		{"sem prazo", func() (*pcap.Opcoes, int) {
			return montarCaptura(true, "lo", "", 443, "", false, 0, 0, "256M")
		}},
		{"teto sem sentido", func() (*pcap.Opcoes, int) {
			return montarCaptura(true, "lo", "", 443, "", false, time.Second, 0, "muito")
		}},
	}
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			var o *pcap.Opcoes
			var code int
			semSaida(t, func() int { o, code = c.f(); return 0 })
			if code != 3 {
				t.Errorf("code = %d, queria 3 (ERROR de invocação)", code)
			}
			if o != nil {
				t.Error("uma invocação recusada não pode devolver captura montada")
			}
		})
	}
}

// O pedido bem formado chega inteiro do outro lado — inclusive o `--all`, que
// existe para que capturar TUDO seja uma decisão escrita, e não um padrão.
func TestCapturaMontaOQueFoiPedido(t *testing.T) {
	o, code := montarCaptura(true, "eth0", "198.51.100.241", 443, "tcp", false, 30*time.Second, 96, "1G")
	if code != 0 || o == nil {
		t.Fatalf("code = %d", code)
	}
	if o.Iface != "eth0" || o.Snaplen != 96 || o.Duracao != 30*time.Second || o.MaxBytes != 1<<30 {
		t.Errorf("opções = %+v", o)
	}
	if d := o.Filtro.Descricao(); d != "host 198.51.100.241 E porta 443 E protocolo tcp" {
		t.Errorf("filtro = %q", d)
	}

	tudo, code := montarCaptura(true, "eth0", "", 0, "", true, time.Minute, 0, "256M")
	if code != 0 || !tudo.Filtro.Vazio() {
		t.Errorf("--all deveria montar captura sem filtro: %+v code=%d", tudo, code)
	}
}

// O diretório de evidência fica no host sob investigação. Um adversário pode
// plantar o nome do manifesto como symlink antes da coleta; sem O_NOFOLLOW o
// append iria para o alvo do link, fora do --out. anexar tem de recusar e não
// tocar no alvo.
func TestManifestoRecusaSymlinkPlantado(t *testing.T) {
	dir := t.TempDir()
	alvo := filepath.Join(dir, "fora.txt")
	if err := os.WriteFile(alvo, []byte("original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "aletheia-manifest.jsonl")
	if err := os.Symlink(alvo, link); err != nil {
		t.Fatal(err)
	}
	if err := anexar(link, &preserve.Coletor{}); err == nil {
		t.Error("anexar seguiu um symlink plantado — devia recusar (O_NOFOLLOW)")
	}
	if b, _ := os.ReadFile(alvo); string(b) != "original\n" {
		t.Errorf("o alvo do symlink foi escrito através do link: %q", b)
	}
}

// O PRODUTO ESTOURAVA E O ESTOURO APAGAVA O TETO.
//
// `--pcap-max 9223372036854G` fazia n*mult passar de MaxInt64 e voltar
// NEGATIVO. O consumidor confere `o.MaxBytes > 0` antes de aplicar o teto,
// então um número negativo não é um teto pequeno: é teto NENHUM, numa captura
// que grava tráfego bruto em disco até o disco acabar.
func TestTamanhoRecusaEmVezDeEstourar(t *testing.T) {
	casos := []struct {
		entrada string
		quer    int64
		ok      bool
	}{
		{"64M", 64 << 20, true},
		{"1G", 1 << 30, true},
		{"1024", 1024, true},
		// O estouro, nas três unidades.
		{"9223372036854G", 0, false},
		{"9223372036854776K", 0, false},
		{"99999999999999999999M", 0, false},
		// E o maior valor que ainda cabe continua aceito: recusar demais seria
		// trocar um defeito por outro.
		{"8589934591G", 8589934591 << 30, true},
		{"0", 0, false},
		{"-1G", 0, false},
		{"", 0, false},
		{"abc", 0, false},
	}
	for _, c := range casos {
		got, ok := tamanho(c.entrada)
		if ok != c.ok || (ok && got != c.quer) {
			t.Errorf("tamanho(%q) = %d,%v; quer %d,%v", c.entrada, got, ok, c.quer, c.ok)
		}
		if got < 0 {
			t.Errorf("tamanho(%q) devolveu NEGATIVO (%d): o consumidor lê isso "+
				"como ausência de teto", c.entrada, got)
		}
	}
}

// O SNAPLEN VIRAVA UMA ALOCAÇÃO DIRETA.
//
// `buf := make([]byte, snap)` com o que o operador digitasse: `--snaplen
// 2000000000` pedia 2 GB de uma vez. E o cabeçalho pcap guarda o snaplen num
// uint32, então acima do teto o arquivo declararia um corte que não foi o
// corte — um pcap com o rótulo errado é decodificado com confiança total a
// partir do byte errado.
func TestSnaplenForaDaFaixaEhRecusado(t *testing.T) {
	casos := []struct {
		snaplen int
		quer    int
	}{
		{0, 0},                   // pacote inteiro
		{1500, 0},                // típico
		{pcap.MaxSnaplen, 0},     // o limite exato passa
		{pcap.MaxSnaplen + 1, 3}, // um a mais não
		{2000000000, 3},          // os 2 GB
		{-1, 3},
	}
	for _, c := range casos {
		_, code := montarCaptura(true, "lo", "", 0, "", true, time.Second, c.snaplen, "64M")
		if code != c.quer {
			t.Errorf("--snaplen %d: código %d, quer %d", c.snaplen, code, c.quer)
		}
	}
}
