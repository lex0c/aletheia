package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/preserve"
	"github.com/lex0c/aletheia/internal/report"
)

// runPreserve é o único comando desta ferramenta que ESCREVE.
//
// Ele existe porque o relatório manda preservar dezenas de vezes e o operador
// montava o comando na mão — no meio do incidente, que é exatamente quando a
// janela se perde. A §19 é explícita: matar o processo destrói a única cópia de
// um binário em memfd ou já apagado.
//
// As travas vêm antes de qualquer leitura: sem `--out` nada acontece, o
// diretório precisa existir, e nada é sobrescrito.
func runPreserve(args []string) int {
	fs := flag.NewFlagSet("preserve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		out     = fs.String("out", "", "diretório onde escrever (obrigatório)")
		mem     = fs.Bool("mem", false, "dump das regiões ANÔNIMAS dos --pid informados")
		maxMem  = fs.String("mem-max", "512M", "teto do dump de memória (ex.: 512M, 2G)")
		jsonOut = fs.String("json", "", "manifesto em JSONL ('-' = stdout)")
		pids    listaFlag
		files   listaFlag
		bpfs    listaFlag
	)
	fs.Var(&pids, "pid", "processo cujo exe preservar (pode repetir)")
	fs.Var(&files, "file", "arquivo a preservar (pode repetir)")
	fs.Var(&bpfs, "bpf", "id de programa eBPF cujo bytecode preservar (pode repetir)")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(args); err != nil {
		return 3
	}

	if *out == "" {
		fmt.Fprintln(os.Stderr, "preserve: --out é obrigatório. Esta é a única "+
			"parte da ferramenta que escreve, e ela não escolhe onde")
		return 3
	}
	if len(pids)+len(files)+len(bpfs) == 0 {
		fmt.Fprintln(os.Stderr, "preserve: informe ao menos um alvo "+
			"(--pid, --file ou --bpf)")
		return 3
	}

	e := env.Probe(env.Options{Version: version})
	defer e.Close()

	c, err := preserve.Novo(*out, e)
	if err != nil {
		fmt.Fprintf(os.Stderr, "preserve: %v: %s\n", err, *out)
		return 3
	}
	if n, ok := tamanho(*maxMem); ok {
		c.MaxMem = n
	} else {
		fmt.Fprintf(os.Stderr, "preserve: --mem-max não entendido: %q\n", *maxMem)
		return 3
	}

	// A ORDEM é a da §19: primeiro o que morre com o processo, depois o que
	// morre com o boot, por último o que está em disco e não vai a lugar nenhum.
	for _, p := range pids {
		n, err := strconv.Atoi(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "preserve: --pid %q não é um número\n", p)
			return 3
		}
		_ = c.Exe(n)
		if *mem {
			_ = c.Memoria(n)
		}
	}
	for _, b := range bpfs {
		n, err := strconv.ParseUint(b, 10, 32)
		if err != nil {
			fmt.Fprintf(os.Stderr, "preserve: --bpf %q não é um id\n", b)
			return 3
		}
		_ = c.BPF(uint32(n))
	}
	for _, p := range files {
		_ = c.Arquivo(p)
	}

	humano := io.Writer(os.Stdout)
	if *jsonOut == "-" {
		humano = os.Stderr
	}
	escreverManifesto(humano, c, *out)

	// O manifesto vai para DENTRO do diretório de evidência sempre, tenha ou não
	// alguém pedido `--json`.
	//
	// Sem isso a cadeia de custódia moraria no terminal: o operador levaria as
	// amostras para a análise e os hashes ficariam na tela que ele fechou. Um
	// diretório de evidência precisa se explicar sozinho — o `--json` é para
	// canalizar a mesma coisa para a automação, não para produzi-la.
	if err := anexar(filepath.Join(*out, "aletheia-manifest.jsonl"), c); err != nil {
		fmt.Fprintf(os.Stderr, "preserve: o manifesto não pôde ser escrito em %s "+
			"(%v): as amostras ficam sem a cadeia de custódia ao lado delas\n", *out, err)
	}
	if err := registrarExecucao(*out, c, e); err != nil {
		fmt.Fprintf(os.Stderr, "preserve: o registro de execução não pôde ser "+
			"escrito (%v): a cadeia de custódia fica sem a linha desta coleta\n", err)
	}
	if *jsonOut != "" {
		if code := manifestoJSONL(*jsonOut, c, e); code != 0 {
			return code
		}
	}

	switch {
	case len(c.Integro()) > 0:
		// O arquivo MUDOU enquanto era lido. Num incidente isso não é falha de
		// cópia: é o alvo se mexendo, e vale o mesmo que um achado crítico.
		return 2
	case len(c.Erros) > 0:
		return 1
	}
	return 0
}

// escreverManifesto é o relatório humano da coleta. O que NÃO foi preservado
// aparece com o mesmo destaque do que foi: uma peça que ficou de fora em
// silêncio é a pior saída possível de uma coleta de evidência.
func escreverManifesto(w io.Writer, c *preserve.Coletor, dir string) {
	var total int64
	for _, i := range c.Itens {
		total += i.Bytes
	}
	fmt.Fprintf(w, "PRESERVADO em %s · %d peça(s) · %s\n\n",
		report.Safe(dir), len(c.Itens), humanoBytes(total))

	for _, i := range c.Itens {
		origem := i.Origem
		if i.OrigemReal != "" {
			origem += " → " + i.OrigemReal
		}
		fmt.Fprintf(w, "  %-28s %s\n", report.Safe(i.Destino), report.Safe(origem))
		fmt.Fprintf(w, "  %-28s %s · sha256=%s\n", "", humanoBytes(i.Bytes), i.HashOrigem[:16]+"…")
		if i.Nota != "" {
			fmt.Fprintf(w, "  %-28s %s\n", "", report.Safe(i.Nota))
		}
	}

	if len(c.Erros) > 0 {
		fmt.Fprintf(w, "\nNÃO PRESERVADO — isto é lacuna de evidência, não detalhe:\n")
		for _, f := range c.Erros {
			fmt.Fprintf(w, "  %s %s: %s\n", f.Tipo, report.Safe(f.Alvo), report.Safe(f.Motivo))
		}
	}
	if div := c.Integro(); len(div) > 0 {
		fmt.Fprintf(w, "\nO ALVO MUDOU DURANTE A CÓPIA:\n")
		for _, d := range div {
			fmt.Fprintf(w, "  %s\n", report.Safe(d))
		}
		fmt.Fprintln(w, "  num incidente isto não é erro de cópia: é o artefato se mexendo")
	}

	fmt.Fprintf(w, "\nA cadeia de custódia (hash da origem E da cópia) está em "+
		"%s — leve o diretório inteiro.\n",
		report.Safe(filepath.Join(dir, "aletheia-manifest.jsonl")))
	fmt.Fprintf(w, "NADA foi executado, e nada fora de %s foi escrito.\n", report.Safe(dir))
}

// manifestoJSONL escreve o manifesto legível por máquina — o mesmo contrato do
// JSONL do scan: uma linha por peça, mais as lacunas.
func manifestoJSONL(path string, c *preserve.Coletor, e *env.Env) int {
	w := io.Writer(os.Stdout)
	if path != "-" {
		fh, err := os.Create(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "preserve: não foi possível escrever %s: %v\n", path, err)
			return 3
		}
		defer fh.Close()
		w = fh
	}
	return escreverLinhas(w, c)
}

// anexar acrescenta o manifesto ao arquivo do diretório de incidente. É append
// pela mesma razão do run log: um diretório de IR acumula coletas, e a ordem
// delas faz parte da história do caso.
func anexar(path string, c *preserve.Coletor) error {
	fh, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer fh.Close()
	if code := escreverLinhas(fh, c); code != 0 {
		return fmt.Errorf("falha ao codificar o manifesto")
	}
	return nil
}

func escreverLinhas(w io.Writer, c *preserve.Coletor) int {
	enc := json.NewEncoder(w)
	for _, i := range c.Itens {
		if err := enc.Encode(i); err != nil {
			return 3
		}
	}
	// As lacunas saem no mesmo arquivo das peças, e de propósito: quem ler o
	// diretório meses depois precisa ver o que NÃO está ali.
	for _, f := range c.Erros {
		if err := enc.Encode(f); err != nil {
			return 3
		}
	}
	return 0
}

// registrarExecucao acrescenta a linha desta coleta ao log do diretório de
// incidente (SPEC 12.4).
//
// É append: um diretório de IR acumula várias coletas, e a ordem delas é parte
// da história. Sobrescrever apagaria a coleta anterior — o mesmo erro que a
// recusa de sobrescrever amostra evita.
func registrarExecucao(dir string, c *preserve.Coletor, e *env.Env) error {
	fh, err := os.OpenFile(filepath.Join(dir, "aletheia-runs.jsonl"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer fh.Close()

	linha := struct {
		ID        string `json:"id"`
		TS        string `json:"ts"`
		Host      string `json:"host"`
		Cmd       string `json:"cmd"`
		Tool      string `json:"tool"`
		ToolSHA   string `json:"tool_sha256,omitempty"`
		Pecas     int    `json:"items"`
		Bytes     int64  `json:"bytes"`
		Falhas    int    `json:"failed"`
		Divergiu  int    `json:"changed_during_copy"`
		Argumento string `json:"argv"`
	}{
		ID: "run", TS: time.Now().UTC().Format(time.RFC3339),
		Host: hostname(), Cmd: "preserve",
		Tool: "aletheia/" + e.ToolVersion, ToolSHA: e.ToolSHA256,
		Pecas: len(c.Itens), Falhas: len(c.Erros), Divergiu: len(c.Integro()),
		Argumento: strings.Join(os.Args[1:], " "),
	}
	for _, i := range c.Itens {
		linha.Bytes += i.Bytes
	}
	return json.NewEncoder(fh).Encode(linha)
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}

// listaFlag aceita a mesma flag repetida: `--pid 10 --pid 20`.
type listaFlag []string

func (l *listaFlag) String() string     { return strings.Join(*l, ",") }
func (l *listaFlag) Set(v string) error { *l = append(*l, v); return nil }

// tamanho lê "512M", "2G", "1048576".
func tamanho(s string) (int64, bool) {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" {
		return 0, false
	}
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "K"):
		mult, s = 1<<10, s[:len(s)-1]
	case strings.HasSuffix(s, "M"):
		mult, s = 1<<20, s[:len(s)-1]
	case strings.HasSuffix(s, "G"):
		mult, s = 1<<30, s[:len(s)-1]
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n * mult, true
}

func humanoBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return strconv.FormatFloat(float64(n)/(1<<30), 'f', 1, 64) + " GB"
	case n >= 1<<20:
		return strconv.FormatFloat(float64(n)/(1<<20), 'f', 1, 64) + " MB"
	case n >= 1<<10:
		return strconv.FormatFloat(float64(n)/(1<<10), 'f', 1, 64) + " KB"
	}
	return strconv.FormatInt(n, 10) + " B"
}
