package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/pcap"
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
	var (
		capturar = fs.Bool("pcap", false, "capturar tráfego para um arquivo .pcap")
		iface    = fs.String("iface", "", "interface da captura (obrigatória com --pcap)")
		host     = fs.String("host", "", "filtro: só o tráfego DESTE endereço")
		porta    = fs.Int("port", 0, "filtro: só esta porta, TCP ou UDP")
		proto    = fs.String("proto", "", "filtro: tcp | udp | icmp")
		tudo     = fs.Bool("all", false, "capturar SEM filtro (pedido explícito)")
		duracao  = fs.Duration("duration", 60*time.Second, "duração da captura")
		snaplen  = fs.Int("snaplen", 0, "bytes por pacote (0 = pacote inteiro)")
		maxPcap  = fs.String("pcap-max", "256M", "teto do arquivo de captura")
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
	if len(pids)+len(files)+len(bpfs) == 0 && !*capturar {
		fmt.Fprintln(os.Stderr, "preserve: informe ao menos um alvo "+
			"(--pid, --file, --bpf ou --pcap)")
		return 3
	}
	// Os alvos são convertidos ANTES de qualquer escrita.
	//
	// Eles eram convertidos dentro do laço que já copiava, então
	// `--pid 100 --pid abc` copiava o exe do 100, batia no "abc" e saía com 3 —
	// deixando um diretório de incidente com peça dentro e SEM manifesto. Numa
	// resposta a incidente, coleta pela metade sem registro é pior que coleta
	// nenhuma: ela parece prova.
	numPids, code := numeros(pids, "--pid")
	if code != 0 {
		return code
	}
	numBPFs, code := numeros(bpfs, "--bpf")
	if code != 0 {
		return code
	}
	opcoesPcap, code := montarCaptura(*capturar, *iface, *host, *porta, *proto,
		*tudo, *duracao, *snaplen, *maxPcap)
	if code != 0 {
		return code
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

	// O tratamento de sinal cobre a coleta INTEIRA, não só a captura.
	//
	// Ele era registrado apenas dentro do ramo do --pcap. Num
	// `preserve --pid 4242 --mem --mem-max 2G` o dump de memória leva minutos, e
	// um Ctrl-C (ou o SIGTERM de um wrapper com timeout) matava o processo no
	// comportamento padrão, ANTES de escreverManifesto: ficavam os .bin no
	// diretório e nenhum aletheia-manifest.jsonl. Os hashes da ORIGEM — que são
	// o que prova que a cópia bate com o alvo, e que só existem na memória deste
	// processo — sumiam para sempre. É o desfecho que este arquivo declara pior
	// que coleta nenhuma.
	interrompido := make(chan struct{})
	sinais := make(chan os.Signal, 1)
	signal.Notify(sinais, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sinais)
	go func() {
		<-sinais
		close(interrompido)
		fmt.Fprintln(os.Stderr, "\npreserve: interrompido — fechando a peça em curso "+
			"e escrevendo o manifesto do que JÁ foi preservado")
	}()
	parou := func() bool {
		select {
		case <-interrompido:
			return true
		default:
			return false
		}
	}

	// A ORDEM é a da §19: primeiro o que morre com o processo, depois o que
	// morre com o boot, por último o que está em disco e não vai a lugar nenhum.
	for _, n := range numPids {
		if parou() {
			break
		}
		_ = c.Exe(int(n))
		if *mem {
			_ = c.Memoria(int(n))
		}
	}
	for _, n := range numBPFs {
		if parou() {
			break
		}
		_ = c.BPF(uint32(n))
	}
	for _, p := range files {
		if parou() {
			break
		}
		_ = c.Arquivo(p)
	}
	// A captura por último, e não por acomodação: ela ESPERA — de segundos a
	// minutos —, e as outras peças morrem se o processo morrer nesse meio tempo.
	if opcoesPcap != nil && !parou() {
		avisoDaCaptura(os.Stderr, *opcoesPcap)
		opcoesPcap.Parar = interrompido
		st, _ := c.PCAP(*opcoesPcap)
		resumoDaCaptura(os.Stderr, st)
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
	case parou():
		// 130 é o que um shell espera de um SIGINT, e o manifesto acima JÁ foi
		// escrito: o que se preservou até aqui tem cadeia de custódia.
		return 130
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
		// openJSONOut e não os.Create: `Create` segue symlink e TRUNCA o alvo.
		// O manifesto é a cadeia de custódia da coleta, e o resto do preserve
		// escreve com O_EXCL e O_NOFOLLOW — não faz sentido que a peça que
		// prova as outras seja a única com a porta aberta.
		fh, err := openJSONOut(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "preserve: %v\n", err)
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
	// O_NOFOLLOW: o diretório de evidência fica no host sob investigação, e um
	// adversário pode plantar este nome como symlink antes da coleta. Sem ele o
	// append iria para o ALVO do link — fora do --out, quebrando a garantia de
	// que nada foi escrito fora dali e a própria cadeia de custódia. As amostras
	// já abrem com O_EXCL|O_NOFOLLOW; o manifesto que as atesta merece o mesmo.
	fh, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
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
	// O_NOFOLLOW pela mesma razão de anexar(): o log de execuções não pode ser
	// desviado para fora do diretório de incidente por um symlink plantado.
	fh, err := os.OpenFile(filepath.Join(dir, "aletheia-runs.jsonl"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY|syscall.O_NOFOLLOW, 0o600)
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

// montarCaptura valida o pedido de captura ANTES de qualquer leitura, e recusa
// as três formas de pedir uma captura que ninguém saberia interpretar depois.
func montarCaptura(ligada bool, iface, host string, porta int, proto string,
	tudo bool, duracao time.Duration, snaplen int, maxBytes string) (*pcap.Opcoes, int) {
	if !ligada {
		if iface != "" || host != "" || porta != 0 || proto != "" || tudo {
			fmt.Fprintln(os.Stderr, "preserve: --iface/--host/--port/--proto/--all "+
				"só fazem sentido com --pcap")
			return nil, 3
		}
		return nil, 0
	}
	if iface == "" {
		fmt.Fprintf(os.Stderr, "preserve --pcap: --iface é obrigatório.\n"+
			"Não há escolha padrão honesta: capturar em \"qualquer interface\" "+
			"mistura enlaces diferentes no mesmo arquivo, e um pcap com o rótulo "+
			"errado é decodificado com confiança total a partir do byte errado.\n"+
			"Interfaces deste host: %s\n", interfacesDoHost())
		return nil, 3
	}
	if err := pcap.ProtoValido(proto); err != nil {
		fmt.Fprintf(os.Stderr, "preserve --pcap: %v\n", err)
		return nil, 3
	}
	if porta < 0 || porta > 65535 {
		fmt.Fprintln(os.Stderr, "preserve --pcap: --port fora da faixa")
		return nil, 3
	}
	if duracao <= 0 {
		fmt.Fprintln(os.Stderr, "preserve --pcap: --duration precisa ser positiva. "+
			"Uma captura sem prazo num incidente é um arquivo que ninguém fecha")
		return nil, 3
	}

	o := &pcap.Opcoes{Iface: iface, Duracao: duracao, Snaplen: snaplen}
	if host != "" {
		a, err := netip.ParseAddr(host)
		if err != nil {
			fmt.Fprintf(os.Stderr, "preserve --pcap: --host %q não é um endereço IP. "+
				"Nome não é aceito de propósito: resolver DNS avisa o atacante\n", host)
			return nil, 3
		}
		o.Filtro.Host = a
	}
	o.Filtro.Porta = porta
	o.Filtro.Proto = proto

	// CAPTURAR TUDO PRECISA SER PEDIDO. Tráfego bruto de um host de produção
	// carrega sessão, cookie e credencial em claro de gente que não é parte do
	// incidente — e o arquivo não tem como ser redigido depois.
	if o.Filtro.Vazio() && !tudo {
		fmt.Fprintln(os.Stderr, "preserve --pcap: sem filtro, esta captura grava "+
			"TODO o tráfego da interface — inclusive credencial em claro de "+
			"terceiros que não são parte do incidente, num arquivo que não tem "+
			"como ser redigido depois.\n"+
			"Diga o que procurar (--host, --port, --proto) ou peça --all explicitamente.")
		return nil, 3
	}
	if !o.Filtro.Vazio() && tudo {
		fmt.Fprintln(os.Stderr, "preserve --pcap: --all com filtro é ambíguo")
		return nil, 3
	}
	n, ok := tamanho(maxBytes)
	if !ok {
		fmt.Fprintf(os.Stderr, "preserve --pcap: --pcap-max não entendido: %q\n", maxBytes)
		return nil, 3
	}
	o.MaxBytes = n
	return o, 0
}

// avisoDaCaptura é impresso ANTES de capturar, e é obrigatório (SPEC 6.3).
//
// As duas frases dizem coisas diferentes e as duas são necessárias: uma sobre o
// que a captura NÃO prova, outra sobre o que ela produz.
func avisoDaCaptura(w io.Writer, o pcap.Opcoes) {
	fmt.Fprintf(w, "CAPTURANDO em %s por %s · %s\n",
		report.Safe(o.Iface), o.Duracao, report.Safe(o.Filtro.Descricao()))
	fmt.Fprintln(w, "  Se houver eBPF hostil em xdp/tc, ESTA CAPTURA MENTE: o pacote é")
	fmt.Fprintln(w, "  escondido antes de chegar ao socket. Captura confiável é")
	fmt.Fprintln(w, "  espelhamento FORA desta máquina.")
	fmt.Fprintln(w, "  O .pcap sai BRUTO: em tráfego sem TLS ele contém credencial em claro.")
	fmt.Fprintln(w, "  Enquanto isto roda, um scan neste host vê um socket AF_PACKET — é este")
	fmt.Fprintln(w, "  processo, e não um sniffer. O modo promíscuo NÃO foi ligado.")
	fmt.Fprintln(w)
}

// interfacesDoHost lista os nomes para a mensagem de erro. Uma recusa que não
// diz quais são as opções manda o operador procurar num host que ele não conhece.
func interfacesDoHost() string {
	ents, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return "(não foi possível listar /sys/class/net)"
	}
	var ns []string
	for _, e := range ents {
		ns = append(ns, e.Name())
	}
	return strings.Join(ns, " ")
}

// resumoDaCaptura diz o que uma contagem sozinha não diz.
//
// Uma captura que gravou zero pacote produz um arquivo de 24 bytes — cabeçalho e
// nada — e o manifesto listaria "1 peça preservada". Lido rápido, isso vira
// "capturei e não houve tráfego". São três coisas diferentes, e o operador
// decide diferente em cada uma:
//
//	nada passou na interface       a conversa não é por aqui, ou a placa é a errada
//	passou e não casou o filtro    o filtro está errado, ou o alvo mudou de porta
//	casou e o kernel descartou     a captura está incompleta, e não passa de novo
func resumoDaCaptura(w io.Writer, st pcap.Estatisticas) {
	if st.Gravados > 0 {
		return
	}
	switch {
	case st.VistosPeloKernel == 0:
		fmt.Fprintln(w, "\nNENHUM pacote passou por esta interface na janela da captura.")
		fmt.Fprintln(w, "  Não é 'nada casou o filtro': não houve tráfego NENHUM aqui.")
		fmt.Fprintln(w, "  Confira a interface — e lembre que sem modo promíscuo só se vê")
		fmt.Fprintln(w, "  o tráfego DESTE host.")
	default:
		fmt.Fprintf(w, "\nZERO pacotes casaram o filtro — %d passaram e foram descartados por ele.\n",
			st.Filtrados)
		fmt.Fprintln(w, "  Isto NÃO é 'não houve tráfego': é 'nada casou o que você pediu'.")
	}
	fmt.Fprintln(w, "  O arquivo tem só o cabeçalho, e isso é resultado — não falha.")
}

// numeros converte os alvos numéricos de uma flag, ou falha antes de a coleta
// escrever qualquer coisa. Ver a chamada: a validação tardia deixava diretório
// de incidente pela metade.
func numeros(vals []string, flag string) ([]uint64, int) {
	out := make([]uint64, 0, len(vals))
	for _, v := range vals {
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			fmt.Fprintf(os.Stderr, "preserve: %s %q não é um número\n", flag, v)
			return nil, 3
		}
		out = append(out, n)
	}
	return out, 0
}
