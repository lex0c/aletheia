package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/dump"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
	"github.com/lex0c/aletheia/internal/info"
	"github.com/lex0c/aletheia/internal/report"
)

// runInfo responde sobre UM alvo, e não sobre o host.
//
// O `scan` responde "isto está comprometido?". Esta é a pergunta que aparece
// ANTES, dezenas de vezes por incidente: *o que é este pid, este IP, esta porta,
// este arquivo?* Hoje ela se responde encadeando `ps`, `ss`, `lsof`, `stat`,
// `getcap`, `lsattr` e `dpkg -S`, e cruzando a saída na cabeça.
//
// O que este comando entrega que a saída crua não entrega:
//
//	junta        os mesmos fatos que os checks usam, já cruzados entre si
//	interpreta   cada número vem com o que ele SIGNIFICA, e com a §ref
//	compara      teto de processos, dono de pacote, exposição da porta
//	continua     os comandos seguintes já preenchidos com o alvo
//
// Ele não conclui nada: não há severidade, não há veredito. Para isso existe o
// `scan`, que traz os falsos positivos junto — e é essa separação que impede um
// dossiê de virar acusação.
func runInfo(args []string) int {
	fs := flag.NewFlagSet("info", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		de      = fs.String("from", "", "responder sobre um retrato (o arquivo do collect)")
		root    = fs.String("root", "", "responder sobre uma imagem montada em PATH")
		jsonOut = fs.String("json", "", "o mesmo dossiê em JSON ('-' = stdout)")
	)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	if err := fs.Parse(args); err != nil {
		return 3
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "info: diga sobre o quê — process, ip, port ou file")
		fmt.Fprintln(os.Stderr, "  aletheia info process        censo: quem roda o quê, e contra que teto")
		fmt.Fprintln(os.Stderr, "  aletheia info process 812")
		fmt.Fprintln(os.Stderr, "  aletheia info ip 51.91.190.241")
		fmt.Fprintln(os.Stderr, "  aletheia info port 4100")
		fmt.Fprintln(os.Stderr, "  aletheia info file /usr/sbin/nginx")
		return 3
	}
	assunto := rest[0]
	alvo := ""
	if len(rest) > 1 {
		alvo = rest[1]
	}

	f, e, code := fatosParaInfo(*de, *root, assunto)
	if code != 0 {
		return code
	}
	defer e.Close()

	// Com --json -, o JSON é o produto do stdout e o texto vai para stderr: é a
	// mesma convenção do scan, e é o que faz `info … --json - > x.json` produzir
	// um arquivo válido.
	w := io.Writer(os.Stdout)
	if *jsonOut == "-" {
		w = os.Stderr
	}
	fmt.Fprintf(w, "%s · %s · %s\n\n",
		report.Safe(nz(f.Host.Hostname, "host-desconhecido")),
		report.Safe(nz(f.CollectedAt, "sem data")), f.Source)

	switch assunto {
	case "process", "processo", "proc":
		if alvo == "" {
			c := info.Censo(f)
			escreverCenso(w, c)
			return comJSON(*jsonOut, c, 0)
		}
		pid, err := strconv.Atoi(alvo)
		if err != nil {
			fmt.Fprintf(os.Stderr, "info process: %q não é um pid\n", alvo)
			return 3
		}
		return dossie(w, *jsonOut, info.Processo(f, pid))
	case "ip", "addr", "endereco", "endereço":
		if alvo == "" {
			fmt.Fprintln(os.Stderr, "info ip: informe o endereço")
			return 3
		}
		return dossie(w, *jsonOut, info.IP(f, alvo))
	case "port", "porta":
		n, err := strconv.Atoi(alvo)
		if err != nil || n < 0 || n > 65535 {
			fmt.Fprintf(os.Stderr, "info port: %q não é uma porta\n", alvo)
			return 3
		}
		return dossie(w, *jsonOut, info.Porta(f, n))
	case "file", "arquivo", "path":
		if alvo == "" {
			fmt.Fprintln(os.Stderr, "info file: informe o caminho")
			return 3
		}
		return dossie(w, *jsonOut, info.Arquivo(f, alvo))
	}
	fmt.Fprintf(os.Stderr, "info: assunto desconhecido %q — use process, ip, port ou file\n", assunto)
	return 3
}

// fatosParaInfo escolhe a coleta pelo que a pergunta precisa.
//
// `process`, `ip` e `port` se respondem com /proc e sockets, que é a coleta
// BARATA — nove vezes mais rápida que a completa. Só `file` precisa da varredura
// de filesystem, porque a pergunta dele é sobre pacote, hash e permissão.
//
// A diferença aparece no relógio de quem está no meio do incidente: perguntar
// sobre um pid não pode custar o mesmo que uma varredura inteira.
func fatosParaInfo(de, root, assunto string) (*facts.Facts, *env.Env, int) {
	if de != "" {
		d, err := dump.Carregar(de)
		if err != nil {
			fmt.Fprintf(os.Stderr, "info --from: %v\n", err)
			return nil, nil, 3
		}
		e, err := d.Env(nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "info: %v\n", err)
			return nil, nil, 3
		}
		return d.Facts, e, 0
	}
	if root != "" {
		if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
			fmt.Fprintf(os.Stderr, "--root: %s não é um diretório acessível\n", root)
			return nil, nil, 3
		}
	}
	e := env.Probe(env.Options{Root: root, Version: version})
	if precisaDeDisco(assunto) || root != "" {
		return facts.Collect(e), e, 0
	}
	f := facts.CollectVolatile(e)
	// O passwd é a única coisa de disco que a resposta barata precisa: sem ele o
	// censo imprime "uid 1000" onde o operador espera "node" — que é o nome que
	// ele digitou no comando que falhou.
	f.Accounts = facts.NomesDeUsuario(e)
	return f, e, 0
}

func precisaDeDisco(assunto string) bool {
	switch assunto {
	case "file", "arquivo", "path":
		return true
	}
	return false
}

// escreverCenso imprime o retrato de quem está rodando o quê.
//
// A ordem é a da urgência: quem estourou o teto primeiro, porque é ele que está
// impedindo o próximo `su`, o próximo deploy e o próximo shell de root.
func escreverCenso(w io.Writer, c *info.CensoDeProcessos) {
	fmt.Fprintf(w, "CENSO · %d processos · %d tarefas (processos + threads)\n\n",
		c.Processos, c.Tarefas)

	fmt.Fprintf(w, "  %-22s %8s %8s %10s\n", "usuário", "proc", "tarefas", "teto")
	for _, u := range c.Usuarios {
		teto := "—"
		switch {
		case !u.TetoLido:
			teto = "não lido"
		case u.Teto < 0:
			teto = "sem limite"
		case u.Teto > 0:
			teto = strconv.Itoa(u.Teto)
		}
		marca := ""
		switch {
		case u.Estourou():
			marca = "  ⛔ NO TETO — fork e execve deste uid falham com EAGAIN"
		case u.Perto():
			marca = "  ⚠ a menos de 10% do teto"
		}
		fmt.Fprintf(w, "  %-22s %8d %8d %10s%s\n",
			report.Safe(corta1(u.Nome, 22)), u.Processos, u.Tarefas, teto, marca)
	}
	fmt.Fprintln(w)

	// O detalhe só do usuário que interessa: quem estourou, quem está perto, ou
	// o maior. Despejar o de todos transformaria a resposta numa parede.
	if u, ok := usuarioQueInteressa(c); ok {
		fmt.Fprintf(w, "O QUE %s ESTÁ RODANDO\n", strings.ToUpper(report.Safe(u.Nome)))
		escreverContagens(w, "por executável REAL", u.PorExecutavel)
		escreverContagens(w, "por linha de comando", u.PorComando)
		escreverContagens(w, "por processo pai", u.PorPai)
		escreverContagens(w, "por estado", u.PorEstado)
		if u.Zumbis > 0 {
			fmt.Fprintf(w, "    %d zumbi(s): terminaram e o pai não os colheu — "+
				"eles continuam contando para o teto\n", u.Zumbis)
		}
		fmt.Fprintln(w)
	}

	for _, p := range c.Padroes {
		fmt.Fprintf(w, "PADRÃO RECONHECIDO — %s · %d cópias\n", strings.ToUpper(p.Tipo), p.N)
		fmt.Fprintf(w, "  %s\n", report.Safe(p.Alvo))
		fmt.Fprintf(w, "  %s\n\n", report.Safe(p.Detalhe))
	}

	if temEstouro(c) {
		fmt.Fprintln(w, "NÃO aumente o teto antes de saber quem o consumiu: num host")
		fmt.Fprintln(w, "suspeito, subir o limite é dar mais munição a quem o está enchendo.")
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, "Isto é um retrato, não um veredito: `aletheia scan` é quem conclui,")
	fmt.Fprintln(w, "e traz os falsos positivos de cada achado junto.")
}

func escreverContagens(w io.Writer, titulo string, cs []info.Contagem) {
	if len(cs) == 0 {
		return
	}
	fmt.Fprintf(w, "  %s\n", titulo)
	for _, c := range cs {
		fmt.Fprintf(w, "    %6d  %s\n", c.N, report.Safe(corta1(c.Rotulo, 96)))
	}
}

func escreverDossie(w io.Writer, d *info.Dossie) int {
	fmt.Fprintf(w, "%s\n\n", report.Safe(d.Alvo))
	for _, b := range d.Blocos {
		fmt.Fprintf(w, "%s\n", b.Titulo)
		for _, l := range b.Linhas {
			fmt.Fprintf(w, "  %-20s %s\n", report.Safe(corta1(l.Rotulo, 20)),
				report.Safe(corta1(l.Valor, 92)))
			if l.Nota != "" {
				fmt.Fprintf(w, "  %-20s   %s\n", "", report.Safe(l.Nota))
			}
		}
		fmt.Fprintln(w)
	}
	if len(d.Sinais) > 0 {
		fmt.Fprintln(w, "O QUE PEDE OLHAR")
		for _, s := range d.Sinais {
			fmt.Fprintf(w, "  · %s\n", report.Safe(s))
		}
		fmt.Fprintln(w)
	}
	if len(d.Proximo) > 0 {
		fmt.Fprintln(w, "EM SEGUIDA")
		for _, s := range d.Proximo {
			fmt.Fprintf(w, "  %s\n", report.Safe(s))
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintln(w, "Isto é um retrato, não um veredito: `aletheia scan` é quem conclui.")
	// Alvo que não existe nos fatos sai com 1, para o script de quem encadeia
	// poder ramificar. Não é erro — é a resposta "não achei", e ela está escrita.
	if !d.Achou {
		return 1
	}
	return 0
}

func usuarioQueInteressa(c *info.CensoDeProcessos) (info.UsuarioNoCenso, bool) {
	if len(c.Usuarios) == 0 {
		return info.UsuarioNoCenso{}, false
	}
	return c.Usuarios[0], true
}

func temEstouro(c *info.CensoDeProcessos) bool {
	for _, u := range c.Usuarios {
		if u.Estourou() || u.Perto() {
			return true
		}
	}
	return false
}

func corta1(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func nz(s, padrao string) string {
	if s == "" {
		return padrao
	}
	return s
}

// dossie imprime o texto e, quando pedido, o mesmo conteúdo em JSON.
func dossie(w io.Writer, jsonOut string, d *info.Dossie) int {
	code := escreverDossie(w, d)
	return comJSON(jsonOut, d, code)
}

// comJSON emite a resposta legível por máquina. O código de saída não muda por
// causa dela: um dossiê que não achou o alvo continua saindo 1, com ou sem JSON.
func comJSON(destino string, v any, code int) int {
	if destino == "" {
		return code
	}
	saida := io.Writer(os.Stdout)
	if destino != "-" {
		fh, err := openJSONOut(destino)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 3
		}
		defer fh.Close()
		saida = fh
	}
	// UMA LINHA, como todo o resto da saída de máquina desta ferramenta. JSON
	// indentado quebraria o contrato de JSONL que a agregação de frota consome —
	// e foi assim que a suíte pegou isto.
	enc := json.NewEncoder(saida)
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(os.Stderr, "info: erro ao escrever JSON: %v\n", err)
		return 3
	}
	return code
}
