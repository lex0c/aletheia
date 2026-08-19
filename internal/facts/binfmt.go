package facts

import (
	"os"
	"strings"

	"github.com/lex0c/aletheia/internal/env"
)

// binfmt_misc, dividido em DOIS fatos porque são duas perguntas (runbook §7.12).
//
//	BinfmtRegistro   o kernel está roteando execução AGORA: /proc/sys/fs/binfmt_misc
//	BinfmtConfig     isso VOLTA no próximo boot: /etc/binfmt.d, /usr/lib/binfmt.d
//
// O mecanismo associa uma ASSINATURA (magic ou extensão) a um INTERPRETADOR;
// executar um arquivo que casa faz o kernel invocar o interpretador. QEMU e Wine
// são os usos legítimos, e a documentação do próprio kernel usa o Wine de
// exemplo — por isso o discriminador é sempre de onde vem o interpretador, e não
// o mecanismo.

// BinfmtRegistro é um interpretador registrado e VIVO no kernel.
type BinfmtRegistro struct {
	Nome        string `json:"name"`
	Fonte       string `json:"source"`
	Interpreter string `json:"interpreter,omitempty"`
	// Flags são as letras do registro (POCF…). 'F' importa para a resposta: o
	// interpretador é ABERTO e fixado no momento do registro, então trocar o
	// arquivo em disco depois NÃO muda o que roda — a limpeza do disco não
	// desfaz a persistência.
	Flags string `json:"flags,omitempty"`
	// Magic é a assinatura em hex, quando o registro é por magic. Serve para a
	// pergunta que só ela responde: este registro casa com ELF NATIVO — e
	// portanto sequestra TODA execução do host — ou só com um formato
	// específico, como o QEMU faz.
	Magic    string `json:"magic,omitempty"`
	Extensao string `json:"extension,omitempty"`
	// Habilitado distingue um registro ativo de um desativado. Desativado não
	// roteia agora, mas continua registrado — e some do relatório sem este bit.
	Habilitado bool `json:"enabled"`
	// BPFOps é o nome do conjunto de operações quando o registro é do tipo 'B'
	// (bpf-backed): o kernel escreve "bpf <nome>" e NUNCA escreve
	// "interpreter ". Sem este campo o registro inteiro era descartado dentro
	// do coletor — o kernel roteando execução agora, e a ferramenta em
	// silêncio, sem achado e sem lacuna.
	BPFOps string `json:"bpf_ops,omitempty"`
	// BPFInterpretadores são os caminhos das linhas "bpf-interpreter <nome>
	// <caminho>". São interpretadores tanto quanto o campo Interpreter.
	BPFInterpretadores []string `json:"bpf_interpreters,omitempty"`
	// NaoEntendido marca registro cujo corpo não trouxe nenhum campo de
	// interpretador reconhecido. Guardá-lo é o que impede "não entendi" de
	// virar "não há" quando o formato do arquivo mudar de novo.
	NaoEntendido bool `json:"not_understood,omitempty"`
}

// TemInterpretador diz se o registro nomeia alguém que passa a receber a
// execução, em qualquer das formas que o kernel escreve.
func (r BinfmtRegistro) TemInterpretador() bool {
	return r.Interpreter != "" || len(r.BPFInterpretadores) > 0
}

// Interpretadores devolve TODOS os caminhos que recebem execução por este
// registro. Um registro 'B' pode ligar vários, e cada um é uma porta.
func (r BinfmtRegistro) Interpretadores() []string {
	var out []string
	if r.Interpreter != "" {
		out = append(out, r.Interpreter)
	}
	return append(out, r.BPFInterpretadores...)
}

// BinfmtConfig é o mesmo registro em ARQUIVO, que o systemd-binfmt reaplica no
// boot. Existe em modo image, onde o kernel é o do analista (§35.6).
type BinfmtConfig struct {
	Fonte       string `json:"source"`
	Nome        string `json:"name,omitempty"`
	Interpreter string `json:"interpreter,omitempty"`
	Flags       string `json:"flags,omitempty"`
}

// collectBinfmt lê os registros VIVOS. É /proc, então live-only, e por isso não
// passa pelo env — a persistência equivalente é o collectBinfmtConfig.
//
// O formato é uma linha por campo:
//
//	enabled
//	interpreter /usr/bin/qemu-aarch64-static
//	flags: OCF
//	offset 0
//	magic 7f454c46...
//	mask ffffffff...
func collectBinfmt(f *Facts) {
	const base = "/proc/sys/fs/binfmt_misc"
	ents, err := os.ReadDir(base)
	if err != nil {
		return // não montado: normal em host sem emulação
	}
	for _, ent := range ents {
		nome := ent.Name()
		// register e status são controles do mecanismo, não registros.
		if nome == "register" || nome == "status" || ent.IsDir() {
			continue
		}
		corpo, ok := readTrim(base + "/" + nome)
		if !ok {
			continue
		}
		r := parseBinfmtRegistro(nome, base+"/"+nome, corpo)
		// O registro entra MESMO sem interpretador reconhecido. Descartá-lo
		// convertia "não entendi este corpo" em "não há registro aqui", e o
		// kernel pode estar roteando execução por uma forma que este parser
		// ainda não conhece — foi o que aconteceu com o tipo 'B' (bpf), que
		// escreve "bpf <ops>" e "bpf-interpreter <nome> <caminho>" e nunca
		// escreve "interpreter ".
		if !r.TemInterpretador() {
			r.NaoEntendido = true
			f.partial("binfmt", "o registro binfmt_misc "+nome+" está ATIVO e "+
				"nenhum campo de interpretador dele foi reconhecido: para onde "+
				"ele roteia a execução NÃO foi determinado")
		}
		f.Binfmt = append(f.Binfmt, r)
	}
}

// parseBinfmtRegistro decodifica o corpo de um registro vivo, uma linha por
// campo. Separado para ser testável sem /proc — e porque o `magic` é conteúdo
// binário em hex, não um caminho, e confundi-los seria a armadilha clássica.
func parseBinfmtRegistro(nome, fonte, corpo string) BinfmtRegistro {
	r := BinfmtRegistro{Nome: nome, Fonte: fonte}
	for _, ln := range strings.Split(corpo, "\n") {
		ln = strings.TrimSpace(ln)
		switch ln {
		case "enabled":
			r.Habilitado = true
		case "disabled":
			r.Habilitado = false
		}
		if v, ok := strings.CutPrefix(ln, "interpreter "); ok {
			r.Interpreter = strings.TrimSpace(v)
		}
		// Tipo 'B': "bpf <ops>" seguido de uma ou mais "bpf-interpreter <nome>
		// <caminho>". A ordem do switch importa — "bpf-interpreter " também
		// casaria com o prefixo "bpf ", não fosse o hífen no lugar do espaço.
		if v, ok := strings.CutPrefix(ln, "bpf-interpreter "); ok {
			if _, caminho, achou := strings.Cut(strings.TrimSpace(v), " "); achou {
				if caminho = strings.TrimSpace(caminho); caminho != "" {
					r.BPFInterpretadores = append(r.BPFInterpretadores, caminho)
				}
			}
		} else if v, ok := strings.CutPrefix(ln, "bpf "); ok {
			r.BPFOps = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(ln, "flags:"); ok {
			r.Flags = strings.TrimSpace(v)
		}
		if v, ok := strings.CutPrefix(ln, "magic "); ok {
			r.Magic = strings.ToLower(strings.TrimSpace(v))
		}
		if v, ok := strings.CutPrefix(ln, "extension "); ok {
			r.Extensao = strings.TrimSpace(v)
		}
	}
	return r
}

// dirsBinfmtConfig são os diretórios que o systemd-binfmt aplica no boot. A
// ordem é a de precedência: /etc vence /run vence /usr/lib.
var dirsBinfmtConfig = []string{"/etc/binfmt.d", "/run/binfmt.d", "/usr/lib/binfmt.d"}

// collectBinfmtConfig lê a configuração em DISCO. Cada linha é um registro no
// formato do `register`, com o primeiro caractere como delimitador:
//
//	:qemu-aarch64:M::\x7fELF…:\xff…:/usr/bin/qemu-aarch64-static:OCF
func collectBinfmtConfig(f *Facts, e *env.Env) {
	for _, dir := range dirsBinfmtConfig {
		nomes, err := e.ReadDirNamesErr(dir)
		if env.EhLacuna(err) {
			f.denyPersist("binfmt", dir+" não pôde ser listado ("+env.MotivoDoErro(err)+
				"): a configuração de binfmt do próximo boot NÃO foi lida")
			continue
		}
		for _, nome := range nomes {
			if !strings.HasSuffix(nome, ".conf") {
				continue
			}
			p := dir + "/" + nome
			b, err := e.ReadFile(p)
			if err != nil {
				f.denyPersist("binfmt", p+" ilegível ("+env.MotivoDoErro(err)+")")
				continue
			}
			for _, ln := range strings.Split(string(b), "\n") {
				ln = strings.TrimSpace(ln)
				if ln == "" || strings.HasPrefix(ln, "#") {
					continue
				}
				if c, ok := parseBinfmtLinha(ln); ok {
					c.Fonte = p
					f.BinfmtConfig = append(f.BinfmtConfig, c)
				}
			}
		}
	}
}

// parseBinfmtLinha decodifica uma linha de registro. O PRIMEIRO caractere é o
// delimitador — quase sempre ':' —, e os campos são name:type:offset:magic:
// mask:interpreter:flags.
func parseBinfmtLinha(ln string) (BinfmtConfig, bool) {
	if len(ln) < 2 {
		return BinfmtConfig{}, false
	}
	delim := string(ln[0])
	campos := strings.Split(ln, delim)
	// ["", name, type, offset, magic, mask, interpreter, flags]
	if len(campos) < 7 {
		return BinfmtConfig{}, false
	}
	c := BinfmtConfig{Nome: campos[1], Interpreter: strings.TrimSpace(campos[6])}
	if len(campos) >= 8 {
		c.Flags = strings.TrimSpace(campos[7])
	}
	if c.Interpreter == "" {
		return BinfmtConfig{}, false
	}
	return c, true
}
