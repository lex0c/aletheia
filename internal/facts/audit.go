package facts

import (
	"strings"

	"github.com/lex0c/aletheia/internal/env"
)

// Capacidade forense do host (runbook §21, §13).
//
// Esta não é uma pergunta sobre ataque. É a pergunta que vem ANTES de todas as
// outras numa resposta a incidente:
//
//	este host consegue dizer o que foi executado antes desta varredura?
//
// Sem regra de auditoria carregada, o kernel não emite registro de execução
// nenhum. Não é uma defesa a menos — é a investigação ficando cega para todo o
// passado, e é a diferença entre reconstruir o incidente e adivinhá-lo.
//
// E há a forma deliberada, que é achado de verdade: auditoria instalada,
// configurada, e DESLIGADA. Quem apaga a própria trilha começa por aqui, porque
// é o único lugar de onde a trilha nasce.
//
// Tudo em disco, e nada exige o binário do host:
//
//	/etc/audit/rules.d/*.rules   as regras que o auditd carrega no boot
//	/etc/audit/audit.rules       a forma antiga, arquivo único
//	/etc/audit/auditd.conf       existe = o pacote está instalado
//	unit e processo              já coletados, dizem se ele está de pé

// Auditoria descreve o que o host consegue registrar.
type Auditoria struct {
	// Instalada é verdade quando há configuração em disco. Um host sem isso
	// nunca teve auditoria, e isso é diferente de tê-la perdido.
	Instalada bool `json:"installed"`

	// Regras são as linhas de regra encontradas, já sem comentário.
	Regras []RegraAudit `json:"rules,omitempty"`

	// Desligada marca a diretiva `-e 0`, que desabilita o subsistema inteiro
	// mesmo com regras carregadas. É a forma mais silenciosa de desligar:
	// os arquivos continuam lá e nada é registrado.
	Desligada bool `json:"disabled,omitempty"`

	// CobreExec diz se alguma regra registra execução. É a única cobertura que
	// importa para reconstruir o que rodou.
	CobreExec bool `json:"covers_exec,omitempty"`
}

// RegraAudit é uma linha de regra, com o arquivo de onde veio.
type RegraAudit struct {
	Arquivo string `json:"file"`
	Linha   int    `json:"line"`
	Texto   string `json:"text"`
}

func collectAuditoria(f *Facts, e *env.Env) {
	arquivos := []string{"/etc/audit/audit.rules"}
	for _, n := range e.ReadDirNames("/etc/audit/rules.d") {
		if strings.HasSuffix(n, ".rules") {
			arquivos = append(arquivos, "/etc/audit/rules.d/"+n)
		}
	}

	a := &f.Audit
	a.Instalada = e.Exists("/etc/audit/auditd.conf") || e.IsDir("/etc/audit/rules.d")

	for _, p := range arquivos {
		b, err := e.ReadFile(p)
		if err != nil {
			continue
		}
		a.Instalada = true
		for i, raw := range strings.Split(string(b), "\n") {
			ln := strings.TrimSpace(raw)
			if ln == "" || strings.HasPrefix(ln, "#") {
				continue
			}
			a.Regras = append(a.Regras, RegraAudit{Arquivo: p, Linha: i + 1, Texto: ln})

			// `-e 0` desabilita o subsistema inteiro. Os arquivos continuam no
			// lugar, as regras continuam escritas, e nada é registrado — é a
			// forma que sobrevive a quem só verifica se a configuração existe.
			if campos := strings.Fields(ln); len(campos) >= 2 &&
				campos[0] == "-e" && campos[1] == "0" {
				a.Desligada = true
			}
			if regraCobreExec(ln) {
				a.CobreExec = true
			}
		}
	}
}

// regraCobreExec diz se a linha registra EXECUÇÃO.
//
// É a única cobertura que interessa para reconstruir o que rodou: uma regra que
// vigia só escrita em arquivo não responde "o que foi executado", e um host com
// dez regras e nenhuma de exec é tão cego quanto um sem regra nenhuma.
func regraCobreExec(ln string) bool {
	if !strings.Contains(ln, "-S ") && !strings.Contains(ln, "-F exe=") {
		return false
	}
	for _, s := range []string{"execve", "execveat", "-F exe="} {
		if strings.Contains(ln, s) {
			return true
		}
	}
	return false
}
