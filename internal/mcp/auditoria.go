package mcp

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// A trilha de auditoria: uma linha JSON por invocação, em stderr.
//
// # Por que stderr, e por que não em arquivo por padrão
//
// A 2026-07-28 DEPRECOU o recurso Logging do protocolo, e a migração que ela
// mesma documenta é "log to stderr (stdio)". Então isto deixou de ser
// gambiarra e virou o mecanismo indicado. O transporte já reserva stderr para
// exatamente isso: o servidor MAY escrever ali, e o cliente NÃO deve tratar
// saída em stderr como sinal de erro.
//
// Em arquivo, só com `--audit-log`. O README promete que `preserve` é o ÚNICO
// comando que escreve, e uma trilha que nasce criando arquivo no host
// investigado quebraria a promessa em silêncio — durante um incidente, num
// diretório que o investigador não escolheu.
//
// O que ela registra é a atividade do AGENTE, que numa resposta a incidente é
// evidência por si: quem perguntou o quê, quando, sobre qual retrato — o método,
// a TOOL e o snapshot_id que a chamada citou. Ela NÃO registra argumento nem
// resultado — argumento pode conter caminho e resultado
// contém dado do host, e a trilha viraria uma segunda cópia não redigida do
// que o servidor acabou de proteger.
type Auditoria struct {
	mu      sync.Mutex
	w       io.Writer
	seq     int
	Relogio func() time.Time
}

func NovaAuditoria(w io.Writer) *Auditoria {
	if w == nil {
		return nil
	}
	return &Auditoria{w: w, Relogio: time.Now}
}

type linhaAuditoria struct {
	Seq    int    `json:"seq"`
	Em     string `json:"at"`
	Metodo string `json:"method"`
	// Alvo é o QUE foi perguntado: o nome da tool e o retrato que a chamada
	// citou. Sem ele toda invocação saía como a constante "tools/call", e a
	// trilha respondia uma das três perguntas que promete — a menos útil.
	Alvo      string `json:"target,omitempty"`
	Status    string `json:"status,omitempty"`
	DuracaoMs int64  `json:"duration_ms,omitempty"`
	Bytes     int    `json:"result_bytes,omitempty"`
	Erro      string `json:"error,omitempty"`
}

func (a *Auditoria) agora() time.Time {
	if a.Relogio != nil {
		return a.Relogio()
	}
	return time.Now()
}

func (a *Auditoria) escrever(l linhaAuditoria) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.seq++
	l.Seq = a.seq
	l.Em = a.agora().UTC().Format(time.RFC3339)
	b, err := json.Marshal(l)
	if err != nil {
		return
	}
	// Falha ao auditar NÃO derruba o servidor nem vira erro de protocolo: o
	// stderr pode estar fechado ou cheio, e perder a trilha é ruim; perder a
	// investigação por causa dela é pior.
	_, _ = a.w.Write(append(b, '\n'))
}

// Comeco marca o início e devolve o fecho. Nil-safe: um servidor sem auditoria
// devolve um fecho que não faz nada, e quem chama não precisa saber.
func (a *Auditoria) Comeco(metodo string) func(alvo, status string, bytes int) {
	if a == nil {
		return func(string, string, int) {}
	}
	t0 := a.agora()
	return func(alvo, status string, bytes int) {
		a.escrever(linhaAuditoria{
			Metodo: metodo, Alvo: alvo, Status: status, Bytes: bytes,
			DuracaoMs: a.agora().Sub(t0).Milliseconds(),
		})
	}
}

func (a *Auditoria) Notificacao(metodo string) {
	if a == nil {
		return
	}
	a.escrever(linhaAuditoria{Metodo: metodo, Status: "notification"})
}

func (a *Auditoria) Falha(metodo string, err error) {
	if a == nil {
		return
	}
	a.escrever(linhaAuditoria{Metodo: metodo, Status: "transport_error", Erro: err.Error()})
}
