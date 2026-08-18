package info

import (
	"sort"
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/facts"
	"github.com/lex0c/aletheia/internal/redact"
)

// nomeDoUID resolve o número para nome usando as contas já coletadas. Sem
// palpite: uid que não está no passwd sai como número, porque inventar um nome
// para ele seria a única parte errada de um relatório correto.
func nomeDoUID(f *facts.Facts, uid int) string {
	for i := range f.Accounts {
		if f.Accounts[i].UID == uid {
			return f.Accounts[i].Name
		}
	}
	if uid == 0 {
		return "root"
	}
	return "uid " + strconv.Itoa(uid)
}

// linhaCurta é a linha de comando REDIGIDA e encurtada, para agrupar sem
// vazar segredo e sem quebrar o alinhamento.
//
// A redação vem antes do corte: `mysqldump -pS3cr3t` truncado ainda mostraria a
// senha se o corte caísse depois dela.
func linhaCurta(p *facts.Process) string {
	if len(p.Argv) == 0 {
		if p.Comm != "" {
			return "[" + p.Comm + "]"
		}
		return "(sem cmdline)"
	}
	s := strings.Join(redact.Cmdline(p.Argv), " ")
	if len(s) > 90 {
		s = s[:87] + "…"
	}
	return s
}

// descreverPai nomeia o processo pai, porque um PPID sozinho não diz nada a
// quem está lendo com pressa.
func descreverPai(f *facts.Facts, ppid int) string {
	if ppid == 0 {
		return "pid=0 (kernel)"
	}
	if p := f.ProcessByPID(ppid); p != nil {
		return "pid=" + strconv.Itoa(ppid) + " (" + nz(p.Comm, "?") + ")"
	}
	// Pai que não está na lista é pai que MORREU: os filhos foram adotados pelo
	// init, e a linhagem original se perdeu. É informação, não lacuna.
	return "pid=" + strconv.Itoa(ppid) + " (já não existe)"
}

func topN(m map[string]int, n int) []Contagem {
	out := make([]Contagem, 0, len(m))
	for k, v := range m {
		out = append(out, Contagem{Rotulo: k, N: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].N != out[j].N {
			return out[i].N > out[j].N
		}
		return out[i].Rotulo < out[j].Rotulo
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func nz(s, padrao string) string {
	if s == "" {
		return padrao
	}
	return s
}
