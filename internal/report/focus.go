package report

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
)

// O bloco de decisão que vai no TOPO. O relatório era orientado à auditoria —
// tudo com o mesmo peso, e a ação consolidada só depois de 300 linhas. Aqui o
// operador sabe ONDE olhar em cinco segundos: o veredito, os poucos objetos que
// importam (com id local C1/W1), e o que fazer AGORA. O detalhe continua abaixo.

// itemFoco é uma entidade de decisão — um alvo correlacionado ("uma história
// com N sinais") ou um grupo de achados do mesmo check. Ganha um id local para
// o operador poder dizer "olha o C1 e depois o W3".
type itemFoco struct {
	id        string
	sev       check.Severity
	alvo      string   // a entidade: pid, caminho, unit, endpoint
	resumo    string   // a linha-chave de uma linha
	sinais    []string // os checks que sustentam (para o correlacionado)
	n         int      // quantos achados/processos a entidade reúne
	correlato bool
	rebaixado bool     // algum achado veio de binário do host (confiança rebaixada)
	novo      bool     // ausente da baseline: o que MUDOU desde a captura
	fkeys     []string // chaves ESTÁVEIS dos achados deste item (id\x00subject)
}

// chaveFinding é a identidade ESTÁVEL de um achado para cruzar o id local do
// topo (C1/W3) com o membro no -v. Antes o cruzamento era por it.alvo, que num
// grupo não-correlacionado com vários achados é a STRING sintetizada
// "subj1, subj2" — não bate com o Subject de cada membro, e o [W3] sumia no
// detalhe. Aqui a chave é o próprio achado.
func chaveFinding(fd check.Finding) string { return fd.ID + "\x00" + fd.Subject }

func chavesDe(fs []check.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, fd := range fs {
		out = append(out, chaveFinding(fd))
	}
	return out
}

// itensDeFoco monta a lista ordenada de entidades e atribui ids locais por
// severidade (C1.., W1.., M1..). Correlacionados primeiro dentro de cada
// severidade: são as histórias, e é para elas que o operador deve ir.
func itensDeFoco(r *check.Report) ([]itemFoco, map[string]string) {
	grupos, resto := r.Correlate()
	var itens []itemFoco

	for _, g := range grupos {
		ids := idsDistintos(g.Findings)
		var curtos []string
		for _, id := range ids {
			curtos = append(curtos, rotuloCurto(id))
		}
		itens = append(itens, itemFoco{
			sev:       g.Sev(),
			alvo:      g.Subject,
			resumo:    strings.Join(curtos, " + "),
			sinais:    ids,
			n:         len(g.Findings),
			correlato: true,
			rebaixado: algumRebaixado(g.Findings),
			novo:      algumNovo(g.Findings),
			fkeys:     chavesDe(g.Findings),
		})
	}
	for _, g := range check.GroupByIDSev(resto) {
		first := g.First()
		if first.Sev == check.SevInfo {
			continue
		}
		alvo := first.Subject
		if g.N() > 1 {
			alvo = g.Subjects(2)
		}
		itens = append(itens, itemFoco{
			sev:       first.Sev,
			alvo:      nz(alvo, first.ID),
			resumo:    rotuloCurto(first.ID),
			n:         g.N(),
			rebaixado: algumRebaixado(g.Findings),
			novo:      algumNovo(g.Findings),
			fkeys:     chavesDe(g.Findings),
		})
	}

	// Mais severo primeiro; dentro da severidade, correlacionado (história)
	// antes de achado solto, e maior antes de menor.
	sort.SliceStable(itens, func(i, j int) bool {
		if itens[i].sev != itens[j].sev {
			return itens[i].sev > itens[j].sev
		}
		if itens[i].correlato != itens[j].correlato {
			return itens[i].correlato
		}
		return itens[i].n > itens[j].n
	})

	// ids locais por severidade, e o mapa ESTÁVEL achado -> id local, para o -v
	// cruzar cada membro com o topo sem depender da string de apresentação.
	idPorFinding := map[string]string{}
	cont := map[check.Severity]int{}
	for i := range itens {
		letra := letraSev(itens[i].sev)
		cont[itens[i].sev]++
		itens[i].id = letra + strconv.Itoa(cont[itens[i].sev])
		for _, k := range itens[i].fkeys {
			idPorFinding[k] = itens[i].id
		}
	}
	return itens, idPorFinding
}

func algumNovo(fs []check.Finding) bool {
	for _, f := range fs {
		if f.Novo {
			return true
		}
	}
	return false
}

func algumRebaixado(fs []check.Finding) bool {
	for _, f := range fs {
		if f.Downgraded {
			return true
		}
	}
	return false
}

func letraSev(s check.Severity) string {
	switch s {
	case check.SevCritical:
		return "C"
	case check.SevWarn:
		return "W"
	case check.SevManual:
		return "M"
	default:
		return "I"
	}
}

func idsDistintos(fs []check.Finding) []string {
	var out []string
	visto := map[string]bool{}
	for _, f := range fs {
		if !visto[f.ID] {
			visto[f.ID] = true
			out = append(out, f.ID)
		}
	}
	return out
}

// writeSumario é a primeira linha operacional: veredito + contagem + cobertura.
// Sai no TOPO, não no fim — é o que o operador lê primeiro.
//
// NÃO usa o prefixo "RESULT:": esse fica ÚNICO no fim (writeResult), com os
// caveats, e a unicidade dele é uma invariante anti-forja — o alvo não pode
// plantar uma segunda linha "RESULT:" pela evidência. Aqui o veredito aparece
// como palavra em destaque, que serve ao olho sem colidir com aquela linha.
func writeSumario(w io.Writer, t Tema, r *check.Report, mostrarCob bool) {
	crit, warn, manual, _ := r.Counts()
	v := r.Verdict()
	titulo := "== " + v + " =="
	if v == "OK" {
		titulo = t.verde(titulo)
	} else {
		titulo = t.pintaSev(sevDoVerdict(v), titulo)
	}
	fmt.Fprintln(w, titulo)
	cov := r.Coverage
	linha := fmt.Sprintf("%d críticos · %d avisos · %d contexto · cobertura %d/%d",
		crit, warn, manual, cov.Complete, cov.Total)
	// Cobertura oculta E incompleta: o número FICA (é a invariante), e uma dica
	// discreta diz como abrir o detalhe. Completa, ou já visível: sem ruído.
	if !mostrarCob && cov.Complete < cov.Total {
		linha += t.fraco(" · --coverage detalha")
	}
	fmt.Fprintln(w, linha)
	fmt.Fprintln(w)
}

func sevDoVerdict(v string) check.Severity {
	switch v {
	case "CRITICAL":
		return check.SevCritical
	case "WARNING", "INCOMPLETE":
		return check.SevWarn
	default:
		return check.SevInfo
	}
}

// rotuloCurto é o nome terse de um sinal: o sufixo do id do check
// (integrity.no_package_owner -> no_package_owner). É o que o operador escaneia
// para saber O QUE é, sem a frase pedagógica do título.
func rotuloCurto(id string) string {
	if i := strings.LastIndexByte(id, '.'); i >= 0 {
		return id[i+1:]
	}
	return id
}

// larguraAlvo é a coluna reservada para a entidade. O alvo pode ser um caminho
// longo; corta-se para manter a linha escaneável, e o caminho completo está no -v.
const larguraAlvo = 34

// writeFoco é o CORPO da decisão: uma linha por entidade que precisa de atenção,
// alinhada em colunas para bater o olho — id local, entidade, o que é. Sem §ref,
// sem explicação, sem prosa. A resposta a incidente é ágil: o operador escaneia
// a lista, não lê um relatório.
func writeFoco(w io.Writer, t Tema, itens []itemFoco, largura int) {
	temAcao := false
	for _, it := range itens {
		if it.sev == check.SevCritical || it.sev == check.SevWarn {
			temAcao = true
			break
		}
	}
	if !temAcao {
		return
	}
	// TTY estreito: a linha larga (id + sev + alvo + resumo ≈ 110 colunas) quebra
	// e desfaz a hierarquia que o redesign criou. Abaixo de 100 col, a entidade
	// fica na 1ª linha e o resumo, indentado, na 2ª — nada quebra. Largura 0
	// (pipe/arquivo) mantém o layout largo: o destino não quebra em 80.
	estreito := largura > 0 && largura < 100
	for _, it := range itens {
		if it.sev != check.SevCritical && it.sev != check.SevWarn {
			continue // contexto/manual sai no resumo de CONTEXT
		}
		et := t.pintaSev(it.sev, t.etiqueta(it.sev))
		marca := "   "
		if it.novo {
			marca = t.negrito("NEW") // ausente da baseline: o que mudou
		}
		sufixo := ""
		if it.n > 1 {
			sufixo += t.fraco(" ×" + strconv.Itoa(it.n))
		}
		if it.rebaixado {
			sufixo += t.fraco(" rebaixado")
		}
		id := "[" + it.id + "]"
		if estreito {
			fmt.Fprintf(w, "  %-3s %s %s %s\n", id, et, marca, Safe(corta(it.alvo, largura-17)))
			fmt.Fprintf(w, "       %s%s\n", Safe(corta(it.resumo, largura-8)), sufixo)
			continue
		}
		fmt.Fprintf(w, "  %-3s %s %s %s  %s%s\n",
			id, et, marca, pad(Safe(corta(it.alvo, larguraAlvo)), larguraAlvo), Safe(corta(it.resumo, 60)), sufixo)
	}
	fmt.Fprintln(w)
}

// writeContext resume os itens de MANUAL/contexto numa linha — inventário que
// vale ter, mas que não é o que precisa de ação. Detalhe no -v.
func writeContext(w io.Writer, t Tema, r *check.Report) {
	_, _, manual, _ := r.Counts()
	if manual == 0 {
		return
	}
	var partes []string
	for _, g := range check.GroupByIDSev(r.Findings) {
		if g.First().Sev != check.SevManual {
			continue
		}
		partes = append(partes, strconv.Itoa(g.N())+"× "+rotuloCurto(g.First().ID))
	}
	fmt.Fprintf(w, "%s  %s\n\n", t.fraco("CONTEXT"), t.fraco(Safe(strings.Join(partes, " · "))))
}
