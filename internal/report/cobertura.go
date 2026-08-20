package report

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
)

// writeCoberturaDetalhe é o -v da cobertura — e não a parede que era. A lista
// por check repetia a MESMA causa dezenas de vezes ("não estamos como root"
// aparecia em 60 checks), e a coleta despejava um gap por arquivo (34
// credenciais, 18 históricos). Aqui a leitura inverte:
//
//   - parcial agrupa por CAUSA e lista os checks que ela degrada. O operador vê
//     a alavanca (uma causa) em vez de sessenta sintomas, e conserta a causa.
//   - coleta agrupa por COLETOR e colapsa a cláusula repetida: "34× não entrou
//     no raio de alcance — <amostra de caminhos>" no lugar de 34 linhas quase
//     iguais.
//
// -vv (verbose>=2) não corta as listas.
func writeCoberturaDetalhe(w io.Writer, t Tema, c check.Coverage, verbose int) {
	lim := 10
	if verbose >= 2 {
		lim = 1 << 30
	}

	// Checks que NEM rodaram (falta pré-requisito) — eixo à parte, raro. Por check.
	if len(c.NotChecked) > 0 {
		fmt.Fprintln(w, "  "+t.negrito("não verificados"))
		for _, nc := range c.NotChecked {
			fmt.Fprintln(w, "    "+Safe(nc.ID)+t.fraco(" — "+Safe(nc.Reason)))
		}
	}

	// parcial: invertido para CAUSA -> checks, causa mais impactante primeiro.
	if len(c.Partial) > 0 {
		causaIDs := map[string][]string{}
		var ordem []string
		for _, p := range c.Partial {
			for _, rz := range dedupe(p.Reasons) {
				if _, ok := causaIDs[rz]; !ok {
					ordem = append(ordem, rz)
				}
				causaIDs[rz] = append(causaIDs[rz], p.ID)
			}
		}
		sort.SliceStable(ordem, func(i, j int) bool {
			return len(causaIDs[ordem[i]]) > len(causaIDs[ordem[j]])
		})
		fmt.Fprintf(w, "  %s %s\n", t.negrito("parcial"),
			t.fraco("— "+strconv.Itoa(len(c.Partial))+" checks, por causa"))
		for _, rz := range ordem {
			ids := causaIDs[rz]
			fmt.Fprintf(w, "  %s  %s\n", contagem(len(ids)), Safe(rz))
			fmt.Fprintln(w, "        "+t.fraco(Safe(juntarCap(ids, lim))))
		}
	}

	// coleta: por coletor, colapsando a cláusula-cauda que se repete.
	if len(c.CollectorGaps) > 0 {
		porColetor := map[string][]string{}
		var colOrdem []string
		for _, g := range dedupe(c.CollectorGaps) {
			col, body := "coleta", g
			if i := strings.Index(g, ": "); i >= 0 {
				col, body = g[:i], g[i+2:]
			}
			if _, ok := porColetor[col]; !ok {
				colOrdem = append(colOrdem, col)
			}
			porColetor[col] = append(porColetor[col], body)
		}
		sort.SliceStable(colOrdem, func(i, j int) bool {
			return len(porColetor[colOrdem[i]]) > len(porColetor[colOrdem[j]])
		})
		fmt.Fprintf(w, "  %s %s\n", t.negrito("coleta"), t.fraco("— leitura que falhou, por coletor"))
		for _, col := range colOrdem {
			bodies := porColetor[col]
			fmt.Fprintf(w, "    %s %s\n", Safe(col), t.fraco("("+strconv.Itoa(len(bodies))+")"))
			for _, l := range colapsarClausulas(bodies, lim) {
				fmt.Fprintln(w, "        "+t.fraco(Safe(l)))
			}
		}
	}
}

// colapsarClausulas junta os gaps de um coletor pela CLÁUSULA (o texto depois do
// último ": ", que é a explicação). O que se repete — 34 credenciais com "não
// entrou no raio de alcance", 18 históricos com "ausência de histórico" — vira
// UMA linha com contagem e amostra dos caminhos. O único fica como está.
// Cláusula mais repetida primeiro.
func colapsarClausulas(bodies []string, lim int) []string {
	heads := map[string][]string{}
	var ordem []string
	for _, b := range bodies {
		head, clause := b, ""
		if i := strings.LastIndex(b, ": "); i >= 0 {
			head, clause = b[:i], b[i+2:]
		}
		if _, ok := heads[clause]; !ok {
			ordem = append(ordem, clause)
		}
		heads[clause] = append(heads[clause], head)
	}
	sort.SliceStable(ordem, func(i, j int) bool {
		return len(heads[ordem[i]]) > len(heads[ordem[j]])
	})
	var out []string
	for _, cl := range ordem {
		hs := heads[cl]
		if len(hs) == 1 {
			if cl == "" {
				out = append(out, hs[0])
			} else {
				out = append(out, hs[0]+": "+cl)
			}
			continue
		}
		amostras := make([]string, 0, len(hs))
		for _, h := range hs {
			amostras = append(amostras, amostraHead(h))
		}
		rotulo := cl
		if rotulo == "" {
			rotulo = "repetido"
		}
		out = append(out, strconv.Itoa(len(hs))+"× "+rotulo+" — "+juntarCap(amostras, 3))
	}
	return out
}

// amostraHead extrai a parte que distingue um gap colapsado: o caminho, quando
// é um; senão o começo do texto. É o que diz ao operador QUAIS caminhos caíram
// naquela cláusula, sem repetir o "não pôde ser examinado" de cada um.
func amostraHead(h string) string {
	if strings.HasPrefix(h, "/") || strings.HasPrefix(h, "~") {
		if i := strings.IndexByte(h, ' '); i >= 0 {
			return h[:i]
		}
		return h
	}
	return corta(h, 40)
}

// juntarCap une com " · ", cortando em n com "… +K" — nunca esconde silenciosamente.
func juntarCap(itens []string, n int) string {
	if len(itens) <= n {
		return strings.Join(itens, " · ")
	}
	return strings.Join(itens[:n], " · ") + " · … +" + strconv.Itoa(len(itens)-n)
}

// contagem formata "  N×" alinhado à direita, para as contagens ficarem em coluna.
func contagem(n int) string {
	return fmt.Sprintf("%3d×", n)
}
