package check

import (
	"github.com/lex0c/aletheia/internal/facts"
)

// marcarDrift liga cada achado ao que MUDOU sob ele.
//
// # A pergunta que nem a baseline nem o drift respondem sozinhos
//
// A baseline responde sobre o ACHADO: "isto já estava na lista da última vez?".
// O drift responde sobre o FATO: "o objeto mudou?". As duas parecem a mesma
// pergunta até o caso em que discordam, e ele é comum:
//
//	persist.unit_exec em nginx.service   já estava na baseline   →  não é novo
//	systemd.unit nginx.service           ExecStart mudou ontem   →  é OUTRA coisa
//
// O achado é velho e o objeto dele é novo. Sem esta ligação, o operador lê "já
// estava presente na baseline" — verdade — e passa adiante uma unit que executa
// um binário diferente do que executava quando aquela baseline foi feita.
//
// # Por que ela NÃO promove severidade
//
// É a tentação óbvia, e é a mesma que a baseline recusou do outro lado: lá,
// casar com a baseline NUNCA apaga um achado — desce um nível e continua no
// relatório. A assimetria é deliberada, e vale nos dois sentidos.
//
// "Mudou desde ontem" tem a forma exata de um deploy. Promover por isso encheria
// de crítico toda janela de implantação, e o crítico desta ferramenta é a
// severidade que faz uma frota parar: gastá-lo com deploy o gasta para sempre.
// O que a marca faz é dirigir o OLHO — a mesma função da coluna ✳NOVO, num eixo
// diferente —, e a evidência sempre nomeia a mudança para o operador julgar.
//
// # Como o alvo é ligado
//
// Pelos ALVOS que a família declara (drift.Entidade.Alvos): o nome da unit, o
// caminho do arquivo, o usuário da regra. Roda DEPOIS da resolução de atores,
// então o binário resolvido de um `pid=N` também casa — é assim que "o
// executável deste processo mudou" alcança o achado que fala do processo.
func marcarDrift(r *Report, f *facts.Facts) {
	if f == nil || f.DriftDados == nil {
		return
	}
	porAlvo := map[string][]facts.MudancaDrift{}
	for _, m := range f.DriftDados.Mudancas {
		for _, a := range m.Alvos {
			if a != "" {
				porAlvo[a] = append(porAlvo[a], m)
			}
		}
	}
	if len(porAlvo) == 0 {
		return
	}
	daDrift := idsDeDrift()

	for i := range r.Findings {
		fd := &r.Findings[i]
		// O achado de drift NÃO se marca: ele já É a mudança, e dizer-lhe que
		// algo mudou sob ele seria a ferramenta se citando como fonte.
		if daDrift[fd.ID] {
			continue
		}
		vistas := map[string]bool{}
		var notas []string
		for _, chave := range []string{fd.Subject, fd.Ator} {
			for _, m := range porAlvo[chave] {
				k := m.Tipo + "|" + m.ID + "|" + m.Kind + "|" + m.Campo
				if vistas[k] {
					continue
				}
				vistas[k] = true
				notas = append(notas, "  "+m.Titulo+" `"+m.ID+"` "+frasePorKind(m))
			}
		}
		if len(notas) == 0 {
			continue
		}
		fd.Driftou = true
		fd.Evidence = append(fd.Evidence,
			"E O OBJETO DESTE ACHADO MUDOU desde o retrato anterior:")
		fd.Evidence = append(fd.Evidence, notas...)
		fd.Evidence = append(fd.Evidence,
			"a severidade NÃO subiu por causa disso — \"mudou desde ontem\" tem a "+
				"forma de um deploy, e o crítico desta ferramenta é caro demais para "+
				"gastar assim. O que a marca faz é dizer onde olhar primeiro")
	}
}

func frasePorKind(m facts.MudancaDrift) string {
	switch m.Kind {
	case "surgiu":
		return "não existia no retrato anterior"
	case "sumiu":
		return "existia no retrato anterior e não existe mais"
	default:
		return "teve o campo `" + m.Campo + "` alterado"
	}
}

// idsDeDrift são os checks que JÁ falam de mudança. Sai do registro, e não de
// uma lista escrita à mão: uma lista à mão envelhece calada no primeiro check
// de drift que alguém acrescentar.
func idsDeDrift() map[string]bool {
	out := map[string]bool{}
	for _, c := range All() {
		if c.Drift {
			out[c.ID] = true
		}
	}
	return out
}
