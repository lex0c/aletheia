package check

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

// A janela de investigação (SPEC 6.5, runbook §9).
//
// # O problema que ela resolve
//
// Um host de dois anos tem centenas de coisas verdadeiras a dizer sobre si
// mesmo, e quase nenhuma pertence ao incidente. Quando se sabe QUANDO a invasão
// aconteceu — e num incidente real quase sempre se sabe, por um log de
// aplicação, um alerta, uma reclamação —, o recorte temporal separa o que é do
// caso do que é a história do servidor.
//
// # A decisão que decide tudo: o achado SEM data
//
// Nem todo achado tem data. Uma conta com uid 0, uma regra de sudo, um socket
// aberto agora: não há mtime que os situe no tempo. A saída fácil seria
// descartá-los junto com o que ficou fora da janela — e ela é a mesma
// truncagem silenciosa que esta base persegue em todo lugar, porque descartaria
// por IGNORÂNCIA e não por escolha do operador.
//
// A regra é a oposta: **o que não tem data FICA**, e o rodapé conta quantos
// foram. O que tem data e caiu fora sai do relatório e também é contado, por
// severidade — um crítico fora da janela é uma frase que o operador precisa
// ler, não um silêncio.

// Janela é o recorte pedido pelo operador.
type Janela struct {
	// Desde é o começo da janela, em UTC.
	Desde time.Time
	// Spec é o que o operador escreveu, para o relatório citar a escolha dele e
	// não a interpretação dela.
	Spec  string
	Ativa bool
}

// ErrJanela é o formato recusado. Recusar é melhor que interpretar: uma janela
// entendida errado recorta o relatório errado, e ninguém percebe.
var ErrJanela = errors.New("--since aceita um instante (2026-04-30T18:00Z, 2026-04-30) " +
	"ou uma duração (72h, 7d, 30m)")

// ParseJanela lê as duas formas da SPEC. `agora` é o relógio da execução, e
// entra como parâmetro para o teste não depender do relógio da máquina.
func ParseJanela(spec string, agora time.Time) (Janela, error) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return Janela{}, nil
	}
	j := Janela{Spec: s, Ativa: true}

	// Duração: 72h, 30m, 7d. O `d` não existe no time.ParseDuration do Go e é a
	// unidade que mais se usa em resposta a incidente — traduzir aqui é mais
	// honesto que obrigar o operador a escrever 168h.
	if d, ok := duracao(s); ok {
		if d <= 0 {
			return Janela{}, ErrJanela
		}
		j.Desde = agora.Add(-d).UTC()
		return j, nil
	}

	for _, layout := range []string{
		time.RFC3339,
		"2006-01-02T15:04Z07:00", // sem segundos: a forma que a SPEC usa
		"2006-01-02T15:04:05",
		"2006-01-02T15:04",
		"2006-01-02",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			// Sem fuso declarado, UTC: a ferramenta inteira trabalha em UTC, e
			// assumir o fuso local faria a mesma janela recortar diferente em
			// dois hosts da mesma frota.
			j.Desde = t.UTC()
			return j, nil
		}
	}
	return Janela{}, ErrJanela
}

func duracao(s string) (time.Duration, bool) {
	if s == "" {
		return 0, false
	}
	if dias, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(dias)
		if err != nil {
			return 0, false
		}
		return time.Duration(n) * 24 * time.Hour, true
	}
	d, err := time.ParseDuration(s)
	return d, err == nil
}

// Recorte é o que a janela FEZ, e existe para ser impresso. Uma janela que
// recorta em silêncio devolve um relatório mais limpo e menos verdadeiro.
type Recorte struct {
	Fora        int
	ForaSev     map[Severity]int
	SemData     int
	MaisRecente string // o achado fora da janela mais próximo dela
}

// Aplicar recorta o relatório. Devolve o que ficou de fora, contado.
func (r *Report) Aplicar(j Janela) Recorte {
	rec := Recorte{ForaSev: map[Severity]int{}}
	if !j.Ativa {
		return rec
	}
	dentro := r.Findings[:0]
	for _, f := range r.Findings {
		t, ok := instante(f.Quando)
		switch {
		case !ok:
			// Sem data: FICA. É a regra que permite acrescentar data aos checks
			// aos poucos sem que a janela comece a esconder o que ainda não foi
			// datado.
			rec.SemData++
			dentro = append(dentro, f)
		case t.Before(j.Desde):
			rec.Fora++
			rec.ForaSev[f.Sev]++
			if f.Sev == SevCritical {
				// Vai para o relatório: o exit code precisa saber que existe um
				// crítico que ESTE recorte escondeu.
				r.CriticosForaDaJanela++
			}
			if t.Format(time.RFC3339) > rec.MaisRecente {
				rec.MaisRecente = t.Format(time.RFC3339)
			}
		default:
			dentro = append(dentro, f)
		}
	}
	r.Findings = dentro
	return rec
}

// Ancora é a data de referência da investigação (runbook §9).
type Ancora struct {
	Quando string
	// Origem diz de onde a data veio, e é o campo que impede a ferramenta de
	// parecer que sabe mais do que sabe.
	Origem string
	// De nomeia o achado que a produziu, quando foi derivada.
	De string
}

// DerivarAncora resolve o ovo-e-galinha da §9: a timeline precisa de um âncora,
// e na primeira execução não existe achado de onde derivá-lo.
//
//	--since informado      o âncora é a janela pedida
//	sem --since, com
//	  achado datável       deriva do achado MAIS SEVERO, e entre iguais do mais
//	                       recente — e DIZ que derivou, com o achado junto
//	sem --since, sem
//	  achado datável       devolve vazio: inventar sete dias e apresentá-los como
//	                       âncora seria fingir que derivou
func (r *Report) DerivarAncora(j Janela, agora time.Time) Ancora {
	if j.Ativa {
		return Ancora{
			Quando: j.Desde.Format(time.RFC3339),
			Origem: "informado em --since " + j.Spec,
		}
	}
	// Data no FUTURO não ancora nada.
	//
	// f.Quando vem de mtime em dezenas de checks, e mtime é forjável com um
	// `touch` — coletarTimestomp existe justamente por isso. Sem esta guarda,
	// um `touch -d 2099-01-01 /etc/systemd/system/backdoor.service` vencia o
	// desempate por ser o mais recente e o relatório imprimia a âncora da
	// investigação setenta e três anos à frente, com Origem "derivado desta
	// execução": a ferramenta afirmando uma data que o adversário escreveu.
	// Data no futuro é SINAL por si, e quem o levanta é o check de timestomp —
	// aqui ela só não pode servir de âncora.
	//
	// O `agora` entra por PARÂMETRO, e é o e.Now — o instante da COLETA, não o
	// relógio de quem analisa. Era time.Now() aqui, e isso quebrava as duas
	// coisas que a guarda existe para garantir. O determinismo: o mesmo dump
	// analisado antes e depois de um timestamp passar do relógio de parede dava
	// âncora e contagem de `futuros` diferentes — mesma entrada, saída
	// diferente, e o drift compara justamente saídas. E a própria guarda: ela
	// passava a valer contra o relógio do ANALISTA, então um `touch -d "+2
	// hours"` era rejeitado hoje e aceito amanhã, bastando ao adversário forjar
	// menos que o atraso entre coletar e analisar. Todo o resto do caminho de
	// análise já usa e.Now por este motivo (ver dump.go, onde o Env do artefato
	// nasce com Now = collected_at).
	agora = agora.UTC()
	var melhor Finding
	var melhorT time.Time
	var futuros int
	for _, f := range r.Findings {
		t, ok := instante(f.Quando)
		if !ok {
			continue
		}
		if t.After(agora) {
			futuros++
			continue
		}
		if melhor.ID == "" || f.Sev > melhor.Sev ||
			(f.Sev == melhor.Sev && t.After(melhorT)) {
			melhor, melhorT = f, t
		}
	}
	if melhor.ID == "" {
		if futuros > 0 {
			return Ancora{Origem: "NÃO derivada: os achados datados têm data no " +
				"FUTURO, que é sinal de data forjada e não serve de âncora"}
		}
		return Ancora{}
	}
	de := melhor.ID
	if melhor.Subject != "" {
		de += " em " + melhor.Subject
	}
	if melhor.QuandoFonte != "" {
		de += " (" + melhor.QuandoFonte + ")"
	}
	origem := "derivado desta execução"
	if futuros > 0 {
		origem += " (" + strconv.Itoa(futuros) + " achado(s) com data no FUTURO " +
			"foram descartados como âncora: data forjada)"
	}
	return Ancora{
		Quando: melhorT.Format(time.RFC3339),
		Origem: origem,
		De:     de,
	}
}

// instante lê a data de um achado. Formato inesperado NÃO vira zero: vira
// "sem data", e sem data o achado é mantido — o contrário faria um erro de
// formatação apagar achado do relatório.
func instante(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z", "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}
