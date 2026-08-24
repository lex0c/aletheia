package facts

import (
	"strconv"
	"strings"
	"time"

	"github.com/lex0c/aletheia/internal/env"
)

// O tempo de uma linha de log (runbook §9, §10).
//
// O syslog tradicional data assim:
//
//	Aug 24 01:20:33 host sshd[1234]: …
//
// Falta o ANO e falta o FUSO. As duas ausências são armadilhas de correlação, e
// nenhuma delas aparece em teste feito no mesmo dia em que o log foi escrito:
//
//	fuso    a data é hora LOCAL do alvo. Comparar com o mtime — que a
//	        ferramenta lê em UTC — erra pelo offset inteiro, e um sudo às 03:22
//	        vira 06:22 num host em -03. A janela de 90 segundos que liga login a
//	        persistência simplesmente não fecha
//	ano     em 31 de dezembro, a linha de dezembro num arquivo rotacionado em
//	        janeiro ganha o ano errado, e o achado sai datado com um ano de
//	        diferença
//
// O `audit.log` é imune às duas: ele carrega epoch UTC.
//
// # Por que não time.LoadLocation
//
// Ela lê o zoneinfo do HOST DE QUEM INVESTIGA. Num `--root` de imagem montada,
// isso dataria o log do alvo com o fuso do analista — o mesmo erro de classe que
// o os.Root existe para impedir no resto da coleta. O TZif do alvo é lido como
// BYTES e decodificado por time.LoadLocationFromTZData, que não toca em disco.

// contextoDeTempo é o que a linha não diz, e o arquivo diz.
type contextoDeTempo struct {
	// Loc é o fuso do ALVO. Nunca nil depois de fusoDoAlvo: quando não dá para
	// saber, é UTC — e Suposto marca que é suposição.
	Loc *time.Location
	// Suposto diz que o fuso é uma SUPOSIÇÃO, não uma leitura. Vai para
	// EventoDeLog.AtInferido e de lá para a evidência: um horário com offset
	// suposto não sustenta correlação de segundos.
	Suposto bool

	// Ancora é o mtime do arquivo, e é de onde o ano é inferido. Zero significa
	// que não houve como datar nada daquele arquivo.
	Ancora time.Time
	// Agora é o instante da COLETA (e.Now). Data depois dele é forjada, e a
	// guarda é a mesma do DerivarAncora (check/janela.go).
	Agora time.Time
}

// folgaDeRelogio é quanto uma data pode passar da âncora sem virar "ano
// anterior", e quanto pode passar do agora sem virar "forjada".
//
// 25 horas, e não zero: entre a última linha e o mtime há a latência da
// escrita; entre o relógio do alvo e o da coleta há deriva; e o offset de fuso
// sozinho já vale 14 horas no extremo. Zero de folga faria toda linha da última
// hora de um arquivo recém-escrito ser jogada para o ano anterior.
const folgaDeRelogio = 25 * time.Hour

// fusoDoAlvo lê /etc/localtime DO ALVO.
//
// A distinção entre AUSENTE e ILEGÍVEL não é preciosismo, e decide se a
// evidência sai com ressalva:
//
//	ausente     a glibc cai em UTC. O host REALMENTE escreve em UTC, então
//	            assumir UTC não é suposição — é o comportamento dele
//	ilegível    o arquivo existe e não pôde ser lido: o offset é desconhecido, e
//	            UTC vira suposição declarada
func fusoDoAlvo(f *Facts, e *env.Env) (*time.Location, bool) {
	b, err := e.ReadFile("/etc/localtime")
	if err != nil {
		// /etc/localtime É UM LINK ABSOLUTO em praticamente toda distribuição
		// (→ /usr/share/zoneinfo/…), e sob `--root` o os.Root RECUSA link
		// absoluto: ele o resolveria contra a raiz do PROCESSO, e essa recusa é
		// justamente o que impede a leitura de escapar para o disco de quem
		// investiga. O erro sai como "path escapes from parent".
		//
		// O efeito era que o fuso do alvo NUNCA era lido em modo image — o
		// caminho da §35.6, que é onde ele mais importa, porque ali o relógio e
		// o fuso do analista não têm nada a ver com os do host varrido. Achado
		// pelo cenário de imagem, não por leitura.
		//
		// Seguir a cadeia DENTRO da raiz é o que o kernel do alvo faria, e é o
		// que alvoFinal já faz para propriedade de pacote. A classe é geral:
		// qualquer coletor que leia um caminho que seja link absoluto no alvo
		// esbarra nisto sob --root.
		if alvo := alvoFinal(e, "/etc/localtime"); alvo != "" {
			if bs, err2 := e.ReadFile(alvo); err2 == nil {
				b, err = bs, nil
			}
		}
	}
	if err != nil {
		if env.EhLacuna(err) {
			f.partial("logeventos", "/etc/localtime não pôde ser lido ("+
				env.MotivoDoErro(err)+"): o fuso do alvo é DESCONHECIDO e as datas "+
				"de log foram lidas como UTC — um offset errado desloca toda "+
				"correlação temporal com mtime e com o wtmp")
			return time.UTC, true
		}
		// ENOENT: sem /etc/localtime a própria glibc usa UTC, então é isto que o
		// host escreveu. Não é suposição.
		return time.UTC, false
	}
	loc, err := time.LoadLocationFromTZData("localtime", b)
	if err != nil {
		f.partial("logeventos", "/etc/localtime foi lido e NÃO é um TZif válido ("+
			err.Error()+"): o fuso do alvo é desconhecido e as datas de log foram "+
			"lidas como UTC")
		return time.UTC, true
	}
	return loc, false
}

// mesDeSyslog traduz o nome de três letras. Não usa time.Parse de propósito: o
// layout do Go aceita variações que o syslog não produz, e uma abreviação
// desconhecida precisa ser RECUSADA — inventar janeiro para um mês ilegível
// dataria o evento sete meses fora.
var mesDeSyslog = map[string]time.Month{
	"Jan": time.January, "Feb": time.February, "Mar": time.March,
	"Apr": time.April, "May": time.May, "Jun": time.June,
	"Jul": time.July, "Aug": time.August, "Sep": time.September,
	"Oct": time.October, "Nov": time.November, "Dec": time.December,
}

// instanteDeSyslog monta o instante UTC de uma data sem ano e sem fuso.
//
// O ano vem da ÂNCORA (o mtime do arquivo) caminhando para trás: uma data que
// cai depois do mtime pertence ao ano anterior, porque o arquivo não pode ter
// sido escrito antes da linha que contém.
//
// Devolve false — e não uma data qualquer — quando:
//
//	não há âncora        arquivo sem mtime: não há de onde inferir ano
//	a data não existe    "Feb 29" num ano não bissexto significa que a inferência
//	                     errou; o time.Date normalizaria para 1º de março em
//	                     silêncio, e o achado sairia datado de um dia que a linha
//	                     não menciona
//	a data é FUTURA      relógio adiantado ou linha plantada. É a mesma guarda do
//	                     DerivarAncora: data no futuro é sinal, e não serve para
//	                     datar coisa nenhuma
func instanteDeSyslog(mes time.Month, dia, hora, min, seg int, ctx contextoDeTempo) (time.Time, bool) {
	if ctx.Ancora.IsZero() {
		return time.Time{}, false
	}
	loc := ctx.Loc
	if loc == nil {
		loc = time.UTC
	}
	ancora := ctx.Ancora.In(loc)

	monta := func(ano int) (time.Time, bool) {
		t := time.Date(ano, mes, dia, hora, min, seg, 0, loc)
		// O time.Date NORMALIZA: 29 de fevereiro de um ano comum vira 1º de
		// março, e a data sai plausível e errada.
		if t.Day() != dia || t.Month() != mes {
			return time.Time{}, false
		}
		return t, true
	}

	t, ok := monta(ancora.Year())
	if !ok || t.After(ancora.Add(folgaDeRelogio)) {
		if t, ok = monta(ancora.Year() - 1); !ok {
			return time.Time{}, false
		}
	}
	if !ctx.Agora.IsZero() && t.After(ctx.Agora.Add(folgaDeRelogio)) {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// instanteISO lê a data COMPLETA que o rsyslog moderno escreve.
//
//	2026-08-24T01:20:33.123456+02:00
//
// Ela traz ano e offset, então não passa por inferência nenhuma — e é por isso
// que vale reconhecê-la antes de tentar a forma tradicional.
func instanteISO(s string) (time.Time, bool) {
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.999999Z0700",
		"2006-01-02T15:04:05Z0700",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// instanteDeEpoch lê o carimbo do auditd: `1755990137.123`.
//
// Segundos e MILISSEGUNDOS, nesta ordem, como o kernel escreve
// (`audit(%llu.%03lu:%u)`, kernel/audit.c). É UTC por construção, e por isso o
// audit.log é a única fonte de log desta ferramenta que não infere nada.
func instanteDeEpoch(s string) (time.Time, bool) {
	seg, ms, ok := strings.Cut(s, ".")
	if !ok {
		return time.Time{}, false
	}
	sec, err := strconv.ParseInt(seg, 10, 64)
	if err != nil || sec <= 0 {
		return time.Time{}, false
	}
	milis, err := strconv.Atoi(ms)
	if err != nil || milis < 0 || milis > 999 {
		return time.Time{}, false
	}
	return time.Unix(sec, int64(milis)*int64(time.Millisecond)).UTC(), true
}

// utc formata para o mesmo layout que o resto dos fatos usa. Instante zero vira
// string VAZIA, nunca "0001-01-01": um campo vazio é lido como "sem data" por
// quem consome, e a data do ano 1 seria lida como data.
func utc(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02T15:04:05Z")
}
