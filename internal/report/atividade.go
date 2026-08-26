package report

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/lex0c/aletheia/internal/activity"
	"github.com/lex0c/aletheia/internal/facts"
)

// O bloco de ATIVIDADE do `wtf`: o denominador que faltava.
//
// O resto do `wtf` responde "há indicador decisivo?". Este bloco responde a
// pergunta ao lado, que é a que o operador faz assim que entra numa VM: quanto
// uso este host teve, de quem, e de onde. É o quadro em que abuso de credencial
// aparece — não como achado, mas como forma.
//
// # Por que ele não conclui nada
//
// Nenhuma linha daqui tem severidade nem mexe no exit code. O achado que cruza
// falha e sucesso já existe (`auth.bruteforce_success`) e já sai na lista
// abaixo; repetir a conclusão aqui, com outro limiar, seria duas verdades sobre
// o mesmo evento. O que este bloco acrescenta é o CONTEXTO que torna aquela
// linha legível — 47 falhas num host que recebeu 12.000 é clima, e num host que
// recebeu 50 é a descrição do ataque.
//
// # O teto de quatro linhas
//
// O `wtf` promete UMA TELA, e ela já é disputada pelos achados. Quatro linhas é
// o que cabe sem empurrar o que decide para fora — e o que não couber tem
// destino nomeado, que é o `activity`.
const maxSessoesNoWtf = 3

// writeAtividade imprime o bloco. Fica calado quando a coleta de login não
// rodou: zero de uma coleta que não aconteceu é a leitura tranquilizadora que
// esta ferramenta inteira existe para não produzir.
func writeAtividade(w io.Writer, t Tema, r activity.Resumo, agora time.Time) {
	if !r.Coletado() {
		return
	}

	// SOLICITADO e OBSERVADO na mesma linha, com os dois rótulos ditos: os
	// números das linhas de baixo foram medidos no OBSERVADO, e um cabeçalho que
	// só dissesse "24h" convidaria a lê-los como se cobrissem 24 horas. É a
	// mesma distinção que LogJanelaEfetiva carrega para o conteúdo dos logs.
	fmt.Fprintln(w, t.fraco("atividade · solicitado "+r.JanelaSolicitada+
		" · observado: "+Safe(observado(r, agora))))

	linha(w, t, "entradas", entradas(r))
	linha(w, t, "recusadas", recusadas(r))

	if len(r.Sessoes) > 0 {
		linha(w, t, "sessões", sessoes(r))
	}
	fmt.Fprintln(w)
}

// entradas tem a MESMA disciplina de recusadas, e ela precisa valer aqui
// também: um wtmp ilegível com "0 aceitas" é exatamente o defeito que o btmp
// fechado produzia — "não olhei" saindo com a cara de "não aconteceu".
//
// O caso não é hipotético: o CIS Benchmark manda pôr 0640 no wtmp, e onde essa
// recomendação foi seguida uma varredura sem root lê zero registro.
func entradas(r activity.Resumo) string {
	s, ok := r.Fonte(facts.PapelHistorico)
	switch {
	case !ok:
		return "NÃO EXAMINADAS — a coleta não registrou esta fonte"
	case !s.Existe():
		return "não há wtmp neste host — o histórico de entrada não é registrado"
	case !s.Lida():
		return "NÃO EXAMINADAS — wtmp: " + nz(s.Motivo, "não foi lido")
	}

	ent := []string{plural(r.Aceitos, "aceita", "aceitas")}
	if r.Usuarios > 0 {
		ent = append(ent, plural(r.Usuarios, "usuário", "usuários"))
	}
	if r.Origens > 0 {
		o := plural(r.Origens, "origem", "origens")
		// O parêntese só sai quando a pergunta pôde ser FEITA. Sem histórico
		// anterior à janela não há "antes" com que comparar, e imprimir 0 ali
		// seria inventar uma negativa. O motivo já está visível na linha de
		// cima: aquela fonte não alcança a janela.
		if r.OrigensNaoObservadasAntesCalc && r.OrigensNaoObservadasAntes > 0 {
			o += " (" + strconv.Itoa(r.OrigensNaoObservadasAntes) +
				" não observadas anteriormente)"
		}
		ent = append(ent, o)
	}
	return strings.Join(ent, " · ")
}

func linha(w io.Writer, t Tema, rotulo, texto string) {
	fmt.Fprintln(w, t.fraco(fmt.Sprintf("  %-10s ", rotulo))+Safe(texto))
}

// observado resume o alcance de cada testemunha. É a linha que impede os
// números de baixo de serem lidos como se valessem para a janela pedida.
func observado(r activity.Resumo, agora time.Time) string {
	var out []string
	for _, s := range r.Fontes {
		out = append(out, nomeDoPapel(s.Papel)+" "+alcance(s, r, agora))
	}
	return strings.Join(out, " · ")
}

// alcance escreve o que UMA testemunha alcançou, contra a janela pedida.
//
// Quando ela cobre a janela inteira, o número que interessa não é quanto
// passado ela tem — é que a resposta vale para o que foi perguntado: `≥24h`.
// Quando não cobre, sai o intervalo REAL, porque é ele que limita toda
// afirmação de ausência feita sobre esta fonte.
func alcance(s activity.Fonte, r activity.Resumo, agora time.Time) string {
	switch {
	case !s.Existe():
		// Arquivo que não existe é ESCOPO: um contêiner sem btmp não tem
		// tentativa recusada a esconder. Diferente de "não pude ler".
		return "ausente"
	case !s.Lida():
		return "NÃO LIDO"
	case s.Papel == facts.PapelSessoes:
		return "agora"
	}

	var alc string
	switch {
	case s.CobreJanela && s.Desde != "":
		alc = "≥" + r.JanelaSolicitada
	case s.Desde != "":
		alc = s.Alcance(agora)
	case s.Lidos == 0:
		// VAZIO, e nada além disso. A frase anterior aqui era "não havia
		// registro para esconder" — uma afirmação sobre o passado tirada de um
		// arquivo de zero byte, que é exatamente a forma que um `: > wtmp`
		// deixa. Vazio prova que a fonte foi lida e não entregou registro.
		alc = "vazio (alcance indeterminado)"
	default:
		// Lido, com registros, e nenhum deles datável: a fonte não sustenta
		// afirmação temporal nenhuma.
		alc = "sem data"
	}
	if s.SemData > 0 && alc != "sem data" {
		alc += " (" + strconv.Itoa(s.SemData) + " sem data)"
	}
	return alc
}

func recusadas(r activity.Resumo) string {
	s, ok := r.Fonte(facts.PapelRecusadas)
	switch {
	case !ok:
		// A fonte nem consta da coleta. Não é "o host não tem o arquivo" —
		// é "ninguém foi olhar", e as duas frases mandam para lugares
		// diferentes.
		return "NÃO EXAMINADAS — a coleta não registrou esta fonte"
	case !s.Existe():
		// Nunca "0 recusadas": o host não tem o arquivo, e ausência de FONTE não
		// é ausência de tentativa.
		return "não há btmp neste host — tentativa recusada não é registrada"
	case !s.Lida():
		// O caso comum, e o que mais importa acertar: sem root o btmp é
		// ilegível em toda distribuição. Zero aqui diria "ninguém tentou
		// entrar" sobre um arquivo que ninguém abriu.
		m := s.Motivo
		if m == "" {
			m = "não foi lido"
		}
		return "NÃO EXAMINADAS — btmp: " + m
	case r.Recusados == 0:
		return "nenhuma"
	}
	out := strconv.Itoa(r.Recusados)
	if len(r.TopOrigensRecusa) > 0 {
		top := r.TopOrigensRecusa[0]
		out += " · maior origem " + top.Chave + " (" + strconv.Itoa(top.N) + ")"
	}
	return out
}

func sessoes(r activity.Resumo) string {
	var out []string
	for i, s := range r.Sessoes {
		if i >= maxSessoesNoWtf {
			out = append(out, "+"+strconv.Itoa(len(r.Sessoes)-maxSessoesNoWtf))
			break
		}
		v := s.User
		// Só ORIGEM DE REDE ganha o `@`. O campo traz `:0` para sessão de X e
		// vazio para tty física, e `lex@:0` faz o display local parecer um
		// endereço de onde alguém entrou — que é exatamente a linha que o
		// operador percorre procurando o que não reconhece.
		if facts.OrigemDeRede(s.Origem) {
			v += "@" + s.Origem
		}
		if s.Linha != "" {
			v += " " + s.Linha
		}
		out = append(out, v)
	}
	return strings.Join(out, " · ")
}

func nomeDoPapel(p string) string {
	switch p {
	case facts.PapelHistorico:
		return "wtmp"
	case facts.PapelRecusadas:
		return "btmp"
	case facts.PapelSessoes:
		return "utmp"
	}
	return p
}

func plural(n int, um, muitos string) string {
	if n == 1 {
		return "1 " + um
	}
	return strconv.Itoa(n) + " " + muitos
}
