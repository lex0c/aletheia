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

// A saída do comando `activity`.
//
// Ela não tem severidade, não tem veredito e não muda exit code — o comando
// RECONSTRÓI, e quem conclui é o `scan`. É a mesma separação que o `info` já
// sustenta: juntar os fatos e dizer o que cada número significa, sem
// transformar o dossiê em acusação.
//
// O que toda saída daqui carrega, sem exceção, é o RODAPÉ DE COBERTURA. Uma
// linha do tempo sem o alcance de quem a testemunhou é a forma mais convincente
// de afirmar que nada aconteceu.

// familiasDeAtividade são TODAS as famílias que o parser de log conhece.
//
// A primeira versão listava só auth, cron e audit — mas `deLogs` renderiza todo
// EventoDeLog, venha ele de onde vier. Um evento de `kern` saía na linha do
// tempo sem nenhuma linha de cobertura por baixo, o que quebra a única
// invariante que este arquivo promete: nenhuma lista de eventos sai sem o
// alcance de quem os viu.
var familiasDeAtividade = []string{"auth", "cron", "audit", "syslog", "kern"}

// ActivityLinha imprime a linha do tempo, agrupada por dia.
func ActivityLinha(w io.Writer, ev []activity.Evento, cor bool) {
	t := temaPara(cor)
	if len(ev) == 0 {
		// NUNCA "nada aconteceu": o rodapé de cobertura, que sai logo abaixo, é
		// quem diz sobre qual intervalo este silêncio vale.
		fmt.Fprintln(w, t.fraco("nenhum evento no recorte pedido — a cobertura abaixo diz sobre o quê"))
		fmt.Fprintln(w)
		return
	}

	dia := ""
	semData := 0
	for i := range ev {
		e := &ev[i]
		if e.At == "" {
			semData++
			continue
		}
		if d := diaDe(e.At); d != "" && d != dia {
			dia = d
			fmt.Fprintln(w, t.negrito(d))
		}
		fmt.Fprintln(w, linhaDoEvento(t, e))
	}

	if semData > 0 {
		// Bloco PRÓPRIO, no fim. Interpolar um evento sem data numa posição
		// plausível seria inventar quando ele aconteceu.
		fmt.Fprintln(w, t.negrito("sem data")+t.fraco(
			"  — estes registros entraram sem instante e não puderam ser situados"))
		for i := range ev {
			if ev[i].At == "" {
				fmt.Fprintln(w, linhaDoEvento(t, &ev[i]))
			}
		}
	}
	fmt.Fprintln(w)
}

// diaDe recorta o dia de um carimbo. Um dump pode ser escrito à mão, e uma data
// curta demais derrubava o comando com panic sobre um índice — a ferramenta
// tratando entrada do alvo como se ela fosse confiável.
func diaDe(at string) string {
	if len(at) < 10 {
		return ""
	}
	return at[:10]
}

func linhaDoEvento(t Tema, e *activity.Evento) string {
	hora := "  --:--:--"
	if len(e.At) >= 19 {
		hora = "  " + e.At[11:19]
	}
	linha := t.fraco(hora) + "  " + pad(Safe(string(e.Kind)), 21) + Safe(sujeito(e))

	var cauda []string
	if s := strings.Join(e.Testemunhas, "+"); s != "" {
		cauda = append(cauda, s)
	}
	// A FORÇA da ligação viaja com o evento: "mesmo pid" e "mesmo usuário e
	// origem no mesmo dia" não são a mesma evidência, e quem for decidir a
	// partir desta linha precisa saber qual das duas sustenta a fusão.
	if e.Fusao != activity.FusaoNenhuma {
		cauda = append(cauda, "⇄"+e.Fusao.String())
	}
	if e.FusaoNota != "" {
		cauda = append(cauda, e.FusaoNota)
	}
	if len(cauda) > 0 {
		linha += t.fraco("  [" + Safe(strings.Join(cauda, " ")) + "]")
	}
	if e.Divergente != "" {
		linha += "  " + t.fraco(Safe(divergencia(e)))
	}
	return linha
}

func sujeito(e *activity.Evento) string {
	var p []string
	v := e.User
	if facts.OrigemDeRede(e.Origem) {
		v += "@" + e.Origem
	}
	if v != "" {
		p = append(p, v)
	}
	if e.Metodo != "" {
		p = append(p, e.Metodo)
	}
	if e.Fingerprint != "" {
		p = append(p, e.Fingerprint)
	}
	if e.Linha != "" {
		p = append(p, e.Linha)
	}
	if len(e.Alvos) > 0 {
		p = append(p, "→ "+strings.Join(e.Alvos, " "))
	}
	if len(p) == 0 && e.Trecho != "" {
		p = append(p, corta(e.Trecho, 40))
	}
	return strings.Join(p, " ")
}

func divergencia(e *activity.Evento) string {
	falta := "o registro binário"
	if len(e.Testemunhas) > 0 && !strings.HasPrefix(e.Testemunhas[0], "log:") {
		falta = "o log em texto"
	}
	if e.Divergente == activity.DivergenteAusente {
		return "◆ divergente: " + falta + " cobria este instante e NÃO registrou"
	}
	return "· ausência não confirmada em " + falta
}

// ActivitySumario imprime os agregados.
func ActivitySumario(w io.Writer, s activity.Sumario, cor bool) {
	t := temaPara(cor)
	tot := strconv.Itoa(s.Total)
	if s.SemData > 0 {
		// À parte, e não somado: um evento sem data não pertence ao intervalo
		// abaixo, e escondê-lo dentro do total faria o intervalo parecer cobrir
		// tudo que foi contado.
		tot += " (" + strconv.Itoa(s.SemData) + " sem data)"
	}
	linha(w, t, "eventos", tot)
	if s.Primeiro != "" {
		linha(w, t, "intervalo", s.Primeiro+" → "+s.Ultimo)
	}
	if len(s.PorKind) > 0 {
		linha(w, t, "por tipo", contagens2(s.PorKind))
	}
	if len(s.TopOrigens) > 0 {
		linha(w, t, "origens", contagens2(s.TopOrigens))
	}
	if len(s.TopUsuarios) > 0 {
		linha(w, t, "contas", contagens2(s.TopUsuarios))
	}
	if s.Divergentes > 0 {
		linha(w, t, "divergentes", strconv.Itoa(s.Divergentes)+
			" — uma testemunha registrou e a outra, tendo como registrar, não")
	}
	fmt.Fprintln(w)
}

func contagens2(cs []activity.Contagem) string {
	var out []string
	for _, c := range cs {
		out = append(out, Safe(c.Chave)+" ("+strconv.Itoa(c.N)+")")
	}
	return strings.Join(out, " · ")
}

// ActivityGrupos imprime a tabela do --group-by.
func ActivityGrupos(w io.Writer, gs []activity.Grupo, por string, cor bool) {
	t := temaPara(cor)
	if len(gs) == 0 {
		fmt.Fprintln(w, t.fraco("nenhum evento no recorte pedido — a cobertura abaixo diz sobre o quê"))
		fmt.Fprintln(w)
		return
	}
	cab, cruz := cabecalhoDoEixo(por)
	fmt.Fprintln(w, t.fraco(fmt.Sprintf("%-24s %8s %10s %7s  %s",
		cab, "ACEITOS", "RECUSADOS", "OUTROS", cruz)))
	for _, g := range gs {
		fmt.Fprintf(w, "%-24s %8d %10d %7d  %s\n",
			Safe(corta(g.Chave, 24)), g.Aceitos, g.Recusados, g.Outros,
			Safe(corta(strings.Join(cruzDoEixo(g, por), ", "), 30)))
	}
	fmt.Fprintln(w)
}

func cabecalhoDoEixo(por string) (string, string) {
	switch por {
	case activity.PorOrigem:
		return "ORIGEM", "CONTAS"
	case activity.PorUsuario:
		return "CONTA", "ORIGENS"
	}
	return "TIPO", "CONTAS"
}

func cruzDoEixo(g activity.Grupo, por string) []string {
	if por == activity.PorUsuario {
		return g.Origens
	}
	return g.Usuarios
}

// ActivityCobertura é o rodapé, e ele é obrigatório em toda saída deste
// comando.
//
// É ele que responde ao `--since`: pedir sete dias não faz a leitura alcançar
// sete dias, e a diferença entre o PEDIDO e o ALCANÇADO é a única coisa que
// separa "não houve" de "não olhei".
func ActivityCobertura(w io.Writer, fontes []activity.Fonte, f *facts.Facts,
	agora time.Time, solicitado, desde string, cor bool) {

	t := temaPara(cor)
	fmt.Fprintln(w, t.fraco("cobertura"))

	for _, s := range fontes {
		fmt.Fprintln(w, t.fraco("  "+pad(nomeDoPapel(s.Papel), 7)+Safe(coberturaBinaria(s))))
	}

	// A linha do PEDIDO cobre as fontes BINÁRIAS também.
	//
	// Ela nasceu olhando só para as famílias de log, e o efeito era o silêncio
	// justamente onde a leitura de login é mais curta: um `--since 7d` contra
	// um wtmp que alcança duas horas não produzia aviso nenhum. A informação
	// estava nas linhas de cima, e a linha que existe para RESUMIR o
	// descompasso pulava metade das fontes.
	var curtas []string
	for _, s := range fontes {
		if s.Papel == facts.PapelSessoes || !s.Lida() || s.CobreJanela || desde == "" {
			continue
		}
		curtas = append(curtas, nomeDoPapel(s.Papel)+" "+motivoDoCurto(s, agora))
	}
	for _, fam := range familiasDeAtividade {
		c := f.CoberturaLog(fam)
		fmt.Fprintln(w, t.fraco("  "+pad(fam, 7)+Safe(coberturaDeFamilia(f, c))))
		if !c.Existe {
			// A via só é NOMEADA quando a pergunta de fato não cabe neste host.
			// Com a leitura desligada, ou com a coleta que não chegou a olhar, o
			// arquivo existe — e mandar o operador ao journal seria conselho
			// errado sobre um alvo que tem o log em texto.
			if ehEscopo(f, c) {
				fmt.Fprintln(w, t.fraco("         via: "+Safe(viaExterna(fam, desde))))
			}
			continue
		}
		if desde != "" && c.Lida && c.ContinuoDesde > desde {
			curtas = append(curtas, fam+" alcança "+alcanceDe(c.ContinuoDesde, agora))
		}
	}
	if nota := notaDoAuditd(f); nota != "" {
		fmt.Fprintln(w, t.fraco("  "+pad("auditd", 7)+Safe(nota)))
	}

	if len(curtas) > 0 {
		fmt.Fprintln(w, t.fraco("  pedido "+Safe(solicitado)+": "+
			Safe(strings.Join(curtas, " · "))))
	}
}

// ehEscopo separa "esta pergunta não cabe neste host" de "ninguém olhou".
//
// CoberturaLog devolve Existe=false para os três casos, e eles mandam o
// operador para lugares opostos: journald-only é escopo; `--no-logs` e uma
// coleta que não chegou ao coletor são LACUNA, e a regra do projeto é que
// lacuna nunca se apresenta como escopo.
func ehEscopo(f *facts.Facts, c facts.CoberturaDeLog) bool {
	return f.LogEstado != "" && f.LogEstado != facts.LogDesativado && !c.Existe
}

// viaExterna monta um comando EXECUTÁVEL.
//
// A primeira versão interpolava o texto que o operador digitou, e ele nem
// sempre é uma duração: `--around 2026-08-26T15:03Z --window 5m` produzia
// `journalctl --since -±5m de 2026-08-26T15:03Z`, e um `--since` absoluto
// produzia `--since -2026-08-26T00:00Z`, que o journalctl recusa. Só a forma
// de duração pura funcionava — e esta linha é o payload inteiro da promessa de
// "escopo declarado, com a via nomeada", impressa em todo host journald-only.
//
// O instante ABSOLUTO da janela sempre funciona, nas duas ferramentas.
func viaExterna(familia, desde string) string {
	quando := ""
	if t, err := time.Parse(time.RFC3339, desde); err == nil {
		quando = t.UTC().Format("2006-01-02 15:04:05")
	}
	// O audit tem ferramenta PRÓPRIA. Mandar `journalctl` para ele é conselho
	// errado com cara de conselho.
	if familia == "audit" {
		if quando == "" {
			return "ausearch -m all"
		}
		return `ausearch -ts ` + quando
	}
	if quando == "" {
		return "journalctl"
	}
	return `journalctl --utc --since "` + quando + `"`
}

// notaDoAuditd diz por que a família `audit` pode estar calada por CONFIGURAÇÃO.
//
// A pergunta que o audit.log responde — o que executou — só vale se alguma
// regra registrar execução. Mas afirmar "SEM regra de execução" exige ter LIDO
// as regras, e /etc/audit é 0700 de root: numa execução sem privilégio o campo
// vem falso porque ninguém olhou. A primeira versão desta linha cometia, dentro
// do próprio rodapé de cobertura, o erro que o rodapé existe para impedir.
func notaDoAuditd(f *facts.Facts) string {
	if !f.Audit.Instalada {
		return ""
	}
	if len(f.PersistDenied["audit"]) > 0 {
		return "instalado, e as REGRAS não puderam ser lidas: não dá para dizer " +
			"se ele registra execução"
	}
	if f.Audit.Desligada {
		return "instalado e DESLIGADO (-e 0): nada é registrado"
	}
	if !f.Audit.CobreExec {
		return "instalado e sem regra de EXECUÇÃO: ausência de exec.audit é a " +
			"configuração, não o host"
	}
	return ""
}

// motivoDoCurto diz POR QUE aquela fonte não sustenta a janela pedida. As três
// razões mandam o operador para lugares diferentes: rodar com sudo, abrir a
// geração rotacionada, ou desconfiar do relógio.
func motivoDoCurto(s activity.Fonte, agora time.Time) string {
	switch {
	case s.RelogioAlterado:
		return "não demonstrável (relógio alterado)"
	case s.Desde == "":
		return "sem registro datável"
	}
	alc := s.Alcance(agora)
	if s.GeracoesNaoLidas > 0 {
		return "alcança " + alc + " (há rotacionado fechado ao lado)"
	}
	return "alcança " + alc
}

func coberturaBinaria(s activity.Fonte) string {
	switch {
	case !s.Existe():
		return "não há este arquivo neste host — o que ele registraria não é registrado"
	case !s.Lida():
		return "NÃO EXAMINADO — " + nz(s.Motivo, "o arquivo não foi lido")
	case s.Papel == facts.PapelSessoes:
		return "agora · " + strconv.Itoa(s.Lidos) + " registro(s)"
	case s.Desde == "" && s.Lidos == 0:
		return "VAZIO — a fonte foi lida e não entregou registro; isso não " +
			"afirma que não houve registro (ver antiforense.wtmp_cleared)"
	case s.Desde == "":
		return strconv.Itoa(s.Lidos) + " registro(s), nenhum datável"
	}
	out := s.Desde + " → " + s.Ate + " · " + strconv.Itoa(s.Lidos)
	if s.RelogioAlterado {
		// O intervalo continua impresso — ele é o que os carimbos DIZEM, e o
		// operador precisa vê-lo —, mas com a ressalva colada, porque as duas
		// pontas vêm de relógios diferentes.
		out = "[intervalo NÃO comparável] " + out
	}
	if s.Truncada {
		out += " de " + strconv.Itoa(s.Total) + " registros (TRUNCADO: o que veio " +
			"antes não foi examinado)"
	} else {
		out += " registro(s), lido inteiro"
	}
	if s.RelogioAlterado {
		out += " · RELÓGIO ALTERADO nesta faixa (ver sistema.clock_changed): o " +
			"alcance não é demonstrável"
	}
	if s.SemData > 0 {
		out += " · " + strconv.Itoa(s.SemData) + " sem data"
	}
	if s.NaoInterpretados > 0 {
		// Lidos e sem tradução para evento (getty ocioso, contabilidade de
		// init). Não somem em silêncio: sem esta contagem o rodapé dizia
		// "59 registros, lido inteiro" sobre uma linha do tempo de 45.
		out += " · " + strconv.Itoa(s.NaoInterpretados) + " sem tradução para evento"
	}
	if s.GeracoesNaoLidas > 0 {
		out += " · " + strconv.Itoa(s.GeracoesNaoLidas) +
			" geração(ões) ROTACIONADA(S) ao lado, não abertas"
	}
	return out
}

func coberturaDeFamilia(f *facts.Facts, c facts.CoberturaDeLog) string {
	switch {
	case f.LogEstado == "":
		return "DESCONHECIDA — esta coleta não chegou a olhar o conteúdo dos logs"
	case f.LogEstado == facts.LogDesativado:
		return "NÃO EXAMINADA — a leitura de conteúdo de log foi DESLIGADA nesta execução"
	case !c.Existe:
		return "FORA DE ESCOPO — " + nz(c.Motivo, "não há arquivo desta família neste host")
	case !c.Lida:
		return "NÃO EXAMINADA — " + nz(c.Motivo, "nenhum arquivo pôde ser lido")
	case c.ContinuoDesde == "":
		return nz(c.Motivo, "lida, sem intervalo datável")
	}
	out := c.ContinuoDesde + " → " + c.ContinuoAte
	if c.Buraco {
		// O trecho contínuo termina no buraco. Chamar a soma das gerações de
		// intervalo afirmaria cobertura sobre o que não foi observado.
		out += " (contínuo até aqui; há BURACO antes)"
	}
	return out
}

func alcanceDe(desde string, agora time.Time) string {
	t, err := time.Parse(time.RFC3339, desde)
	if err != nil {
		return desde
	}
	return activity.Duracao(agora.Sub(t))
}
