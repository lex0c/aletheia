package checks

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() {
	check.Register(chaveForaDasLocais)
	check.Register(sudoParaAlvoIncomum)
	check.Register(trilhaDeAuditoriaComBuraco)
	check.Register(buracoTemporalNoLog)
	check.Register(coberturaDeLog)
}

// Os checks sobre CONTEÚDO de log (runbook §10, §11, §12).
//
// # A regra que governa todos eles
//
// Log é ALEGAÇÃO, não fato: qualquer usuário escreve em /dev/log com um
// `logger`, e root reescreve o arquivo inteiro. Nenhum destes checks sai
// CRITICAL, e não é modéstia — é o que a fonte sustenta. CRITICAL a partir de
// log exige testemunha INDEPENDENTE (o inode, a base de pacotes, /proc, o utmp
// binário), e é isso que as correlações da próxima rodada fazem.
//
// # O que eles NÃO fazem
//
// Não repetem o que o utmp já dá. O wtmp/btmp registram quem entrou, quem
// falhou e quando, em binário de tamanho fixo, e checks/login.go já os lê —
// inclusive a força bruta que teve sucesso. Um check de força bruta a partir de
// texto seria a mesma conclusão por uma fonte mais fraca.
//
// # Escopo por FAMÍLIA, e não pela coleta inteira
//
// Um host pode ter audit.log lido e nenhum auth.log — é o Debian 12, que não
// instala rsyslog. Aí a pergunta sobre chave SSH não CABE, e sai do
// denominador; a sobre a trilha de auditoria cabe e roda. Cada check declara a
// família de que depende.

// escopoDaFamilia monta o Escopo de um check a partir da cobertura da família.
//
// A distinção que ele carrega é a que separa as duas leituras de uma lista
// vazia: o arquivo NÃO EXISTE (a pergunta não cabe neste host) e o arquivo
// existe e NÃO ABRIU (a pergunta cabe e ficou sem resposta). A primeira sai do
// denominador; a segunda fica nele e vira lacuna.
func escopoDaFamilia(familias ...string) func(*facts.Facts, *env.Env) (bool, string, []string) {
	return func(f *facts.Facts, _ *env.Env) (bool, string, []string) {
		if f.LogEstado == "" {
			// Dump anterior a esta versão, ou coleta que não chegou aqui. NÃO é
			// escopo: é desconhecimento, e desconhecimento fica no denominador
			// para virar lacuna no Run.
			return true, "", nil
		}
		if f.LogEstado == facts.LogDesativado {
			// Escolha de quem rodou, e não propriedade do host. Continua no
			// denominador: o Run declara a lacuna.
			return true, "", nil
		}
		for _, fam := range familias {
			if f.CoberturaLog(fam).Existe {
				return true, "", nil
			}
		}
		return false, "este host não tem log em TEXTO da(s) família(s) " +
				strings.Join(familias, ", ") + ": a pergunta não cabe aqui. É o caso do " +
				"journald-only (Debian 12, Fedora), onde a distribuição não instala " +
				"rsyslog e o journal é binário — não é que o log não pôde ser lido, é " +
				"que ele não existe em texto",
			[]string{
				"o journal responde a mesma pergunta e esta versão não o lê: " +
					"`journalctl -u ssh --since -7d` no host",
			}
	}
}

// lacunaDeLog é o preâmbulo COMUM a todos: a lacuna do coletor entra antes de
// qualquer saída, e o estado da coleta decide se há o que concluir.
//
// O padrão é o de checks/bpf.go, e existe porque o motor conta
// Coverage.Complete++ quando res.Partial sai vazio — um check que não lê a
// chave sai COMPLETO sobre uma fonte que o coletor declarou ilegível.
func lacunaDeLog(f *facts.Facts, r *check.Result) bool {
	r.Partial = append(r.Partial, f.Partial["logeventos"]...)
	switch f.LogEstado {
	case "":
		r.Partial = append(r.Partial, "este retrato não traz conteúdo de log "+
			"(coleta anterior à versão que o lê): nada pode ser afirmado sobre o "+
			"que os logs deste host registraram")
		return false
	case facts.LogDesativado:
		r.Partial = append(r.Partial, "a leitura de conteúdo de log foi DESLIGADA "+
			"nesta coleta (--no-logs, ou o orçamento do `wtf`): os logs NÃO foram "+
			"examinados, e ausência de evento não pode ser afirmada")
		return false
	}
	return true
}

// declaraHorizonte acrescenta à evidência ATÉ ONDE do passado esta família foi
// observada.
//
// Sem esta linha, todo achado de log carrega uma afirmação implícita e falsa:
// a de que o que não apareceu não aconteceu. O intervalo contínuo é a única
// coisa sobre a qual se pode dizer isso.
// familiaDoArquivo devolve a família da fonte de onde o evento veio.
//
// Existe porque o mesmo Kind chega por caminhos diferentes: um `auth.sudo` pode
// vir da linha do sudo no auth.log ou de um USER_CMD do auditd. Declarar o
// horizonte da família ERRADA imprimiria "nenhum evento da família auth pôde ser
// datado" ao lado de um achado que veio, datado, do audit.log.
func familiaDoArquivo(f *facts.Facts, path, padrao string) string {
	for i := range f.FontesDeLog {
		if f.FontesDeLog[i].Path != path {
			continue
		}
		if len(f.FontesDeLog[i].Familias) > 0 {
			return f.FontesDeLog[i].Familias[0]
		}
	}
	return padrao
}

func declaraHorizonte(f *facts.Facts, familia string, ev []string) []string {
	c := f.CoberturaLog(familia)
	if c.ContinuoDesde == "" {
		return append(ev, "ATENÇÃO: nenhum evento de log da família "+familia+
			" pôde ser datado — não há intervalo sobre o qual afirmar ausência")
	}
	linha := "observado de forma contínua entre " + c.ContinuoDesde + " e " +
		c.ContinuoAte + " (o que for anterior a isso NÃO foi lido)"
	if c.Buraco {
		linha += "; há BURACO antes disso: gerações mais antigas foram lidas em " +
			"pedaços, e o que está entre eles não foi observado"
	}
	return append(ev, linha)
}

// ---------------------------------------------------------------------------

// chaveForaDasLocais — runbook §12.
//
// O que só o log tem, e nenhuma outra fonte deste host: o FINGERPRINT da chave
// que abriu a sessão. O wtmp registra que alguém entrou; ele não registra COM O
// QUE. E com o fingerprint dá para fazer uma pergunta que não existia:
//
//	esta chave ainda está em algum authorized_keys?
//
// Quando não está, uma das coisas aconteceu: a chave foi removida DEPOIS de ser
// usada — que é o que se faz ao limpar o rastro —, ou ela nunca esteve ali e a
// autorização veio de outro lugar (CA, AuthorizedKeysCommand). O nome do check
// diz o FATO OBSERVADO, e não a conclusão: o fingerprint não aparece nas chaves
// locais.
var chaveForaDasLocais = check.Check{
	ID:       "logs.pubkey_not_in_local_keys",
	Ref:      "12",
	Title:    "login por chave cujo fingerprint não está em nenhum authorized_keys de agora",
	Group:    "priv",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Escopo:   escopoDaFamilia("auth"),
	FalsePositives: []string{
		"CERTIFICADO DE CA (`TrustedUserCAKeys`) autoriza sem que a chave esteja " +
			"em arquivo nenhum do host — é o desenho de frota grande, e ali este " +
			"achado sai em todo login legítimo",
		"`AuthorizedKeysCommand` busca a chave em LDAP, SSSD ou num serviço: o " +
			"authorized_keys local é vazio por construção",
		"ROTAÇÃO DE CHAVE legítima produz exatamente esta forma — a chave antiga " +
			"aparece no log e não está mais no arquivo",
		"o log pode alcançar mais para trás que a vida da chave: um login de " +
			"seis dias atrás com uma chave trocada ontem não é achado nenhum",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		if !lacunaDeLog(f, &r) {
			return r
		}
		// A AFIRMAÇÃO É SOBRE UMA AUSÊNCIA — "este fingerprint não está nas
		// chaves" —, e ausência só vale como evidência quando a fonte foi
		// olhada inteira. Sem root, o authorized_keys do home alheio é
		// ilegível, e acusar aqui seria acusar a partir de cegueira.
		if !f.SSHChavesCompleto {
			r.Partial = append(r.Partial, "o inventário de authorized_keys NÃO está "+
				"completo (home ilegível, ou coleta sem privilégio): não se pode "+
				"afirmar que um fingerprint está ausente dele")
			return r
		}

		locais := map[string]bool{}
		semImpressao := 0
		for i := range f.SSHKeys {
			if fp := f.SSHKeys[i].Fingerprint; fp != "" {
				locais[fp] = true
				continue
			}
			semImpressao++
		}
		// CHAVE SEM FINGERPRINT sai do conjunto de comparação, e o conjunto é o
		// que sustenta a afirmação de ausência. Medido: uma linha de
		// authorized_keys com base64 malformado é lida como chave (tipo e
		// comentário saem) e não produz impressão nenhuma.
		//
		// O achado CONTINUA saindo, e essa é a escolha: suprimi-lo deixaria uma
		// linha quebrada em qualquer authorized_keys do host desligar o check
		// inteiro — um jeito barato demais de calar a ferramenta. O que a lacuna
		// faz é impedir que a cobertura diga que a pergunta foi respondida.
		if semImpressao > 0 {
			r.Partial = append(r.Partial, strconv.Itoa(semImpressao)+" chave(s) "+
				"autorizada(s) não tiveram o fingerprint calculado (linha malformada): "+
				"elas ficaram FORA da comparação, e um login com uma delas apareceria "+
				"aqui como se a chave não existisse")
		}

		type uso struct {
			user, ip, quando string
			n                int
		}
		porChave := map[string]*uso{}
		var ordem []string
		for i := range f.EventosDeLog {
			ev := &f.EventosDeLog[i]
			if ev.Kind != "auth.accepted" || ev.Fingerprint == "" || locais[ev.Fingerprint] {
				continue
			}
			u := porChave[ev.Fingerprint]
			if u == nil {
				u = &uso{user: ev.User, ip: ev.RemoteIP, quando: ev.At}
				porChave[ev.Fingerprint] = u
				ordem = append(ordem, ev.Fingerprint)
			}
			u.n++
			if ev.At != "" && (u.quando == "" || ev.At > u.quando) {
				u.quando = ev.At
			}
		}
		sort.Strings(ordem)

		for _, fp := range ordem {
			u := porChave[fp]
			ev := []string{
				"o login foi ACEITO com a chave " + fp + " (usuário " + u.user +
					", origem " + nzLog(u.ip, "não registrada") + ")",
				"esse fingerprint não aparece em nenhum dos " +
					strconv.Itoa(len(locais)) + " authorized_keys observados AGORA",
				caveatDeChavesSemImpressao(semImpressao),
				strconv.Itoa(u.n) + " login(s) com esta chave no intervalo lido",
				"o log é ALEGAÇÃO do host sobre o próprio passado, não prova: quem " +
					"tem root reescreve estas linhas",
			}
			ev = declaraHorizonte(f, "auth", ev)
			fd := self.F(check.SevWarn, fp, "", ev...)
			fd.Chave = fp
			if u.quando != "" {
				fd.Quando, fd.QuandoFonte = u.quando, "último login registrado com esta chave"
			}
			fd.NextSteps = []string{
				"confirme com o dono da conta " + u.user + " se a chave foi removida " +
					"e quando — a data separa rotação de limpeza de rastro",
				"se o host usa CA ou AuthorizedKeysCommand, este achado é esperado: " +
					"confira `TrustedUserCAKeys` e `AuthorizedKeysCommand` no sshd_config",
				"procure o mesmo fingerprint nos outros hosts da frota: chave é IOC",
			}
			r.Findings = append(r.Findings, fd)
		}
		return r
	},
}

// ---------------------------------------------------------------------------

// diretoriosIncomuns são as árvores de onde software de sistema NÃO é
// executado como root.
//
// A lista é de CAMINHO, e não de conteúdo: ela não afirma que o programa é
// malicioso — afirma que o lugar de onde ele foi rodado não é de onde o
// sistema roda as coisas dele. É peneira, e o achado diz isso.
var diretoriosIncomuns = []string{
	"/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/home/", "/root/",
	"/var/www/", "/srv/", "/media/", "/mnt/",
}

// sudoParaAlvoIncomum — runbook §12.
//
// O `sudo … COMMAND=` é a segunda coisa que só o log tem: ele diz o que foi
// executado COMO ROOT, com o comando inteiro. O utmp não registra isso, e o
// processo já morreu.
var sudoParaAlvoIncomum = check.Check{
	ID:       "logs.sudo_unusual_target",
	Ref:      "12",
	Title:    "sudo executou programa de diretório de onde o sistema não roda nada",
	Group:    "priv",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Escopo:   escopoDaFamilia("auth", "audit"),
	FalsePositives: []string{
		"INSTALADOR E DEPLOY rodam de /tmp o tempo todo: ansible copia o módulo " +
			"para /tmp e o executa com sudo, cloud-init e CI fazem o mesmo, e um " +
			"`.deb`/`.rpm` baixado para /tmp é instalado exatamente assim",
		"administrador rodando um script do próprio home é rotina em servidor " +
			"pequeno, e cai em /home/",
		"o alvo é o que a LINHA diz, não o que rodou: quem tem root reescreve a " +
			"linha, e o programa pode ter sido outro",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		if !lacunaDeLog(f, &r) {
			return r
		}

		// SUDO CUJO ALVO NÃO PÔDE SER RESOLVIDO fica sem resposta, e o silêncio
		// sobre ele precisa ser dito.
		//
		// `sudo sh -c 'eval "$CMD"'` executa algo que este resolvedor não segue:
		// a pergunta "de que diretório?" simplesmente não tem resposta ali. Sem
		// esta linha, aquelas execuções saíam do relatório como se tivessem sido
		// avaliadas e aprovadas — a diferença entre "olhei e está bem" e "não
		// consegui olhar" desaparecendo dentro de um check.
		indeterminados := 0
		for i := range f.EventosDeLog {
			if f.EventosDeLog[i].Kind == "auth.sudo" && f.EventosDeLog[i].AlvoIndeterminado {
				indeterminados++
			}
		}
		if indeterminados > 0 {
			r.Partial = append(r.Partial, strconv.Itoa(indeterminados)+" linha(s) de "+
				"sudo executam algo que o resolvedor de alvos NÃO conseguiu seguir "+
				"(eval, substituição de comando, estrutura de controle): o diretório "+
				"de onde elas rodaram não foi avaliado")
		}

		for _, ag := range f.AgregarLog("auth.sudo") {
			if len(ag.Exemplos) == 0 {
				continue
			}
			for _, alvo := range ag.Exemplos[0].Alvos {
				dir, incomum := diretorioIncomum(alvo)
				if !incomum {
					continue
				}
				user := ag.Exemplos[0].User
				ev := []string{
					"sudo executou `" + alvo + "` (usuário " + nzLog(user, "não registrado") + ")",
					"o diretório " + dir + " não é de onde o sistema executa software: " +
						"pacote nenhum instala ali",
					strconv.Itoa(ag.Contagem) + " execução(ões) no intervalo lido" +
						intervaloDe(ag),
				}
				if temDono, sabido := propriedadeSabida(f, alvo); sabido && !temDono {
					// A testemunha INDEPENDENTE, quando existe: o inode está lá e
					// pacote nenhum o reivindica. Ainda assim não sobe para
					// CRITICAL — quem decide isso é a correlação, com o arquivo em
					// mãos.
					ev = append(ev, "e o arquivo existe HOJE sem dono de pacote: "+
						"as duas pontas apontam para o mesmo lugar")
				}
				ev = append(ev,
					"o log é ALEGAÇÃO do host sobre o próprio passado, não prova")
				ev = declaraHorizonte(f, familiaDoArquivo(f, ag.Exemplos[0].File, "auth"), ev)

				fd := self.F(check.SevWarn, alvo, "", ev...)
				fd.Chave = user + " " + alvo
				if ag.Ultimo != "" {
					fd.Quando, fd.QuandoFonte = ag.Ultimo, "última execução registrada no log"
				}
				fd.NextSteps = []string{
					"o arquivo pode não existir mais: `ls -la " + alvo + "` responde " +
						"se ele sobreviveu, e o ctime data a criação",
					"confirme com o time se " + nzLog(user, "o usuário") + " tinha " +
						"motivo para rodar isso — instalador e automação produzem a mesma forma",
					"se o arquivo existe, preserve antes de qualquer coisa: " +
						"`aletheia preserve " + alvo + "`",
				}
				r.Findings = append(r.Findings, fd)
			}
		}
		return r
	},
}

func diretorioIncomum(alvo string) (string, bool) {
	for _, d := range diretoriosIncomuns {
		if strings.HasPrefix(alvo, d) {
			return strings.TrimSuffix(d, "/"), true
		}
	}
	return "", false
}

// ---------------------------------------------------------------------------

// trilhaDeAuditoriaComBuraco — runbook §11.
//
// A trilha do auditd é a fonte que preserva EXECUÇÃO, e é a que responde o que
// rodou antes da varredura. Ela ganha buraco de três jeitos, e os três estão no
// próprio kernel (kernel/audit.c):
//
//	audit_lost=N            o kernel não conseguiu entregar N registros
//	backlog limit exceeded  a fila encheu — inundar o auditd é técnica de evasão
//	DAEMON_ABORT            o daemon caiu
//
// E de um quarto, que NÃO é a mesma coisa:
//
//	DAEMON_END              alguém parou o auditd. Reinício administrativo é o
//	                        caso comum, e por isso ele sai MANUAL
var trilhaDeAuditoriaComBuraco = check.Check{
	ID:       "logs.audit_records_lost",
	Ref:      "11",
	Title:    "a trilha de auditoria tem buraco",
	Group:    "logs",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Escopo: func(f *facts.Facts, e *env.Env) (bool, string, []string) {
		if f.LogEstado == "" || f.LogEstado == facts.LogDesativado {
			return true, "", nil
		}
		if f.Audit.Instalada || f.CoberturaLog("audit").Existe {
			return true, "", nil
		}
		return false, "este host não tem auditoria instalada: não há trilha para " +
				"ter buraco. Auditoria não é padrão em quase nenhuma distribuição, e " +
				"contêiner nunca tem — a pergunta não cabe aqui",
			[]string{
				"a capacidade de registrar execução deste host é assunto do " +
					"antiforense.audit_disabled, que roda sempre",
			}
	},
	FalsePositives: []string{
		"PICO DE CARGA legítimo com `-b` baixo enche a fila: um backup, uma " +
			"compilação ou um deploy grande produzem perda sem que ninguém tenha " +
			"atacado nada",
		"REINÍCIO ADMINISTRATIVO do auditd (atualização de pacote, mudança de " +
			"regra) emite DAEMON_END — e é por isso que ele sai MANUAL, e não como " +
			"aviso",
		"rotação do próprio audit.log emite registros de parada em algumas " +
			"configurações",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		if !lacunaDeLog(f, &r) {
			return r
		}

		var perdaForte, paradaLimpa int
		var quando string
		var exemplos []string
		for i := range f.EventosDeLog {
			ev := &f.EventosDeLog[i]
			if ev.Kind != "audit.lost" {
				continue
			}
			if ev.At > quando {
				quando = ev.At
			}
			if len(exemplos) < 3 && ev.Trecho != "" {
				exemplos = append(exemplos, ev.Trecho)
			}
			if ev.Metodo == "end" {
				paradaLimpa++
				continue
			}
			perdaForte++
		}
		if perdaForte == 0 && paradaLimpa == 0 {
			return r
		}

		sev := check.SevWarn
		sujeito := "registros perdidos"
		linhas := []string{
			strconv.Itoa(perdaForte) + " ocorrência(s) de PERDA de registro " +
				"(audit_lost, backlog estourado, ou queda do daemon)",
			"o que não foi registrado não volta: a execução daquele intervalo não " +
				"tem trilha",
			"encher a fila do auditd de propósito é técnica de evasão — barata, e " +
				"não deixa outro rastro",
		}
		if perdaForte == 0 {
			// PARADA LIMPA sozinha é MANUAL: atualização de pacote e mudança de
			// regra param o auditd, e acusá-las como evasão gritaria em toda
			// frota que mantém o auditd atualizado.
			sev = check.SevManual
			sujeito = "auditoria parada"
			linhas = []string{
				strconv.Itoa(paradaLimpa) + " parada(s) LIMPA(s) do auditd (DAEMON_END)",
				"parada limpa é o que uma atualização de pacote ou uma mudança de " +
					"regra fazem: sozinha, não é achado",
				"o que ela significa é que houve um intervalo SEM trilha, e é isso " +
					"que precisa ser datado",
			}
		} else if paradaLimpa > 0 {
			linhas = append(linhas, "e mais "+strconv.Itoa(paradaLimpa)+
				" parada(s) limpa(s) do daemon")
		}
		for _, x := range exemplos {
			linhas = append(linhas, "registro: "+x)
		}
		linhas = declaraHorizonte(f, "audit", linhas)

		fd := self.F(sev, sujeito, "", linhas...)
		if quando != "" {
			fd.Quando, fd.QuandoFonte = quando, "última perda registrada no audit.log"
		}
		fd.NextSteps = []string{
			"`auditctl -s` mostra lost e backlog ATUAIS: compare com o que o log diz",
			"o intervalo sem trilha precisa ser coberto por outra fonte — o " +
				"auth.log, o journal, ou o log central, se houver",
			"se a perda for recorrente e sem pico de carga que a explique, trate o " +
				"intervalo como não observado",
		}
		r.Findings = append(r.Findings, fd)
		return r
	},
}

// ---------------------------------------------------------------------------

// buracoMinimoNoLog é a distância a partir da qual um silêncio entre duas
// gerações passa a merecer uma linha no relatório.
//
// 24 horas, e generoso de propósito: a rotação normalmente encosta uma geração
// na outra em segundos, mas um servidor pouco acessado fica dias sem uma linha
// de autenticação, legitimamente. Um limiar apertado transformaria calmaria em
// achado.
const buracoMinimoNoLog = 24 * time.Hour

// buracoTemporalNoLog — runbook §10.
//
// Apagar linha é mais barato que apagar arquivo, e não deixa buraco na
// sequência de rotação — que é o que o antiforense.log_rotation_gap procura.
// O que sobra é o TEMPO: entre o fim de uma geração e o começo da seguinte não
// deveria haver um vão.
//
// # Por que MANUAL, e não aviso
//
// Porque ausência de linha não prova remoção. Um host desligado, um servidor
// que ninguém acessou, o `minsize` do logrotate adiando a rotação: os três
// produzem exatamente esta forma. Promover isso a aviso por falta de reboot
// seria concluir de uma ausência (não houve reboot) sobre outra ausência (não
// houve linha) — e nenhuma das duas é testemunha.
//
// A promoção pertence à correlação com o wtmp, onde há testemunha INDEPENDENTE:
// um login que o wtmp registrou DENTRO do vão que o auth.log não tem.
var buracoTemporalNoLog = check.Check{
	ID:       "antiforense.log_time_gap",
	Ref:      "10",
	Title:    "vão de tempo entre duas gerações do log de autenticação",
	Group:    "logs",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Escopo:   escopoDaFamilia("auth"),
	FalsePositives: []string{
		"HOST DESLIGADO ou ocioso não escreve linha nenhuma: um servidor pouco " +
			"acessado fica dias sem registro de autenticação, legitimamente",
		"`minsize` do logrotate adia a rotação até o arquivo crescer — as datas " +
			"das gerações deixam de ser regulares por desenho, e é o padrão do " +
			"wtmp no RHEL",
		"mudança de configuração de rotação (frequência, compressão) reposiciona " +
			"os limites das gerações",
		"log movido à mão durante a resposta a incidente deixa exatamente esta " +
			"forma: quem varre um host DEPOIS de outra pessoa vê o rastro dela",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		if !lacunaDeLog(f, &r) {
			return r
		}

		type faixa struct {
			path       string
			desde, ate string
		}
		var faixas []faixa
		for i := range f.FontesDeLog {
			s := &f.FontesDeLog[i]
			if !ehFamilia(s, "auth") || s.CobertoDesde == "" || s.CobertoAte == "" {
				continue
			}
			// O arquivo lido em DUAS PONTAS tem um vão que é NOSSO, não do host:
			// o miolo não foi lido. Usá-lo aqui acusaria o host do teto da
			// ferramenta.
			if s.LeituraDescontinua {
				continue
			}
			faixas = append(faixas, faixa{s.Path, s.CobertoDesde, s.CobertoAte})
		}
		if len(faixas) < 2 {
			return r
		}
		sort.Slice(faixas, func(i, j int) bool { return faixas[i].ate < faixas[j].ate })

		for i := 0; i+1 < len(faixas); i++ {
			fim, err1 := time.Parse(time.RFC3339, faixas[i].ate)
			ini, err2 := time.Parse(time.RFC3339, faixas[i+1].desde)
			if err1 != nil || err2 != nil {
				continue
			}
			vao := ini.Sub(fim)
			if vao < buracoMinimoNoLog {
				continue
			}
			dias := int(vao.Hours() / 24)
			ev := []string{
				faixas[i].path + " termina em " + faixas[i].ate,
				faixas[i+1].path + " começa em " + faixas[i+1].desde,
				"são " + strconv.Itoa(dias) + " dia(s) sem UMA linha de autenticação " +
					"entre duas gerações consecutivas",
				"a rotação encosta uma geração na outra em segundos: um vão aqui é " +
					"tempo sem registro, e apagar linhas produz exatamente esta forma",
				"NÃO é prova de remoção: host desligado, servidor ocioso e `minsize` " +
					"do logrotate produzem a mesma coisa — por isso isto é MANUAL",
			}
			fd := self.F(check.SevManual, faixas[i+1].path, "", ev...)
			fd.Chave = faixas[i].path + "→" + faixas[i+1].path
			fd.Quando, fd.QuandoFonte = faixas[i].ate, "última linha antes do vão"
			fd.NextSteps = []string{
				"o wtmp é testemunha INDEPENDENTE: `last -F` mostra se houve login " +
					"dentro do vão. Se houve, o silêncio do auth.log deixa de ter " +
					"explicação inocente",
				"`last -x reboot` diz se o host esteve desligado no período",
				"o ctime das gerações data a última escrita em cada uma",
				"se houver servidor de log central, compare o mesmo intervalo lá",
			}
			r.Findings = append(r.Findings, fd)
		}
		return r
	},
}

func ehFamilia(s *facts.FonteDeLog, familia string) bool {
	for _, fam := range s.Familias {
		if fam == familia {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------

// coberturaDeLog — runbook §10.
//
// Este check não acusa nada: ele DIZ ATÉ ONDE se olhou. É o que impede os
// outros quatro de carregarem uma afirmação implícita e falsa — a de que o que
// não apareceu no log não aconteceu.
//
// Ele é o único sem Escopo, e de propósito: num host journald-only os outros
// saem do denominador, e alguém precisa continuar dizendo por quê.
var coberturaDeLog = check.Check{
	ID:       "logs.source_coverage",
	Ref:      "10",
	Title:    "até onde do passado os logs deste host foram observados",
	Group:    "logs",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	FalsePositives: []string{
		"nenhum: este check não acusa comportamento nenhum. Ele reporta o ALCANCE " +
			"da observação, e é o que permite ler o silêncio dos outros",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		if !lacunaDeLog(f, &r) {
			return r
		}

		if f.LogEstado == facts.LogForaDeEscopo {
			// O PRECEDENTE do `dateext` em checks/logs.go: isto é ESCOPO, e sai
			// como informação. Como lacuna, faria toda varredura de host moderno
			// sair INCOMPLETE — inclusive a de um host limpo —, e uma lacuna que
			// nunca fecha deixa de ser lida.
			fd := self.F(check.SevInfo, "sem log em texto", "",
				"este host não tem arquivo de log em TEXTO sob /var/log",
				"é o journald-only: Debian 12, Fedora e derivados não instalam "+
					"rsyslog, e o journal é binário — esta versão não o lê",
				"não é que o log não pôde ser lido: ele não existe nesta forma. Por "+
					"isso a cobertura NÃO cai — é escopo, não lacuna",
				"para este host, a via é o journal: `journalctl --since -7d`")
			fd.NextSteps = []string{
				"`journalctl -u ssh --since -7d` para autenticação",
				"`journalctl -k --since -7d` para o kernel",
				"se houver auditd, /var/log/audit/audit.log é texto e FOI lido",
			}
			r.Findings = append(r.Findings, fd)
			return r
		}

		var linhas []string
		familias := []string{"auth", "syslog", "kern", "cron", "audit"}
		observadas := 0
		for _, fam := range familias {
			c := f.CoberturaLog(fam)
			if !c.Existe {
				continue
			}
			observadas++
			if c.ContinuoDesde == "" {
				linhas = append(linhas, fam+": os arquivos existem e NENHUM evento "+
					"pôde ser datado")
				continue
			}
			l := fam + ": contínuo de " + c.ContinuoDesde + " a " + c.ContinuoAte
			if c.Buraco {
				l += " — e com BURACO antes disso"
			}
			linhas = append(linhas, l)
		}
		if observadas == 0 {
			return r
		}

		if f.LogJanelaSolicitada != "" {
			linhas = append(linhas, "o horizonte PEDIDO foi "+f.LogJanelaSolicitada+
				", e o ALCANÇADO é o que está acima: num arquivo grande a leitura "+
				"pega a cauda, e a diferença entre os dois é o que ninguém leu")
		}
		linhas = append(linhas,
			strconv.Itoa(len(f.EventosDeLog))+" evento(s) normalizados de "+
				strconv.Itoa(len(f.FontesDeLog))+" arquivo(s)",
			"log é ALEGAÇÃO do host sobre o próprio passado: quem tem root "+
				"reescreve estas linhas, e ausência de registro não é ausência de fato")

		if !f.FusoDoAlvoLido {
			linhas = append(linhas, "ATENÇÃO: o fuso do alvo (/etc/localtime) não "+
				"foi lido — as datas do syslog foram interpretadas como UTC, e um "+
				"offset errado desloca toda correlação com mtime e com o wtmp")
		}

		fd := self.F(check.SevInfo, "cobertura de log", "", linhas...)
		fd.NextSteps = []string{
			"o que for anterior ao intervalo acima não foi lido: `--logs-all` " +
				"amplia a seleção, e `--since` amplia a janela",
			"para o intervalo não coberto, a via é o servidor de log central, se houver",
		}
		r.Findings = append(r.Findings, fd)
		return r
	},
}

// caveatDeChavesSemImpressao entra na EVIDÊNCIA, e não só na cobertura: quem lê
// o achado precisa saber que a comparação foi feita contra um conjunto
// incompleto — a lacuna aparece no rodapé, e o achado é lido no meio.
func caveatDeChavesSemImpressao(n int) string {
	if n == 0 {
		return "o inventário de chaves foi lido inteiro, e a comparação é contra ele"
	}
	return "ATENÇÃO: " + strconv.Itoa(n) + " chave(s) autorizada(s) ficaram fora da " +
		"comparação por não ter fingerprint calculável — esta pode ser uma delas"
}

func nzLog(s, padrao string) string {
	if s == "" {
		return padrao
	}
	return s
}

func intervaloDe(ag facts.AgregadoDeLog) string {
	if ag.Primeiro == "" || ag.Ultimo == "" {
		return ""
	}
	if ag.Primeiro == ag.Ultimo {
		return " (em " + ag.Primeiro + ")"
	}
	return " (de " + ag.Primeiro + " a " + ag.Ultimo + ")"
}
