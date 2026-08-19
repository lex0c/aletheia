package checks

import (
	"sort"
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() {
	check.Register(mapsRWXAnon)
	check.Register(mapsExecAnon)
	check.Register(mapeamentoApagado)
	check.Register(nsDivergent)
}

// mapsRWXAnon — runbook §3.10.
//
// Região gravável E executável, sem arquivo nenhum por trás: código que nunca
// existiu em disco. É o que o malfind do Volatility procura, e o que
// `MemoryDenyWriteExecute=yes` torna impossível (runbook §34.1).
//
// O que o check NÃO faz é disparar em rwx com arquivo por trás, nem em runtime
// com JIT. Java, Node e .NET geram código em memória o tempo todo — é a
// operação normal deles, e reportá-los transformaria o check em ruído de fundo
// em metade dos hosts.
var mapsRWXAnon = check.Check{
	ID:       "proc.maps_rwx_anon",
	Ref:      "3.10",
	Title:    "região de memória gravável, executável e sem arquivo por trás",
	Group:    "proc",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Optional: env.CapRoot | env.CapPkgDB,
	Wtf:      true,
	FalsePositives: []string{
		"runtime com JIT (Java, Node, .NET, navegador, QEMU) usa rwx anônimo por " +
			"projeto — os conhecidos, de diretório de sistema E COM DONO DE PACOTE, " +
			"são pulados. Payload copiado para /usr/bin/node não escapa: casa o nome, " +
			"não o dono (a matriz adversarial provou o bypass)",
		"empacotador (UPX e afins) descomprime para memória rwx: binário legítimo " +
			"empacotado cai aqui",
		"BLIND SPOT do descarte acima: código injetado DENTRO de uma JVM ou de um " +
			"processo Node não é visto por este check. Para esses, o sinal é o " +
			"proc.tracer e a §29 (dump de memória)",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		var denied int
		semDono := caminhosSemDono(f)
		temPkgDB := e.Has(env.CapPkgDB)
		// isentos são os processos que a regra de runtime com JIT tirou da
		// pergunta. Eles NÃO foram avaliados, e o número precisa chegar à
		// cobertura.
		var isentos []string
		for i := range f.Processes {
			p := &f.Processes[i]
			if p.Self || p.Vanished {
				continue
			}
			// Conta a lacuna, mas NÃO descarta: um maps lido pela metade pode
			// já ter revelado a região rwx, e achado é achado.
			if p.MapsDenied {
				denied++
			}
			var anon []string
			for _, m := range p.MapsRWX {
				if strings.Contains(m, "(anônimo)") {
					anon = append(anon, m)
				}
			}
			if len(anon) == 0 {
				continue
			}
			if ehJITConfiavel(p, semDono, temPkgDB) {
				// A isenção existe e é necessária — sem ela, todo host com
				// navegador ou JVM vira uma parede de achados. Mas ela é uma
				// decisão de NÃO OLHAR, e decisão de não olhar se DECLARA.
				//
				// A ressalva morava só em FalsePositives, que é impresso junto
				// de um achado — e supressão significa achado nenhum, então ela
				// nunca era impressa para os processos a que se aplicava. Medido
				// num contêiner: implante com rwx anônimo dentro de
				// /usr/lib/node/node saía com "cobertura 89/89 completa".
				isentos = append(isentos, nz(p.Exe, p.Comm))
				continue
			}

			ev := []string{
				strconv.Itoa(len(anon)) + " região(ões) rwx sem arquivo: " + firstN(anon, 3),
				"exe=" + nz(p.Exe, "?") + " comm=" + p.Comm + " uid=" + strconv.Itoa(p.UID),
			}
			if len(p.MapsOdd) > 0 {
				// Biblioteca carregada de fora dos diretórios de sistema junto
				// com memória rwx é a forma de LD_PRELOAD (runbook §7.8).
				ev = append(ev, "e mapeia biblioteca fora dos diretórios de sistema: "+
					firstN(p.MapsOdd, 3))
			}
			for _, t := range p.Truncated {
				ev = append(ev, "atenção: "+t)
			}

			fd := self.F(check.SevWarn, "pid="+strconv.Itoa(p.PID), "", ev...)
			fd.Quando, fd.QuandoFonte = p.StartUTC, "início do processo"
			fd.Irreversible = true
			fd.NextSteps = []string{
				"o código só existe na memória deste processo: matá-lo destrói a " +
					"única cópia (runbook §29)",
				// `--mem` dumpa as regiões ANÔNIMAS sem ptrace — sem parar o
				// processo e sem escrever TracerPid, que é o que o `gcore`
				// recomendado aqui antes fazia. As regiões rwx entram primeiro,
				// caso o teto corte a coleta.
				preservarPID(e, p.PID, "--mem"),
				"o binário em disco não explica o que está rodando — compare com " +
					"a §24 antes de concluir que o pacote está íntegro",
			}
			r.Findings = append(r.Findings, fd)
		}
		if denied > 0 {
			r.Partial = append(r.Partial, strconv.Itoa(denied)+
				" processos com /proc/<pid>/maps ilegível não foram avaliados")
		}
		if n := len(isentos); n > 0 {
			// UMA linha, e não uma por processo: um desktop tem dezenas de
			// processos de navegador, e N degradações pela mesma decisão
			// afogariam a seção que existe para ser lida.
			r.Partial = append(r.Partial, strconv.Itoa(n)+
				" processo(s) com região rwx anônima NÃO foram avaliados por serem "+
				"runtime com JIT em diretório de sistema e com dono de pacote ("+firstN(dedupOrdenado(isentos), 3)+
				"): código injetado DENTRO de um deles não é distinguível daqui do "+
				"código que o próprio runtime gera")
		}
		return r
	},
}

// mapsExecAnon — runbook §3.10.
//
// # A metade que o mapsRWXAnon não alcança
//
// O check irmão procura gravável E executável ao mesmo tempo, que é a forma de
// quem escreve o código e o executa sem cerimônia. A injeção que respeita W^X
// nunca apresenta esse estado:
//
//	mmap(RW) → write(payload) → mprotect(RX)
//
// Depois do mprotect a região é r-xp anônima, e o 'w' que o outro check exige
// não existe mais. Um retrato tirado um segundo depois não vê nada.
//
// # Por que "sem nome" faz parte do critério
//
// Desde o 5.17 o kernel guarda um rótulo por região anônima
// (PR_SET_VMA_ANON_NAME), e o JIT moderno rotula o código que gera. Medido num
// desktop com Firefox, Sublime e node vivos: 85 regiões
// [anon:js-executable-memory], 1 [anon:JSJITCode] — e ZERO regiões executáveis
// anônimas sem rótulo em 313 processos legíveis. O piso de ruído deste check,
// naquele host, é nenhum achado.
//
// O rótulo não é prova: quem injeta também pode chamar prctl e escrever
// "[anon:js-executable-memory]" na própria região. Ele é DISCRIMINADOR — e o
// caso em que discrimina bem é o que está descrito abaixo, no runtime que
// rotula as suas e deixa uma sem rótulo.
//
// # Severidade: WARN, e não CRITICAL
//
// Duas razões, e as duas são de coerência. O mapsRWXAnon, que é o sinal MAIS
// forte, é WARN — um irmão mais fraco não pode acusar mais. E o motor já
// resolve a correlação por conta própria: promover aqui por conjunção de sinais
// seria a aritmética que engine.go recusa explicitamente, e que quebra o exit
// code de toda frota que compila software fora do gerenciador de pacotes. As
// correlações entram como EVIDÊNCIA, e quem as junta num alvo só é o motor.
var mapsExecAnon = check.Check{
	ID:       "proc.maps_exec_anon",
	Ref:      "3.10",
	Title:    "código executável em memória, sem arquivo e sem rótulo",
	Group:    "proc",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Optional: env.CapRoot | env.CapPkgDB,
	Wtf:      true,
	FalsePositives: []string{
		"runtime com JIT em kernel ANTIGO é pulado — até o 5.17 não havia rótulo " +
			"de região e o JIT aparece como anônimo sem nome —, mas SÓ se o binário " +
			"tiver dono de pacote: um payload rodando como /usr/bin/node sem dono " +
			"NÃO é isento (o bypass que a matriz adversarial demonstrou)",
		"empacotador (UPX e afins) que descomprime para memória e protege a " +
			"região depois: binário legítimo empacotado cai aqui",
		"o rótulo é escrito pelo PROCESSO (prctl), não pelo kernel: por isso ele " +
			"só é confiado em RUNTIME confiável (nome de JIT conhecido, diretório de " +
			"sistema, dono de pacote). Num não-JIT, região executável rotulada conta " +
			"como qualquer injeção — o rótulo roubado não protege",
		"BLIND SPOT: em runtime com JIT de kernel antigo, injeção DENTRO dele " +
			"não é distinguível daqui — o sinal para esses é o proc.tracer e a §29",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		var denied int
		var isentos []string
		semDono := caminhosSemDono(f)
		temPkgDB := e.Has(env.CapPkgDB)
		for i := range f.Processes {
			p := &f.Processes[i]
			if p.Self || p.Vanished {
				continue
			}
			// Conta a lacuna e NÃO descarta: um maps lido pela metade pode já
			// ter revelado a região, e achado é achado.
			if p.MapsDenied {
				denied++
			}
			confiavel := ehJITConfiavel(p, semDono, temPkgDB)
			// O runtime que rotula as PRÓPRIAS regiões executáveis se
			// autodenuncia como capaz de rotular. Nesse processo, uma região
			// sem rótulo não é explicada pelo que ele gera — e é justamente o
			// BLIND SPOT que o check irmão declara e não consegue cobrir.
			autorrotula := len(p.MapsExecNomes) > 0

			// Rótulos ROUBADOS, o segundo bypass da mesma classe que o exe
			// /usr/bin/node: o rótulo de região é settável por prctl, e um
			// processo que NÃO é um JIT confiável usando [anon:js-executable-memory]
			// está copiando a etiqueta para escapar da contagem. Num não-JIT, a
			// região executável anônima ROTULADA vale tanto quanto a sem rótulo —
			// o rótulo não vem de um runtime, vem do atacante.
			var rotulados []string
			if !confiavel {
				rotulados = p.MapsExecNomes
			}

			if p.MapsExecAnonN == 0 && len(rotulados) == 0 {
				continue
			}
			if confiavel && !autorrotula {
				isentos = append(isentos, nz(p.Exe, p.Comm))
				continue
			}

			total := p.MapsExecAnonN + len(rotulados)
			ev := []string{
				strconv.Itoa(total) + " região(ões) executáveis anônimas sem arquivo: " +
					firstN(p.MapsExecAnon, 3),
				"exe=" + nz(p.Exe, "?") + " comm=" + p.Comm + " uid=" + strconv.Itoa(p.UID),
			}
			if p.MapsExecAnonN > len(p.MapsExecAnon) {
				ev = append(ev, "a amostra acima tem "+strconv.Itoa(len(p.MapsExecAnon))+
					" de "+strconv.Itoa(p.MapsExecAnonN)+" regiões sem rótulo")
			}
			if len(rotulados) > 0 {
				ev = append(ev, strconv.Itoa(len(rotulados))+" região(ões) usam RÓTULO de JIT "+
					"sem o processo ser um runtime confiável ("+firstN(rotulados, 2)+"): o "+
					"rótulo é settável e não vale nada aqui — é a mesma etiqueta roubada "+
					"do bypass do exe")
			} else if autorrotula {
				ev = append(ev, "e este processo ROTULA as próprias regiões de JIT ("+
					firstN(p.MapsExecNomes, 2)+"): o que ele gera se identifica, e "+
					"estas não se identificam")
			}
			// As correlações NÃO promovem a severidade — ver o comentário do
			// check. Elas dizem ao operador por onde continuar, e o motor as
			// junta num alvo só quando o check de cada uma também dispara.
			if p.TracerPID > 0 {
				ev = append(ev, "e o processo está sob ptrace (TracerPid="+
					strconv.Itoa(p.TracerPID)+"): alguém tem acesso de escrita a esta memória")
			}
			switch {
			case p.ExeMemfd:
				ev = append(ev, "e o executável nunca esteve em disco (memfd)")
			case p.ExeDeleted:
				ev = append(ev, "e o executável foi apagado do disco")
			}
			if p.Exe != "" && semDono[p.Exe] {
				if d := destinosPublicos(f, p.PID); len(d) > 0 {
					ev = append(ev, "e nenhum pacote reivindica o binário, que fala com "+
						firstN(d, 3))
				} else {
					ev = append(ev, "e nenhum pacote reivindica o binário")
				}
			}
			if len(p.MapsOdd) > 0 {
				ev = append(ev, "e mapeia biblioteca fora dos diretórios de sistema: "+
					firstN(p.MapsOdd, 3))
			}
			for _, t := range p.Truncated {
				ev = append(ev, "atenção: "+t)
			}

			fd := self.F(check.SevWarn, "pid="+strconv.Itoa(p.PID), "", ev...)
			fd.Quando, fd.QuandoFonte = p.StartUTC, "início do processo"
			fd.Irreversible = true
			fd.NextSteps = []string{
				"o código só existe na memória deste processo: matá-lo destrói a " +
					"única cópia (runbook §29)",
				preservarPID(e, p.PID, "--mem"),
				"compare a região com o que o binário em disco explica antes de " +
					"concluir que o pacote está íntegro (runbook §24)",
			}
			r.Findings = append(r.Findings, fd)
		}
		if denied > 0 {
			r.Partial = append(r.Partial, strconv.Itoa(denied)+
				" processos com /proc/<pid>/maps ilegível não foram avaliados")
		}
		if n := len(isentos); n > 0 {
			r.Partial = append(r.Partial, strconv.Itoa(n)+
				" processo(s) com região executável anônima NÃO foram avaliados por "+
				"serem runtime com JIT em diretório de sistema SEM rótulo de região ("+
				firstN(dedupOrdenado(isentos), 3)+"): em kernel anterior ao 5.17 o "+
				"código que o runtime gera é indistinguível daqui do código injetado nele")
		}
		return r
	},
}

// mapeamentoApagado — runbook §3.14.
//
// # O que o proc.exe_deleted não vê
//
// O executável apagado já tem check. Uma BIBLIOTECA apagada, não:
//
//	dlopen("/tmp/.x.so")  →  unlink("/tmp/.x.so")
//
// O processo continua executando aquele código, e o /proc/<pid>/exe dele
// continua apontando para um caminho perfeitamente legítimo. Nada no
// executável principal registra o que aconteceu.
//
// # O filtro que decide tudo: EXECUTÁVEL
//
// Medido num desktop, em 313 processos legíveis: 713 mapeamentos apagados NÃO
// executáveis — /memfd:mozilla-ipc, /etc/ld.so.cache, /SYSV…, dconf — e ZERO
// executáveis. Sem o filtro, o check afoga na primeira execução; com ele, o
// piso de ruído naquele host é nenhum achado.
//
// # A história legítima, e como ela é separada
//
// Atualização de pacote com o serviço no ar deixa exatamente esta linha no
// maps: o arquivo foi substituído, e todo processo vivo segura o inode antigo.
// É o estado que o needrestart detecta, e num servidor sem reinício ele vale
// por centenas de processos.
//
// O discriminador é o caminho VOLTAR a existir. Quando volta, isto vira uma
// linha informativa — que ainda é útil, porque reinício pendente explica outros
// achados. Quando não volta, alguém apagou e ninguém repôs.
var mapeamentoApagado = check.Check{
	ID:       "proc.deleted_mapping",
	Ref:      "3.14",
	Title:    "biblioteca apagada do disco, ainda mapeada e executável",
	Group:    "proc",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Optional: env.CapRoot | env.CapPkgDB,
	Wtf:      true,
	FalsePositives: []string{
		"ATUALIZAÇÃO DE PACOTE é a causa comum, e não vira aviso: o caminho volta " +
			"a existir e o achado sai como uma linha informativa agregada — que " +
			"é a mesma condição que o needrestart reporta",
		"runtime que carrega código por memfd (JIT, empacotador) é pulado pelo " +
			"nome do binário quando roda de diretório de sistema",
		"desinstalação de pacote com o serviço ainda no ar deixa o caminho sem " +
			"voltar a existir — é a forma de um aviso legítimo aqui",
		"sem root, o maps de processo alheio é ilegível e não há o que avaliar",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		var denied int
		var isentos []string
		semDono := caminhosSemDono(f)
		temPkgDB := e.Has(env.CapPkgDB)
		// Os recriados viram UMA linha agregada. Uma por processo seria uma
		// parede de centenas num servidor com reinício pendente, e a parede
		// enterraria os poucos que importam.
		var recriados int
		var recriadosEx []string
		for i := range f.Processes {
			p := &f.Processes[i]
			if p.Self || p.Vanished {
				continue
			}
			if p.MapsDenied {
				denied++
			}
			for _, m := range p.MapsApagados {
				if m.Memfd {
					if ehJITConfiavel(p, semDono, temPkgDB) {
						isentos = append(isentos, nz(p.Exe, p.Comm))
						continue
					}
					r.Findings = append(r.Findings, achadoDeMapaApagado(self, e, p, m,
						check.SevWarn,
						"biblioteca carregada de memória anônima (memfd): este código "+
							"NUNCA esteve em disco, e não há o que o find ache nem o "+
							"que o pacote compare (runbook §3.16)"))
					continue
				}
				if m.Verificado && m.Recriado {
					recriados++
					if len(recriadosEx) < 3 {
						recriadosEx = append(recriadosEx, m.Caminho)
					}
					continue
				}
				sev := check.SevWarn
				nota := "o arquivo não está mais neste caminho: a única cópia do " +
					"código está na memória deste processo"
				if motivo, gravavel := suspectDir(m.Caminho); gravavel {
					// Não existe atualização de pacote que entregue biblioteca
					// em /tmp: aqui a história legítima acabou.
					sev = check.SevCritical
					nota = "o arquivo foi apagado e estava " + motivo
				}
				if !m.Verificado {
					nota = "não foi possível verificar se o caminho voltou a existir: " +
						nota
				}
				r.Findings = append(r.Findings, achadoDeMapaApagado(self, e, p, m, sev, nota))
			}
		}
		if recriados > 0 {
			// INFO de propósito: não mexe no exit code nem no veredito, e o
			// motor não o correlaciona. É contexto, e contexto que explica
			// outros achados — um host com reinício pendente tem binário em
			// disco que não é o que está rodando.
			fd := self.F(check.SevInfo, "(agregado)",
				"biblioteca substituída ainda mapeada: reinício pendente",
				strconv.Itoa(recriados)+" mapeamento(s) executáveis apagados cujo "+
					"caminho VOLTOU a existir: "+firstN(recriadosEx, 3),
				"é a forma de uma atualização de pacote com o serviço no ar — o "+
					"processo executa o código ANTIGO, e o arquivo em disco já é o novo",
			)
			fd.NextSteps = []string{
				"o que está em disco NÃO é o que está rodando: hash de arquivo não " +
					"responde por estes processos (runbook §24)",
			}
			r.Findings = append(r.Findings, fd)
		}
		if denied > 0 {
			r.Partial = append(r.Partial, strconv.Itoa(denied)+
				" processos com /proc/<pid>/maps ilegível não foram avaliados")
		}
		if n := len(isentos); n > 0 {
			r.Partial = append(r.Partial, strconv.Itoa(n)+
				" processo(s) com mapeamento executável por memfd NÃO foram avaliados "+
				"por serem runtime com JIT em diretório de sistema ("+
				firstN(dedupOrdenado(isentos), 3)+"): carregar código de memfd é "+
				"operação normal neles")
		}
		return r
	},
}

// achadoDeMapaApagado monta o achado dos dois caminhos que chegam nele. Existe
// para que a evidência do memfd e a do arquivo apagado não divirjam com o
// tempo: é a mesma pergunta — que código é este, e onde está a cópia dele.
func achadoDeMapaApagado(self check.Check, e *env.Env, p *facts.Process,
	m facts.MapaApagado, sev check.Severity, nota string) check.Finding {
	faixa := m.Caminho + " (deleted)"
	if m.Ini != 0 && m.Fim != 0 {
		faixa = strconv.FormatUint(m.Ini, 16) + "-" + strconv.FormatUint(m.Fim, 16) +
			" " + faixa
	}
	ev := []string{
		m.Perms + " " + faixa,
		nota,
		"exe=" + nz(p.Exe, "?") + " comm=" + p.Comm + " uid=" + strconv.Itoa(p.UID),
	}
	if p.TracerPID > 0 {
		ev = append(ev, "e o processo está sob ptrace (TracerPid="+
			strconv.Itoa(p.TracerPID)+")")
	}
	fd := self.F(sev, "pid="+strconv.Itoa(p.PID), "", ev...)
	fd.Quando, fd.QuandoFonte = p.StartUTC, "início do processo"
	fd.Irreversible = true
	fd.NextSteps = []string{
		"o arquivo não existe mais: a cópia está na memória do processo, e " +
			"matá-lo a destrói (runbook §6)",
		// `--mem` passou a capturar o SEGMENTO DE CÓDIGO do arquivo apagado
		// direto de /proc/<pid>/mem, além das regiões anônimas: a aquisição do
		// payload deixou de ser manual.
		preservarPID(e, p.PID, "--mem"),
	}
	return fd
}

// dedupOrdenado tira as repetições e ordena. Um navegador tem trinta processos
// com o mesmo exe, e listar o mesmo caminho trinta vezes não informa nada.
func dedupOrdenado(ss []string) []string {
	visto := map[string]bool{}
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if !visto[s] {
			visto[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// nsDivergent — runbook §3.15.
//
// Namespace próprio sem container é `unshare` na mão. Explica dois
// "impossíveis" sem precisar de rootkit: o arquivo que o cwd aponta e o `ls`
// não acha, e a conexão que o tcpdump vê e o `ss` não lista.
//
// A dificuldade aqui é o oposto da dos outros checks: divergência de namespace
// é COMUM em host moderno. Toda unit com PrivateTmp=yes tem mount namespace
// próprio. Por isso o critério não é "divergiu", é "divergiu em lugar onde
// ninguém configurou isso".
var nsDivergent = check.Check{
	ID:       "proc.ns_divergent",
	Ref:      "3.15",
	Title:    "namespace próprio fora de container e fora de unit",
	Group:    "proc",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive,
	Requires: env.CapProcfs,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"navegador, Flatpak, Snap e Podman rootless criam namespace de usuário para " +
			"sandbox — em estação de trabalho isto é constante; em servidor, não",
		"BLIND SPOT deliberado: processo sob uma unit de systemd é pulado por " +
			"inteiro. PrivateTmp=, PrivateNetwork= e PrivateUsers= criam mount, " +
			"rede e usuário próprios legitimamente — num desktop, udevd, polkit, " +
			"upower e accounts-daemon já somam dezenas. Quem comprometeu uma unit " +
			"não aparece aqui; aparece nos outros checks",
		"sem root, /proc/<pid>/ns/* de processo alheio é ilegível e não há o que comparar",
		"thread de KERNEL não entra: kdevtmpfs tem mount namespace próprio por " +
			"design, em todo kernel. Isso é do kernel, não de quem o administra",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result

		// Sem a linha de base não existe divergência a medir. Dizer "nenhum
		// namespace divergente" sem ter lido o do PID 1 seria inventar.
		init1 := f.ProcessByPID(1)
		if init1 == nil || len(init1.NS) == 0 {
			r.Partial = []string{"os namespaces do PID 1 não puderam ser lidos: sem " +
				"linha de base, divergência nenhuma pôde ser avaliada"}
			return r
		}

		var denied int
		// sobUnit conta os processos que a isenção de unit tirou da pergunta.
		var sobUnit int
		for i := range f.Processes {
			p := &f.Processes[i]
			if p.Self || p.Vanished || p.PID == 1 {
				continue
			}
			// Thread de kernel tem namespace próprio por design — kdevtmpfs é o
			// caso clássico, e aparece em TODO host. Um guest de kernel 4.14,
			// com sete processos ao todo, foi o que deixou isso visível: no
			// desktop ele se perdia no meio do ruído do sandbox de navegador.
			if isKernelThread(p) {
				continue
			}
			if p.NSDenied || len(p.NS) == 0 {
				denied++
				continue
			}
			// Container e unit ficam de fora: nos dois, namespace próprio é
			// configuração, não anomalia. Sobra o caso da §3.15 — namespace
			// criado por quem não tinha por que criar, tipicamente `unshare`
			// a partir de uma sessão.
			if isContainerCgroup(p.Cgroup) {
				continue
			}
			if isUnitCgroup(p.Cgroup) {
				// Mesmo caso do runtime com JIT: a isenção é necessária —
				// PrivateTmp=, PrivateNetwork= e PrivateUsers= criam namespace
				// legitimamente, e num desktop udevd, polkit e upower já somam
				// dezenas —, mas ela é uma decisão de NÃO OLHAR, e essas se
				// declaram. Quem comprometeu uma unit some daqui, e o operador
				// precisa saber que sumiu.
				sobUnit++
				continue
			}

			var diff []string
			for _, kind := range []string{"mnt", "net", "pid", "user"} {
				mine, base := p.NS[kind], init1.NS[kind]
				if mine == "" || base == "" || mine == base {
					continue
				}
				diff = append(diff, kind+"="+mine+" (PID 1: "+base+")")
			}
			if len(diff) == 0 {
				continue
			}

			ev := []string{
				"namespace próprio: " + strings.Join(diff, " · "),
				"exe=" + nz(p.Exe, "?") + " comm=" + p.Comm + " uid=" + strconv.Itoa(p.UID),
				"cgroup=" + nz(p.Cgroup, "(nenhum)") + " — não é container nem unit de systemd",
			}
			if p.Cwd != "" {
				ev = append(ev, "cwd="+p.Cwd+" — este caminho é resolvido no namespace DELE, não no seu")
			}

			fd := self.F(check.SevWarn, "pid="+strconv.Itoa(p.PID), "", ev...)
			fd.Quando, fd.QuandoFonte = p.StartUTC, "início do processo"
			fd.NextSteps = []string{
				"olhe de DENTRO: sudo nsenter -t " + strconv.Itoa(p.PID) + " -a ls -la /",
				"o `find` da §8 e o `ss` da §2 não enxergam o que está aqui — descarte " +
					"isto antes de concluir rootkit (runbook §35)",
			}
			r.Findings = append(r.Findings, fd)
		}
		if denied > 0 {
			r.Partial = append(r.Partial, strconv.Itoa(denied)+
				" processos com /proc/<pid>/ns/* ilegível não foram avaliados")
		}
		if sobUnit > 0 {
			r.Partial = append(r.Partial, strconv.Itoa(sobUnit)+
				" processo(s) sob unit de systemd NÃO foram avaliados: "+
				"PrivateTmp e PrivateUsers criam namespace legitimamente, e "+
				"quem comprometeu uma unit não aparece por este caminho")
		}
		return r
	},
}

// isKernelThread reconhece a thread de kernel de verdade: o kernel não associa
// executável nenhum ao PID. A distinção com "exe ILEGÍVEL" é o que separa isto
// de um implante — que tem exe, e cai no proc.kthread_disguise.
//
// Não dá para usar CmdlineEmpty aqui: o coletor só o marca em processo que TEM
// exe, porque é assim que o check de disfarce precisa. Numa thread de kernel de
// verdade ele nunca fica true.
func isKernelThread(p *facts.Process) bool {
	return p.ExeMissing
}

// jitRuntimes gera código em memória por projeto. A isenção só vale para o
// binário RODANDO DE DIRETÓRIO DE SISTEMA: um "node" em /tmp não herda a
// reputação do node.
var jitRuntimes = map[string]bool{
	"java": true, "node": true, "deno": true, "bun": true,
	"dotnet": true, "mono": true, "mono-sgen": true,
	"chrome": true, "chromium": true, "chromium-browser": true,
	"firefox": true, "thunderbird": true, "electron": true,
	"wine": true, "wineserver": true, "wine-preloader": true,
	"luajit": true, "julia": true, "php": true, "php-fpm": true,
	"beam.smp": true, "erl": true, "qemu-system-x86_64": true,
}

// ehJITConfiavel decide se um processo pode ser ISENTO como runtime com JIT.
//
// Casar o NOME e o DIRETÓRIO não basta, e a matriz adversarial provou por quê:
// copiar o payload para /usr/bin/node casa os dois e some do check de injeção.
// O que fecha o bypass é a mesma pergunta do §24 — o binário veio de um PACOTE?
// Um /usr/bin/node de verdade veio do nodejs; um payload copiado para lá, não.
//
// Sem a base de pacotes a pergunta não tem resposta, e aí a isenção CONTINUA:
// distinguir é impossível, e errar para "isenta" evita encher de FP todo host
// com navegador ou JVM. Com a base, só o que tem dono de pacote é isento.
func ehJITConfiavel(p *facts.Process, semDono map[string]bool, temPkgDB bool) bool {
	if p.Exe == "" || !diretorioDeSistema(p.Exe) {
		return false
	}
	if !jitRuntimes[baseDe(p.Exe)] {
		return false
	}
	if !temPkgDB {
		return true // sem base de pacotes, não dá para distinguir: isenta
	}
	return !semDono[p.Exe]
}

// containerMarkers são os caminhos de cgroup que os runtimes escrevem. Um
// processo dentro de container tem namespace próprio por definição, e não é
// disso que a §3.15 fala.
var containerMarkers = []string{
	"docker", "containerd", "crio", "cri-o", "libpod", "kubepods",
	"lxc", "machine.slice", "garden", "podman",
}

func isContainerCgroup(cg string) bool {
	for _, m := range containerMarkers {
		if strings.Contains(cg, m) {
			return true
		}
	}
	return false
}

// isUnitCgroup diz se o processo roda sob uma unit de systemd — onde as opções
// de isolamento explicam qualquer divergência de namespace.
//
// Contains e não HasSuffix: o cgroup de um serviço com subgrupo é
// `/system.slice/systemd-udevd.service/udev`, e testar o sufixo deixava passar
// 25 processos de uma vez.
func isUnitCgroup(cg string) bool {
	return strings.Contains(cg, ".service")
}

func firstN(ss []string, n int) string {
	if len(ss) <= n {
		return strings.Join(ss, " · ")
	}
	return strings.Join(ss[:n], " · ") + " · … (+" + strconv.Itoa(len(ss)-n) + ")"
}
