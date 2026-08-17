package checks

import (
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() {
	check.Register(arquivoDePacoteAlterado)
	check.Register(dataFalsificada)
}

// arquivoDePacoteAlterado — runbook §24, fase 7.
//
// A pergunta de propriedade responde "veio de um pacote?". Esta responde a
// seguinte, e é a que faltava:
//
//	e continua sendo o que o pacote entregou?
//
// A distância entre as duas é a distância entre ver e não ver o Ebury. Ele
// substitui `libkeyutils.so.1` NO LUGAR dela — caminho legítimo, nome certo,
// dono de pacote em ordem. Todos os checks de propriedade respondem "sim, veio
// de um pacote", e todos estão certos e cegos ao mesmo tempo.
//
// Fecha também dois limites que estavam escritos em outros checks: a
// modificação de um script empacotado (acrescentar uma linha ao
// /etc/cron.daily/apt mantém o dono) e a substituição de binário de sistema.
var arquivoDePacoteAlterado = check.Check{
	ID:       "integrity.pkg_file_modified",
	Ref:      "24",
	Title:    "arquivo entregue por um pacote não confere com o que o pacote declara",
	Group:    "integrity",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"ARQUIVO DE CONFIGURAÇÃO muda por desenho, e é para isso que ele existe: " +
			"num host administrado há tempo, vários divergem legitimamente. Eles " +
			"saem como AVISO, e só voltam a ser críticos quando o arquivo " +
			"EXECUTA algo (init.d, pam.d, cron.*, profile.d)",
		"atualização de pacote INTERROMPIDA deixa arquivo novo com hash da versão " +
			"antiga na base, ou o contrário. É raro e o `dpkg --audit` confirma",
		"recompilação local por cima do pacote (o clássico `make install` sobre " +
			"um binário empacotado) produz exatamente esta divergência, e é o time " +
			"que sabe se alguém fez isso",
		"LIMITE do algoritmo: o dpkg declara MD5, que é quebrado para colisão. " +
			"Contra um adversário que forje colisão isto não vale nada; contra " +
			"substituição de binário, que é o que Ebury e HiddenWasp fazem, vale " +
			"tudo. O apk usa SHA1 e o pacman SHA256",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for i := range f.HashDiff {
			d := &f.HashDiff[i]
			ev := []string{
				d.Path + " não confere com o que o pacote " + d.Pacote + " declara",
				"esperado (" + d.Algo + "): " + d.Esperado,
				"obtido:              " + d.Obtido,
				"a pergunta 'veio de um pacote?' responde SIM para este arquivo — " +
					"o dono está certo, o caminho está certo, e o conteúdo não é o " +
					"que foi entregue",
			}

			// CONFIGURAÇÃO é feita para ser editada, e editar é o trabalho do
			// administrador. A divergência ali é um FATO, não um achado — o que
			// muda o peso é o arquivo EXECUTAR alguma coisa.
			sev := check.SevCritical
			if d.Config {
				sev = check.SevWarn
				ev = append(ev, "é um arquivo de CONFIGURAÇÃO que o pacote entrega "+
					"para ser editado: divergir é o normal, e o que interessa é se "+
					"quem editou foi o administrador")
				if gatilhoDeExecucao(d.Path) {
					sev = check.SevCritical
					ev = append(ev, "MAS ele EXECUTA: acrescentar uma linha aqui é "+
						"persistência que mantém o dono de pacote e passa por toda "+
						"auditoria que só pergunta pela origem (runbook §7.7)")
				}
			}
			// Biblioteca substituída é a forma do Ebury e do HiddenWasp: o
			// carregador passa a executar código do invasor em todo processo que
			// linkar contra ela.
			if strings.HasSuffix(d.Path, ".so") || strings.Contains(d.Path, ".so.") {
				ev = append(ev, "e é uma BIBLIOTECA: trocá-la põe código do invasor "+
					"dentro de todo processo que linkar contra ela, sem nenhum "+
					"processo novo aparecer (runbook §7.8)")
			}

			fd := self.F(sev, d.Path, "", ev...)
			fd.Irreversible = true
			fd.NextSteps = []string{
				"sudo cp " + d.Path + " \"$IR/\"   # a amostra, antes de qualquer coisa (runbook §6)",
				"baixe o pacote " + d.Pacote + " de um espelho e compare os dois " +
					"binários FORA deste host",
				"a partir daqui, resposta vinda deste host não vale como prova: " +
					"o que responde por ela pode ser o arquivo trocado (runbook §35.6)",
			}
			r.Findings = append(r.Findings, fd)
		}
		// "Não pude comparar" nunca pode sair igual a "confere".
		r.Partial = append(r.Partial, f.PersistDenied["hash"]...)
		r.Partial = append(r.Partial, f.PersistDenied["pkg"]...)
		return r
	},
}

// dataFalsificada — runbook §9.
//
// `touch -r /bin/ls implante` copia a data do vizinho, e toda a evidência
// temporal morre junto. Esta ferramenta cita data em dezenas de evidências —
// "modificado em X, compare com a janela do incidente" — e nenhuma delas
// sobrevive a isso.
//
// O que o `touch` NÃO consegue mexer é o ctime: só o kernel escreve ali, e ele
// o atualiza justamente quando alguém mexe nos metadados. A pegada da
// falsificação é a própria falsificação.
var dataFalsificada = check.Check{
	ID:       "integrity.timestomp",
	Ref:      "9",
	Title:    "data de modificação muito anterior à de metadados: a evidência temporal foi mexida",
	Group:    "integrity",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"EXTRAIR TARBALL preservando datas (`tar -p`, `cp -p`, rsync com -t) " +
			"produz exatamente esta forma, e é como metade do software instalado " +
			"à mão chega em /opt e /usr/local — camada de contêiner também. Por " +
			"isso o check só reporta arquivo que FAZ TRABALHO: com bit setuid ou " +
			"alvo de algum mecanismo de persistência",
		"restauração de backup e migração de host reescrevem o ctime de tudo, " +
			"mantendo o mtime original: depois de uma restauração, o host inteiro " +
			"tem esta forma",
		"arquivo de pacote NÃO é avaliado: ali a diferença é de desenho — o mtime " +
			"vem do arquivo dentro do pacote, construído meses antes, e o ctime é " +
			"a hora da instalação",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for i := range f.Timestomps {
			t := &f.Timestomps[i]
			ev := []string{
				t.Path,
				"modificado em " + t.ModUTC + ", metadados em " + t.MetaUTC +
					" — " + duracaoEmDias(t.DeltaH) + " de diferença",
				"o `touch` mexe na data de modificação e NÃO consegue mexer na de " +
					"metadados: só o kernel escreve ali, e ele a atualiza quando " +
					"alguém mexe no arquivo",
				"nenhum pacote reivindica este arquivo, então a diferença não é a " +
					"da instalação — em arquivo de pacote ela é normal e por isso " +
					"eles não são avaliados aqui",
			}

			// SÓ REPORTA O QUE FAZ TRABALHO, e a razão é o volume.
			//
			// A diferença sozinha descreve extração de tarball, restauração de
			// backup e camada de contêiner — na debian:12 foram doze arquivos de
			// configuração do próprio Docker. Nenhum é falsificação, e reportar
			// todos ensinaria o operador a ignorar este check.
			//
			// Falsificar data custa esforço, e ninguém gasta esse esforço num
			// arquivo que não faz nada. O que dá sinal é a data mexida num
			// binário com privilégio ou num alvo de persistência.
			motivo := arquivoComPoder(f, t.Path)
			if motivo == "" {
				continue
			}
			ev = append(ev, motivo)

			fd := self.F(check.SevCritical, t.Path, "", ev...)
			fd.NextSteps = []string{
				"a data de METADADOS é a que vale para a linha do tempo: " +
					t.MetaUTC + " (runbook §9)",
				"procure o que mais mudou nessa mesma janela — falsificação " +
					"costuma vir em lote",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.PersistDenied["pkg"]...)
		return r
	},
}

// arquivoComPoder diz se o arquivo faz algum trabalho — tem privilégio ou está
// persistido. É o que separa extração de tarball de falsificação deliberada.
//
// A comparação é pelo PRIMEIRO TOKEN e não por prefixo: prefixo faria
// `/usr/local/bin/foo` casar com um comando que executa `/usr/local/bin/foobar`,
// e a diferença entre os dois é um arquivo diferente.
func arquivoComPoder(f *facts.Facts, p string) string {
	for i := range f.Suid {
		if f.Suid[i].Path == p {
			return "e o arquivo tem bit SETUID: a data foi mexida num binário que " +
				"dá privilégio"
		}
	}
	for i := range f.Units {
		for _, ex := range f.Units[i].Exec {
			if primeiroCaminho(ex.Cmd) == p {
				return "e a unit " + f.Units[i].Name + " o executa: a data foi mexida " +
					"num alvo de persistência"
			}
		}
	}
	for i := range f.Cron {
		if primeiroCaminho(f.Cron[i].Cmd) == p {
			return "e o agendamento em " + f.Cron[i].File + " o executa: a data foi " +
				"mexida num alvo de persistência"
		}
	}
	return ""
}

func duracaoEmDias(h int) string {
	if h < 48 {
		return strconv.Itoa(h) + "h"
	}
	return strconv.Itoa(h/24) + " dias"
}

// gatilhoDeExecucao diz se o arquivo de configuração EXECUTA alguma coisa.
// Modificar um deles é persistência que mantém o dono de pacote.
func gatilhoDeExecucao(p string) bool {
	for _, d := range []string{
		"/etc/init.d/", "/etc/pam.d/", "/etc/cron.", "/etc/profile.d/",
		"/etc/update-motd.d/", "/etc/rc.local", "/etc/rc.d/",
		"/etc/NetworkManager/dispatcher.d/", "/etc/apt/apt.conf.d/",
	} {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}
