package checks

import (
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() { check.Register(donoSemConta) }

// minArquivosParaProporcao é o mínimo de arquivos varridos para a regra de
// dominância valer. Uma varredura que viu pouco não sustenta proporção, e
// aplicar a regra ali transformaria escassez de dado em conclusão.
const minArquivosParaProporcao = 1000

// donoSemConta — runbook §7.9.
//
// `userdel` remove a linha do passwd. Não toca em disco. Um atacante que criou
// conta, trabalhou e apagou a conta na faxina deixa para trás arquivos cujo uid
// não traduz para nome nenhum — e esse número é o recibo de uma identidade que
// existiu e foi escondida. É o oposto do check de conta sem shadow: lá a conta
// está e não devia; aqui a conta não está e alguma coisa ainda pertence a ela.
//
// `ls -l` já mostra isso — imprime o número cru no lugar do nome —, e é
// justamente por ser tão discreto que passa. Ninguém lê o dono de um arquivo
// procurando um número.
//
// A gravidade sai da FORMA, não da existência:
//
//   - executável dentro de árvore de distribuição é o caso duro. /usr/bin tem
//     um dono esperado — o gerenciador de pacotes, como root. Um programa ali
//     pertencendo a ninguém não veio de pacote nenhum.
//   - executável em qualquer outro lugar é o segundo caso: ferramenta deixada
//     para trás.
//   - só dado, sem executável, é observação. Volume de contêiner, tarball
//     extraído com dono preservado, árvore de chroot — todas produzem isso
//     legitimamente, e chamar de achado gastaria a atenção do operador.
//
// Medido no host que originou o check: 571 mil arquivos varridos, um único uid
// órfão, zero executáveis — o volume de dados de um redis em contêiner. A
// classe é rara o bastante para valer, e a regra de forma é o que a mantém
// silenciosa quando não há nada.
var donoSemConta = check.Check{
	ID:       "priv.file_owner_no_account",
	Ref:      "7.9",
	Title:    "arquivo pertence a uid/gid que não existe em passwd/group",
	Group:    "priv",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"volume de contêiner montado no host guarda arquivos com o uid de DENTRO " +
			"da imagem, que não existe no passwd do host — foi exatamente o " +
			"único caso do host onde isto foi medido",
		"tarball, backup ou imagem extraída com `tar -p` preserva o dono numérico " +
			"da máquina de origem, e a tabela de contas de lá não veio junto",
		"árvore de chroot, debootstrap ou rootfs de build tem a própria tabela de " +
			"contas, que não é a do host que a hospeda",
		"contêiner rootless mapeia uid por subordinação (100000+), e nenhum " +
			"desses números está no passwd — a árvore inteira aparece com um dono só",
		"conta servida por LDAP/NIS/SSSD existe sem estar no /etc/passwd local: " +
			"o `getent passwd` do passo seguinte é o que separa isso de conta apagada",
		"pacote removido que deixou arquivos de um usuário de sistema também " +
			"produz a forma, e sem executável ela sai como observação",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		r.Partial = append(r.Partial, f.PersistDenied["suid"]...)
		r.Partial = append(r.Partial, f.PersistDenied["users"]...)

		// A trava que impede a pior saída possível.
		//
		// Sem passwd legível o conjunto de conhecidos vem VAZIO, e aí todo uid
		// do host vira órfão — o relatório acusaria a máquina inteira. Tabela
		// ausente é desconhecimento, não resposta, e o coletor de users já
		// declarou a lacuna.
		uids, gids := map[int]bool{}, map[int]bool{}
		for i := range f.Accounts {
			uids[f.Accounts[i].UID] = true
		}
		for i := range f.Grupos {
			gids[f.Grupos[i].GID] = true
		}
		if len(uids) == 0 || len(gids) == 0 {
			if len(f.Donos) > 0 {
				r.Partial = append(r.Partial, "a tabela de contas não foi lida: "+
					"sem ela TODO dono pareceria órfão, e nenhum arquivo foi avaliado")
			}
			return r
		}

		// O gid GÊMEO é dobrado dentro do achado do uid, e não vira achado
		// próprio.
		//
		// A convenção de grupo privado por usuário — Debian, RHEL, Arch — dá a
		// cada conta um grupo de mesmo número. Uma conta apagada leva os dois
		// embora juntos, e `chown 1337:1337` deixa os dois órfãos apontando
		// para o MESMO arquivo. Dois achados para um arquivo não acrescentam
		// nada e diluem o crítico num aviso ao lado.
		//
		// Isto apareceu no cenário J2, não na revisão: o plantio usa a forma
		// que o caso real usa, e a duplicata saiu junto.
		porUID := map[int]int{}

		// DOMINÂNCIA é o que separa implante de árvore importada, e é medida —
		// não suposta.
		//
		// Um dono sem conta que responde pela MAIORIA dos arquivos vistos não
		// largou nada aqui: a árvore inteira chegou pronta com ele. Contêiner
		// rootless mapeia tudo para um uid subordinado; um `tar -x` como
		// usuário reescreve o dono de cada arquivo para quem extraiu.
		var total int
		for _, d := range f.Donos {
			if !d.Grupo {
				total += d.Arquivos
			}
		}

		// Modo imagem: o dono do arquivo é do EXTRATOR, não do sistema.
		//
		// Exportar um rootfs para diretório reescreve o dono de tudo para quem
		// rodou o `tar`. Uma imagem montada de disco de verdade preserva os
		// uids originais, e daqui não dá para saber qual dos dois se está
		// olhando — então a ferramenta não acusa: relata e diz por quê.
		//
		// Isto NÃO saiu de revisão: os três cenários de modo imagem passaram a
		// sair com um crítico cada, todos o mesmo uid do extrator.
		imagem := e != nil && e.Source == env.SourceImage
		if imagem && len(f.Donos) > 0 {
			r.Partial = append(r.Partial, "modo imagem: o dono dos arquivos pode "+
				"ser o de quem EXTRAIU a árvore e não o do sistema original — "+
				"nenhum dono sem conta é acusado aqui, só relatado")
		}

		for _, d := range f.Donos {
			conhecido := uids
			rotulo, tabela := "uid", "/etc/passwd"
			if d.Grupo {
				conhecido, rotulo, tabela = gids, "gid", "/etc/group"
			}
			if conhecido[d.ID] {
				continue
			}
			if d.Grupo {
				if i, ok := porUID[d.ID]; ok {
					r.Findings[i].Evidence = append(r.Findings[i].Evidence,
						"e o gid "+strconv.Itoa(d.ID)+" também não existe em "+
							"/etc/group: conta apagada leva junto o grupo privado "+
							"de mesmo número, e é a forma que `userdel` deixa")
					continue
				}
			}

			nome := rotulo + " " + strconv.Itoa(d.ID)
			base := "passwd"
			if d.Grupo {
				base = "group"
			}
			ev := []string{
				nome + " é dono de " + contagem(d.Arquivos, "arquivo") +
					" e não tem entrada em " + tabela,
				"o kernel guarda o NÚMERO no inode; o nome é tradução, e aqui não " +
					"há para o que traduzir",
			}

			// O piso existe porque proporção sobre amostra minúscula não diz
			// nada: "1 de 1 arquivo" não é dominância, é uma varredura que mal
			// começou. Abaixo dele a forma decide, como sempre.
			dominante := total >= minArquivosParaProporcao && d.Arquivos*2 > total

			sev := check.SevInfo
			switch {
			case imagem:
				ev = append(ev, "em modo imagem o dono é o de quem extraiu a "+
					"árvore tanto quanto o do sistema original, e daqui não dá "+
					"para separar os dois: isto é relato, não acusação")
			case dominante:
				ev = append(ev, "e responde por mais da METADE dos "+
					strconv.Itoa(total)+" arquivos varridos: esse é o formato de "+
					"uma árvore que chegou pronta — contêiner rootless, rootfs "+
					"extraído —, não o de algo largado aqui")
			case d.Executaveis > 0 && d.EmSistema > 0 && !d.Grupo:
				sev = check.SevCritical
				ev = append(ev, "e há executável dentro de árvore de distribuição: "+
					d.ExemploSistema+" — essas árvores têm dono esperado, que é o "+
					"gerenciador de pacotes rodando como root")
			case d.Executaveis > 0:
				sev = check.SevWarn
				ev = append(ev, contagem(d.Executaveis, "executável")+
					" com esse dono, p.ex. "+d.ExemploExec)
			default:
				ev = append(ev, "nenhum executável: a forma é de dado copiado de "+
					"outro sistema, e por isso sai como observação e não como achado")
			}

			// O volume inverte a leitura, e é contraintuitivo o bastante para
			// ser dito: uma árvore inteira com um dono só veio de outro lugar
			// pronta. Dois arquivos soltos é que são estranhos.
			if d.Arquivos > 1000 {
				ev = append(ev, "são muitos arquivos para um implante: esse volume "+
					"é a forma de uma árvore importada inteira, não de algo "+
					"largado aqui")
			}
			if len(d.Exemplos) > 0 {
				ev = append(ev, "exemplos: "+strings.Join(d.Exemplos, ", "))
			}

			fd := self.F(sev, nome, "", ev...)
			fd.NextSteps = []string{
				"`getent " + base + " " + strconv.Itoa(d.ID) + "` resolve diretório " +
					"central: se responder, a identidade existe e só não é local",
				"`find / -xdev -" + rotulo[:1] + "id " + strconv.Itoa(d.ID) +
					" -ls` dá a lista inteira, que este resumo não guarda",
				"o ctime desses arquivos data quando a identidade ainda existia, " +
					"e apagar a linha de " + tabela + " não apaga isso (runbook §9)",
			}
			if !d.Grupo {
				fd.NextSteps = append(fd.NextSteps,
					"procure o mesmo número em /var/log/auth.log e no wtmp: um uid "+
						"que logou e depois sumiu do passwd é conta apagada, não "+
						"arquivo importado")
			}
			if !d.Grupo {
				porUID[d.ID] = len(r.Findings)
			}
			r.Findings = append(r.Findings, fd)
		}
		return r
	},
}

// contagem escreve "1 arquivo" ou "12 arquivos". O plural existe porque o
// achado é lido por gente, e "1 arquivos" faz o leitor parar na frase errada.
func contagem(n int, singular string) string {
	s := strconv.Itoa(n) + " " + singular
	if n == 1 {
		return s
	}
	if strings.HasSuffix(singular, "l") {
		return strconv.Itoa(n) + " " + strings.TrimSuffix(singular, "l") + "is"
	}
	return s + "s"
}
