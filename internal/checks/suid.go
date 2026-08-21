package checks

import (
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() { check.Register(suidInesperado) }

// suidInesperado — runbook §7.11.
//
// A retenção de root mais antiga que existe, e ainda a mais usada. Com qualquer
// foothold sem privilégio:
//
//	cp /bin/bash /usr/local/bin/.x && chmod 4755 /usr/local/bin/.x
//
// E a forma MODERNA da mesma coisa, que um `find -perm -4000` não encontra:
//
//	setcap cap_setuid+ep /usr/local/bin/.x
//
// A capability fica num atributo estendido, o modo do arquivo continua 755, e
// nenhuma varredura por bit a vê. O /usr/bin/ping das distribuições atuais é
// exatamente assim — sem setuid, com `cap_net_raw` no xattr. Quem procura só
// pelo bit está procurando a metade que caiu em desuso.
//
// Não deixa processo, não deixa conexão, não deixa agendamento. Sobrevive a
// reboot, a limpeza de cron e a troca de senha — e nenhum dos outros vinte
// checks de persistência olha para isto, porque nenhum deles procura o que está
// PARADO no disco.
//
// O discriminador é o mesmo do §24, e aqui ele vale mais que em qualquer outro
// lugar: o conjunto legítimo de binários com setuid é pequeno, conhecido e vem
// TODO de pacote — `sudo`, `su`, `passwd`, `mount`, `ping`. Um setuid que nenhum
// pacote reivindica quase não tem explicação inocente.
var suidInesperado = check.Check{
	ID:       "persist.suid_unowned",
	Ref:      "25",
	Title:    "binário que carrega privilégio e nenhum pacote entregou",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"a TERCEIRA porta (bit setuid num binário empacotado que executa comando " +
			"arbitrário) tem um falso positivo próprio e conhecido: appliance e " +
			"imagem endurecida à mão às vezes marcam um utilitário para uma " +
			"finalidade específica. É raro, o time reconhece pelo nome, e a " +
			"pergunta certa é `dpkg -S` seguida de `rpm -V`/`apk audit` — o " +
			"pacote nunca entregou o arquivo assim",
		"software instalado à mão que precisa de setuid legitimamente existe — " +
			"agente de monitoração que lê contadores privilegiados, binário de " +
			"appliance, ferramenta interna antiga. São poucos e o time reconhece " +
			"cada um pelo nome",
		"compilação local em /usr/local a partir de fonte que instala setuid " +
			"(alguns pacotes de rede fazem isso) cai aqui e é legítima",
		"LIMITE de escopo, e ele tem QUATRO partes. A varredura não atravessa " +
			"montagem: montagem de rede e volume externo ficam fora, e isso é " +
			"declarado quando acontece. Ela não desce em árvore de dependência " +
			"e cache (node_modules, .cache, .git, site-packages e semelhantes), " +
			"que é o que a torna viável num home de desenvolvedor. Dentro de " +
			"/home e /root ela desce no máximo cinco níveis. E ela não entra em " +
			"/usr/share/{doc,man,locale,icons,fonts} nem em /usr/src, que são " +
			"documentação e dado — exclusão FIXA, igual em toda máquina",
		"ARMAZENAMENTO DE IMAGEM de contêiner fica fora, e isso é declarado " +
			"quando a árvore existe: /var/lib/{docker,containerd,containers,lxc}, " +
			"rancher e k0s guardam o filesystem de OUTRAS máquinas em camadas. " +
			"Cada camada traz o conjunto setuid inteiro de uma distribuição, " +
			"nenhum reivindicado pelo gerenciador DESTE host — varrê-las daqui " +
			"dava trezentos críticos falsos num desktop. A forma certa de olhar " +
			"uma camada é `aletheia scan --root <camada>`, onde o kernel é o seu",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		semDono := caminhosSemDono(f)

		for i := range f.Suid {
			s := &f.Suid[i]
			gravavel := s.DirGravavelPorTodos()
			prim := primitivaDoBinario(s.Path)

			// A TERCEIRA porta: setuid num binário que TEM DONO DE PACOTE e que
			// devolve execução arbitrária.
			//
			// As duas portas anteriores — sem dono de pacote, ou em diretório
			// gravável — deixavam passar em SILÊNCIO a forma mais barata que
			// existe:
			//
			//	chmod u+s /usr/bin/find
			//
			// O dono de pacote continua certo (findutils entregou o arquivo), o
			// conteúdo continua conferindo com o hash declarado (nada foi
			// reescrito), o diretório é /usr/bin. Nenhum dos vinte e tantos
			// checks olhava para o BIT, e o comentário abaixo — "o conjunto
			// legítimo de setuid vem TODO de pacote" — estava certo sobre a
			// origem e cego sobre o modo.
			//
			// A regra que fecha isso não precisa de metadado de pacote nenhum,
			// e é universal: `find`, `tar`, `vim` e `awk` entregam a identidade
			// do dono pelo bit, e distribuição NENHUMA os entrega com o bit. Se
			// o arquivo tem os dois, ninguém empacotou isso assim.
			//
			// O conjunto de fábrica não é o contrário disso — `sudo`, `mount` e
			// `pkexec` também executam comando arbitrário, e o bit deles É o
			// desenho. Por isso a pergunta desta porta tem DUAS partes, e não
			// uma: ver `primitivaViaSetuid` em primitiva.go. Colapsá-las custou
			// três falsos críticos no teste e um quarto num desktop limpo —
			// poder via SUDO não é poder via SETUID, e o que a distribuição
			// entrega com o bit não é achado.
			//
			// LIMITE declarado, e ele é maior que o da tabela: a lista do bit é
			// deliberadamente CONSERVADORA. `systemctl`, `apt-get`, `docker` e
			// `crontab` ficaram de fora, e um `chmod u+s` sobre binário fora
			// dela continua invisível aqui. Vale menos do que parece —
			// atacante põe o bit onde ele rende, e onde rende é onde há
			// primitiva —, mas é lacuna e está dita.
			comPrimitiva := (s.Setuid || s.Setgid) && primitivaViaSetuid(s.Path)
			if !gravavel && !semDono[s.Path] && !comPrimitiva {
				continue
			}

			sev := check.SevWarn
			ev := []string{s.Path + " " + comoCarregaPrivilegio(s)}

			// Capability em arquivo é a forma que a varredura por MODO não vê, e
			// nomear cada uma importa: `cap_net_raw` é um sniffer, `cap_setuid`
			// é root inteiro, `cap_dac_override` lê e escreve qualquer arquivo.
			if s.CapPerm != 0 {
				nomes := capNamesOf(s.CapPerm)
				ev = append(ev, "capabilities no atributo estendido: "+
					strings.Join(nomes, " "))
				if s.CapEfetivo {
					ev = append(ev, "e com o bit EFETIVO: elas já sobem ativas na "+
						"execução — o binário não precisa nem pedir")
				}
				if equivalenteARoot(s.CapPerm) {
					sev = check.SevCritical
					ev = append(ev, "e ao menos uma delas equivale a root: quem "+
						"executar isto pode virar root por outro caminho")
				}
			}
			switch {
			case s.CapPerm != 0 && !s.Setuid && !s.Setgid && !gravavel:
				// A severidade já foi decidida acima pelas capabilities; o modo
				// não acrescenta nada porque não há bit nenhum.
			case gravavel:
				sev = check.SevCritical
				ev = append(ev, "e está em diretório gravável por qualquer usuário: "+
					"nada se instala ali de propósito, e o bit não chega ali por acidente")
			case s.Setuid && s.UID == 0:
				sev = check.SevCritical
				ev = append(ev, "e o dono é root: quem executar isto vira root, "+
					"independente de quem seja")
			case s.Setgid && !s.Setuid:
				// SETGID SEM SETUID escala para o GRUPO, e o ramo faltava.
				//
				// Antes da terceira porta ele era inalcançável: um arquivo com
				// dono de pacote, fora de diretório gravável, nunca chegava
				// aqui. Com ela, um `chmod g+s /usr/bin/find` chega — e caía no
				// `default`, que fala de DONO e imprimia "o dono não é root"
				// sobre um arquivo root:root, contradizendo a linha seguinte
				// que o marcava como crítico.
				if s.GID == 0 {
					sev = check.SevCritical
					ev = append(ev, "e o grupo é root: o bit de setgid faz quem "+
						"executar isto rodar com o GRUPO root, que em vários "+
						"caminhos do sistema é escrita")
				} else {
					ev = append(ev, "é SETGID (não setuid): escala para o grupo "+
						strconv.Itoa(s.GID)+", não para root — o poder é o que "+
						"aquele grupo puder ler e escrever")
				}
			default:
				ev = append(ev, "o dono não é root — escala para a identidade do dono, "+
					"não para root, e por isso pesa menos")
			}
			if prim != primNenhuma {
				// EVIDÊNCIA, e não severidade — e a diferença veio de um teste de
				// mutação.
				//
				// Rebaixar este ramo de crítico para aviso passou pela suíte
				// inteira sem ninguém reclamar, e a investigação explicou por quê:
				// ele só MUDA alguma coisa num caso contorcido — sem dono de
				// pacote, fora de diretório gravável, dono não-root e nome
				// preservado. Nos caminhos reais a severidade já é crítica por
				// outro motivo.
				//
				// A nota continua: saber que executar aquilo já devolve
				// privilégio, sem análise nem exploração, muda o que o operador
				// faz primeiro. O que saiu foi o ramo de decisão que não se
				// pagava.
				ev = append(ev, "e `"+baseDe(s.Path)+"` "+prim.frase())
			}
			if comPrimitiva && !gravavel && !semDono[s.Path] {
				// Este é o caso que entrou pela terceira porta, e ele precisa
				// dizer POR QUE está aqui — senão a evidência inteira fala de
				// origem, a origem está em ordem, e o operador conclui o oposto.
				//
				// A SEVERIDADE não é decidida aqui, e isso é deliberado: quem a
				// decide é o switch acima, pela mesma escada que vale para as
				// outras duas portas — quem executar isto vira QUEM? Um
				// `chmod g+s` para um grupo comum é anomalia inexplicada e não é
				// root, então é aviso. Carimbar crítico aqui atropelava essa
				// escada e dizia "root" sobre um bit que não leva a root.
				ev = append(ev, "e um pacote REIVINDICA este arquivo, com o conteúdo "+
					"conferindo: quem mudou não trocou o binário, mudou o MODO dele "+
					"— um `chmod u+s` não altera conteúdo, não altera dono e não "+
					"aparece em nenhuma verificação de hash")
				ev = append(ev, "e distribuição NENHUMA entrega este binário com o "+
					"bit: o conjunto de fábrica é pequeno, conhecido e nomeado "+
					"(sudo, su, passwd, mount, ping, pkexec e a vizinhança), e este "+
					"caminho não está nele")
			}
			if semDono[s.Path] {
				ev = append(ev, "nenhum pacote reivindica este arquivo (base: "+
					f.Pkg.Kind+") — e o conjunto legítimo de setuid é pequeno, "+
					"conhecido, e vem todo de pacote")
			}
			// O FILESYSTEM pode tornar o achado inerte, e isso muda a urgência
			// sem mudar o fato. É a mesma distinção que o rc.local sem bit de
			// execução já fazia: inerte HOJE, e um remount o ativa.
			if m := f.MontagemDe(s.Path); m != nil && m.NoSuid && (s.Setuid || s.Setgid) {
				if sev == check.SevCritical {
					sev = check.SevWarn
				}
				ev = append(ev, "MAS "+m.Ponto+" está montado com `nosuid`: o bit é "+
					"INERTE hoje — um `mount -o remount,suid` o ativa, e o arquivo "+
					"continua ali esperando por isso")
			}
			ev = append(ev, "uid="+strconv.Itoa(s.UID)+" gid="+strconv.Itoa(s.GID)+
				" tamanho="+strconv.FormatInt(s.Size, 10))
			if s.ModUTC != "" {
				ev = append(ev, "modificado em "+s.ModUTC+
					" — compare com a janela do incidente")
			}

			fd := self.F(sev, s.Path, "", ev...)
			fd.Quando, fd.QuandoFonte = s.ModUTC, "mtime do arquivo"
			fd.Irreversible = true
			fd.NextSteps = []string{
				"sudo cp " + check.Arg(s.Path) + " \"$IR/\"   # a amostra, antes de qualquer coisa",
				"`chmod u-s,g-s " + s.Path + "` tira o poder sem apagar a prova",
				"o mesmo caminho na frota diz se é padrão da casa ou incidente",
			}
			r.Findings = append(r.Findings, fd)
		}

		// Truncamento e escopo de filesystem NUNCA podem sair como silêncio:
		// "nenhum SUID inesperado" e "parei antes de olhar" são respostas
		// diferentes.
		r.Partial = append(r.Partial, f.PersistDenied["suid"]...)
		r.Partial = append(r.Partial, f.PersistDenied["pkg"]...)
		r.Partial = append(r.Partial, f.PersistDenied["mounts"]...)
		return r
	},
}

// A tabela de primitivas mudou de lugar: ela era `interpretadorConhecido`, com
// dezenove nomes, e virou checks/primitiva.go, com ~110 e classes separadas.
//
// LIMITE, e ele continua sendo o mesmo: o reconhecimento é por NOME, e invasor
// renomeia. Uma cópia de /bin/sh chamada `.dbus-helper` não casa com nada — foi
// medido no cenário 98. Quem detecta AQUELE caso é a pergunta de propriedade e
// o diretório gravável, e as duas independem do nome.

// comoCarregaPrivilegio descreve a FORMA pela qual o arquivo confere poder. As
// duas formas coexistem no mesmo arquivo, e o operador precisa saber qual é.
func comoCarregaPrivilegio(s *facts.SuidFile) string {
	switch {
	case s.Setuid && s.Setgid:
		return "tem bit de setuid e setgid"
	case s.Setuid:
		return "tem bit de setuid"
	case s.Setgid:
		return "tem bit de setgid"
	default:
		return "carrega capability em atributo estendido, SEM bit de setuid"
	}
}

// capsEquivalentesARoot são as que dão root por outro caminho. Não é a lista
// inteira: é a das que um invasor escolhe quando quer o mesmo que o setuid dava.
// Os nomes vêm da mesma tabela usada nos processos, e ela é SEM o prefixo
// `cap_` — usar a grafia do `getcap` aqui faria a lista casar com nada, em
// silêncio, e o check sairia sempre com a severidade menor.
var capsEquivalentesARoot = map[string]bool{
	"setuid": true, "setgid": true, "sys_admin": true,
	"sys_module": true, "sys_ptrace": true, "dac_override": true,
	"dac_read_search": true, "chown": true, "fowner": true,
	"sys_rawio": true, "bpf": true, "perfmon": true, "setfcap": true,
}

func equivalenteARoot(mask uint64) bool {
	for _, n := range capNamesOf(mask) {
		if capsEquivalentesARoot[n] {
			return true
		}
	}
	return false
}
