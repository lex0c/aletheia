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

			// Num diretório gravável por qualquer um, o bit setuid é a forma do
			// backdoor mesmo que a base de pacotes não tenha sido consultada:
			// nada se instala ali de propósito.
			if !gravavel && !semDono[s.Path] {
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
			default:
				ev = append(ev, "o dono não é root — escala para a identidade do dono, "+
					"não para root, e por isso pesa menos")
			}
			if ehInterpretador(s.Path) {
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
				ev = append(ev, "e é um interpretador ("+baseDe(s.Path)+"): não "+
					"precisa de análise nem de exploração — executar já devolve "+
					"a identidade do dono")
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
					" — compare com a janela do incidente (runbook §9)")
			}

			fd := self.F(sev, s.Path, "", ev...)
			fd.Quando, fd.QuandoFonte = s.ModUTC, "mtime do arquivo"
			fd.Irreversible = true
			fd.NextSteps = []string{
				"sudo cp " + check.Arg(s.Path) + " \"$IR/\"   # a amostra, antes de qualquer coisa (runbook §6)",
				"`chmod u-s,g-s " + s.Path + "` tira o poder sem apagar a prova",
				"o mesmo caminho na frota diz se é padrão da casa ou incidente " +
					"(runbook §23)",
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

// interpretadorConhecido são os binários que, com setuid, entregam root direto.
//
// LIMITE, e ele é grande: o reconhecimento é por NOME, e invasor renomeia. Uma
// cópia de /bin/sh chamada `.dbus-helper` não casa com nada aqui — foi medido
// no cenário 98. A nota serve para o caso descuidado e não custa nada, mas NÃO
// é a detecção: quem detecta é a pergunta de propriedade e o diretório
// gravável, e as duas independem do nome.
//
// Reconhecer a CÓPIA exigiria comparar conteúdo com os binários do sistema,
// que é o check de integridade por hash — ainda não existe.
var interpretadorConhecido = map[string]bool{
	"bash": true, "sh": true, "dash": true, "zsh": true, "ksh": true,
	"perl": true, "python": true, "python3": true, "ruby": true,
	"awk": true, "gawk": true, "mawk": true, "find": true, "vim": true,
	"nmap": true, "tar": true, "cp": true, "env": true, "busybox": true,
}

func ehInterpretador(p string) bool {
	b := baseDe(p)
	b = strings.TrimPrefix(b, ".")
	return interpretadorConhecido[b]
}

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
