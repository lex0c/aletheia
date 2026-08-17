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
	Ref:      "7.11",
	Title:    "binário com setuid/setgid que nenhum pacote entregou",
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
		"LIMITE de escopo, e ele tem três partes. A varredura não atravessa " +
			"montagem: montagem de rede e volume externo ficam fora, e isso é " +
			"declarado quando acontece. Ela não desce em árvore de dependência " +
			"e cache (node_modules, .cache, .git, site-packages e semelhantes), " +
			"que é o que a torna viável num home de desenvolvedor. E dentro de " +
			"/home e /root ela desce no máximo cinco níveis",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		semDono := caminhosSemDono(f)

		for i := range f.Suid {
			s := &f.Suid[i]
			gravavel := facts.DirGravavelPorTodos(s.Path)

			// Num diretório gravável por qualquer um, o bit setuid é a forma do
			// backdoor mesmo que a base de pacotes não tenha sido consultada:
			// nada se instala ali de propósito.
			if !gravavel && !semDono[s.Path] {
				continue
			}

			bits := "setuid"
			if s.Setuid && s.Setgid {
				bits = "setuid e setgid"
			} else if !s.Setuid {
				bits = "setgid"
			}

			sev := check.SevWarn
			ev := []string{
				s.Path + " tem bit de " + bits,
			}
			switch {
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
				// Um shell ou interpretador com setuid não precisa de análise
				// nenhuma: `.x -p` já devolve root. É a forma mais direta que
				// existe, e o operador precisa saber que é imediata.
				sev = check.SevCritical
				ev = append(ev, "e é um interpretador ("+baseDe(s.Path)+"): não "+
					"precisa de análise nem de exploração — executar já devolve "+
					"a identidade do dono")
			}
			if semDono[s.Path] {
				ev = append(ev, "nenhum pacote reivindica este arquivo (base: "+
					f.Pkg.Kind+") — e o conjunto legítimo de setuid é pequeno, "+
					"conhecido, e vem todo de pacote")
			}
			ev = append(ev, "uid="+strconv.Itoa(s.UID)+" gid="+strconv.Itoa(s.GID)+
				" tamanho="+strconv.FormatInt(s.Size, 10))
			if s.ModUTC != "" {
				ev = append(ev, "modificado em "+s.ModUTC+
					" — compare com a janela do incidente (runbook §9)")
			}

			fd := self.F(sev, s.Path, "", ev...)
			fd.Irreversible = true
			fd.NextSteps = []string{
				"sudo cp " + s.Path + " \"$IR/\"   # a amostra, antes de qualquer coisa (runbook §6)",
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
