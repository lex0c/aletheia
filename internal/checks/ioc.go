package checks

import (
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
	"github.com/lex0c/aletheia/internal/ioc"
)

func init() { check.Register(indicadorDoIncidente) }

// indicadorDoIncidente — SPEC 6.4, runbook §23.
//
// # O que muda com este check
//
// Todos os outros perguntam "isto tem forma de comprometimento?". Este pergunta
// outra coisa: **este comprometimento, o que já foi confirmado em outro host,
// está aqui?** A diferença é a §23 inteira — responder "rode o mesmo comando em
// N hosts" nunca foi o mesmo que responder "ESTE incidente está em N hosts".
//
// E é o único check cuja fonte vem de FORA. Todo o resto do catálogo codifica o
// que o autor pensou; um indicador é conhecimento de terceiro — do relatório de
// CTI, do host irmão já analisado, da amostra que o time coletou ontem.
//
// # Severidade
//
// CRITICAL, e a SPEC é explícita: não é heurística, é o artefato confirmado
// deste incidente aparecendo em outro host. Mas a força do achado é a força da
// LISTA, e isso está dito nos falsos positivos — a ferramenta não tem como
// julgar o indicador que recebeu.
var indicadorDoIncidente = check.Check{
	ID:      "ioc.match",
	Ref:     "23",
	Title:   "indicador deste incidente encontrado neste host",
	Group:   "ioc",
	Mode:    check.ModeAuto,
	Sources: env.SourceLive | env.SourceImage,
	// Sem Requires: o casamento acontece contra o que a coleta conseguiu ler,
	// seja num host vivo ou numa imagem montada. O que muda de um caso para o
	// outro é a COBERTURA, e ela é declarada.
	Optional: env.CapRoot,
	Wtf:      false, // a caça por indicador é varredura, não overview de 1s
	FalsePositives: []string{
		"A QUALIDADE DO ACHADO É A QUALIDADE DA LISTA, e a ferramenta não tem " +
			"como julgar o indicador que recebeu: um IP de CDN, o hash de um " +
			"binário legítimo ou uma string curta produzem casamento verdadeiro " +
			"e conclusão errada",
		"indicador de TEXTO casa por conteúdo, em qualquer lugar: uma palavra " +
			"comum como `backup` aparece em caminho, unit e cron legítimos de " +
			"quase todo servidor",
		"o hash é comparado só contra os arquivos que ESTA varredura examinou — " +
			"o que roda, o que está agendado, o que tem poder e o que está " +
			"escondido. Um hash que não bate aqui NÃO significa que o arquivo não " +
			"está no host: significa que ele não estava entre os examinados",
		"sem root, metade dos processos e o home dos outros usuários são " +
			"ilegíveis: casar menos não é a mesma coisa que não haver",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		if e.IOC == nil || len(e.IOC.Itens) == 0 {
			// Sem lista não há o que procurar, e isso não é lacuna: é a
			// execução normal, sem `--ioc`.
			return r
		}
		b := &caçaIOC{self: self, lista: e.IOC, vistos: map[string]bool{}}

		varrerRede(b, f)
		varrerArquivos(b, f)
		varrerProcessos(b, f)
		varrerPersistencia(b, f)
		varrerContas(b, f)
		varrerChaves(b, f)
		varrerBPF(b, f)

		r.Findings = b.achados
		r.Partial = append(r.Partial, f.Partial["ioc"]...)
		// Os avisos da CARGA entram na cobertura deste check: uma linha da lista
		// que não foi entendida é um indicador que ninguém procurou.
		for _, a := range e.IOC.Avisos {
			r.Partial = append(r.Partial, "lista de indicadores, "+a)
		}
		return r
	},
}

// caçaIOC acumula os achados e evita repetir o mesmo par indicador×lugar.
type caçaIOC struct {
	self    check.Check
	lista   *ioc.Lista
	vistos  map[string]bool
	achados []check.Finding
}

// casar compara UM valor do host contra a lista, e registra o que bater.
//
//	sujeito  o alvo no host — é ele que correlaciona com os outros checks
//	onde     a frase que diz em que lugar o valor estava
func (b *caçaIOC) casar(t ioc.Tipo, valor, sujeito, onde string) {
	for _, ind := range b.lista.Casar(t, valor) {
		b.registrar(ind, valor, sujeito, onde)
	}
}

func (b *caçaIOC) registrar(ind ioc.Indicador, valor, sujeito, onde string) {
	k := string(ind.Tipo) + "|" + ind.Valor + "|" + sujeito
	if b.vistos[k] {
		return
	}
	b.vistos[k] = true

	ev := []string{
		"indicador de " + string(ind.Tipo) + ": " + ind.Bruto,
		"casou em: " + onde,
	}
	// Quando a comparação não é exata — curinga e conteúdo —, o valor do host
	// precisa aparecer: sem ele o operador não sabe o que casou.
	if (ind.Tipo == ioc.Caminho || ind.Tipo == ioc.Texto) && valor != ind.Bruto {
		ev = append(ev, "valor no host: "+valor)
	}
	ev = append(ev, "a lista veio de "+b.lista.Arquivo+" (linha "+
		strconv.Itoa(ind.Linha)+"): este achado é do incidente que a produziu, "+
		"não de heurística desta ferramenta")

	fd := b.self.F(check.SevCritical, sujeito, "", ev...)
	fd.Irreversible = true
	fd.NextSteps = []string{
		"trate este host como parte do MESMO incidente: o indicador veio dele",
		"preserve antes de mexer — a ordem da §19 vale aqui como em qualquer " +
			"achado crítico",
		"procure o mesmo indicador nos hosts restantes: é a agregação da §23, " +
			"e o `id` deste achado é a chave",
	}
	b.achados = append(b.achados, fd)
}

func varrerRede(b *caçaIOC, f *facts.Facts) {
	for i := range f.Sockets {
		s := &f.Sockets[i]
		alvo := "socket inode " + strconv.FormatUint(s.Inode, 10)
		if s.PID > 0 {
			alvo = "pid=" + strconv.Itoa(s.PID)
		}
		if s.PeerIP != "" {
			b.casar(ioc.IP, s.PeerIP, alvo, "conexão "+s.Proto+" para "+s.Peer()+
				" ("+nz(s.Comm, "dono desconhecido")+")")
		}
		b.casar(ioc.IP, s.LocalIP, alvo, "endereço local de "+s.Proto+" em "+s.Local())
	}
	for _, h := range f.Hosts {
		b.casar(ioc.IP, h.IP, h.IP, "entrada de /etc/hosts na linha "+
			strconv.Itoa(h.Line)+": "+strings.Join(h.Names, " "))
		for _, n := range h.Names {
			b.casar(ioc.Texto, n, h.IP, "nome em /etc/hosts")
		}
	}
	for _, ns := range f.Resolver.Nameservers {
		b.casar(ioc.IP, ns, ns, "servidor de nomes configurado no resolver")
	}
	for i := range f.Logins {
		l := &f.Logins[i]
		if l.Origem == "" {
			continue
		}
		b.casar(ioc.IP, l.Origem, "login "+l.User, "registro de login de "+l.User+
			" em "+l.QuandoU+", vindo de "+l.Origem)
	}
	for _, d := range f.Destinos {
		if !d.Hasheado {
			b.casar(ioc.IP, d.Host, d.Host, "destino conhecido em "+d.Arquivo)
			b.casar(ioc.Texto, d.Host, d.Host, "destino conhecido em "+d.Arquivo)
		}
	}
}

func varrerArquivos(b *caçaIOC, f *facts.Facts) {
	for _, h := range f.HashesIOC {
		b.casar(ioc.Hash, h.Hash, h.Path, "hash "+h.Algo+" do arquivo "+h.Path)
	}
	caminho := func(p, onde string) {
		b.casar(ioc.Caminho, p, p, onde)
		b.casar(ioc.Texto, p, p, onde)
	}
	for _, o := range f.Ownership {
		caminho(o.Path, "arquivo examinado ("+strings.Join(o.Onde, ", ")+")")
	}
	for _, s := range f.Suid {
		caminho(s.Path, "arquivo com bit setuid/setgid ou capability")
	}
	for _, p := range f.ExecOculto {
		caminho(p, "executável em diretório oculto")
	}
	for _, t := range f.ToolArtifacts {
		caminho(t.Path, "artefato da família "+t.Family)
	}
	for _, m := range f.ModuleFiles {
		caminho(m, "módulo de kernel em disco")
	}
	for _, s := range f.Segredos {
		caminho(s.Path, "arquivo de credencial inventariado")
	}
}

func varrerProcessos(b *caçaIOC, f *facts.Facts) {
	for i := range f.Processes {
		p := &f.Processes[i]
		if p.Self {
			continue // a própria ferramenta não é alvo
		}
		alvo := "pid=" + strconv.Itoa(p.PID)
		onde := "processo " + p.Comm + " (pid " + strconv.Itoa(p.PID) + ")"
		if p.Exe != "" {
			b.casar(ioc.Caminho, p.Exe, alvo, "exe do "+onde)
			b.casar(ioc.Texto, p.Exe, alvo, "exe do "+onde)
		}
		b.casar(ioc.Texto, p.Comm, alvo, "nome do "+onde)
		if len(p.Argv) > 0 {
			b.casar(ioc.Texto, strings.Join(p.Argv, " "), alvo, "linha de comando do "+onde)
		}
		for _, k := range p.EnvKeys {
			b.casar(ioc.Texto, k, alvo, "variável de ambiente do "+onde)
		}
		if p.Cwd != "" {
			b.casar(ioc.Caminho, p.Cwd, alvo, "diretório de trabalho do "+onde)
		}
	}
}

func varrerPersistencia(b *caçaIOC, f *facts.Facts) {
	for i := range f.Units {
		u := &f.Units[i]
		b.casar(ioc.Caminho, u.Path, u.Name, "arquivo da unit "+u.Name)
		for _, x := range u.Exec {
			b.casar(ioc.Texto, x.Cmd, u.Name, x.Key+"= da unit "+u.Name)
			b.casar(ioc.Caminho, primeiroToken(x.Cmd), u.Name, "binário do "+x.Key+
				"= da unit "+u.Name)
		}
		if u.User != "" {
			b.casar(ioc.Usuario, u.User, u.Name, "User= da unit "+u.Name)
		}
	}
	for i := range f.Cron {
		c := &f.Cron[i]
		alvo := c.File
		b.casar(ioc.Texto, c.Cmd, alvo, "comando agendado em "+c.File)
		b.casar(ioc.Caminho, primeiroToken(c.Cmd), alvo, "binário agendado em "+c.File)
		b.casar(ioc.Caminho, c.File, alvo, "arquivo de agendamento")
		if c.User != "" {
			b.casar(ioc.Usuario, c.User, alvo, "usuário da entrada de cron em "+c.File)
		}
	}
	for i := range f.Triggers {
		t := &f.Triggers[i]
		b.casar(ioc.Caminho, t.File, t.File, "gatilho de execução ("+t.Kind+")")
	}
	for _, hk := range f.HooksInterp {
		onde := hk.Key + "= definida em " + hk.Fonte
		b.casar(ioc.Texto, hk.Value, hk.Fonte, onde)
		b.casar(ioc.Caminho, hk.Value, hk.Fonte, onde)
		b.casar(ioc.Caminho, hk.Fonte, hk.Fonte, "arquivo que define hook de interpretador")
	}
}

func varrerContas(b *caçaIOC, f *facts.Facts) {
	for i := range f.Accounts {
		a := &f.Accounts[i]
		b.casar(ioc.Usuario, a.Name, "conta "+a.Name, "conta local, uid "+strconv.Itoa(a.UID))
		b.casar(ioc.Texto, a.Name, "conta "+a.Name, "nome de conta local")
		if a.Home != "" {
			b.casar(ioc.Caminho, a.Home, "conta "+a.Name, "home da conta "+a.Name)
		}
	}
	for i := range f.Logins {
		l := &f.Logins[i]
		if l.User == "" {
			continue
		}
		b.casar(ioc.Usuario, l.User, "login "+l.User, "registro de login em "+l.QuandoU+
			" vindo de "+nz(l.Origem, "(local)"))
	}
}

// varrerBPF procura o indicador no que está carregado no KERNEL.
//
// A tag é o IOC de frota mais forte que existe para implante fileless: o kernel
// a calcula a partir do bytecode, então o mesmo programa carregado em duzentos
// hosts tem a mesma tag — e ela não depende de nome, caminho, arquivo nem data,
// que é tudo o que um programa eBPF não tem.
//
// Ela entra como indicador de TEXTO, e não de hash: tem oito bytes, e a lista
// recusa hash que não seja md5, sha1 ou sha256. Quem a tem escreve
// `strings: [a04f5eef06a7f555]`.
func varrerBPF(b *caçaIOC, f *facts.Facts) {
	for i := range f.BPF.Programas {
		p := &f.BPF.Programas[i]
		alvo := "bpf prog id=" + strconv.Itoa(int(p.ID))
		onde := "programa eBPF carregado no kernel (tipo " + p.Tipo + ")"
		b.casar(ioc.Texto, p.Tag, alvo, "tag do "+onde)
		b.casar(ioc.Texto, p.Nome, alvo, "nome do "+onde)
		for _, pin := range p.Pins {
			b.casar(ioc.Caminho, pin, alvo, "pin no bpffs do "+onde)
		}
	}
}

// varrerChaves compara por IMPRESSÃO DIGITAL, não por texto.
//
// A mesma chave aparece com opções na frente e comentário atrás, e comparar a
// linha inteira faria a chave do invasor não casar consigo mesma quando ele a
// colou com outro comentário. A impressão digital é derivada pelo mesmo código
// que o coletor usa — duas derivações divergiriam no dia em que o formato
// mudasse.
func varrerChaves(b *caçaIOC, f *facts.Facts) {
	for _, ind := range b.lista.Do(ioc.Chave) {
		fp := ind.Valor
		if !strings.HasPrefix(fp, "SHA256:") {
			fp = facts.FingerprintSSH(ind.Valor)
		}
		if fp == "" {
			continue
		}
		for i := range f.SSHKeys {
			k := &f.SSHKeys[i]
			if k.Fingerprint != fp {
				continue
			}
			onde := "chave autorizada em " + k.File + ", linha " + strconv.Itoa(k.Line)
			if k.Comment != "" {
				onde += " (comentário: " + k.Comment + ")"
			}
			b.registrar(ind, fp, k.File, onde)
		}
	}
}

// primeiroToken extrai o binário de uma linha de comando. O ExecStart de uma
// unit e a linha de um cron vêm com argumentos, e o indicador de caminho é do
// binário.
func primeiroToken(cmd string) string {
	for _, c := range strings.Fields(cmd) {
		// Prefixos do systemd: `-`, `@`, `+`, `!` mudam a semântica da execução
		// e não fazem parte do caminho.
		c = strings.TrimLeft(c, "-@+!:")
		if c != "" {
			return c
		}
	}
	return ""
}
