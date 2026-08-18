package facts

import (
	"io/fs"
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/env"
)

// O que EU escrevo e o ROOT executa (runbook §36.4).
//
// É a rota de escalada mais comum na prática, e a mais fácil de corrigir: não é
// bug de software, é permissão. Um script citado num cron de root, com dono
// `deploy` ou modo 664, é root para quem for `deploy` — sem exploit, sem
// vulnerabilidade, sem nada para o atacante estudar.
//
// A ferramenta já sabia quem executa o quê (cron, unit, gatilho) e já sabia
// olhar modo de arquivo (SUID). O que faltava era cruzar as duas coisas.
//
// # A pergunta não é "é gravável por qualquer um"
//
// Essa é a versão fácil e a menos comum. As três formas que importam:
//
//	dono não é root      o dono reescreve o arquivo quando quiser
//	grupo grava          e o grupo não é o root: quem estiver nele reescreve
//	todos gravam         o caso óbvio, e o mais raro em host de verdade
//
// E há a variante que engana: o ARQUIVO pode estar 644 root:root e o DIRETÓRIO
// ser gravável — aí não se reescreve o arquivo, troca-se por outro.

// AlvoDeRoot é um caminho que algo executa com privilégio de root, com o que o
// inode diz sobre quem pode alterá-lo.
type AlvoDeRoot struct {
	// Caminho é o que será executado.
	Caminho string `json:"path"`
	// Origem é quem manda executar: "cron", "unit", "gatilho".
	Origem string `json:"source"`
	// Onde é o arquivo que contém a ordem — o crontab, a unit, o rc.local.
	Onde string `json:"declared_in"`

	UID  int    `json:"uid"`
	GID  int    `json:"gid"`
	Modo uint32 `json:"mode"`

	// DirUID e DirModo descrevem o diretório: um arquivo intocável dentro de um
	// diretório gravável é substituível, e o efeito é o mesmo.
	DirUID  int    `json:"dir_uid"`
	DirGID  int    `json:"dir_gid"`
	DirModo uint32 `json:"dir_mode"`

	// Existe separa "está lá e é gravável" de "não está lá" — um caminho que
	// não existe e é executado por root é OUTRO achado: quem criar o arquivo
	// primeiro ganha a execução.
	Existe bool `json:"exists"`
	// DirSticky marca o /tmp: ali todos escrevem, mas só o dono apaga o
	// próprio arquivo. Muda o que dá para fazer, e precisa ser dito.
	DirSticky bool `json:"dir_sticky,omitempty"`
}

// QuemGrava descreve quem pode alterar o alvo, ou vazio quando só o root pode.
//
// A ordem é a da gravidade: o dono não-root é a forma que mais aparece em host
// real, e a que menos gente enxerga.
func (a AlvoDeRoot) QuemGrava() string {
	switch {
	case a.Existe && a.UID > 0:
		return "o dono do arquivo (uid " + strconv.Itoa(a.UID) + ") não é root, e o dono " +
			"reescreve o que quiser"
	case a.Existe && a.Modo&0o002 != 0:
		return "o arquivo é gravável por QUALQUER usuário (modo " + modoStr(a.Modo) + ")"
	case a.Existe && a.Modo&0o020 != 0 && a.GID > 0:
		return "o arquivo é gravável pelo grupo " + strconv.Itoa(a.GID) + ", que não é o do root"
	case !a.Existe && a.DirGravavel():
		return "o arquivo NÃO EXISTE e o diretório é gravável: quem criá-lo " +
			"primeiro ganha a execução"
	case a.DirGravavel():
		return "o diretório é gravável: o arquivo em si está protegido, mas dá " +
			"para trocá-lo por outro"
	}
	return ""
}

// DirGravavel diz se o diretório aceita escrita de quem não é root.
func (a AlvoDeRoot) DirGravavel() bool {
	if a.DirModo&0o002 != 0 {
		return true
	}
	if a.DirModo&0o020 != 0 && a.DirGID > 0 {
		return true
	}
	return a.DirUID > 0
}

// donoConfiavel decide se DÁ PARA PERGUNTAR quem é o dono dos arquivos.
//
// A pergunta do §36.4 é inteiramente sobre propriedade, e há um caso em que a
// propriedade que se lê não é a do alvo: um rootfs extraído por usuário comum —
// `docker export | tar -x` sem privilégio — fica INTEIRO com o uid de quem
// extraiu. Ali `/bin/sh` aparece como dono 1000, e o check acusaria o sistema
// operacional inteiro.
//
// Isso não é hipótese: as três fixtures de servidor de referência produziram 89,
// 91 e 112 achados em modo imagem, todos falsos, todos convincentes.
//
// A sonda são caminhos que em QUALQUER Linux pertencem ao root. Se algum deles
// existe e tem outro dono, a propriedade daquela árvore foi achatada — e a
// resposta honesta é declarar que não dá para responder.
func donoConfiavel(f *Facts, e *env.Env) bool {
	sentinelas := []string{"/etc/passwd", "/bin/sh", "/usr/bin/env", "/etc/hostname"}
	achou := false
	for _, p := range sentinelas {
		fi, err := e.Stat(p)
		if err != nil {
			continue
		}
		achou = true
		if uid, _ := donoDe(fi); uid != 0 {
			f.partial("gravavel", "a propriedade dos arquivos desta árvore não é a "+
				"do sistema de origem ("+p+" tem dono "+strconv.Itoa(uid)+", e em "+
				"Linux nenhum ele pertence a outro que não o root): rootfs extraído "+
				"por usuário comum achata o dono de tudo. A pergunta 'quem pode "+
				"reescrever o que o root executa' NÃO foi respondida aqui")
			return false
		}
	}
	if !achou {
		f.partial("gravavel", "nenhum caminho de sistema legível para aferir a "+
			"propriedade: a pergunta do §36.4 não foi respondida")
	}
	return achou
}

// collectAlvosDeRoot resolve os caminhos que root executa e os stateia.
func collectAlvosDeRoot(f *Facts, e *env.Env) {
	if !donoConfiavel(f, e) {
		return
	}
	visto := map[string]bool{}
	add := func(caminho, origem, onde string) {
		caminho = strings.TrimSpace(caminho)
		if !ehCaminhoExecutavel(caminho) || visto[caminho+onde] {
			return
		}
		visto[caminho+onde] = true
		a := AlvoDeRoot{Caminho: caminho, Origem: origem, Onde: onde, UID: -1, GID: -1}
		if fi, err := e.Stat(caminho); err == nil {
			// DIRETÓRIO NÃO É ALVO DE EXECUÇÃO, e tratá-lo como se fosse produziu
			// falso positivo em série: `run-parts /etc/periodic/daily` no Alpine e
			// `find /var/log/nginx …` num servidor de web viravam achado, porque o
			// primeiro caminho absoluto da linha é um diretório.
			//
			// O diretório gravável É uma rota da §36.4 — quem escreve nele deixa
			// um script para o run-parts executar —, mas é OUTRA pergunta, com
			// outra taxa de acerto: um diretório de deploy com dono da aplicação
			// é a norma em qualquer servidor. Fica declarado nos falsos
			// positivos em vez de virar ruído.
			if fi.IsDir() {
				return
			}
			a.Existe = true
			a.UID, a.GID = donoDe(fi)
			a.Modo = uint32(fi.Mode().Perm())
		}
		dir := caminho[:strings.LastIndex(caminho, "/")+1]
		if fi, err := e.Stat(strings.TrimSuffix(dir, "/")); err == nil {
			a.DirUID, a.DirGID = donoDe(fi)
			a.DirModo = uint32(fi.Mode().Perm())
			a.DirSticky = fi.Mode()&fs.ModeSticky != 0
		}
		f.AlvosDeRoot = append(f.AlvosDeRoot, a)
	}

	for i := range f.Cron {
		c := &f.Cron[i]
		// Job de usuário escala para AQUELE usuário, não para root — é outra
		// conversa, e acusá-la aqui inventaria uma escalada que não existe.
		if !rodaComoRoot(c.User, c.Kind) {
			continue
		}
		for _, p := range caminhosDoComando(c.Cmd) {
			add(p, "cron", c.File)
		}
	}
	for i := range f.Units {
		u := &f.Units[i]
		// `User=` na unit muda a identidade; sem ele, systemd roda como root.
		if u.Scope != "system" || (u.User != "" && u.User != "root") {
			continue
		}
		for _, ex := range u.Exec {
			for _, p := range caminhosDoComando(ex.Cmd) {
				add(p, "unit", u.Path)
			}
		}
	}
	for i := range f.Triggers {
		t := &f.Triggers[i]
		// Gatilho de usuário (perfil de shell) escala para aquele usuário, e o
		// dono do próprio arquivo já pode escrevê-lo — não é a §36.4.
		if t.User != "" && t.User != "root" {
			continue
		}
		for _, ln := range t.Lines {
			for _, p := range caminhosDoComando(ln.Text) {
				add(p, "gatilho", t.File)
			}
		}
	}
}

// rodaComoRoot decide pela FONTE do agendamento. Os diretórios de sistema
// (/etc/cron.daily e companhia) não têm campo de usuário e rodam como root.
func rodaComoRoot(user, kind string) bool {
	if user != "" {
		return user == "root"
	}
	return kind == "dir" || kind == "system" || kind == "dropin"
}

// caminhosDoComando extrai o que a linha de comando de fato EXECUTA.
//
// A regra tem duas partes, e a segunda custou dois falsos positivos na primeira
// medição contra um host real:
//
//	o primeiro caminho absoluto   é o executável
//	os seguintes                  são ARGUMENTO, e só contam quando parecem
//	                              script — porque aí quem executa é o
//	                              interpretador do primeiro
//
// Sem a segunda parte, `gpm -m /dev/input/mice` acusava o dispositivo de mouse
// e `lastlog2-import /var/log/lastlog` acusava o log: os dois são graváveis por
// grupo, os dois são argumento, e nenhum dos dois é executado.
//
// Só caminhos ABSOLUTOS, também de propósito: `tar czf x *` é outra rota da
// §36.4 (PATH hijack e wildcard), mas resolver o PATH de um processo que ainda
// não existe é adivinhação, e adivinhar aqui produziria acusação contra binário
// de sistema. O que se afirma é o que está escrito.
func caminhosDoComando(cmd string) []string {
	campos := strings.Fields(cmd)
	if len(campos) == 0 {
		return nil
	}
	var out []string
	// A posição de COMANDO é a primeira, e só ela. Pegar o primeiro caminho
	// absoluto de qualquer posição fazia `dmesg > /var/log/dmesg` acusar o log:
	// o alvo do redirecionamento é escrito pelo root, não executado por ele.
	if c := strings.Trim(campos[0], `"';|&()`); strings.HasPrefix(c, "/") && len(c) > 1 {
		out = append(out, c)
	}
	for _, tok := range campos[1:] {
		tok = strings.Trim(tok, `"';|&()`)
		if strings.HasPrefix(tok, "/") && ehScript(tok) {
			out = append(out, tok)
		}
	}
	return out
}

// ehScript reconhece o argumento que o interpretador vai executar. A lista é a
// mesma que o runbook usa no grep da §36.4.
func ehScript(p string) bool {
	for _, ext := range []string{".sh", ".py", ".pl", ".rb", ".bash", ".php"} {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}

// ehCaminhoExecutavel filtra o que não é alvo de execução: argumento, redireção
// e caminho de dado entram na linha de comando e não são o que roda.
func ehCaminhoExecutavel(p string) bool {
	if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "*?[]$") {
		return false
	}
	// Caminhos de dado e de log aparecem como argumento e não são executados.
	for _, ruim := range []string{"/dev/null", "/dev/stdout", "/dev/stderr"} {
		if p == ruim {
			return false
		}
	}
	return !strings.HasSuffix(p, ".log") && !strings.HasSuffix(p, ".conf") &&
		!strings.HasSuffix(p, ".json") && !strings.HasSuffix(p, ".yaml")
}

// modoStr imprime o modo em octal, que é como o operador vai comparar com o
// `stat` que ele rodar em seguida.
func modoStr(m uint32) string {
	s := ""
	for i := 2; i >= 0; i-- {
		s += string(rune('0' + (m>>(uint(i)*3))&7))
	}
	return "0" + s
}
