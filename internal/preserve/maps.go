package preserve

import (
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// A leitura de /proc/<pid>/maps para o dump de memória.
//
// O formato de cada linha:
//
//	7f3c1a000000-7f3c1a021000 rw-p 00000000 00:00 0        [heap]
//	│                         │    │        │     │        └─ o que há por trás
//	│                         │    │        │     └─ inode (0 = anônimo)
//	│                         └─ permissões
//	└─ faixa de endereços
//
// O que interessa é o que NÃO tem arquivo por trás. Região com arquivo está no
// disco e se copia com `Arquivo`; região anônima é o único lugar onde código
// injetado existe.

type regiao struct {
	ini, fim uint64
	perms    string
	rotuloFS string // [heap], [stack], o caminho apagado, ou vazio
	// apagado marca o mapeamento de ARQUIVO cujo arquivo foi removido do disco:
	// a única cópia do código está nesta faixa, e o `Arquivo` não a alcança.
	apagado bool
}

func (r regiao) rotulo() string {
	return strconv.FormatUint(r.ini, 16) + "-" + strconv.FormatUint(r.fim, 16)
}

// rwx é a assinatura clássica de código injetado: uma região que se pode
// ESCREVER e depois EXECUTAR. Código legítimo vem de arquivo mapeado r-xp; quem
// precisa de w+x na mesma página anônima está construindo o que vai rodar.
//
// (JIT — JVM, V8, .NET — faz exatamente isso, e por isso a região é evidência a
// olhar, não veredito.)
func (r regiao) rwx() bool {
	return len(r.perms) >= 3 && r.perms[1] == 'w' && r.perms[2] == 'x'
}

// regioesAnonimas escolhe o que vale dumpar, e a escolha é a metade do valor
// desta funcionalidade.
//
// Entra:
//
//	sem arquivo por trás   é onde mora código injetado, e não existe em disco
//	[heap] e [stack]       têm nome, não têm arquivo: mesma propriedade
//
// Fica de fora:
//
//	região com arquivo     está no disco; copiar o arquivo é melhor e mais barato
//	sem permissão de leitura  não há o que ler
//	[vvar], [vsyscall]     mapeamentos do kernel, iguais em todo processo
func regioesAnonimas(maps string) []regiao {
	var out []regiao
	for _, ln := range strings.Split(maps, "\n") {
		campos := strings.Fields(ln)
		if len(campos) < 5 {
			continue
		}
		ini, fim, ok := faixa(campos[0])
		if !ok || fim <= ini {
			continue
		}
		perms := campos[1]
		if len(perms) < 1 || perms[0] != 'r' {
			continue // sem leitura não há dump
		}
		nome := ""
		if len(campos) >= 6 {
			nome = campos[5]
		}
		switch {
		case nome == "", nome == "[heap]", nome == "[stack]":
			// os três casos sem arquivo por trás
		default:
			continue
		}
		out = append(out, regiao{ini: ini, fim: fim, perms: perms, rotuloFS: nome})
	}
	return out
}

// regioesApagadas seleciona os mapeamentos de ARQUIVO EXECUTÁVEL cujo arquivo
// foi apagado do disco — a biblioteca aberta com dlopen e removida em seguida.
// É o caso que o `Arquivo` não cobre (o arquivo não existe mais) e o
// `regioesAnonimas` também não (o mapeamento TEM nome): a única cópia do código
// está nesta faixa de memória, e é por isso que ela entra no dump.
//
// Executável e legível: é o SEGMENTO DE CÓDIGO do arquivo apagado, o que
// importa. Segmento de dado apagado é outra pergunta, e capturá-lo aumentaria o
// volume sem trazer o que se procura — o código que roda.
func regioesApagadas(maps string) []regiao {
	var out []regiao
	for _, ln := range strings.Split(maps, "\n") {
		campos := strings.Fields(ln)
		// precisa do nome E do sufixo "(deleted)", que é sempre o último token.
		if len(campos) < 6 || campos[len(campos)-1] != "(deleted)" {
			continue
		}
		perms := campos[1]
		// legível e executável: sem 'r' não há dump, sem 'x' não é código.
		if len(perms) < 3 || perms[0] != 'r' || perms[2] != 'x' {
			continue
		}
		ini, fim, ok := faixa(campos[0])
		if !ok || fim <= ini {
			continue
		}
		// o caminho vai do campo 6 até ANTES do "(deleted)" — e pode conter
		// espaço, que o kernel não escapa.
		caminho := strings.Join(campos[5:len(campos)-1], " ")
		if !strings.HasPrefix(caminho, "/") {
			continue // só arquivo de verdade (inclui /memfd:); [anon:...] não
		}
		out = append(out, regiao{ini: ini, fim: fim, perms: perms, rotuloFS: caminho, apagado: true})
	}
	return out
}

func faixa(s string) (uint64, uint64, bool) {
	a, b, ok := strings.Cut(s, "-")
	if !ok {
		return 0, 0, false
	}
	ini, err1 := strconv.ParseUint(a, 16, 64)
	fim, err2 := strconv.ParseUint(b, 16, 64)
	return ini, fim, err1 == nil && err2 == nil
}

// donoEDatas extrai o que a interface padrão do Go não expõe: uid, gid e o
// ctime — que é a data que o `touch` não consegue falsificar (runbook §9).
func donoEDatas(fi os.FileInfo) (uid, gid int, ctime string, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, "", false
	}
	// O tipo do campo muda entre arquiteturas de 32 e 64 bits: a conversão
	// explícita é o que faz este arquivo compilar em i686.
	sec := int64(st.Ctim.Sec)
	nsec := int64(st.Ctim.Nsec)
	return int(st.Uid), int(st.Gid),
		time.Unix(sec, nsec).UTC().Format(time.RFC3339), true
}
