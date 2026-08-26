package env

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/lex0c/aletheia/internal/safeio"
)

// A leitura DIRECIONADA de um arquivo, para o perfil completo do servidor MCP.
//
// # Por que ela não é ReadFile
//
// ReadFile responde "me dê o conteúdo" e some com todo o resto. Quem investiga
// precisa do resto: o inode, o dispositivo, quantos nomes apontam para ele, e
// se o caminho que ele pediu era um link para outra coisa. Um `/tmp/x` que
// resolve para `/etc/shadow` não é uma leitura de /tmp — e a diferença só
// aparece se alguém a devolver.
//
// # Tudo é decidido no DESCRITOR
//
// É o mesmo princípio de ReadFile, e pelo mesmo motivo: caminho é uma pergunta
// que pode ser respondida diferente duas vezes seguidas. Abrir com O_NONBLOCK e
// então perguntar ao fd o que ele é fecha a janela em que um usuário sem
// privilégio troca o alvo entre a checagem e o uso. Os xattr também saem do fd,
// por fgetxattr — o coletor de SUID os lê por CAMINHO, e ali a raiz travada do
// modo image não intercepta, então um link dentro da imagem escapa para o host
// do analista.

// Identidade é o que o descritor REALMENTE aberto é.
//
// Ela é a defesa que sobra quando O_NOFOLLOW não basta — e ele não basta: ele
// protege só o ÚLTIMO componente. `/tmp/mau/shadow` com `/tmp/mau -> /etc`
// resolve, e openat2(RESOLVE_NO_SYMLINKS) exigiria Linux 5.6 contra o piso de
// 3.2 que esta ferramenta declara.
//
// Então em vez de fingir uma trava que o kernel-piso não sustenta, o objeto
// aberto se identifica. Dev e Inode transformam o risco em EVIDÊNCIA — que é o
// que quem investiga precisa de qualquer forma.
type Identidade struct {
	Dev      uint64 `json:"dev"`
	Inode    uint64 `json:"inode"`
	Modo     string `json:"mode"`
	Tipo     string `json:"type"`
	Nlink    uint64 `json:"nlink"`
	UID      uint32 `json:"uid"`
	GID      uint32 `json:"gid"`
	Tamanho  int64  `json:"size"`
	MtimeUTC string `json:"mtime"`
	CtimeUTC string `json:"ctime"`

	// Mtim e Ctim são os timestamps CRUS, em nanossegundos, e não viajam no
	// protocolo: eles existem para COMPARAÇÃO.
	//
	// Os campos formatados perdem a fração de segundo, e comparar as strings
	// deles fazia duas leituras a 300ms de distância parecerem o mesmo estado —
	// que é exatamente o intervalo em que uma reescrita acontece.
	Mtim, Ctim syscall.Timespec `json:"-"`
}

// MesmoEstado diz se dois olhares para o MESMO descritor descrevem o mesmo
// arquivo.
//
// Tamanho, mtime E ctime, em nanossegundo. O ctime é o que fecha o caso
// interessante: um processo que escreve o arquivo pode RESTAURAR o mtime — é
// uma chamada de utimes —, e não pode restaurar o ctime, que o kernel atualiza
// em toda mudança de inode. Num host comprometido isso deixa de ser hipótese.
func (i Identidade) MesmoEstado(o Identidade) bool {
	return i.Tamanho == o.Tamanho &&
		i.Mtim.Sec == o.Mtim.Sec && i.Mtim.Nsec == o.Mtim.Nsec &&
		i.Ctim.Sec == o.Ctim.Sec && i.Ctim.Nsec == o.Ctim.Nsec
}

// ErrEhLink é a recusa de seguir um symlink quando o chamador não pediu.
var ErrEhLink = errors.New("algum componente do caminho é um symlink e " +
	"follow_symlinks é false: NENHUM link foi atravessado")

// MaxLeituraDirecionada é o teto de UMA chamada de leitura direcionada.
//
// 64 KiB não é economia de memória — MaxLeitura já cuida disso. É o teto de uma
// JANELA: quem quer mais pede outra janela com offset, e cada janela é uma
// decisão registrada na auditoria. Uma leitura de 8 MiB num único pedido some
// numa linha de log; oitenta leituras de 64 KiB não somem.
const MaxLeituraDirecionada = 64 << 10

// AbrirParaInspecao abre p e devolve o descritor e a identidade do que foi
// EFETIVAMENTE aberto.
//
// seguirLink=false traduz para a recusa de atravessar symlink em QUALQUER
// posição, e o erro vira ErrEhLink — que é resposta, e não falha: "isto é um
// link" é exatamente o que quem investiga quer saber.
//
// Só arquivo COMUM. Fifo, socket e dispositivo são recusados no descritor, pelo
// mesmo motivo de sempre: `mkfifo /etc/ld.so.preload` faz o open bloquear para
// sempre, e /dev/zero não tem fim.
//
// # Ela deixou de ser um caminho especial
//
// Esta função era a ÚNICA do pacote que abria direito. ReadFile, Open e OpenFD
// faziam um O_RDONLY real e só depois perguntavam ao fstat o que era aquilo —
// e para um device node isso é tarde. Hoje as quatro entram pela mesma porta,
// e a diferença entre elas voltou a ser só o que devolvem.
//
// A resolução de symlink também mudou de lugar. Ela era feita aqui, por
// CadeiaDeLinks, e o caminho resolvido era aberto num segundo percurso: duas
// resoluções independentes, com a troca de um link cabendo no meio. Agora o
// link é lido do DESCRITOR dele, dentro do mesmo percurso — a cadeia que sai em
// path_binding continua sendo observação, e a abertura deixou de depender dela.
func (e *Env) AbrirParaInspecao(p string, seguirLink bool) (*os.File, Identidade, error) {
	return e.abrirPorDescritor(p, seguirLink)
}

// identidadeDe extrai a identidade de um FileInfo, indo ao Stat_t por baixo.
//
// UMA função, e não duas. Havia uma segunda que montava o mesmo Identidade a
// partir do Stat_t cru, e as duas já divergiam na forma de derivar o Tipo — a
// primeira por os.FileMode, a segunda por S_IFMT. Duas implementações da mesma
// tradução divergem, e a que diverge é a que ninguém está olhando.
// IdentidadeDe é a versão exportada: quem já tem um FileInfo do MESMO descritor
// consegue montar a identidade sem reabrir nada. É o que file.hash usa para o
// segundo olhar.
func IdentidadeDe(fi os.FileInfo) Identidade { return identidadeDe(fi) }

func identidadeDe(fi os.FileInfo) Identidade {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return identidadeDeStat(st)
	}
	// Sem Stat_t não há inode, e inode é metade do que esta struct existe para
	// dizer. Devolver o pouco que dá é melhor que devolver zeros com cara de
	// fato.
	return Identidade{
		Modo:     fmt.Sprintf("%04o", fi.Mode().Perm()),
		Tamanho:  fi.Size(),
		MtimeUTC: fi.ModTime().UTC().Format(time.RFC3339),
	}
}

// LerJanela lê no máximo n bytes a partir de offset. Devolve o que leu e se
// havia mais depois.
func LerJanela(fh *os.File, offset int64, n int64) ([]byte, bool, error) {
	if offset < 0 {
		return nil, false, errors.New("offset negativo")
	}
	if n <= 0 || n > MaxLeituraDirecionada {
		n = MaxLeituraDirecionada
	}
	if _, err := fh.Seek(offset, io.SeekStart); err != nil {
		return nil, false, err
	}
	// n+1 para descobrir se sobrou, sem uma segunda syscall e sem confiar no
	// tamanho do stat: um arquivo de /proc reporta zero e tem conteúdo.
	buf := make([]byte, n+1)
	lido, err := io.ReadFull(fh, buf)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, false, err
	}
	if int64(lido) > n {
		return buf[:n], true, nil
	}
	return buf[:lido], false, nil
}

// Xattr é um atributo estendido, com o valor CRU.
type Xattr struct {
	Nome    string `json:"name"`
	Tamanho int    `json:"size"`
	Valor   []byte `json:"-"`
}

// MaxXattr é o teto do valor de UM atributo. Xattr aceita conteúdo arbitrário,
// e o teto do kernel costuma ser 64 KiB por atributo.
const MaxXattr = 64 << 10

// XattrsDoFD lista e lê os atributos estendidos do DESCRITOR, dentro de um
// ORÇAMENTO.
//
// Por fd, e não por caminho: o coletor de SUID lê `security.capability` por
// caminho, e ali a raiz travada do modo image não intercepta — um link dentro
// da imagem sai para o filesystem do analista. Num fd já aberto e identificado
// não sobra caminho a resolver.
//
// # O orçamento é da AQUISIÇÃO, e não da resposta
//
// A tool tinha um teto agregado e o aplicava DEPOIS: esta função lia e retinha
// todos os valores, e só então a resposta era cortada. Contra um host que
// escolhe quantos xattr plantar — e o threat model é esse —, o teto protegia o
// tamanho do JSON e não a memória do processo, que roda na máquina investigada.
//
// Agora ele para de LER ao esgotar. `total` conta o que existe, para a resposta
// poder dizer quantos ficaram de fora: a ausência de um atributo na lista nunca
// prova que ele não existe.
func XattrsDoFD(fh *os.File, maxAttrs int, maxBytes int) (xs []Xattr, total int, cortado bool, err error) {
	nomes, err := listarXattr(fh)
	if err != nil {
		return nil, 0, false, err
	}
	total = len(nomes)
	var soma int
	for _, n := range nomes {
		if len(xs) >= maxAttrs || soma >= maxBytes {
			cortado = true
			break
		}
		tam, err := tamanhoDeXattr(fh, n)
		if err != nil {
			// Um atributo ilegível é LACUNA, e não motivo para descartar os
			// outros: o tamanho negativo diz que ele existe e não foi lido.
			xs = append(xs, Xattr{Nome: n, Tamanho: -1})
			continue
		}
		if tam > MaxXattr || soma+tam > maxBytes {
			cortado = true
			continue
		}
		v, err := lerXattr(fh, n, tam)
		if err != nil {
			xs = append(xs, Xattr{Nome: n, Tamanho: -1})
			continue
		}
		soma += len(v)
		xs = append(xs, Xattr{Nome: n, Tamanho: len(v), Valor: v})
	}
	return xs, total, cortado, nil
}

// tamanhoDeXattr pergunta o tamanho ANTES de alocar.
//
// fgetxattr com tamanho zero devolve o comprimento sem copiar nada. Sem isso, o
// buffer era sempre de 64 KiB e o `buf[:n]` devolvido mantinha o array inteiro
// vivo: um atributo de dez bytes custava 64 KiB de memória retida, no processo
// que roda no host investigado.
func tamanhoDeXattr(fh *os.File, nome string) (int, error) {
	nb, err := syscall.BytePtrFromString(nome)
	if err != nil {
		return 0, err
	}
	n, _, errno := syscall.Syscall6(syscall.SYS_FGETXATTR, fh.Fd(),
		uintptr(unsafe.Pointer(nb)), 0, 0, 0, 0)
	if errno != 0 {
		return 0, errno
	}
	return int(n), nil
}

func listarXattr(fh *os.File) ([]string, error) {
	buf := make([]byte, 4096)
	for {
		n, _, errno := syscall.Syscall(syscall.SYS_FLISTXATTR, fh.Fd(),
			uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		if errno == syscall.ERANGE && len(buf) < 1<<20 {
			buf = make([]byte, len(buf)*4)
			continue
		}
		if errno != 0 {
			if errno == syscall.ENOTSUP {
				return nil, nil // filesystem sem xattr: ausência, não falha
			}
			return nil, errno
		}
		return separarNUL(buf[:n]), nil
	}
}

func lerXattr(fh *os.File, nome string, tam int) ([]byte, error) {
	nb, err := syscall.BytePtrFromString(nome)
	if err != nil {
		return nil, err
	}
	if tam <= 0 {
		return nil, nil
	}
	// O buffer tem o tamanho do DADO, e não o teto. Ver tamanhoDeXattr.
	buf := make([]byte, tam)
	n, _, errno := syscall.Syscall6(syscall.SYS_FGETXATTR, fh.Fd(),
		uintptr(unsafe.Pointer(nb)), uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)), 0, 0)
	if errno != 0 {
		return nil, errno
	}
	return buf[:n], nil
}

func separarNUL(b []byte) []string {
	var out []string
	inicio := 0
	for i, c := range b {
		if c != 0 {
			continue
		}
		if i > inicio {
			out = append(out, string(b[inicio:i]))
		}
		inicio = i + 1
	}
	return out
}

// maxSaltos é o limite do kernel para resolução de symlink (ELOOP em 40).
// Usar o mesmo número faz a cadeia parar onde o open pararia.
const maxSaltos = 40

// CadeiaDeLinks percorre os COMPONENTES do caminho e devolve os que são
// symlink, mais o caminho resolvido.
//
// # Por que ela existe
//
// Porque O_NOFOLLOW protege só o componente FINAL, e isso foi medido, não
// suposto: com `/tmp/mau -> /etc`, abrir `/tmp/mau/shadow` com O_NOFOLLOW abre
// o /etc/shadow de verdade — nos dois modos, live e image. openat2 com
// RESOLVE_NO_SYMLINKS resolveria, e exige Linux 5.6 contra o piso de 3.2 que
// esta ferramenta declara sustentar.
//
// Então em vez de uma trava que o kernel-piso não sustenta, a cadeia. Ela não
// IMPEDE nada: ela conta. E contar é o que serve a quem investiga — "o caminho
// que você pediu passa por um link plantado" é um achado, não um obstáculo.
func (e *Env) CadeiaDeLinks(p string) (cadeia []string, resolvido string, err error) {
	// A recusa vem ANTES de qualquer resposta, e o erro é o canal.
	//
	// Sem ele, um ambiente selado devolveria cadeia vazia e o próprio caminho
	// como resolvido — que se lê como "olhei, e não há link nenhum aqui". É a
	// ausência virando fato, dentro da função que existe para impedir
	// exatamente isso em outro lugar.
	if err := e.raizIndisponivel(); err != nil {
		return nil, "", err
	}
	atual := path.Clean("/" + p)
	// Atravessar o MESMO link duas vezes é o ciclo. Descobri-lo assim, e não
	// esgotando os 40 saltos, é a diferença entre uma linha que explica e
	// quarenta linhas idênticas que o modelo tem de ler para chegar à mesma
	// conclusão.
	visto := map[string]bool{}
	for saltos := 0; saltos < maxSaltos; saltos++ {
		trocou := false
		partes := strings.Split(strings.TrimPrefix(atual, "/"), "/")
		prefixo := ""
		for i, parte := range partes {
			if parte == "" {
				continue
			}
			prefixo += "/" + parte
			fi, err := e.Lstat(prefixo)
			if err != nil || fi.Mode()&os.ModeSymlink == 0 {
				continue
			}
			alvo, err := e.Readlink(prefixo)
			if err != nil {
				continue
			}
			if visto[prefixo] {
				return append(cadeia, "ciclo de symlink: "+prefixo+
					" já foi atravessado nesta resolução, e o kernel devolveria "+
					"ELOOP aqui"), atual, nil
			}
			visto[prefixo] = true
			cadeia = append(cadeia, prefixo+" -> "+alvo)
			// O alvo relativo resolve contra o DIRETÓRIO do link, e o absoluto
			// substitui o prefixo inteiro. É a regra do kernel, e errá-la faria
			// a cadeia apontar para um arquivo que ninguém abriu.
			var novo string
			if strings.HasPrefix(alvo, "/") {
				novo = alvo
			} else {
				novo = path.Join(path.Dir(prefixo), alvo)
			}
			atual = path.Clean(path.Join(novo, path.Join(partes[i+1:]...)))
			trocou = true
			break
		}
		if !trocou {
			return cadeia, atual, nil
		}
	}
	// Sem link repetido e ainda assim quarenta saltos: uma escada de links
	// distintos, que é o que o kernel também recusa.
	return append(cadeia, "cadeia longa demais: parei em "+strconv.Itoa(maxSaltos)+
		" saltos, que é o mesmo teto do kernel"), atual, nil
}

// abrirPorDescritor é a ponte deste pacote para safeio.
//
// Ela carrega as duas coisas que só o Env sabe — a raiz travada do modo image e
// a preferência por preservar o atime do alvo — e traduz as recusas de volta
// para os sentinelas que os chamadores de env já conferem.
//
// O percurso em si mora em safeio porque a regra não é sobre o alvo: um dump,
// uma baseline e uma lista de indicadores precisam da mesma disciplina. Havia
// CINCO implementações dela nesta árvore, em três estados de acerto:
//
//	abrirPorDescritor / preserve   certas, e separadas uma da outra
//	abrirComExtras / dump          fechavam o fifo e deixavam passar o device
//	baseline / ioc                 os.Open seco: nem o fifo
//
// A que diverge é sempre a que ninguém está olhando, e a que estava mais errada
// era a menos visível: `ioc`, que travava para SEMPRE num fifo.
//
// # A contenção continua sendo por construção
//
// safeio.Opcoes.Raiz vira o descritor de onde o percurso parte, e todo caminho
// é normalizado contra "/" antes de ser andado. Um symlink absoluto para
// /etc/shadow dentro de uma imagem resolve para o /etc/shadow DA IMAGEM, que é
// o que o kernel faria num chroot. Medido contra uma imagem montada, com
// /../fora.txt e /etc/../../fora.txt.
func (e *Env) abrirPorDescritor(p string, seguirLink bool) (*os.File, Identidade, error) {
	if err := e.raizIndisponivel(); err != nil {
		return nil, Identidade{}, err
	}
	fh, st, err := safeio.Abrir(p, safeio.Opcoes{
		Raiz:       e.Root,
		SeguirLink: seguirLink,
		// O atime é EVIDÊNCIA: quando um arquivo foi lido pela última vez é
		// fato sobre o host investigado, e uma ferramenta de resposta a
		// incidente que o apaga ao olhar destrói o que veio buscar.
		PreservarAtime: true,
	})
	var id Identidade
	if st.Mode != 0 {
		// Mode zero é a falha que aconteceu ANTES de qualquer fstat — abrir a
		// própria raiz. Montar uma identidade a partir dela devolveria zeros
		// com cara de fato.
		id = identidadeDeStat(&st)
	}
	switch {
	case errors.Is(err, safeio.ErrEhLink):
		return nil, id, ErrEhLink
	case errors.Is(err, safeio.ErrNaoRegular):
		// A identidade sai completa mesmo na recusa: "isto é um device node,
		// dev tal, inode tal" é o que quem investiga queria saber.
		return nil, id, ErrNaoEhArquivo
	case err != nil:
		return nil, id, err
	}
	return fh, id, nil
}

func identidadeDeStat(st *syscall.Stat_t) Identidade {
	id := Identidade{
		Dev: uint64(st.Dev), Inode: uint64(st.Ino),
		// 07777, e não os 0777 de FileMode.Perm().
		//
		// Perm() descarta setuid, setgid e sticky — e um binário 4755 saía
		// daqui como 0755. É precisamente o bit que se procura num host
		// comprometido: `find -perm /4000` é a caça clássica, e a família file.*
		// existe para dizer o que o objeto aberto É. Reportar 0755 sobre um
		// setuid root é uma falsa tranquilidade vinda da tool que promete
		// identidade.
		Modo:  fmt.Sprintf("%04o", st.Mode&0o7777),
		Nlink: uint64(st.Nlink), UID: st.Uid, GID: st.Gid,
		Tamanho: st.Size,
		// RFC3339Nano, e não RFC3339: um timestamp que descarta a fração em
		// silêncio esconde exatamente a janela em que uma reescrita cabe. Na
		// análise de linha do tempo, que é o ofício desta ferramenta, a fração
		// é o que ordena dois eventos do mesmo segundo.
		MtimeUTC: time.Unix(int64(st.Mtim.Sec), int64(st.Mtim.Nsec)).UTC().Format(time.RFC3339Nano),
		CtimeUTC: time.Unix(int64(st.Ctim.Sec), int64(st.Ctim.Nsec)).UTC().Format(time.RFC3339Nano),
		Mtim:     st.Mtim, Ctim: st.Ctim,
	}
	switch st.Mode & syscall.S_IFMT {
	case syscall.S_IFREG:
		id.Tipo = "regular"
	case syscall.S_IFLNK:
		id.Tipo = "symlink"
	case syscall.S_IFDIR:
		id.Tipo = "dir"
	case syscall.S_IFIFO:
		id.Tipo = "fifo"
	case syscall.S_IFSOCK:
		id.Tipo = "socket"
	case syscall.S_IFCHR:
		id.Tipo = "chardev"
	case syscall.S_IFBLK:
		id.Tipo = "blockdev"
	default:
		id.Tipo = "other"
	}
	return id
}
