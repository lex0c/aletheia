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
// seguirLink=false traduz para O_NOFOLLOW, e o erro vira ErrEhLink — que é
// resposta, e não falha: "isto é um link" é exatamente o que quem investiga
// quer saber.
//
// Só arquivo COMUM. Fifo, socket e dispositivo são recusados no descritor, pelo
// mesmo motivo de sempre: `mkfifo /etc/ld.so.preload` faz o open bloquear para
// sempre, e /dev/zero não tem fim.
func (e *Env) AbrirParaInspecao(p string, seguirLink bool) (*os.File, Identidade, error) {
	extra := syscall.O_NOFOLLOW
	if seguirLink {
		extra = 0
	}
	// SEM SEGUIR LINK, O CAMINHO É PERCORRIDO POR DESCRITOR.
	//
	// É a diferença entre observar e garantir. A versão anterior resolvia a
	// cadeia com uma série de Lstat e DEPOIS abria o caminho de novo: duas
	// resoluções independentes, e entre elas cabia a troca de um link. A
	// resposta trazia a identidade real do fd — isso estava certo —, mas
	// afirmava junto uma link_chain e um resolved_path que podiam pertencer a
	// outra resolução. Num host comprometido, que é o threat model, a cadeia é
	// justamente a defesa escolhida.
	//
	// Agora cada componente é aberto com openat + O_NOFOLLOW a partir do
	// descritor do anterior. Nenhum symlink é atravessado, em nenhuma posição —
	// nem o final nem os do meio. É o que openat2(RESOLVE_NO_SYMLINKS) faria, e
	// funciona no piso de kernel que esta ferramenta declara, porque openat com
	// O_NOFOLLOW é de sempre.
	//
	// A garantia que sai daqui é MAIS FORTE que a anterior, e mais forte que a
	// do kernel para um open comum: com follow_symlinks:false, o arquivo aberto
	// está exatamente no caminho pedido. A cadeia vazia deixa de ser "não vi
	// link" e passa a ser "não há link", e resolved_path deixa de ser
	// observação e vira o próprio caminho.
	if !seguirLink {
		return e.abrirPorDescritor(p)
	}

	// O os.Root NÃO honra O_NOFOLLOW, e isto foi medido: com a raiz travada, um
	// `/tmp/atalho -> ../etc/shadow` abriu o shadow com follow_symlinks:false.
	// Ele resolve os componentes por conta própria — é assim que garante que
	// nada escapa da raiz — e a flag chega ao openat final, quando já não há
	// link nenhum para recusar.
	//
	// Então a recusa vem de um Lstat antes. É uma pré-checagem, e não a trava do
	// kernel: entre ela e o open cabe uma troca. A janela é DENTRO da raiz
	// travada — uma imagem montada, que o analista monta somente-leitura —, e o
	// que sobra dela a identidade devolvida fecha: dev e inode dizem o que foi
	// aberto, tenha sido o que for.
	//
	// Prometer O_NOFOLLOW aqui e não entregá-lo seria pior que não oferecer a
	// opção: quem lê "não segui link" concluiria que o caminho pedido é o
	// caminho lido.
	fh, err := e.abrirComExtras(p, extra)
	if err != nil {
		// ELOOP com O_NOFOLLOW significa "o componente final É um link", e não
		// "há um ciclo". Traduzir isso é a diferença entre uma resposta e um
		// errno cru.
		if !seguirLink && errors.Is(err, syscall.ELOOP) {
			return nil, Identidade{}, ErrEhLink
		}
		return nil, Identidade{}, err
	}
	fi, err := fh.Stat()
	if err != nil {
		fh.Close()
		return nil, Identidade{}, err
	}
	id := identidadeDe(fi)
	if !fi.Mode().IsRegular() {
		fh.Close()
		return nil, id, ErrNaoEhArquivo
	}
	return fh, id, nil
}

func identidadeDe(fi os.FileInfo) Identidade {
	id := Identidade{
		Modo:     fmt.Sprintf("%04o", fi.Mode().Perm()),
		Tipo:     tipoDe(fi.Mode()),
		Tamanho:  fi.Size(),
		MtimeUTC: fi.ModTime().UTC().Format(time.RFC3339),
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return id
	}
	id.Dev, id.Inode = uint64(st.Dev), uint64(st.Ino)
	id.Nlink, id.UID, id.GID = uint64(st.Nlink), st.Uid, st.Gid
	id.CtimeUTC = time.Unix(int64(st.Ctim.Sec), int64(st.Ctim.Nsec)).
		UTC().Format(time.RFC3339)
	return id
}

func tipoDe(m os.FileMode) string {
	switch {
	case m.IsRegular():
		return "regular"
	case m&os.ModeSymlink != 0:
		return "symlink"
	case m.IsDir():
		return "dir"
	case m&os.ModeNamedPipe != 0:
		return "fifo"
	case m&os.ModeSocket != 0:
		return "socket"
	case m&os.ModeDevice != 0:
		if m&os.ModeCharDevice != 0 {
			return "chardev"
		}
		return "blockdev"
	}
	return "other"
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

// XattrsDoFD lista e lê os atributos estendidos do DESCRITOR.
//
// Por fd, e não por caminho: o coletor de SUID lê `security.capability` por
// caminho, e ali a raiz travada do modo image não intercepta — um link dentro
// da imagem sai para o filesystem do analista. Num fd já aberto e identificado
// não sobra caminho a resolver.
func XattrsDoFD(fh *os.File) ([]Xattr, error) {
	nomes, err := listarXattr(fh)
	if err != nil {
		return nil, err
	}
	out := make([]Xattr, 0, len(nomes))
	for _, n := range nomes {
		v, err := lerXattr(fh, n)
		if err != nil {
			// Um atributo ilegível é LACUNA, e não motivo para descartar os
			// outros: o tamanho negativo diz que ele existe e não foi lido.
			out = append(out, Xattr{Nome: n, Tamanho: -1})
			continue
		}
		out = append(out, Xattr{Nome: n, Tamanho: len(v), Valor: v})
	}
	return out, nil
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

func lerXattr(fh *os.File, nome string) ([]byte, error) {
	nb, err := syscall.BytePtrFromString(nome)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, MaxXattr)
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

// oPath é O_PATH. O Go não o exporta em syscall, e o valor é 010000000 no
// asm-generic do kernel — o mesmo em x86, arm, arm64 e mips. Um teste o
// verifica em tempo de execução em vez de confiar: ele abre um diretório com a
// flag e exige que a LEITURA falhe, que é a propriedade que importa.
const oPath = 0x200000

// abrirPorDescritor percorre o caminho componente a componente, sem atravessar
// symlink nenhum, e sem ACORDAR driver de dispositivo.
//
// Cada componente é aberto com O_PATH: o kernel devolve uma referência ao
// objeto e NÃO chama o open() do driver. É isso que separa "descobri que era um
// device node" de "abri um device node para descobrir". Num host comprometido
// com root — que é o threat model desta entrega — um caminho de aparência banal
// pode ser um /dev/qualquer-coisa que faz algo ao ser aberto.
//
// O symlink é detectado pelo TIPO no fstat, e não por errno: O_PATH com
// O_NOFOLLOW devolve um descritor para o PRÓPRIO link, em vez de ELOOP. Medido.
//
// Só depois de provado regular o arquivo é reaberto para leitura, por
// /proc/self/fd/N — que reabre o MESMO inode, sem uma segunda resolução de
// caminho. A raiz do percurso é "/" no host vivo e a raiz da imagem em modo
// image; como nenhum link é atravessado e validarCaminho já recusou caminho não
// normalizado — logo, sem ".." —, a contenção é por construção.
func (e *Env) abrirPorDescritor(p string) (*os.File, Identidade, error) {
	if err := e.raizIndisponivel(); err != nil {
		return nil, Identidade{}, err
	}
	raiz := "/"
	if e.Root != "" {
		raiz = e.Root
	}
	// A raiz é aberta SEGUINDO link de propósito: ela é o caminho que o
	// OPERADOR deu na linha de comando, não um componente que o alvo escolheu.
	dirfd, err := syscall.Open(raiz,
		syscall.O_RDONLY|oPath|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, Identidade{}, &os.PathError{Op: "open", Path: raiz, Err: err}
	}
	defer syscall.Close(dirfd)

	partes := strings.Split(strings.Trim(path.Clean("/"+p), "/"), "/")
	atual := dirfd
	fechar := func() {
		if atual != dirfd {
			syscall.Close(atual)
		}
	}
	for i, parte := range partes {
		if parte == "" {
			continue
		}
		fd, err := syscall.Openat(atual, parte,
			syscall.O_RDONLY|oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			fechar()
			return nil, Identidade{}, &os.PathError{Op: "openat", Path: parte, Err: err}
		}
		fechar()
		atual = fd

		var st syscall.Stat_t
		if err := syscall.Fstat(atual, &st); err != nil {
			syscall.Close(atual)
			return nil, Identidade{}, err
		}
		id := identidadeDeStat(&st)

		// Um link em QUALQUER posição encerra o percurso. Não é erro do kernel:
		// é a decisão desta função, e é mais forte do que um open comum daria.
		if st.Mode&syscall.S_IFMT == syscall.S_IFLNK {
			syscall.Close(atual)
			return nil, id, ErrEhLink
		}
		if i < len(partes)-1 {
			if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
				syscall.Close(atual)
				return nil, id, &os.PathError{
					Op: "openat", Path: parte, Err: syscall.ENOTDIR}
			}
			continue
		}
		if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
			syscall.Close(atual)
			// A identidade sai completa mesmo na recusa: "isto é um device
			// node, dev tal, inode tal" é o que quem investiga queria saber.
			return nil, id, ErrNaoEhArquivo
		}
		fh, err := reabrirParaLeitura(atual)
		syscall.Close(atual)
		if err != nil {
			return nil, id, err
		}
		return fh, id, nil
	}
	// Só "/" sobrou depois do Clean, e "/" não é arquivo comum.
	return nil, Identidade{Tipo: "dir"}, ErrNaoEhArquivo
}

// reabrirParaLeitura converte o descritor O_PATH num descritor de leitura.
//
// Por /proc/self/fd/N, que reabre o MESMO inode — não é uma segunda resolução
// do caminho, e por isso não reabre a janela que o percurso fechou.
func reabrirParaLeitura(fd int) (*os.File, error) {
	return os.OpenFile("/proc/self/fd/"+strconv.Itoa(fd),
		os.O_RDONLY|syscall.O_NONBLOCK, 0)
}

func identidadeDeStat(st *syscall.Stat_t) Identidade {
	id := Identidade{
		Dev: uint64(st.Dev), Inode: uint64(st.Ino),
		Modo:  fmt.Sprintf("%04o", os.FileMode(st.Mode).Perm()),
		Nlink: uint64(st.Nlink), UID: st.Uid, GID: st.Gid,
		Tamanho:  st.Size,
		MtimeUTC: time.Unix(int64(st.Mtim.Sec), int64(st.Mtim.Nsec)).UTC().Format(time.RFC3339),
		CtimeUTC: time.Unix(int64(st.Ctim.Sec), int64(st.Ctim.Nsec)).UTC().Format(time.RFC3339),
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
