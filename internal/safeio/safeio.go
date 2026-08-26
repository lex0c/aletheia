// Package safeio é a ÚNICA porta de abertura de arquivo desta ferramenta.
//
// # Por que um pacote, e não um método a mais em env
//
// Porque a regra não é sobre o alvo: ela é sobre QUALQUER arquivo cujo tipo
// quem abre não escolheu. O host investigado escolhe o que há em
// /etc/ld.so.preload; o operador aponta --ioc para um caminho que pode ter sido
// escrito por outra pessoa; um dump chega de um host que ninguém confia. Os
// três precisam da mesma disciplina, e havia três implementações dela:
//
//	env.abrirComExtras  open(O_RDONLY|O_NONBLOCK) e DEPOIS fstat
//	dump.AbrirArtefato  open(O_RDONLY|O_NONBLOCK) e DEPOIS fstat
//	baseline / ioc      os.Open, sem nem O_NONBLOCK
//
// A terceira travava para sempre num fifo — medido: `mkfifo indicators.yml`
// pendura `scan --ioc` antes de qualquer teto ter chance de agir. E as duas
// primeiras têm o defeito que não aparece no valor de retorno: para um DEVICE
// NODE, o open() do driver já rodou quando o fstat responde "não era arquivo
// comum". Uma ferramenta forense que pode ARMAR o watchdog ao olhar para
// /etc/ld.so.preload não é read-only, por mais que a recusa saia bonita.
//
// # A disciplina
//
//	O_PATH em cada componente    o kernel devolve uma referência ao objeto e
//	                             NÃO chama o open() do driver
//	fstat no descritor           o tipo sai do que foi aberto, não do caminho —
//	                             não há janela para trocar nada no meio
//	só então reabrir             pelo MESMO inode, via /proc/self/fd/N
//
// O symlink é detectado pelo TIPO no fstat, e não por errno: O_PATH com
// O_NOFOLLOW devolve um descritor para o PRÓPRIO link em vez de ELOOP.
//
// # O piso de kernel
//
// O_PATH é de 2.6.39 e readlinkat com caminho vazio também. A ferramenta
// declara piso 3.2, então os dois cabem. openat2(RESOLVE_NO_SYMLINKS), que
// resolveria a contenção num só passo, exige 5.6 e ficaria de fora — é por
// isso que o percurso é componente a componente, à mão.
package safeio

import (
	"errors"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// oPath é O_PATH. syscall não o exporta em todas as arquiteturas que este
// binário cruza, e o valor é o mesmo em todas as que o Linux suporta.
const oPath = 0x200000

// maxSaltos é o limite do kernel para resolução de symlink (ELOOP em 40).
// Usar o mesmo número faz o percurso parar onde o open pararia.
const maxSaltos = 40

var (
	// ErrEhLink é a recusa de atravessar symlink quando o chamador não pediu.
	// Não é falha: "isto é um link" costuma ser a resposta que interessa.
	ErrEhLink = errors.New("algum componente do caminho é um symlink e " +
		"seguir links não foi pedido: NENHUM link foi atravessado")

	// ErrNaoRegular recusa fifo, socket, device e diretório.
	ErrNaoRegular = errors.New("não é arquivo comum (fifo, socket ou dispositivo): " +
		"NÃO foi aberto, porque abrir isto bloqueia, consome sem fim ou " +
		"ACORDA o driver de um dispositivo")

	// ErrTrocado é a corrida perdida virando recusa em vez de resposta errada.
	ErrTrocado = errors.New("o arquivo foi TROCADO entre a identificação e a " +
		"leitura: o par (dev, inode) mudou. A leitura foi RECUSADA em vez de " +
		"devolver o conteúdo de outro objeto com o nome pedido")
)

// ObservarAberturaReal é o gancho que permite a um teste PROVAR onde um open()
// de verdade acontece.
//
// Ele existe porque a asserção óbvia não distingue nada: a recusa de um device
// sai idêntica no código que abre-depois-verifica e no que verifica-antes-de-
// abrir. O que separa os dois é se o open() do driver rodou — e isso não
// aparece no valor de retorno.
//
// Depois deste pacote existir há UM open() real em todo o caminho de leitura, e
// ele está em reabrir(), depois da prova. Um teste que aponte a ferramenta para
// um device e veja este gancho disparar encontrou uma regressão.
//
// nil em produção; o custo é uma comparação por abertura.
var ObservarAberturaReal func(caminho string)

// Opcoes são as três decisões que o chamador realmente tem.
type Opcoes struct {
	// Raiz TRAVA o percurso: nenhum caminho, nem por symlink absoluto, sai
	// dela. "" é o host vivo, sem trava.
	//
	// A contenção não é uma checagem: é o percurso partir do descritor da raiz
	// e todo caminho ser normalizado contra "/". Um link para /etc/shadow
	// dentro de uma imagem resolve para o /etc/shadow DA IMAGEM, que é o que o
	// kernel faria num chroot.
	Raiz string

	// SeguirLink resolve a cadeia de symlinks, como um open comum faria — mas
	// SEM nunca abrir de verdade um objeto ainda não provado regular. Falso
	// recusa o link em QUALQUER posição, que é mais forte do que O_NOFOLLOW dá
	// (ele protege só o último componente).
	SeguirLink bool

	// PreservarAtime tenta O_NOATIME e DEGRADA se não for dono do arquivo.
	//
	// Quando um arquivo foi lido pela última vez é FATO sobre o host
	// investigado, e uma ferramenta de resposta a incidente que o apaga ao
	// olhar destrói a evidência que veio buscar.
	PreservarAtime bool
}

// Abrir devolve o descritor de LEITURA de um arquivo comum e o Stat_t do que
// foi EFETIVAMENTE aberto.
//
// O Stat_t sai preenchido inclusive nas recusas: "isto é um device node, dev
// tal, inode tal" é o que quem investiga queria saber, e devolver zeros
// transformaria a recusa em silêncio.
func Abrir(caminho string, o Opcoes) (*os.File, syscall.Stat_t, error) {
	// O CAMINHO QUENTE: sem raiz travada e seguindo link, quem resolve é o
	// kernel, num open só.
	//
	// É a combinação de ReadFile, Open e OpenFD no host vivo — dezenas de
	// milhares de aberturas numa varredura. O percurso componente a componente
	// custa 2K+1 syscalls contra 3, e as duas coisas que ele acrescenta não
	// estão sendo pedidas aqui: a contenção numa raiz (não há raiz) e a recusa
	// de link em posição intermediária (o chamador pediu para seguir).
	//
	// A propriedade que importa NÃO é abrir mão de nada: O_PATH não chama o
	// open() do driver, e o tipo continua saindo do fstat do descritor. E a
	// resolução passa a ser a do kernel, que é a autoridade sobre ela — o
	// percurso à mão só reimplementa essa regra porque nos outros dois casos
	// não dá para delegar.
	if o.Raiz == "" && o.SeguirLink {
		if fh, st, err, resolveu := atalho(caminho, o); resolveu {
			return fh, st, err
		}
		// /proc indisponível: cai no percurso, que sabe reabrir pelo pai.
	}

	raiz := o.Raiz
	if raiz == "" {
		raiz = "/"
	}
	// A raiz é aberta SEGUINDO link de propósito: ela é o caminho que o
	// OPERADOR deu na linha de comando, não um componente que o alvo escolheu.
	raizfd, err := syscall.Open(raiz,
		syscall.O_RDONLY|oPath|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, syscall.Stat_t{}, &os.PathError{Op: "open", Path: raiz, Err: err}
	}
	defer syscall.Close(raizfd)

	// Clean sobre caminho absoluto absorve todo "..", porque não há como subir
	// acima da raiz. É o mecanismo da contenção, e não uma validação em outro
	// pacote — uma garantia que depende de validação alheia é uma garantia que
	// o próximo chamador quebra sem saber.
	alvo := path.Clean("/" + caminho)
	for saltos := 0; ; saltos++ {
		fh, st, prox, err := percorrer(raizfd, alvo, caminho, o)
		if prox == "" {
			return fh, st, err
		}
		if saltos >= maxSaltos {
			// Uma escada de links distintos, que é o que o kernel também
			// recusa — e no mesmo número, para que a recusa aqui e a dele
			// concordem.
			return nil, st, &os.PathError{Op: "open", Path: caminho, Err: syscall.ELOOP}
		}
		alvo = prox
	}
}

// AbrirArtefato abre um arquivo do lado de QUEM INVESTIGA — dump, baseline,
// lista de indicadores — com a mesma disciplina e SEM trava de raiz.
//
// Sem trava porque o caminho é do operador, e travá-lo em "/" quebraria um
// `--ioc ../casos/x.yml`. Com a disciplina porque o CONTEÚDO não é do operador:
// um baseline num share que o host investigado escreve, uma lista de
// indicadores que alguém trocou por fifo. `mkfifo indicators.yml` pendurava o
// `scan` para sempre — medido, e é o que esta função fecha.
func AbrirArtefato(caminho string) (*os.File, error) {
	abs, err := filepath.Abs(caminho)
	if err != nil {
		return nil, err
	}
	fh, _, err := Abrir(abs, Opcoes{SeguirLink: true})
	if errors.Is(err, ErrNaoRegular) {
		// O caminho veio do operador: dizer QUAL arquivo foi recusado é a
		// diferença entre uma mensagem acionável e um enigma.
		return nil, &os.PathError{Op: "open", Path: caminho, Err: err}
	}
	return fh, err
}

// atalho resolve o caminho inteiro com UM O_PATH e devolve resolveu=false
// quando não conseguiu terminar o trabalho — o único caso é /proc não estar
// montado, e aí quem responde é o percurso, que reabre pelo descritor do pai.
//
// A recusa NÃO é um caso de resolveu=false: um device node recusado aqui está
// tão decidido quanto recusado lá, e reprocessá-lo no percurso seria abrir a
// mesma pergunta duas vezes.
func atalho(caminho string, o Opcoes) (*os.File, syscall.Stat_t, error, bool) {
	var st syscall.Stat_t
	fd, err := syscall.Open(caminho, syscall.O_RDONLY|oPath|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, st, &os.PathError{Op: "open", Path: caminho, Err: err}, true
	}
	defer syscall.Close(fd)

	if err := syscall.Fstat(fd, &st); err != nil {
		return nil, st, &os.PathError{Op: "fstat", Path: caminho, Err: err}, true
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return nil, st, ErrNaoRegular, true
	}

	if ObservarAberturaReal != nil {
		ObservarAberturaReal(caminho)
	}
	flags := os.O_RDONLY | syscall.O_NONBLOCK
	viaProc := "/proc/self/fd/" + strconv.Itoa(fd)
	if o.PreservarAtime {
		if fh, err := os.OpenFile(viaProc, flags|syscall.O_NOATIME, 0); err == nil {
			return fh, st, nil, true
		}
	}
	if fh, err := os.OpenFile(viaProc, flags, 0); err == nil {
		return fh, st, nil, true
	}
	return nil, st, nil, false
}

// percorrer anda os componentes de `alvo` a partir de `raizfd`, sem atravessar
// symlink nenhum e sem ACORDAR driver de dispositivo.
//
// Devolve (fh, st, "", nil) quando abriu, (nil, st, "", err) quando recusou, e
// (nil, st, próximoCaminho, nil) quando encontrou um link e o chamador pediu
// para segui-lo — a resolução volta ao laço de Abrir em vez de recursão, para
// que o teto de saltos seja um número só e visível.
func percorrer(raizfd int, alvo, pedido string, o Opcoes) (*os.File, syscall.Stat_t, string, error) {
	var st syscall.Stat_t
	partes := strings.Split(strings.Trim(alvo, "/"), "/")

	// pai é o descritor do diretório que contém o componente atual. Ele fica
	// vivo até o fim porque a reabertura sem /proc precisa dele — reabrir pelo
	// NOME a partir do pai pinado não é uma segunda resolução do caminho.
	atual, pai := raizfd, raizfd
	defer func() {
		if atual != raizfd {
			syscall.Close(atual)
		}
		if pai != raizfd && pai != atual {
			syscall.Close(pai)
		}
	}()

	// O erro carrega o caminho PEDIDO, e não o componente que falhou. Um
	// "openat ld.so.preload: no such file" numa lacuna de relatório manda quem
	// lê procurar um arquivo que não sabe onde fica.
	falha := func(op string, err error) (*os.File, syscall.Stat_t, string, error) {
		return nil, st, "", &os.PathError{Op: op, Path: pedido, Err: err}
	}

	for i, parte := range partes {
		if parte == "" {
			continue
		}
		fd, err := syscall.Openat(atual, parte,
			syscall.O_RDONLY|oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			return falha("openat", err)
		}
		antigo := pai
		pai, atual = atual, fd
		if antigo != raizfd && antigo != pai {
			syscall.Close(antigo)
		}

		if err := syscall.Fstat(atual, &st); err != nil {
			return falha("fstat", err)
		}

		if st.Mode&syscall.S_IFMT == syscall.S_IFLNK {
			if !o.SeguirLink {
				// Um link em QUALQUER posição encerra o percurso. Não é erro do
				// kernel: é a decisão desta função, e é mais forte do que um
				// open comum daria.
				return nil, st, "", ErrEhLink
			}
			// O destino sai do DESCRITOR do link, e não de um readlink por
			// caminho: um segundo readlink resolveria o caminho de novo, e
			// entre as duas resoluções cabe a troca do link.
			destino, err := readlinkDoFD(atual)
			if err != nil {
				return falha("readlinkat", err)
			}
			// O alvo relativo resolve contra o DIRETÓRIO do link, e o absoluto
			// substitui o prefixo inteiro. É a regra do kernel, e errá-la faria
			// a leitura cair num arquivo que ninguém pediu.
			base := destino
			if !strings.HasPrefix(destino, "/") {
				base = path.Join("/"+strings.Join(partes[:i], "/"), destino)
			}
			return nil, st, path.Clean(path.Join(base, path.Join(partes[i+1:]...))), nil
		}

		if i < len(partes)-1 {
			if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
				return falha("openat", syscall.ENOTDIR)
			}
			continue
		}
		if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
			return nil, st, "", ErrNaoRegular
		}
		fh, err := reabrir(atual, pai, parte, pedido, st, o.PreservarAtime)
		if err != nil {
			return nil, st, "", err
		}
		return fh, st, "", nil
	}
	// Só "/" sobrou depois do Clean, e "/" não é arquivo comum.
	st.Mode = syscall.S_IFDIR
	return nil, st, "", ErrNaoRegular
}

// reabrir converte o descritor O_PATH num descritor de leitura.
//
// # É AQUI, e só aqui, que um open() de verdade acontece
//
// Depois da prova de que o objeto é um arquivo comum. É a linha que separa esta
// ferramenta de um `cat` cuidadoso.
//
// # E por que existem dois caminhos
//
// /proc/self/fd/N reabre o MESMO inode sem resolver caminho de novo, e é o
// preferido. Mas /proc pode não estar montado — um shell de resgate, um
// initramfs — e ali a leitura falharia inteira, com um erro que fala de
// /proc/self/fd/3 para quem pediu /etc/shadow.
//
// O segundo caminho reabre pelo NOME a partir do descritor do diretório pai,
// que continua pinado, e então CONFERE o inode. Se alguém trocou o arquivo
// entre as duas aberturas, a corrida vira recusa em vez de resposta errada.
func reabrir(fd, pai int, nome, pedido string, esperado syscall.Stat_t, semAtime bool) (*os.File, error) {
	if ObservarAberturaReal != nil {
		ObservarAberturaReal(pedido)
	}
	flags := os.O_RDONLY | syscall.O_NONBLOCK
	viaProc := "/proc/self/fd/" + strconv.Itoa(fd)
	if semAtime {
		if fh, err := os.OpenFile(viaProc, flags|syscall.O_NOATIME, 0); err == nil {
			return fh, nil
		}
	}
	if fh, err := os.OpenFile(viaProc, flags, 0); err == nil {
		return fh, nil
	}
	return reabrirPeloPai(pai, nome, esperado, flags, semAtime)
}

func reabrirPeloPai(pai int, nome string, esperado syscall.Stat_t, flags int, semAtime bool) (*os.File, error) {
	abrir := func(f int) (int, error) {
		return syscall.Openat(pai, nome, f|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	}
	novo := -1
	if semAtime {
		// O_NOATIME exige ser DONO do arquivo ou ter CAP_FOWNER: como root
		// funciona para tudo, e sem root falha com EPERM em arquivo alheio. Aí
		// a leitura acontece do jeito normal, porque não ler é pior que mover o
		// atime — e a varredura sem root já é degradada por motivos maiores.
		if fd, err := abrir(flags | syscall.O_NOATIME); err == nil {
			novo = fd
		}
	}
	if novo < 0 {
		fd, err := abrir(flags)
		if err != nil {
			return nil, err
		}
		novo = fd
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(novo, &st); err != nil {
		syscall.Close(novo)
		return nil, err
	}
	// A identidade do Linux é o PAR (st_dev, st_ino), e não o inode sozinho.
	//
	// Num host onde o atacante pode montar filesystem, outro dispositivo pode
	// aparecer naquele nome e trazer um inode de mesmo número — números de
	// inode só são únicos DENTRO de um filesystem.
	if st.Dev != esperado.Dev || st.Ino != esperado.Ino {
		syscall.Close(novo)
		return nil, ErrTrocado
	}
	// O tipo é conferido DE NOVO no descritor que vai ser lido. O par
	// (dev,inode) sozinho não basta: um inode reciclado depois de um unlink
	// pode ter voltado como outra coisa, e esta é a última chance de descobrir
	// isso antes de alguém ler.
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		syscall.Close(novo)
		return nil, ErrNaoRegular
	}
	return os.NewFile(uintptr(novo), nome), nil
}

// readlinkDoFD lê o destino de um symlink a partir do DESCRITOR O_PATH dele.
//
// readlinkat com pathname vazio opera sobre o próprio dirfd, e é uma das
// operações que o kernel permite num descritor O_PATH desde 2.6.39. syscall não
// exporta Readlinkat, então a chamada é crua — o mesmo que este projeto já faz
// para fgetxattr.
func readlinkDoFD(fd int) (string, error) {
	vazio := []byte{0}
	buf := make([]byte, syscall.PathMax)
	n, _, errno := syscall.Syscall6(syscall.SYS_READLINKAT, uintptr(fd),
		uintptr(unsafe.Pointer(&vazio[0])),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0, 0)
	if errno != 0 {
		return "", errno
	}
	if int(n) >= len(buf) {
		// O destino não coube: seguir um caminho truncado abriria outro
		// arquivo, e a recusa é o lado seguro.
		return "", syscall.ENAMETOOLONG
	}
	return string(buf[:n]), nil
}
