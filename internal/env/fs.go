package env

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"syscall"
)

// Acesso a filesystem, e o motivo de ele não ser `os.ReadFile(e.Path(p))`.
//
// Prefixar string resolve só a metade LÉXICA do problema: `filepath.Join` limpa
// "..", mas nada impede um symlink ABSOLUTO dentro da imagem de apontar para
// fora dela — e symlink absoluto é situação normal em rootfs real
// (/etc/os-release → /usr/lib/os-release). Sem trava, `scan --root <img>`
// lê /etc/hostname do ANALISTA e atribui o valor à imagem.
//
// Pior: os probes de capacidade compartilham a fuga. Um /var/lib/dpkg/status
// plantado como link faria os checks futuros rodarem contra os arquivos do
// analista e reportarem a imagem como limpa.
//
// os.Root resolve isso no kernel (openat2/RESOLVE_BENEATH): qualquer caminho
// que escape da raiz falha, incluindo por symlink.

// MaxLeitura é o teto de UM arquivo lido do alvo.
//
// Ele existe porque o conteúdo é hostil por definição. Sem teto, um usuário sem
// privilégio nenhum derruba a varredura com um comando:
//
//	truncate -s 8G ~/.ssh/authorized_keys   → arquivo esparso, 0 byte de disco
//
// O `os.ReadFile` aloca os 8 GB, o runtime morre em `fatal error: out of
// memory`, e o processo sai com status 2 — que o contrato desta ferramenta
// define como "CRITICAL: indicador de alta confiança". Um recover não alcança
// isso: o runtime aborta sem passar por panic.
//
// 32 MB é folgado para tudo que esta ferramenta lê de propósito (config, chave,
// crontab, unit, log de rotação) e barato de recusar.
const MaxLeitura = 32 << 20

// ErrGrandeDemais e ErrNaoEhArquivo são recusas, não falhas: quem chama precisa
// declarar a lacuna em vez de tratar como "não havia nada".
var (
	ErrGrandeDemais = errors.New("arquivo maior que o teto de leitura: NÃO foi lido")
	ErrNaoEhArquivo = errors.New("não é arquivo comum (fifo, socket ou dispositivo): " +
		"NÃO foi lido, porque abrir isto bloqueia ou consome sem fim")
	// ErrSelado recusa QUALQUER leitura num Env reconstruído a partir de um
	// artefato. Um dump é o registro de uma coleta que TERMINOU: o ambiente que
	// dump.Env() devolve descreve as condições daquela coleta, e não é uma porta
	// para o filesystem de agora.
	//
	// Sem isto a recusa cobria só metade do problema. Um dump com Source=image
	// batia em ErrSemRaiz — mas um dump coletado no HOST VIVO tem Root vazio e
	// Source=live, e aí ReadFile caía direto no os.ReadFile do processo. Medido:
	// `d.Env(nil).ReadFile("/etc/hostname")` devolveu o hostname da máquina do
	// ANALISTA, sete bytes, sem erro nenhum. A ferramenta responderia sobre a
	// estação de quem investiga achando que fala do alvo.
	//
	// Nenhum check e nenhum dossiê lê filesystem hoje — todos são função pura
	// sobre Facts —, então a porta nunca foi atravessada. É exatamente por isso
	// que ela se fecha agora: uma porta que ninguém usa é barata de trancar, e
	// cara de descobrir aberta depois que alguém passou.
	ErrSelado = errors.New("este ambiente descreve uma coleta ENCERRADA: a " +
		"leitura foi RECUSADA para não responder sobre o host de agora")
	// ErrSemRaiz recusa leitura num Env de IMAGEM cuja raiz travada não está
	// aberta. Ver raizIndisponivel.
	ErrSemRaiz = errors.New("raiz travada da imagem indisponível: a leitura foi " +
		"RECUSADA para não cair no filesystem de quem investiga")
)

// raizIndisponivel é a trava que impede o modo image de degradar para o host do
// analista sem dizer nada.
//
// `root == nil` significa "host vivo" em todos os acessores deste arquivo, e
// Close() põe exatamente isso — então qualquer leitura depois do Close passava
// a ler o /etc do ANALISTA enquanto Path() continuava imprimindo o caminho sob
// a imagem. É a fronteira que este arquivo inteiro existe para defender,
// falhando aberta. O mesmo estado nasce por construção em dump.Env(), que monta
// um Env com Root preenchido e Source=SourceImage sem raiz nenhuma.
//
// probeCaps já trata este par como ausência de CapFilesystem; aqui ele vira
// recusa explícita, para que um acessor chamado mesmo assim erre alto.
func (e *Env) raizIndisponivel() error {
	if e.selado {
		return ErrSelado
	}
	if e.Source == SourceImage && e.root == nil {
		return ErrSemRaiz
	}
	return nil
}

// ReadFile lê um arquivo, travado na raiz quando em modo image.
//
// Duas recusas, e as duas foram reproduzidas contra o binário real:
//
//	fifo       `mkfifo /etc/ld.so.preload` — caminho que a ferramenta SEMPRE lê
//	           e que o atacante já toca. O open bloqueia para sempre e a
//	           varredura nunca termina
//	tamanho    arquivo esparso de 8 GB derruba o processo por falta de memória
//
// As duas são decididas no DESCRITOR, nunca no caminho. A versão anterior fazia
// Lstat, Stat e open como três resoluções independentes do mesmo caminho, e a
// janela entre elas era vencível sem privilégio nenhum: um usuário alternando o
// próprio ~/.ssh/authorized_keys entre arquivo comum e fifo num laço fazia a
// guarda ver "comum, 100 bytes" e o open pegar o fifo. Um open com O_NONBLOCK
// seguido de fstat responde as duas perguntas sobre o objeto que foi REALMENTE
// aberto, e não sobra janela para trocar nada no meio.
func (e *Env) ReadFile(p string) ([]byte, error) {
	fh, fi, err := e.abrirVerificado(p)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	if fi.Size() > MaxLeitura {
		return nil, ErrGrandeDemais
	}
	b := make([]byte, 0, fi.Size())
	buf := make([]byte, 32*1024)
	for {
		n, err := fh.Read(buf)
		b = append(b, buf[:n]...)
		if err == io.EOF {
			return b, nil
		}
		if err != nil {
			return nil, err
		}
		if len(b) > MaxLeitura {
			return nil, ErrGrandeDemais
		}
	}
}

// abrirSemTocarAtime abre para leitura preservando o ATIME do arquivo.
//
// Ler um arquivo MOVE o atime dele, e num filesystem montado com `relatime` —
// o padrão de toda distribuição — isso apaga a data em que o arquivo foi lido
// pela última vez. Medido: um `authorized_keys` com atime de 1º de junho saía
// da varredura com o atime de HOJE.
//
// A ferramenta usa data como evidência (§9) e não pode destruir uma das três
// que existem. Quem leu o `authorized_keys` da conta invadida, e quando, é
// pergunta de incidente — e a resposta estava sendo apagada por quem foi
// investigar.
//
// O_NOATIME exige ser DONO do arquivo ou ter CAP_FOWNER: como root funciona
// para tudo, e sem root falha com EPERM em arquivo alheio. Aí a leitura
// acontece do jeito normal, porque não ler é pior que mover o atime — e a
// varredura sem root já é degradada por motivos maiores.
//
// O_NONBLOCK vai junto e não é detalhe: num arquivo comum ele não tem efeito
// nenhum, e num fifo é a diferença entre retornar na hora e pendurar a
// varredura para sempre — `open(2)` de um fifo para leitura bloqueia até
// aparecer um escritor, e não existe timeout nem cancelamento nesse caminho.
// Quem decide o tipo do objeto é quem escreve no disco do alvo, então a decisão
// tem que ser tomada DEPOIS de abrir, sobre o descritor.
func (e *Env) abrirSemTocarAtime(p string) (*os.File, error) {
	return e.abrirComExtras(p, 0)
}

// abrirComExtras é o abrirSemTocarAtime com flags a mais.
//
// As flags eram `const` dentro dele, e a leitura direcionada do perfil completo
// precisa de O_NOFOLLOW. Um segundo abridor copiado seria a segunda
// implementação da mesma fronteira — a raiz travada, o O_NOATIME que degrada em
// silêncio quando não se é dono, o O_NONBLOCK que impede o fifo de prender a
// varredura para sempre. Duas cópias disso divergem, e a que diverge é sempre a
// que ninguém está olhando.
// observarAberturaReal é o gancho que permite a um teste PROVAR que nenhum
// caminho da família de inspeção chega aqui com um objeto que ainda não foi
// provado regular.
//
// Ele existe porque a asserção óbvia não distingue nada: uma recusa com
// ErrNaoEhArquivo sai igual no código que abre-depois-verifica e no que
// verifica-antes-de-abrir. O que separa os dois é se o open() do driver rodou —
// e isso não aparece no valor de retorno.
//
// nil em produção; o custo é uma comparação por abertura.
var observarAberturaReal func(caminho string)

func (e *Env) abrirComExtras(p string, extras int) (*os.File, error) {
	if observarAberturaReal != nil {
		observarAberturaReal(p)
	}
	flags := os.O_RDONLY | syscall.O_NONBLOCK | extras
	if err := e.raizIndisponivel(); err != nil {
		return nil, err
	}
	if e.root == nil {
		if fh, err := os.OpenFile(p, flags|syscall.O_NOATIME, 0); err == nil {
			return fh, nil
		}
		return os.OpenFile(p, flags, 0)
	}
	if fh, err := e.root.OpenFile(rel(p), flags|syscall.O_NOATIME, 0); err == nil {
		return fh, nil
	}
	return e.root.OpenFile(rel(p), flags, 0)
}

// abrirVerificado abre e só então decide se aquilo devia ter sido aberto.
//
// É o único ponto onde ReadFile e Open concordam sobre o que é legível, e ele
// existe porque os dois divergiam: ReadFile gastava um Lstat para recusar fifo
// e Open não recusava nada. Um `mkfifo /var/log/wtmp` travava lerUtmp em
// open(2), e um arquivo com dono de pacote trocado por fifo travava
// hashDoArquivo DENTRO de um worker — com o wg.Wait() do chamador esperando
// para sempre. Sem timeout e sem lacuna declarada: a varredura simplesmente
// não terminava.
func (e *Env) abrirVerificado(p string) (*os.File, fs.FileInfo, error) {
	fh, err := e.abrirSemTocarAtime(p)
	if err != nil {
		return nil, nil, err
	}
	fi, err := fh.Stat()
	if err != nil {
		fh.Close()
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		fh.Close()
		return nil, nil, ErrNaoEhArquivo
	}
	return fh, fi, nil
}

// Stat segue symlink, mas nunca para fora da raiz.
func (e *Env) Stat(p string) (fs.FileInfo, error) {
	if err := e.raizIndisponivel(); err != nil {
		return nil, err
	}
	if e.root == nil {
		return os.Stat(p)
	}
	return e.root.Stat(rel(p))
}

// Lstat não segue o link final — é o que se quer para DETECTAR um link
// plantado, em vez de silenciosamente segui-lo.
func (e *Env) Lstat(p string) (fs.FileInfo, error) {
	if err := e.raizIndisponivel(); err != nil {
		return nil, err
	}
	if e.root == nil {
		return os.Lstat(p)
	}
	return e.root.Lstat(rel(p))
}

// Readlink devolve o alvo bruto do link, sem resolvê-lo.
func (e *Env) Readlink(p string) (string, error) {
	if err := e.raizIndisponivel(); err != nil {
		return "", err
	}
	if e.root == nil {
		return os.Readlink(p)
	}
	return e.root.Readlink(rel(p))
}

// Open abre um arquivo para leitura em FLUXO, travado na raiz quando em modo
// image. Existe para o cálculo de hash: carregar um binário de centenas de
// megabytes inteiro na memória para depois copiá-lo num hash gasta o dobro do
// necessário, e alguns candidatos são grandes.
//
// Recusa não-arquivo pelo mesmo caminho que ReadFile: quem lê em fluxo tem
// MENOS defesa, não mais — não há teto de tamanho aqui, e o chamador costuma
// estar dentro de um pool de workers.
func (e *Env) Open(p string) (io.ReadCloser, error) {
	fh, _, err := e.abrirVerificado(p)
	if err != nil {
		return nil, err
	}
	return fh, nil
}

// OpenFD abre um arquivo comum e devolve o DESCRITOR, para quem precisa de
// ioctl ou fstat e não só de leitura. Mesmas recusas de Open, e a mesma trava
// de raiz — que é o ponto: `os.OpenFile(e.Path(p))` resolve o caminho com os
// symlinks do HOST DE QUEM INVESTIGA, e um /var/run → /run dentro da imagem faz
// a chamada cair no arquivo do analista. Env.Path é para EXIBIÇÃO.
func (e *Env) OpenFD(p string) (*os.File, error) {
	fh, _, err := e.abrirVerificado(p)
	return fh, err
}

// ReadDir lista um diretório dentro da raiz.
func (e *Env) ReadDir(p string) ([]fs.DirEntry, error) {
	if err := e.raizIndisponivel(); err != nil {
		return nil, err
	}
	if e.root == nil {
		return os.ReadDir(p)
	}
	f, err := e.root.Open(rel(p))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.ReadDir(-1)
}

// ReadDirNames lista os nomes de um diretório, ou nada. Existe porque a metade
// dos usos aqui só quer os nomes e trata "diretório ausente" como resposta
// legítima — persistência é feita de diretórios que costumam não existir.
func (e *Env) ReadDirNames(p string) []string {
	ents, err := e.ReadDir(p)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(ents))
	for _, ent := range ents {
		out = append(out, ent.Name())
	}
	return out
}

// ReadDirNamesErr é a versão que DEVOLVE o erro, para coletor de segurança que
// precisa separar "diretório ausente" (resposta legítima) de "não consegui
// listar" (lacuna). ReadDirNames engole o erro e serve só onde a diferença não
// decide cobertura — nunca numa fonte que responde por integridade.
func (e *Env) ReadDirNamesErr(p string) ([]string, error) {
	ents, err := e.ReadDir(p)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ents))
	for _, ent := range ents {
		out = append(out, ent.Name())
	}
	return out, nil
}

// Estado de um ponto de montagem de filesystem virtual.
//
// /sys/kernel/tracing e /sys/kernel/security são diretórios que o kernel cria
// em todo host com o Kconfig ligado, montados ou não — `IsDir` responde sim nos
// dois casos, e o sim errado vira capacidade CONCEDIDA sobre um diretório
// vazio. São QUATRO estados e não dois, porque "não está montado", "não existe
// neste kernel" e "não consigo listar" levam o operador a coisas diferentes.
type Montagem int

const (
	MontagemAusente       Montagem = iota // o ponto não existe neste host
	MontagemVazia                         // o ponto existe e nada está montado nele
	MontagemAtiva                         // há filesystem montado ali
	MontagemIndeterminada                 // existe e não pôde ser listado
)

// EstadoDeMontagem sonda pelo CONTEÚDO: montado, o diretório tem entradas;
// ponto de montagem ocioso não tem. É a distinção que dá para fazer sem
// depender do mountinfo, que não existe em modo image.
func (e *Env) EstadoDeMontagem(p string) Montagem {
	ents, err := e.ReadDir(p)
	switch {
	case err == nil && len(ents) > 0:
		return MontagemAtiva
	case err == nil:
		return MontagemVazia
	case errors.Is(err, fs.ErrNotExist):
		return MontagemAusente
	}
	// O tracefs montado é 0700 de root, e o ponto ocioso é 0755. Chamar isto de
	// "não montado" seria trocar lacuna por resposta — o erro que esta função
	// existe para não cometer.
	return MontagemIndeterminada
}

// IsDir é o predicado usado pelos probes de capacidade.
func (e *Env) IsDir(p string) bool {
	fi, err := e.Stat(p)
	return err == nil && fi.IsDir()
}

// Exists diz se o caminho existe DENTRO da raiz. Um link que escapa conta como
// inexistente, que é a resposta correta: aquele arquivo não pertence à imagem.
func (e *Env) Exists(p string) bool {
	_, err := e.Stat(p)
	return err == nil
}

// rel converte um caminho absoluto do alvo em caminho relativo à raiz. os.Root
// recusa caminho absoluto, e é ele quem rejeita "..": aqui só se remove a barra
// inicial.
func rel(p string) string {
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return "."
	}
	return p
}

// EhLacuna separa "não existe" de "não consegui olhar".
//
// Ausência é RESPOSTA: metade dos caminhos de persistência não existe na
// maioria dos hosts, e tratar isso como buraco encheria todo relatório de
// ruído. Permissão negada, tamanho acima do teto e tipo que não se lê são
// LACUNA — e é essa distinção que sustenta a tese inteira da ferramenta,
// porque quem trata as duas igual afirma limpeza onde só houve cegueira.
func EhLacuna(err error) bool {
	return err != nil && !errors.Is(err, fs.ErrNotExist)
}

// MotivoDoErro reduz o erro do sistema à CAUSA, sem repetir o caminho. Quem
// chama já tem o caminho e vai escrevê-lo na frase; sem isto a linha sai como
// "/etc/shadow não pôde ser lido (open /etc/shadow: permission denied)".
func MotivoDoErro(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}
