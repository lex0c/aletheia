package env

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
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
)

// ReadFile lê um arquivo, travado na raiz quando em modo image.
//
// Duas recusas antes de abrir, e as duas foram reproduzidas contra o binário
// real por uma revisão:
//
//	fifo       `mkfifo /etc/ld.so.preload` — caminho que a ferramenta SEMPRE lê
//	           e que o atacante já toca. O open bloqueia para sempre e a
//	           varredura nunca termina
//	tamanho    arquivo esparso de 8 GB derruba o processo por falta de memória
//
// O `Lstat` antes do open é o que impede as duas. Ele é uma chamada a mais por
// arquivo lido, e é o preço de ler o disco de um host que não é seu.
func (e *Env) ReadFile(p string) ([]byte, error) {
	fi, err := e.Lstat(p)
	if err != nil {
		return nil, err
	}
	// Symlink é seguido de propósito (é assim que /etc/rc.local funciona em
	// RHEL), mas o ALVO precisa passar pelas mesmas travas.
	if fi.Mode()&fs.ModeSymlink != 0 {
		if fi, err = e.Stat(p); err != nil {
			return nil, err
		}
	}
	if !fi.Mode().IsRegular() {
		return nil, ErrNaoEhArquivo
	}
	if fi.Size() > MaxLeitura {
		return nil, ErrGrandeDemais
	}
	if e.root == nil {
		return os.ReadFile(p)
	}
	return e.root.ReadFile(rel(p))
}

// Stat segue symlink, mas nunca para fora da raiz.
func (e *Env) Stat(p string) (fs.FileInfo, error) {
	if e.root == nil {
		return os.Stat(p)
	}
	return e.root.Stat(rel(p))
}

// Lstat não segue o link final — é o que se quer para DETECTAR um link
// plantado, em vez de silenciosamente segui-lo.
func (e *Env) Lstat(p string) (fs.FileInfo, error) {
	if e.root == nil {
		return os.Lstat(p)
	}
	return e.root.Lstat(rel(p))
}

// Readlink devolve o alvo bruto do link, sem resolvê-lo.
func (e *Env) Readlink(p string) (string, error) {
	if e.root == nil {
		return os.Readlink(p)
	}
	return e.root.Readlink(rel(p))
}

// Open abre um arquivo para leitura em FLUXO, travado na raiz quando em modo
// image. Existe para o cálculo de hash: carregar um binário de centenas de
// megabytes inteiro na memória para depois copiá-lo num hash gasta o dobro do
// necessário, e alguns candidatos são grandes.
func (e *Env) Open(p string) (io.ReadCloser, error) {
	if e.root == nil {
		return os.Open(p)
	}
	return e.root.Open(rel(p))
}

// ReadDir lista um diretório dentro da raiz.
func (e *Env) ReadDir(p string) ([]fs.DirEntry, error) {
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
