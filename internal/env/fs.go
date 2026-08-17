package env

import (
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

// ReadFile lê um arquivo, travado na raiz quando em modo image.
func (e *Env) ReadFile(p string) ([]byte, error) {
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
