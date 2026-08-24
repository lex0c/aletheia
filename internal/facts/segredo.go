package facts

import (
	"strings"

	"github.com/lex0c/aletheia/internal/env"
)

// Credencial em arquivo (runbook §23).
//
// É o que um invasor procura PRIMEIRO depois de entrar, e o que define até onde
// ele vai a partir daqui. Uma chave de nuvem no home do usuário de deploy vale
// mais que qualquer implante: com ela não é preciso voltar ao host.
//
// O que a ferramenta faz aqui é INVENTÁRIO, e a razão é a mesma do
// `known_hosts`: ela não sabe quais credenciais são esperadas. Tentar julgar
// produziria falso positivo em cada host que tem uma aplicação — e toda
// aplicação tem.
//
// O que ela pode dizer com precisão são duas coisas, e as duas são objetivas:
//
//	onde estão      o raio de alcance, para dimensionar a §23
//	quem lê         permissão frouxa num arquivo de segredo é fato, não opinião
//
// Deliberadamente NÃO se lê o conteúdo. O valor está em existir e em quem
// alcança; carregar segredo para dentro da memória da ferramenta — e daí para
// dentro de um relatório — cria exposição em vez de reduzi-la.

// Segredo é um arquivo que costuma guardar credencial.
type Segredo struct {
	Path string `json:"path"`
	// Tipo é o que aquele caminho costuma guardar, em uma palavra.
	Tipo string `json:"kind"`
	// Modo é a permissão, em octal. Legível por outros é o que importa.
	Modo string `json:"mode"`
	// Aberto marca o arquivo que grupo ou outros conseguem ler.
	Aberto bool   `json:"world_readable,omitempty"`
	ModUTC string `json:"mod_utc,omitempty"`
}

// caminhosDeSegredo são relativos ao home, com o que cada um guarda.
//
// A lista é curta de propósito, e o critério é estreito: o arquivo tem que
// CONTER credencial, não apontar para uma. `.ssh/config` e `.aws/config` saíram
// por isso — os dois são configuração, os dois vivem em 0644 legitimamente, e o
// primeiro rendeu um aviso num host limpo antes de eu notar a diferença.
//
// Apontar não é conter, e onde este host se conecta já é respondido pelo
// `known_hosts`.
var caminhosDeSegredo = []struct{ rel, tipo string }{
	{".aws/credentials", "chave de acesso da AWS"},
	{".config/gcloud/credentials.db", "credencial do Google Cloud"},
	{".config/gcloud/application_default_credentials.json", "credencial padrão do Google Cloud"},
	{".azure/accessTokens.json", "token do Azure"},
	{".kube/config", "acesso ao cluster Kubernetes"},
	{".docker/config.json", "credencial de registro de contêiner"},
	{".netrc", "senha de máquina remota, em texto claro por desenho"},
	{".pgpass", "senha de banco PostgreSQL"},
	{".my.cnf", "senha de banco MySQL"},
	{".git-credentials", "credencial de repositório, em texto claro"},
	{".npmrc", "token de publicação de pacote"},
	{".pypirc", "token de publicação de pacote"},
	{".terraform.d/credentials.tfrc.json", "credencial do Terraform Cloud"},
}

// arquivosDeAmbiente são nomes que guardam segredo de aplicação. Ficam em
// árvore de serviço, não em home.
var arquivosDeAmbiente = []string{".env", ".env.local", ".env.production"}

// raizesDeServico são onde aplicação mora. É a mesma lista dos hooks de git,
// pelo mesmo motivo: é onde deploy coloca coisa.
var raizesDeServico = []string{"/srv", "/opt", "/var/www", "/data", "/usr/share/nginx"}

func collectSegredos(f *Facts, e *env.Env) {
	for _, h := range homeDirs(f, e, "segredo") {
		for _, c := range caminhosDeSegredo {
			registraSegredo(f, e, h+"/"+c.rel, c.tipo)
		}
	}
	// Um nível só nas raízes de serviço: `.env` fica na raiz do projeto, e
	// descer mais transformaria isto numa varredura de filesystem.
	for _, raiz := range raizesDeServico {
		nomes, err := e.ReadDirNamesErr(raiz)
		if env.EhLacuna(err) {
			f.denyPersist("segredo", raiz+" não pôde ser listado ("+
				env.MotivoDoErro(err)+"): os .env de aplicação sob ele NÃO foram "+
				"procurados")
			continue
		}
		for _, n := range nomes {
			for _, env := range arquivosDeAmbiente {
				registraSegredo(f, e, raiz+"/"+n+"/"+env, "segredo de aplicação")
			}
		}
		for _, env := range arquivosDeAmbiente {
			registraSegredo(f, e, raiz+"/"+env, "segredo de aplicação")
		}
	}
}

func registraSegredo(f *Facts, e *env.Env, p, tipo string) {
	fi, err := e.Lstat(p)
	if err != nil {
		// O inventário de segredo mede o RAIO DE ALCANCE de quem invadiu: o
		// que ele leva junto. Caminho que não pôde ser examinado sai da conta
		// sem aparecer, e o raio sai menor do que é.
		if env.EhLacuna(err) {
			f.denyPersist("segredo", p+" não pôde ser examinado ("+
				env.MotivoDoErro(err)+"): não entrou no raio de alcance")
		}
		return
	}
	if !fi.Mode().IsRegular() {
		return
	}
	modo := fi.Mode().Perm()
	s := Segredo{
		Path: p, Tipo: tipo,
		Modo: "0" + strings.TrimPrefix(modoOctal(uint32(modo)), "0"),
		// Grupo ou outros conseguindo LER é o que importa: o segredo deixa de
		// depender da conta dona.
		Aberto: modo&0o044 != 0,
	}
	if !fi.ModTime().IsZero() {
		s.ModUTC = fi.ModTime().UTC().Format("2006-01-02T15:04:05Z")
	}
	f.Segredos = append(f.Segredos, s)
}

func modoOctal(m uint32) string {
	var d [4]byte
	for i := 3; i >= 0; i-- {
		d[i] = byte('0' + m%8)
		m /= 8
	}
	return string(d[:])
}

// CaminhosDeSegredo expõe a lista para o teste que trava o critério: o arquivo
// tem que CONTER credencial, não apontar para uma.
func CaminhosDeSegredo() []string {
	out := make([]string, 0, len(caminhosDeSegredo))
	for _, c := range caminhosDeSegredo {
		out = append(out, c.rel)
	}
	return out
}
