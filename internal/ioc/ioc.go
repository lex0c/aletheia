// Package ioc carrega e casa os indicadores DESTE incidente (SPEC 6.4,
// runbook §23).
//
// # O que ele NÃO é
//
// Não é base de assinatura e não é feed de fornecedor. A ferramenta não tem
// catálogo de malware por decisão de projeto: assinatura envelhece em semanas e
// falha justamente contra quem compilou o implante ontem.
//
// Isto é o contrário: são os indicadores que ESTA investigação produziu — o IP
// que o host comprometido falava, o hash do binário que foi coletado, a chave
// que o invasor acrescentou. A §23 inteira consiste em varrer a frota com eles,
// e sem isto a ferramenta não cobre a §23 de verdade: responder "rode o mesmo
// comando em N hosts" é diferente de responder "ESTE comprometimento está em N
// hosts".
//
// # Por que o formato é lido à mão
//
// A SPEC descreve o arquivo em YAML. Uma biblioteca de YAML custaria a primeira
// dependência do projeto — e o que se ganha é o parse de seis chaves com listas
// de string. O leitor daqui aceita a forma da SPEC, a forma em bloco e a lista
// crua de uma linha por indicador, que é como uma lista chega colada de um
// relatório.
//
// A regra que decide o desenho: **toda linha que não for entendida vira aviso
// visível**. Uma lista de indicadores que carrega pela metade em silêncio, no
// meio de um incidente, é pior que uma que falha.
package ioc

import (
	"errors"
	"io"
	"os"
	"strings"
)

// MaxLista é o teto do arquivo de indicadores, pela mesma razão que
// env.MaxLeitura existe: o caminho é escolhido pelo operador, mas o CONTEÚDO
// costuma vir do host investigado.
var MaxLista int64 = 16 << 20

// ErrGrandeDemais recusa uma lista acima do teto em vez de tentar lê-la.
var ErrGrandeDemais = errors.New("lista de IoC maior que o teto de leitura: NÃO foi lida")

// Tipo é a natureza do indicador. É ele que decide a COMPARAÇÃO: caminho casa
// com curinga, texto casa por conteúdo, IP casa exato.
type Tipo string

const (
	IP      Tipo = "ip"
	Hash    Tipo = "hash"
	Caminho Tipo = "path"
	Texto   Tipo = "string"
	Chave   Tipo = "key"
	Usuario Tipo = "user"
)

// Indicador é uma linha da lista, já classificada.
type Indicador struct {
	Tipo Tipo
	// Valor é o que se compara: normalizado (minúsculas em hash e IP).
	Valor string
	// Bruto é como o operador escreveu, para o achado citar a lista dele e não
	// uma versão editada.
	Bruto string
	Linha int
	// Algo só existe em hash: md5 | sha1 | sha256, deduzido do tamanho ou
	// declarado com prefixo.
	Algo string
}

// Lista é o conteúdo do arquivo de indicadores.
type Lista struct {
	Arquivo string
	Itens   []Indicador
	// Avisos são as linhas que o leitor NÃO entendeu. Elas existem para o
	// operador saber que parte da lista dele não entrou — nunca para serem
	// engolidas.
	Avisos []string
}

var (
	// ErrVazia é o caso mais perigoso: um arquivo que existe, foi lido e não
	// produziu indicador nenhum. A varredura seguiria limpa e o operador leria
	// "nada encontrado" achando que procurou.
	ErrVazia = errors.New("a lista não trouxe indicador nenhum")
)

// chaves aceitas na forma da SPEC.
var chavesDeLista = map[string]Tipo{
	"ips": IP, "ip": IP,
	"hashes": Hash, "hash": Hash,
	"paths": Caminho, "path": Caminho, "caminhos": Caminho,
	"strings": Texto, "string": Texto,
	"keys": Chave, "key": Chave, "chaves": Chave,
	"users": Usuario, "user": Usuario, "usuarios": Usuario,
}

// Carregar lê o arquivo. Falha quando ele não abre e quando não produz
// indicador nenhum; linhas soltas que não foram entendidas viram aviso.
func Carregar(caminho string) (*Lista, error) {
	fh, err := os.Open(caminho)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	// Teto, pela mesma razão de env.MaxLeitura: o arquivo é apontado pelo
	// operador e num IR real vem do host investigado, no mesmo pendrive que o
	// dump. Sem teto, um arquivo esparso de 8 GB derruba a ferramenta por falta
	// de memória com status 2 — que o contrato lê como CRITICAL.
	b, err := io.ReadAll(io.LimitReader(fh, MaxLista+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > MaxLista {
		return nil, ErrGrandeDemais
	}
	l := &Lista{Arquivo: caminho}
	var contexto Tipo // chave aberta, para a forma em bloco

	for n, linha := range strings.Split(string(b), "\n") {
		num := n + 1
		crua := linha
		// Comentário e linha vazia não são erro: são o normal de um arquivo
		// escrito à mão durante um incidente.
		//
		// Mas o corte é no "#" que ABRE comentário — começo de linha ou
		// precedido de branco —, e não em qualquer "#". Cortar em todos
		// truncava o indicador em silêncio: `/tmp/.cache#1`, uma URL com
		// fragmento e um nome de arquivo com cerquilha viravam prefixos que não
		// casam com nada. É um falso negativo no único lugar do programa onde o
		// operador disse, com todas as letras, o que procurar.
		if i := inicioDeComentario(linha); i >= 0 {
			linha = linha[:i]
		}
		linha = strings.TrimSpace(linha)
		if linha == "" {
			continue
		}

		// Forma em bloco: "- valor" pertence à chave aberta acima.
		if v, ok := strings.CutPrefix(linha, "- "); ok {
			if contexto == "" {
				l.avisar(num, crua, "item de lista sem chave acima")
				continue
			}
			l.acrescentar(contexto, v, num)
			continue
		}

		// "chave: ..." — com valor inline ou abrindo um bloco.
		if chave, resto, ok := strings.Cut(linha, ":"); ok {
			if t, conhecida := chavesDeLista[strings.ToLower(strings.TrimSpace(chave))]; conhecida {
				resto = strings.TrimSpace(resto)
				if resto == "" {
					contexto = t // abre bloco
					continue
				}
				for _, v := range separarInline(resto) {
					l.acrescentar(t, v, num)
				}
				continue
			}
			// Uma chave desconhecida NÃO é tratada como valor solto: seria a
			// forma mais fácil de a ferramenta engolir um erro de digitação
			// numa chave e varrer com metade da lista.
			if pareceChave(chave) {
				l.avisar(num, crua, "chave desconhecida — as aceitas são: ips, hashes, paths, strings, keys, users")
				continue
			}
		}

		// Linha crua: um indicador por linha, classificado pela FORMA. É como
		// uma lista chega colada de um relatório.
		contexto = ""
		l.acrescentar("", linha, num)
	}

	if len(l.Itens) == 0 {
		return l, ErrVazia
	}
	return l, nil
}

func (l *Lista) avisar(linha int, texto, motivo string) {
	l.Avisos = append(l.Avisos, "linha "+itoa(linha)+": "+motivo+" — "+strings.TrimSpace(texto))
}

// acrescentar classifica e normaliza. Tipo vazio significa "deduza da forma".
func (l *Lista) acrescentar(t Tipo, bruto string, linha int) {
	v := strings.TrimSpace(bruto)
	v = strings.Trim(v, `"',`)
	v = strings.TrimSpace(v)
	if v == "" {
		return
	}
	if t == "" {
		t = deduzir(v)
	}
	ind := Indicador{Tipo: t, Bruto: v, Valor: v, Linha: linha}
	switch t {
	case Hash:
		ind.Algo, ind.Valor = normalizarHash(v)
		if ind.Valor == "" {
			l.avisar(linha, bruto, "hash com tamanho que não é de md5, sha1 nem sha256")
			return
		}
	case IP:
		ind.Valor = strings.ToLower(v)
	case Chave:
		ind.Valor = blobDeChave(v)
		if ind.Valor == "" {
			l.avisar(linha, bruto, "chave sem blob base64 reconhecível")
			return
		}
	}
	l.Itens = append(l.Itens, ind)
}

// deduzir classifica pela FORMA, e a ordem importa: hash antes de texto, porque
// um hash é um texto válido; caminho antes de texto pela mesma razão.
func deduzir(v string) Tipo {
	switch {
	case pareceHash(v):
		return Hash
	case pareceIP(v):
		return IP
	case strings.HasPrefix(v, "ssh-") || strings.HasPrefix(v, "ecdsa-") ||
		strings.HasPrefix(v, "sk-") || strings.HasPrefix(v, "AAAA"):
		return Chave
	case strings.ContainsAny(v, "/*"):
		return Caminho
	}
	// O resto vira TEXTO, e não usuário: adivinhar "usuário" a partir de uma
	// palavra solta produziria casamento em qualquer conta com nome comum. Quem
	// quer usuário escreve `users: [nome]`, e o resumo da carga mostra em que
	// tipo cada linha caiu.
	return Texto
}

// Casar devolve os indicadores daquele tipo que casam com o valor dado. A
// SEMÂNTICA da comparação é do tipo, não de quem chama.
func (l *Lista) Casar(t Tipo, valor string) []Indicador {
	if l == nil || valor == "" {
		return nil
	}
	var out []Indicador
	for _, ind := range l.Itens {
		if ind.Tipo != t {
			continue
		}
		var bate bool
		switch t {
		case Caminho:
			bate = casaCuringa(ind.Valor, valor)
		case Texto:
			bate = strings.Contains(valor, ind.Valor)
		case Hash, IP:
			bate = strings.EqualFold(ind.Valor, valor)
		case Chave:
			bate = ind.Valor == blobDeChave(valor)
		default:
			bate = ind.Valor == valor
		}
		if bate {
			out = append(out, ind)
		}
	}
	return out
}

// Do devolve os indicadores de um tipo. Existe para o caso em que a comparação
// não é do valor cru: uma chave SSH casa por IMPRESSÃO DIGITAL, e derivá-la
// depende de código que este pacote não pode importar sem criar ciclo.
func (l *Lista) Do(t Tipo) []Indicador {
	if l == nil {
		return nil
	}
	var out []Indicador
	for _, ind := range l.Itens {
		if ind.Tipo == t {
			out = append(out, ind)
		}
	}
	return out
}

// Tem responde se há indicador daquele tipo. Serve para o coletor não pagar
// custo nenhum quando a lista não pede — hashear arquivo sem hash na lista
// seria trabalho puro.
func (l *Lista) Tem(t Tipo) bool {
	if l == nil {
		return false
	}
	for _, ind := range l.Itens {
		if ind.Tipo == t {
			return true
		}
	}
	return false
}

// Algoritmos devolve os algoritmos de hash presentes na lista.
func (l *Lista) Algoritmos() []string {
	if l == nil {
		return nil
	}
	visto := map[string]bool{}
	var out []string
	for _, ind := range l.Itens {
		if ind.Tipo == Hash && !visto[ind.Algo] {
			visto[ind.Algo] = true
			out = append(out, ind.Algo)
		}
	}
	return out
}

// Resumo é o que a execução IMPRIME sobre a lista que carregou. Sem ele, uma
// lista mal entendida — dois indicadores lidos de quarenta linhas — passaria
// por uma varredura limpa.
func (l *Lista) Resumo() string {
	if l == nil || len(l.Itens) == 0 {
		return "nenhum indicador"
	}
	ordem := []Tipo{IP, Hash, Caminho, Texto, Chave, Usuario}
	conta := map[Tipo]int{}
	for _, ind := range l.Itens {
		conta[ind.Tipo]++
	}
	var partes []string
	for _, t := range ordem {
		if conta[t] > 0 {
			partes = append(partes, itoa(conta[t])+" "+string(t))
		}
	}
	return strings.Join(partes, " · ")
}

// casaCuringa compara com `*` e `?`, e o `*` ATRAVESSA a barra.
//
// É a diferença deliberada para o glob de shell: um indicador de caminho vem
// escrito como `*/htop/defunct` justamente porque quem o escreveu não sabe em
// que home o arquivo está. Um `*` que parasse na barra não casaria com
// /home/n/.config/htop/defunct, que é o caso que a SPEC dá de exemplo.
func casaCuringa(padrao, valor string) bool {
	if padrao == "" {
		return false
	}
	if !strings.ContainsAny(padrao, "*?") {
		return padrao == valor
	}
	// Duas posições e um ponto de retorno: casamento de curinga sem recursão,
	// que não estoura pilha com padrão patológico.
	p, v := 0, 0
	estrela, marca := -1, 0
	for v < len(valor) {
		switch {
		case p < len(padrao) && (padrao[p] == valor[v] || padrao[p] == '?'):
			p++
			v++
		case p < len(padrao) && padrao[p] == '*':
			estrela = p
			marca = v
			p++
		case estrela >= 0:
			p = estrela + 1
			marca++
			v = marca
		default:
			return false
		}
	}
	for p < len(padrao) && padrao[p] == '*' {
		p++
	}
	return p == len(padrao)
}

// normalizarHash aceita "sha256:abc…" e o hex cru, e deduz o algoritmo pelo
// TAMANHO quando não vem declarado.
func normalizarHash(v string) (algo, hex string) {
	s := v
	if pre, resto, ok := strings.Cut(s, ":"); ok {
		p := strings.ToLower(strings.TrimSpace(pre))
		if p == "md5" || p == "sha1" || p == "sha256" {
			algo, s = p, strings.TrimSpace(resto)
		}
	}
	s = strings.ToLower(strings.TrimSpace(s))
	if !soHex(s) {
		return "", ""
	}
	switch len(s) {
	case 32:
		return "md5", s
	case 40:
		return "sha1", s
	case 64:
		return "sha256", s
	}
	return "", ""
}

// blobDeChave extrai a parte base64 de uma linha de chave pública. A mesma
// chave aparece com opções na frente e comentário atrás, e comparar a linha
// inteira faria a mesma chave não casar consigo mesma.
func blobDeChave(v string) string {
	melhor := ""
	for _, campo := range strings.Fields(v) {
		if len(campo) > len(melhor) && strings.HasPrefix(campo, "AAAA") {
			melhor = campo
		}
	}
	if melhor == "" && strings.HasPrefix(v, "AAAA") {
		return v
	}
	return melhor
}

func separarInline(s string) []string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// pareceChave separa "ips:" de um valor que por acaso tem dois pontos, como um
// endereço IPv6 ou um hash prefixado.
func pareceChave(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || strings.ContainsAny(s, " /\\") {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func pareceHash(v string) bool {
	algo, hex := normalizarHash(v)
	return algo != "" && hex != ""
}

// pareceIP reconhece v4 e v6 sem trazer o pacote net para cá: o que interessa é
// a FORMA, e a comparação é textual de qualquer jeito.
func pareceIP(v string) bool {
	if strings.Count(v, ".") == 3 {
		for _, o := range strings.Split(v, ".") {
			if o == "" || len(o) > 3 || !soDigitos(o) {
				return false
			}
		}
		return true
	}
	if strings.Count(v, ":") >= 2 {
		for i := 0; i < len(v); i++ {
			c := v[i]
			if !(c == ':' || c == '.' || c >= '0' && c <= '9' ||
				c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				return false
			}
		}
		return true
	}
	return false
}

func soHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func soDigitos(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// inicioDeComentario acha o "#" que abre comentário, ou -1.
//
// A convenção é a de quase todo formato de configuração: cerquilha no começo
// da linha, ou depois de branco. Colada em texto, ela é parte do valor.
func inicioDeComentario(linha string) int {
	for i := 0; i < len(linha); i++ {
		if linha[i] != '#' {
			continue
		}
		if i == 0 || linha[i-1] == ' ' || linha[i-1] == '\t' {
			return i
		}
	}
	return -1
}
