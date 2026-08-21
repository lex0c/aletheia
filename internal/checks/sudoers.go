package checks

import "strings"

// Parser mínimo de sudoers — a camada que precisava existir antes da tabela de
// primitivas crescer mais.
//
// # O defeito que isto conserta
//
// primitiva.go responde "o que este binário devolve com privilégio emprestado".
// A resposta só vale se as perguntas ANTERIORES a ela estiverem certas:
//
//	isto roda como root?          (Runas_Spec)
//	esta regra vale NESTE host?   (Host_List)
//	este comando está sem senha?  (Tag_Spec, que é HERDADA pelos seguintes)
//	o `ALL` é o comando, ou é um argumento chamado ALL?
//
// A versão anterior respondia as quatro com `strings.Index` sobre a linha
// inteira, e cada uma errava de um jeito medido:
//
//	viraRoot       pegava o PRIMEIRO `(` da linha. Em
//	               `web ALL=NOPASSWD: /usr/bin/vim ^(/etc/motd|/etc/issue)$`
//	               o parêntese é do REGEX de argumento (sudoers 1.9.10+), não do
//	               runas — e uma regra que abre o vim COMO ROOT saía dizendo
//	               "como /etc/motd|/etc/issue, e não como root": WARN no lugar
//	               de CRITICAL, com a evidência afirmando o contrário do fato.
//
//	regraAmpla     varria a specification atrás de um campo `ALL`. Em
//	               `NOPASSWD: /usr/bin/printf ALL` o `ALL` é ARGUMENTO do
//	               printf, e a regra saía CRITICAL "é root inteiro": falso
//	               crítico determinístico.
//
//	specDeComando  cortava no último `NOPASSWD:` e quebrava por vírgula. Um
//	               token de tag depois dele — `NOPASSWD: SETENV: /usr/bin/find`,
//	               que é forma comum — virava o "binário" `SETENV:`, e o `find`
//	               virava argumento fixado: o comando perigoso sumia do
//	               relatório inteiro.
//
//	(nenhuma)      o Host_List não era lido. Num sudoers distribuído por
//	               configuração central, `ops db01=(root) NOPASSWD: ALL` saía
//	               CRITICAL em web01, api02 e em toda a frota.
//
// # Onde ele mora, e por que não nos fatos
//
// A leitura é do CHECK e não do coletor: o fato guardado continua sendo a linha
// crua. Assim um dump gravado por uma versão anterior é reanalisado com este
// parser — a correção alcança o que já foi coletado, e o SchemaVersion não
// precisa subir por uma mudança que não é de coleta.
//
// # O que ele NÃO faz
//
// Não resolve alias (User_Alias/Runas_Alias/Host_Alias/Cmnd_Alias), netgroup
// (`+grupo`) nem endereço de rede no Host_List. Nenhum deles vira "não se
// aplica": viram INDETERMINADO, e indeterminado MANTÉM a severidade que a regra
// teria. O que não se sabe não absolve — é a mesma regra que vale para o resto
// da ferramenta.

// tagSudo é o estado das tags ao longo de um Cmnd_Spec_List. O sudoers as
// HERDA: `NOPASSWD:` vale para todos os Cmnd seguintes da mesma lista até
// `PASSWD:` aparecer, e o mesmo para o par NOEXEC/EXEC.
type tagSudo struct {
	nopasswd bool
	noexec   bool
}

// tagsNeutras são reconhecidas para NÃO virarem "binário" — que foi exatamente
// o defeito do SETENV. Nenhuma delas muda o que a regra concede a quem já pode
// chamá-la.
var tagsNeutras = map[string]bool{
	"SETENV": true, "NOSETENV": true,
	"LOG_INPUT": true, "NOLOG_INPUT": true,
	"LOG_OUTPUT": true, "NOLOG_OUTPUT": true,
	"FOLLOW": true, "NOFOLLOW": true,
	"MAIL": true, "NOMAIL": true,
	"INTERCEPT": true, "NOINTERCEPT": true,
}

func ehNomeDeTag(nome string) bool {
	switch n := strings.ToUpper(nome); n {
	case "NOPASSWD", "PASSWD", "NOEXEC", "EXEC":
		return true
	default:
		return tagsNeutras[n]
	}
}

// aplicaTag consome o nome de uma tag e devolve se ele ERA uma tag.
func aplicaTag(t *tagSudo, nome string) bool {
	switch n := strings.ToUpper(nome); n {
	case "NOPASSWD":
		t.nopasswd = true
	case "PASSWD":
		t.nopasswd = false
	case "NOEXEC":
		t.noexec = true
	case "EXEC":
		t.noexec = false
	default:
		return tagsNeutras[n]
	}
	return true
}

// juntaTagsSoltas cola o dois-pontos que ficou separado da tag. O sudo aceita
// branco ali —
//
//	ops ALL=(root) NOPASSWD : ALL
//
// — e um leitor que não aceitasse leria `NOPASSWD` como o comando e `ALL` como
// argumento dele, perdendo um root irrestrito. Roda ANTES do corte por seção,
// senão aquele `:` seria lido como separador de Host_List.
func juntaTagsSoltas(toks []string) []string {
	out := make([]string, 0, len(toks))
	for i := 0; i < len(toks); i++ {
		if i+1 < len(toks) && toks[i+1] == ":" && ehNomeDeTag(toks[i]) {
			out = append(out, toks[i]+":")
			i++
			continue
		}
		out = append(out, toks[i])
	}
	return out
}

// specSudo é UM Cmnd_Spec já resolvido: o comando com o runas e as tags que
// valiam NAQUELE ponto da lista, e não as que aparecem em qualquer lugar da
// linha.
type specSudo struct {
	// RunasTexto é o que a evidência cita: o runas declarado, ou a frase que
	// diz que a ausência dele é root.
	RunasTexto string
	ComoRoot   bool

	// RunasInvocador é a forma `(:grupo)` e `()`: quem roda é o usuário que
	// invocou, e a regra entrega um GRUPO — não uma conta.
	RunasInvocador bool
	// RunasNota é a ressalva sobre COMO o runas foi resolvido — o padrão
	// trocado, o `Defaults` escopado. Fica separada do RunasTexto porque o
	// texto é citado no meio de uma frase, e explicação embutida ali vira
	// evidência ilegível.
	RunasNota string
	// RunasDeclarado diz se a regra escreveu um Runas_Spec. Sem ele, quem
	// decide é o `runas_default`, e ele pode ter sido trocado por um
	// `Defaults` — ver runasPadraoDoSudoers.
	RunasDeclarado bool

	Nopasswd bool
	Noexec   bool
	Negado   bool

	// Tudo é o Cmnd `ALL` — o comando, não um argumento com esse nome.
	Tudo bool
	Cmd  Comando

	// Hosts é o Host_List da SEÇÃO de que esta spec veio. Uma linha pode ter
	// mais de uma seção, cada uma com o seu.
	Hosts []string
}

// regraSudo é uma linha de User_Spec lida.
type regraSudo struct {
	Usuarios []string
	Hosts    []string
	Specs    []specSudo
	// Ok é falso para o que não é User_Spec: `Defaults`, definição de alias,
	// linha malformada. O chamador NÃO pode tratar isso como "regra sem
	// comando perigoso" — é "não li", e a evidência precisa dizer.
	Ok bool
}

// prefixosNaoSpec são as linhas que têm `=` e não são concessão a usuário. Ler
// `Cmnd_Alias PGCTL = /usr/bin/pg_ctl` como User_Spec inventaria um usuário
// chamado Cmnd_Alias.
// As duas formas de include entram porque `@includedir` casa `@include` sem
// terminar em fronteira — o coletor já as filtra antes, e depender disso seria
// acoplar dois arquivos por um detalhe que ninguém releria.
var prefixosNaoSpec = []string{
	"defaults", "user_alias", "runas_alias", "host_alias", "cmnd_alias",
	"@include", "@includedir", "#include", "#includedir",
}

func ehLinhaNaoSpec(t string) bool {
	for _, p := range prefixosNaoSpec {
		if prefixoDePalavra(t, p) {
			return true
		}
	}
	return false
}

// ehDefinicaoDeAliasSudo separa a DEFINIÇÃO de alias da concessão. Ela nomeia
// um conjunto e não concede nada — quem concede é a User_Spec que cita o nome.
func ehDefinicaoDeAliasSudo(t string) bool {
	t = strings.TrimSpace(t)
	for _, p := range []string{"user_alias", "runas_alias", "host_alias", "cmnd_alias"} {
		if prefixoDePalavra(t, p) {
			return true
		}
	}
	return false
}

// prefixoDePalavra exige que o prefixo termine numa fronteira. Sem isso, um
// usuário chamado `defaultsdeploy` seria lido como diretiva `Defaults` e a
// regra dele deixaria de ser avaliada — a leitura por `HasPrefix` cru
// transformava o NOME do sujeito em sintaxe.
func prefixoDePalavra(t, p string) bool {
	if len(t) < len(p) || !strings.EqualFold(t[:len(p)], p) {
		return false
	}
	if len(t) == len(p) {
		return true
	}
	switch c := t[len(p)]; {
	case c == '_' || c == '-',
		c >= 'a' && c <= 'z',
		c >= 'A' && c <= 'Z',
		c >= '0' && c <= '9':
		return false
	}
	return true
}

func parseRegraSudo(texto string) regraSudo {
	t := strings.TrimSpace(texto)
	if ehLinhaNaoSpec(t) {
		return regraSudo{}
	}
	esq, dir, ok := strings.Cut(t, "=")
	if !ok {
		return regraSudo{}
	}
	usuarios, resto := listaSudo(tokensCabecalho(esq))
	hosts, _ := listaSudo(resto)
	if len(usuarios) == 0 || len(hosts) == 0 {
		return regraSudo{}
	}
	reg := regraSudo{Usuarios: usuarios, Hosts: hosts, Ok: true}
	for _, sec := range seccoesSudo(hosts, juntaTagsSoltas(palavrasSpec(dir))) {
		// Cada seção tem o PRÓPRIO Host_List, e as specs dela carregam o dela.
		for _, sp := range specsDaSecao(sec.Toks) {
			sp.Hosts = sec.Hosts
			reg.Specs = append(reg.Specs, sp)
		}
	}
	return reg
}

// tokensCabecalho quebra `User_List Host_List` em tokens, com a vírgula como
// token próprio: é ela que diz onde uma lista termina e a outra começa.
func tokensCabecalho(s string) []string {
	var out []string
	var campo strings.Builder
	flush := func() {
		if campo.Len() > 0 {
			out = append(out, campo.String())
			campo.Reset()
		}
	}
	for _, r := range s {
		switch r {
		case ' ', '\t':
			flush()
		case ',':
			flush()
			out = append(out, ",")
		default:
			campo.WriteRune(r)
		}
	}
	flush()
	return out
}

// listaSudo lê uma lista separada por vírgula e devolve o que sobrou. A lista
// continua enquanto o próximo token for uma vírgula — é assim que
// `root, %wheel ALL` separa dois usuários de um host.
func listaSudo(toks []string) (lista, resto []string) {
	i := 0
	for i < len(toks) {
		if toks[i] == "," {
			i++
			continue
		}
		lista = append(lista, toks[i])
		i++
		if i < len(toks) && toks[i] == "," {
			continue
		}
		break
	}
	return lista, toks[i:]
}

// palavrasSpec quebra a specification preservando o que `strings.Fields`
// destruía:
//
//	`(...)` que ABRE uma palavra é grupo de runas e sai inteiro
//	`(` no MEIO de uma palavra é do regex, e não abre grupo nenhum
//	`,` separa, colada ou não
//
// A distinção de posição é o conserto do viraRoot: em `^(/etc/motd|/etc/issue)$`
// o parêntese não abre a palavra, e por isso não é runas.
func palavrasSpec(s string) []string {
	var out []string
	i, n := 0, len(s)
	for i < n {
		switch c := s[i]; {
		case c == ' ' || c == '\t':
			i++
		case c == ',':
			out = append(out, ",")
			i++
		case c == '(':
			j := i + 1
			for j < n && s[j] != ')' {
				j++
			}
			if j < n {
				j++
			}
			out = append(out, s[i:j])
			i = j
		default:
			j := i
			for j < n && s[j] != ' ' && s[j] != '\t' && s[j] != ',' {
				j++
			}
			out = append(out, s[i:j])
			i = j
		}
	}
	return out
}

// secaoSudo é um `Host_List = Cmnd_Spec_List`. Uma linha pode ter vários,
// separados por `:` — é raro e é gramática:
//
//	ops web01 = /bin/systemctl restart api : db01 = ALL
type secaoSudo struct {
	Hosts []string
	Toks  []string
}

func seccoesSudo(hosts []string, palavras []string) []secaoSudo {
	sec := secaoSudo{Hosts: hosts}
	var out []secaoSudo
	i := 0
	for i < len(palavras) {
		p := palavras[i]
		// `:` só abre seção quando há um `=` depois dele. Sem essa guarda, um
		// `:` que fosse ARGUMENTO cortaria a regra ao meio e o resto dela
		// herdaria um Host_List inventado — que é justamente o caminho para
		// suprimir um achado por engano.
		if p != ":" || !temIgualDepois(palavras[i+1:]) {
			sec.Toks = append(sec.Toks, p)
			i++
			continue
		}
		out = append(out, sec)
		i++
		var h []string
		sec = secaoSudo{}
		for i < len(palavras) {
			q := palavras[i]
			i++
			if q == "," {
				continue
			}
			k := strings.Index(q, "=")
			if k < 0 {
				h = append(h, q)
				continue
			}
			if k > 0 {
				h = append(h, q[:k])
			}
			sec.Hosts = h
			if resto := q[k+1:]; resto != "" {
				sec.Toks = append(sec.Toks, palavrasSpec(resto)...)
			}
			break
		}
		if sec.Hosts == nil {
			sec.Hosts = h
		}
	}
	out = append(out, sec)
	return out
}

func temIgualDepois(palavras []string) bool {
	for _, p := range palavras {
		if strings.Contains(p, "=") {
			return true
		}
	}
	return false
}

// specsDaSecao lê o Cmnd_Spec_List: runas e tags são ESTADO, e valem para os
// comandos seguintes até serem trocados.
func specsDaSecao(toks []string) []specSudo {
	toks = juntaTagsSoltas(toks)
	var out []specSudo
	var tags tagSudo
	runas := ""
	runasDeclarado := false

	bin, neg, temCmd := "", false, false
	var args []string

	flush := func() {
		if !temCmd {
			return
		}
		sp := specSudo{Nopasswd: tags.nopasswd, Noexec: tags.noexec, Negado: neg}
		sp.RunasDeclarado = runasDeclarado
		sp.ComoRoot, sp.RunasInvocador, sp.RunasTexto = interpretaRunas(runas, runasDeclarado)
		if bin == "ALL" {
			sp.Tudo = true
		} else {
			sp.Cmd = classificaComando(bin, args)
		}
		out = append(out, sp)
		bin, args, neg, temCmd = "", nil, false, false
	}

	for _, t := range toks {
		switch {
		case t == ",":
			flush()
		case temCmd:
			args = append(args, t)
		case strings.HasPrefix(t, "("):
			runas, runasDeclarado = strings.Trim(t, "()"), true
		case t == ":":
			// `NOPASSWD :` com espaço antes do dois-pontos.
		default:
			t = descascaTags(t, &tags)
			if t == "" || ehOpcaoSudo(t) {
				continue
			}
			for strings.HasPrefix(t, "!") {
				neg = true
				t = t[1:]
			}
			if t == "" {
				continue
			}
			bin, temCmd = t, true
		}
	}
	flush()
	return out
}

// descascaTags tira do token as tags coladas nele — `NOPASSWD:`,
// `NOPASSWD:SETENV:/usr/bin/find` — aplicando cada uma ao estado. Devolve o que
// sobrou, que é "" quando o token era só tag.
func descascaTags(t string, tags *tagSudo) string {
	for {
		i := strings.Index(t, ":")
		if i < 0 {
			return t
		}
		if !aplicaTag(tags, t[:i]) {
			return t
		}
		t = t[i+1:]
	}
}

// ehOpcaoSudo reconhece o Option_Spec (`CWD=/tmp`, `TIMEOUT=5m`, `CHROOT=/srv`),
// que vem antes do comando e não é comando.
func ehOpcaoSudo(t string) bool {
	i := strings.Index(t, "=")
	if i <= 0 {
		return false
	}
	for _, r := range t[:i] {
		if (r < 'A' || r > 'Z') && r != '_' {
			return false
		}
	}
	return true
}

// interpretaRunas lê o `(usuario:grupo)`, e as QUATRO formas dele têm respostas
// diferentes. O sudoers(5) as separa uma a uma:
//
//	sem Runas_Spec     roda pelo `runas_default`, que de fábrica é root
//	(usuario)          roda como aquele usuário
//	(usuario:grupo)    aquele usuário, com aquele grupo
//	(:grupo)           roda como o USUÁRIO INVOCADOR, com aquele grupo
//	()                 roda como o usuário invocador, e só
//
// As duas últimas são o conserto de um erro meu: a versão anterior lia `(:grupo)`
// como root — "só o grupo foi declarado, o usuário continua sendo root" — e
// chegou a travar isso num teste com essa frase. É o contrário do que o manual
// diz. `ana ALL=(:www-data) NOPASSWD: ALL` NÃO é root: é a própria `ana` com o
// grupo `www-data`, e chamar aquilo de "root inteiro, sem responder nada" é um
// CRÍTICO inventado em cima de uma regra que entrega um grupo.
func interpretaRunas(dentro string, declarado bool) (comoRoot, invocador bool, texto string) {
	if !declarado {
		return true, false, "root (padrão do sudo, sem runas declarado)"
	}
	usuarios, grupos, temGrupo := strings.Cut(dentro, ":")
	if strings.TrimSpace(usuarios) != "" {
		for _, campo := range strings.FieldsFunc(usuarios, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t'
		}) {
			switch c := strings.TrimSpace(campo); c {
			case "root", "ALL", "#0":
				return true, false, c
			}
		}
		return false, false, strings.TrimSpace(dentro)
	}
	// Lista de usuários VAZIA: quem roda é o próprio invocador.
	if temGrupo && strings.TrimSpace(grupos) != "" {
		return false, true, "o PRÓPRIO usuário invocador, com o grupo `" +
			strings.TrimSpace(grupos) + "`"
	}
	return false, true, "o PRÓPRIO usuário invocador (runas vazio)"
}

// aplicSudo é a resposta da pergunta que faltava: esta regra vale NESTE host?
type aplicSudo int

const (
	// sudoAplicavel — o Host_List casa este host (ou é ALL).
	sudoAplicavel aplicSudo = iota
	// sudoIndeterminado — há alias, netgroup, endereço de rede ou o hostname
	// não é conhecido. MANTÉM a severidade: não saber não absolve.
	sudoIndeterminado
	// sudoOutroHost — todo o Host_List é literal, e nenhum é este host. A
	// regra está no arquivo e NÃO vale aqui.
	sudoOutroHost
)

// aplicabilidadeSudo decide, e devolve o texto para a evidência citar.
//
// Sem isto, um sudoers distribuído por configuração central — que é como uma
// frota inteira recebe o arquivo — fazia a regra do banco de dados sair
// CRITICAL em cada servidor web.
//
// # A ÚLTIMA entrada que casa é a que decide, e não a primeira
//
// A primeira versão desta função devolvia no primeiro casamento, e isso quebrava
// a forma que a própria gramática oferece para EXCLUIR:
//
//	ops ALL,!web01=(root) NOPASSWD: ALL
//
// Em web01 ela lia o `ALL`, devolvia "aplicável" e imprimia CRITICAL — sobre a
// regra escrita justamente para não valer ali. O sudo percorre a lista ao
// CONTRÁRIO e para no primeiro casamento, que é o mesmo que dizer: vence a
// última entrada que casa.
//
// Entrada que não dá para resolver (alias, netgroup, endereço) POSTERIOR a um
// casamento apaga a decisão em vez de mantê-la: ela pode casar, é mais nova, e
// supor que não casa seria inventar uma absolvição.
func aplicabilidadeSudo(hosts []string, hostname string) (aplicSudo, string) {
	if len(hosts) == 0 || hostname == "" {
		return sudoIndeterminado, strings.Join(hosts, ",")
	}
	const (
		semDecisao = iota
		decideSim
		decideNao
		decideNaoSei
	)
	decisao := semDecisao
	var casou, outros []string
	for _, h := range hosts {
		neg := strings.HasPrefix(h, "!")
		nome := strings.TrimPrefix(h, "!")
		if !ehHostLiteral(nome) && nome != "ALL" {
			decisao = decideNaoSei
			continue
		}
		if nome != "ALL" && !casaHostname(nome, hostname) {
			if !neg {
				outros = append(outros, nome)
			}
			continue
		}
		casou = append(casou, h)
		if neg {
			decisao = decideNao
		} else {
			decisao = decideSim
		}
	}
	switch decisao {
	case decideSim:
		return sudoAplicavel, ultimo(casou)
	case decideNao:
		return sudoOutroHost, "excluído por `" + ultimo(casou) + "`"
	case decideNaoSei:
		return sudoIndeterminado, strings.Join(hosts, ",")
	}
	if len(outros) > 0 {
		return sudoOutroHost, strings.Join(outros, ",")
	}
	return sudoIndeterminado, strings.Join(hosts, ",")
}

func ultimo(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[len(s)-1]
}

// runasPadrao é o que responde por uma regra SEM Runas_Spec. De fábrica é root,
// e o sudoers deixa trocar:
//
//	Defaults runas_default=postgres
//
// A partir daí `ops ALL=NOPASSWD: ALL` não é root — é postgres. Afirmar root
// ali seria um CRÍTICO em cima de uma linha que não concede root nenhum.
type runasPadrao struct {
	// Valor é o runas_default declarado; "" quando ninguém trocou.
	Valor string
	// Escopado é o `Defaults:usuario runas_default=...` — vale só para o alvo
	// dele, e esta ferramenta não resolve escopo. Não muda a leitura: entra
	// como ressalva, porque supor que se aplica seria inventar do outro lado.
	Escopado bool
}

func runasPadraoDoSudoers(linhas []string) runasPadrao {
	var out runasPadrao
	for _, l := range linhas {
		t := strings.TrimSpace(l)
		if !prefixoDePalavra(t, "defaults") {
			continue
		}
		i := strings.Index(strings.ToLower(t), "runas_default")
		if i < 0 {
			continue
		}
		_, v, ok := strings.Cut(t[i:], "=")
		if !ok {
			continue
		}
		campos := strings.Fields(v)
		if len(campos) == 0 {
			continue
		}
		if v = strings.Trim(campos[0], `"'`); v == "" {
			continue
		}
		esc := len(t) > len("defaults") &&
			strings.ContainsRune(":@>!", rune(t[len("defaults")]))
		// O ÚLTIMO vence, que é como o sudo resolve `Defaults` repetido.
		out = runasPadrao{Valor: v, Escopado: esc}
	}
	return out
}

// ehHostLiteral separa o que dá para decidir do que não dá. Alias em CAIXA
// ALTA, netgroup `+`, endereço/CIDR e curinga ficam de fora — cada um deles
// PODE casar este host, e chutar que não casa seria inventar uma absolvição.
func ehHostLiteral(h string) bool {
	if h == "" || strings.HasPrefix(h, "+") {
		return false
	}
	if strings.ContainsAny(h, "/*?[") {
		return false
	}
	temLetra, soMaiuscula, soIP := false, true, true
	for _, r := range h {
		switch {
		case r >= 'a' && r <= 'z':
			temLetra, soMaiuscula = true, false
		case r >= 'A' && r <= 'Z':
			temLetra = true
			soIP = false
		case r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_':
			if r != '.' {
				soIP = false
			}
		default:
			return false
		}
	}
	// Nome sem letra nenhuma é endereço IP.
	if !temLetra && soIP {
		return false
	}
	// CAIXA ALTA inteira é a convenção de Host_Alias.
	return !(temLetra && soMaiuscula)
}

// casaHostname compara pelo nome curto dos dois lados: o sudoers costuma trazer
// `web01` e o host se chamar `web01.interno.example`, e o sudo casa os dois.
func casaHostname(regra, host string) bool {
	if strings.EqualFold(regra, host) {
		return true
	}
	return strings.EqualFold(curtoDeHost(regra), curtoDeHost(host))
}

func curtoDeHost(h string) string {
	if i := strings.Index(h, "."); i > 0 {
		return h[:i]
	}
	return h
}
