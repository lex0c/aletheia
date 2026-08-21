// Package drift responde a pergunta que nem o check nem a baseline respondem:
//
//	o que MUDOU desde um estado conhecido?
//
// # Por que existe, e por que não é "mais um check"
//
// Os 109 checks desta ferramenta são conhecimento: cada um sabe que uma forma
// específica é perigosa. Isso alcança o que alguém já viu antes, e só isso.
//
//	check   conhecimento   "eu sei que ISTO é ruim"
//	drift   expectativa    "eu sei que isto NÃO ERA assim"
//
// A diferença não é de grau. Uma unit cujo `ExecStart` passa a apontar para
// OUTRO binário de pacote, uma chave de `authorized_keys` trocada por outra bem
// formada, uma regra de sudo reescrita para um alias diferente — nada disso
// produz achado hoje, e nada disso vai produzir, porque não há regra a
// escrever: as duas pontas são legítimas em forma. O que denuncia é a
// TRANSIÇÃO, e transição é a única coisa que um retrato não tem.
//
// É também o limite: drift não pode virar check disfarçado. Ele não sabe se a
// mudança é maligna — sabe que houve mudança, em que campo, e se aquele campo é
// dos que decidem privilégio. Quem conclui é o check que lê estes fatos.
//
// # As três regras que o diff não pode quebrar
//
// Elas não são detalhe de implementação: são as mesmas invariantes do resto da
// ferramenta, aplicadas à comparação. Sem qualquer uma delas, drift vira
// fábrica de falso positivo em uma execução.
//
//	COMPARABILIDADE      dois estados com cobertura diferente NÃO são
//	                     comparáveis. Um dump feito com root contra outro sem
//	                     root fabrica "sumiu" para tudo que só root enxerga. A
//	                     classe inteira é declarada não-comparável — vira
//	                     lacuna, nunca achado.
//
//	SUMIR ≠ NÃO OLHAR    medido nesta base: entre duas coletas com segundos de
//	                     intervalo, `/usr/bin/tail` "sumiu" de hash_verified —
//	                     porque estava RODANDO na primeira e por isso entrou no
//	                     conjunto hasheado. Só classe com enumeração exaustiva
//	                     nos dois lados admite "sumiu"; as demais admitem
//	                     apenas "surgiu" e "mudou".
//
//	MESMA NORMALIZAÇÃO   o dump é REDIGIDO ao ser escrito (redact.Cmdline), o
//	                     host vivo não é. Comparar um contra o outro sem passar
//	                     os dois pela mesma normalização inventa drift em todo
//	                     processo com segredo na linha de comando. O preço, que
//	                     fica dito, é que drift em campo redigido é invisível.
//
// # Por que um registro explícito, e não reflexão sobre facts.Facts
//
// São 78 campos, e cada um tem identidade e volatilidade próprias. Reflexão não
// adivinha que o `where` do Ownership carrega `pid=` dentro (e por isso muda a
// cada coleta sem nada ter mudado), nem que `kworker/0:3-events` não é uma
// identidade — o nome codifica o índice do pool. As duas coisas foram MEDIDAS
// aqui, e as duas produziriam ruído puro.
//
// Cada classe declara o que a identifica, o que nela é estado e de que
// capacidade a enumeração dela depende. A tabela cresce por adição revisável;
// a alternativa cresce por acidente.
package drift

import (
	"sort"
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

// Entidade é uma coisa com identidade ESTÁVEL entre execuções, e os campos
// dela que significam alguma coisa para segurança.
//
// O que não entra aqui não é comparado — e isso é metade do desenho. Contador,
// amostra ilustrativa, proveniência com pid dentro e tudo o mais que muda
// sozinho fica de fora por NÃO SER EXTRAÍDO, e não por um filtro depois.
type Entidade struct {
	ID     string
	Campos map[string]string

	// Alvos são os SUJEITOS que esta entidade responde no relatório — o nome da
	// unit, o caminho do arquivo, o usuário da regra. É por eles que o motor
	// liga uma mudança aos achados que falam da mesma coisa.
	//
	// Sem isso, drift e checks viveriam em dois relatórios paralelos sobre o
	// mesmo host: um dizendo "isto está errado", outro dizendo "isto mudou", e
	// o operador juntando na cabeça — que é exatamente o que a resolução de
	// ator já existe para não pedir.
	Alvos []string
}

// Classe é uma família de entidades e tudo que se precisa saber para
// compará-las honestamente.
type Classe struct {
	// Tipo é o nome estável da família, e aparece no achado: "systemd.unit".
	Tipo string
	// Titulo é como o operador lê o Tipo.
	Titulo string

	// Requires são as capacidades sem as quais a enumeração desta classe é
	// PARCIAL. Faltando em qualquer um dos dois lados, a classe não é
	// comparada.
	Requires env.Cap

	// Lacunas são as chaves de f.Partial/PersistDenied que degradam esta
	// classe. Presente em qualquer lado, mesma consequência do Requires.
	//
	// A comparação é pela CHAVE e nunca pelo texto: o texto das lacunas carrega
	// contador ("261 processos com fds ilegíveis" vira 262 na coleta seguinte),
	// e compará-lo faria toda execução parecer degradada de forma diferente.
	Lacunas []string

	// Exaustiva diz que a enumeração vê TODAS as entidades da família nos dois
	// lados. Só ela admite "sumiu" — ver a segunda regra no topo do arquivo.
	Exaustiva bool

	// Multiplicidade diz que DUAS entidades idênticas não são a mesma entidade.
	//
	// O índice colapsa por ID, e para quase toda família isso é o certo: duas
	// leituras da mesma unit são a mesma unit. Para o cron não é — duas linhas
	// idênticas fazem o job rodar DUAS VEZES, e passar de uma para duas era
	// invisível porque o valor fundido é igual ao original.
	Multiplicidade bool

	// Incompleta é a pergunta que a família faz aos fatos de UM lado: "o
	// conjunto que eu comparo está inteiro aqui?". Devolve o motivo quando não
	// está, e "" quando está.
	//
	// Existe porque a chave de lacuna é grosseira demais em alguns casos. A
	// família de portas depende de /proc/net/tcp{,6} ter sido lido INTEIRO, e
	// isso é um subconjunto estreito do que a chave `net` cobre — consumir a
	// chave suprimia a família em quase todo host; ignorá-la fazia tabela
	// truncada virar "porta removida". A pergunta específica é a saída.
	//
	// Lida como lacuna: presente nos dois lados é ESCOPO, num só é ASSIMETRIA.
	Incompleta func(*facts.Facts) string

	// Efemera é a família cuja PRESENÇA é volátil nos dois sentidos: o que não
	// aparece num retrato não deixou de existir, e o que aparece no outro não
	// nasceu ali. Só `mudou` vale.
	//
	// Programa em execução é o caso: um `sleep` de cron rodando na segunda
	// coleta e não na primeira não é um programa novo no host — é o relógio.
	// Reportá-lo encheria todo servidor movimentado de "surgiu", e a família
	// perderia o único sinal que ela tem de verdade, que é o MESMO executável
	// passando a rodar sob outra identidade.
	//
	// É a mesma regra do Exaustiva, pelo outro lado: ali "sumiu" não é
	// confiável, aqui nenhuma das duas presenças é.
	Efemera bool

	// Decide são os campos cuja mudança É o evento de segurança, e não uma
	// pista sobre ele. `ExecStart` de uma unit é isto; o mtime dela não é.
	Decide map[string]bool

	// Observacional são os campos em que VAZIO significa "não foi observado", e
	// não "não existe".
	//
	// É a regra "sumir ≠ não olhar" descida ao nível do campo, e ela nasceu de
	// um caso concreto: o dono de um socket em escuta (`comm`, `uid`) sai vazio
	// quando o processo é de outro usuário e não se está como root. Entre dois
	// retratos, a mesma porta atendida pelo mesmo programa aparecia mudando de
	// `sshd` para vazio — porque numa das coletas o dono não pôde ser lido.
	//
	// A transição de/para vazio nestes campos é CONTADA e não vira achado. Em
	// campo comum ela continua valendo, e tem de valer: `options` de uma chave
	// de SSH indo para vazio é justamente o achado mais importante da família.
	Observacional map[string]bool

	// Extrair produz as entidades a partir dos fatos. É aqui que mora a
	// normalização — ver Entidade.
	Extrair func(*facts.Facts) []Entidade
}

// campoRepeticoes é onde a multiplicidade mora, quando a família a declara.
// O nome começa com `_` para não colidir com campo de extrator nenhum.
const campoRepeticoes = "_repeticoes"

// Kind é o que aconteceu com uma entidade.
const (
	Surgiu = "surgiu"
	Sumiu  = "sumiu"
	Mudou  = "mudou"
)

// Lado é um dos dois estados comparados, com as condições em que foi obtido.
//
// As condições viajam junto porque a comparação depende delas: sem os caps de
// cada ponta, não há como saber se "sumiu" quer dizer que sumiu.
type Lado struct {
	F    *facts.Facts
	Caps env.Cap
	Host string
	// Quando é o instante da coleta em RFC3339, e é o que dá ao achado o
	// intervalo em que a mudança aconteceu. Um instante exato seria preciso e
	// falso: o que se sabe é "entre as duas coletas".
	Quando string
}

// Comparar produz o drift entre dois estados.
func Comparar(antes, depois Lado) facts.Drift {
	d := facts.Drift{
		DeHost:    antes.Host,
		DeQuando:  antes.Quando,
		AteQuando: depois.Quando,
		ParaHost:  depois.Host,
	}
	for _, c := range classes {
		cob := comparabilidadeDe(c, antes, depois)
		ma, semIDa := indexar(c, antes.F)
		mb, semIDb := indexar(c, depois.F)
		if n := semIDa + semIDb; n > 0 {
			// Entidade sem identidade estável fica FORA da comparação, e isso
			// precisa sair dito: descartá-la em silêncio esconderia justamente
			// a linha malformada — que é onde uma inserção estranha se
			// esconde. Ver a decisão simétrica em chaveAutorizada.
			cob.Motivos = append(cob.Motivos, strconv.Itoa(n)+" entidade(s) sem "+
				"identidade estável ficaram fora da comparação: sem identidade não "+
				"há como dizer se são as mesmas dos dois lados")
		}
		d.Cobertura = append(d.Cobertura, cob)
		compararClasse(c, cob, ma, mb, &d)
	}
	sort.Slice(d.Mudancas, func(i, j int) bool {
		a, b := d.Mudancas[i], d.Mudancas[j]
		if a.Tipo != b.Tipo {
			return a.Tipo < b.Tipo
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return a.Campo < b.Campo
	})
	return d
}

// comparabilidadeDe aplica a PRIMEIRA regra, e ela é por DIREÇÃO.
//
// O que invalida uma comparação não é a limitação — é a assimetria dela. Ver
// facts.CoberturaDrift, onde essa leitura está escrita por extenso e com o
// defeito que a produziu.
func comparabilidadeDe(c Classe, antes, depois Lado) facts.CoberturaDrift {
	cob := facts.CoberturaDrift{Tipo: c.Tipo, Titulo: c.Titulo, Simetrico: true}

	if c.Efemera {
		cob.SemSurgiu, cob.SemSumiu = true, true
		cob.Motivos = append(cob.Motivos, "a PRESENÇA desta família é volátil nos "+
			"dois sentidos: o que não aparece num retrato não deixou de existir. Só "+
			"a mudança de campo em entidade presente nas duas pontas é reportada")
	}
	faltaAntes := c.Requires &^ antes.Caps
	faltaDepois := c.Requires &^ depois.Caps
	if comum := faltaAntes & faltaDepois; comum != 0 {
		// Faltou nos DOIS: é o escopo da pergunta, e a comparação vale sobre o
		// que os dois enxergaram.
		cob.SemSurgiu, cob.SemSumiu = true, true
		cob.Motivos = append(cob.Motivos, "os DOIS retratos foram feitos sem "+
			strings.Join(comum.Names(), "+")+": a enumeração é parcial nos dois lados, "+
			"e só a mudança de campo em entidade presente nas duas pontas é confiável")
	}
	if so := faltaAntes &^ faltaDepois; so != 0 {
		cob.Simetrico, cob.SemMudou = false, true
		cob.SemSurgiu = true
		cob.Motivos = append(cob.Motivos, "o retrato ANTES foi feito sem "+
			strings.Join(so.Names(), "+")+" e o DEPOIS não: o que aparecer como NOVO "+
			"pode ser coisa que sempre esteve lá e ninguém olhou")
	}
	if so := faltaDepois &^ faltaAntes; so != 0 {
		cob.Simetrico, cob.SemMudou = false, true
		cob.SemSumiu = true
		cob.Motivos = append(cob.Motivos, "o retrato DEPOIS foi feito sem "+
			strings.Join(so.Names(), "+")+" e o ANTES não: o que aparecer como REMOVIDO "+
			"pode continuar lá, sem ter sido olhado")
	}

	// A pergunta ESPECÍFICA da família tem a mesma leitura das lacunas: nos
	// dois lados é escopo, num só é assimetria.
	if c.Incompleta != nil {
		ia, id := c.Incompleta(antes.F), c.Incompleta(depois.F)
		switch {
		case ia != "" && id != "":
			cob.SemSurgiu, cob.SemSumiu = true, true
			cob.Motivos = append(cob.Motivos, "nos dois retratos, "+ia)
		case ia != "":
			cob.Simetrico, cob.SemSurgiu, cob.SemMudou = false, true, true
			cob.Motivos = append(cob.Motivos, "só no retrato ANTES, "+ia)
		case id != "":
			cob.Simetrico, cob.SemSumiu, cob.SemMudou = false, true, true
			cob.Motivos = append(cob.Motivos, "só no retrato DEPOIS, "+id)
		}
	}

	// Lacuna declarada tem a mesma leitura, e é comparada pela CHAVE — nunca
	// pelo texto, que carrega contador ("261 processos" vira 262 na coleta
	// seguinte) e faria toda execução parecer degradada de outro jeito.
	for _, k := range c.Lacunas {
		la, ld := temLacuna(antes.F, k), temLacuna(depois.F, k)
		switch {
		case la && ld:
			cob.SemSurgiu, cob.SemSumiu = true, true
			cob.Motivos = append(cob.Motivos, "os dois retratos declararam lacuna em `"+
				k+"`: o alcance da coleta foi parcial nos dois")
		case la:
			cob.Simetrico, cob.SemSurgiu, cob.SemMudou = false, true, true
			cob.Motivos = append(cob.Motivos, "só o retrato ANTES declarou lacuna em `"+
				k+"`: o que aparecer como NOVO pode ser o que ele não conseguiu ler")
		case ld:
			cob.Simetrico, cob.SemSumiu, cob.SemMudou = false, true, true
			cob.Motivos = append(cob.Motivos, "só o retrato DEPOIS declarou lacuna em `"+
				k+"`: o que aparecer como REMOVIDO pode ser o que ele não conseguiu ler")
		}
	}
	return cob
}

func temLacuna(f *facts.Facts, chave string) bool {
	if f == nil {
		return true
	}
	return len(f.Partial[chave]) > 0 || len(f.PersistDenied[chave]) > 0
}

func compararClasse(c Classe, cob facts.CoberturaDrift, ma, mb map[string]Entidade, d *facts.Drift) {
	for id, eb := range mb {
		ea, existia := ma[id]
		if !existia {
			if cob.SemSurgiu {
				// Não é achado e não é silêncio: a família inteira já saiu
				// declarada na cobertura da comparação, com a direção que foi
				// suprimida e o motivo.
				continue
			}
			d.Mudancas = append(d.Mudancas, facts.MudancaDrift{
				Tipo: c.Tipo, Titulo: c.Titulo, ID: id, Kind: Surgiu,
				Decide: true, Campos: ordenar(eb.Campos), Alvos: eb.Alvos,
			})
			continue
		}
		if cob.SemMudou {
			// ASSIMETRIA: um lado enxergou mais que o outro, e a diferença de
			// FIDELIDADE aparece como mudança de campo. Ver CoberturaDrift.SemMudou.
			continue
		}
		// A UNIÃO das chaves, e não só as do DEPOIS.
		//
		// As classes de hoje emitem conjunto fixo, então a diferença é zero.
		// Uma classe futura com chaves variáveis — uma variável de ambiente por
		// chave, por exemplo — perderia a REMOÇÃO em silêncio: a chave some do
		// lado de depois e o laço nunca a visita. Três linhas contra um falso
		// negativo que ninguém acharia depois.
		for _, campo := range chavesDaUniao(ea.Campos, eb.Campos) {
			va, vb := ea.Campos[campo], eb.Campos[campo]
			if va == vb {
				continue
			}
			if c.Observacional[campo] && (va == "" || vb == "") {
				// Não se distingue "o dono mudou" de "o dono não foi lido desta
				// vez". A contagem sai no número; a afirmação, não.
				d.Contadas++
				continue
			}
			if !c.Decide[campo] {
				// TERCEIRA FAIXA: nem imprime individualmente, sai o número.
				// Truncar em silêncio lê-se como "cobri tudo".
				d.Contadas++
				continue
			}
			// "mudou" sobrevive a restrição SIMÉTRICA — os dois lados
			// enxergaram com a mesma fidelidade —, e não à assimétrica, que é
			// filtrada acima.
			d.Mudancas = append(d.Mudancas, facts.MudancaDrift{
				Tipo: c.Tipo, Titulo: c.Titulo, ID: id, Kind: Mudou,
				Campo: campo, Antes: va, Depois: vb, Decide: true,
				Alvos: eb.Alvos,
			})
		}
	}
	if !c.Exaustiva || cob.SemSumiu {
		return
	}
	for id, ea := range ma {
		if _, continua := mb[id]; continua {
			continue
		}
		d.Mudancas = append(d.Mudancas, facts.MudancaDrift{
			Tipo: c.Tipo, Titulo: c.Titulo, ID: id, Kind: Sumiu,
			Decide: true, Campos: ordenar(ea.Campos), Alvos: ea.Alvos,
		})
	}
}

// indexar aplica a identidade. ID repetido é COLAPSADO com aviso implícito: a
// segunda entidade de mesmo ID sobrescreveria a primeira em silêncio, e o
// silêncio esconderia justamente a que foi acrescentada.
func indexar(c Classe, f *facts.Facts) (map[string]Entidade, int) {
	out := map[string]Entidade{}
	if f == nil {
		return out, 0
	}
	var semID int
	for _, e := range c.Extrair(f) {
		if e.ID == "" {
			semID++
			continue
		}
		if ja, dup := out[e.ID]; dup {
			e = fundir(ja, e)
			if c.Multiplicidade {
				n, _ := strconv.Atoi(e.Campos[campoRepeticoes])
				if n == 0 {
					n = 1
				}
				e.Campos[campoRepeticoes] = strconv.Itoa(n + 1)
			}
		} else if c.Multiplicidade {
			e.Campos[campoRepeticoes] = "1"
		}
		out[e.ID] = e
	}
	return out, semID
}

// chavesDaUniao devolve as chaves dos dois mapas, em ordem estável.
func chavesDaUniao(a, b map[string]string) []string {
	vistas := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, m := range []map[string]string{a, b} {
		for k := range m {
			if !vistas[k] {
				vistas[k] = true
				out = append(out, k)
			}
		}
	}
	sort.Strings(out)
	return out
}

// fundir junta duas entidades de mesmo ID num valor ESTÁVEL: campo divergente
// vira a lista ordenada dos valores. Sem isto, a ordem da coleta decidiria qual
// das duas venceu, e a mesma máquina daria drift contra si mesma.
func fundir(a, b Entidade) Entidade {
	out := Entidade{ID: a.ID, Campos: map[string]string{}, Alvos: unirAlvos(a.Alvos, b.Alvos)}
	for k, v := range a.Campos {
		out.Campos[k] = v
	}
	for k, v := range b.Campos {
		if ja, existe := out.Campos[k]; existe && ja != v {
			partes := append(strings.Split(ja, "\x1f"), v)
			sort.Strings(partes)
			out.Campos[k] = strings.Join(partes, "\x1f")
			continue
		}
		out.Campos[k] = v
	}
	return out
}

func unirAlvos(a, b []string) []string {
	vistos := map[string]bool{}
	var out []string
	for _, v := range append(append([]string{}, a...), b...) {
		if v != "" && !vistos[v] {
			vistos[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// ordenar serializa os campos de uma entidade para a evidência de "surgiu" e
// "sumiu", em ordem estável.
func ordenar(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		if v == "" {
			continue
		}
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}
