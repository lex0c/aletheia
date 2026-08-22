package facts

// Drift é o resultado de comparar ESTE estado com um estado anterior.
//
// Mora nos fatos, e não num relatório à parte, porque é isso que ele é: um
// fato derivado, do mesmo tipo do Cross (visão cruzada) e do HashDiff. Assim
// os checks o leem como leem qualquer outro fato, e o achado de drift herda de
// graça a cobertura, a janela `--since`, o JSONL, a baseline e a correlação
// por ator. Um motor de relatório paralelo teria que reconquistar cada uma
// dessas coisas, e divergiria na primeira que esquecesse.
//
// NÃO é serializado no dump (`json:"-"`), e a razão é conceitual: o dump é o
// RETRATO de um host, e comparação não é propriedade do host — é da pergunta
// que alguém fez. Um dump que carregasse drift dentro de si passaria a
// depender de contra o que ele foi comparado. Como consequência prática, o
// SchemaVersion não sobe por causa desta feature: nenhum dump gravado antes
// dela descreve menos do que descrevia.
type Drift struct {
	// De onde e até quando. O par é o que permite ao achado dizer "apareceu
	// ENTRE t0 e t1" — que é tudo o que se sabe de verdade. Um instante exato
	// seria mais bonito e seria inventado.
	DeHost    string
	ParaHost  string
	DeQuando  string
	AteQuando string

	Mudancas []MudancaDrift

	// Cobertura é o que ESTA comparação alcançou, família por família.
	//
	// Sem ela um drift vazio não distingue "nada mudou" de "nada foi
	// comparado", que é a distinção que a ferramenta inteira existe para não
	// perder.
	Cobertura []CoberturaDrift

	// Contadas são as mudanças em campos que NÃO decidem nada: hash, mtime,
	// tamanho. Não saem uma a uma — sai o número, porque um corte silencioso
	// se lê como "cobri tudo".
	Contadas int
}

// CoberturaDrift é o alcance da comparação para UMA família de entidades.
//
// # Por que não é um booleano
//
// A primeira versão era: as duas pontas viram tudo, ou a família não é
// comparada. Rodando contra um host de verdade sem root, isso recusou três das
// quatro famílias — por lacunas como "6 diretórios de unit de usuário
// ilegíveis". Jogar fora a comparação inteira de systemd por causa de seis
// diretórios de conta de serviço é honesto e é inútil, e inútil vira desligado.
//
// A leitura certa é por DIREÇÃO, e ela cai de uma observação simples: o que
// invalida uma comparação não é a limitação, é a ASSIMETRIA dela.
//
//	os dois lados viram menos, igualmente  a comparação vale sobre a
//	                                       interseção — faltou nos dois
//	o ANTES viu menos                      "surgiu" pode ser coisa que sempre
//	                                       esteve lá e ninguém olhou
//	o DEPOIS viu menos                     "sumiu" pode ser coisa que continua
//	                                       lá e ninguém olhou
//
// E "mudou" sobrevive a todas: ele exige a entidade presente nos DOIS lados,
// então nenhuma das duas pode não tê-la olhado. É também o sinal mais valioso —
// `ExecStart` trocado, `command=` retirado de uma chave.
//
// # Simetrico decide entre ESCOPO e LACUNA
//
// Rodar sem root é uma decisão de quem roda, não um defeito da comparação: se
// os dois retratos foram feitos sem root, a limitação é o ESCOPO da pergunta e
// não pode bloquear o exit 0 — uma lacuna que nunca fecha é uma que as pessoas
// aprendem a ignorar. Já a assimetria É um defeito, e é consertável: recolha as
// duas pontas com o mesmo privilégio.
type CoberturaDrift struct {
	Tipo   string
	Titulo string

	// SemSurgiu/SemSumiu/SemMudou dizem qual leitura foi SUPRIMIDA por não ser
	// confiável nesta comparação.
	SemSurgiu bool
	SemSumiu  bool
	// SemMudou é a terceira, e ela custou uma afirmação falsa para aparecer.
	//
	// A versão anterior suprimia só as duas presenças, sob o argumento de que
	// "mudou exige a entidade presente nos DOIS lados, então nenhum pode não
	// tê-la olhado". A frase confunde PRESENÇA DA ENTIDADE com OBSERVABILIDADE
	// DO CAMPO: um campo pode ser ilegível com a entidade bem visível.
	//
	//	ANTES  (root)     conta deploy  sem_senha=true
	//	DEPOIS (sem root) conta deploy  sem_senha=false   ← não leu o shadow
	//	                  → "a conta deixou de estar sem senha"
	//
	// Por isso ela acompanha a ASSIMETRIA, e só ela: quando os dois lados
	// enxergaram o mesmo, a fidelidade dos campos é a mesma nos dois e `mudou`
	// continua valendo — que é o que faz a comparação servir sem root.
	SemMudou bool
	// Simetrico é falso quando um lado viu menos que o outro.
	Simetrico bool

	Motivos []string
}

// Restrita diz se alguma leitura foi suprimida.
func (c CoberturaDrift) Restrita() bool { return c.SemSurgiu || c.SemSumiu || c.SemMudou }

// Muda diz se sobrou alguma leitura. Uma família em que as três caíram não
// respondeu nada, e o silêncio dela não pode ser lido como "nada mudou".
func (c CoberturaDrift) Muda() bool { return !c.SemSurgiu || !c.SemSumiu || !c.SemMudou }

// MudancaDrift é uma entidade que surgiu, sumiu ou teve um campo alterado.
type MudancaDrift struct {
	Tipo   string // systemd.unit
	Titulo string // como o operador lê o tipo
	ID     string // sshd.service
	Kind   string // surgiu | sumiu | mudou

	// Campo, Antes e Depois só existem no `mudou`. Para surgiu/sumiu o que
	// interessa é a entidade inteira, que vai em Campos.
	Campo  string
	Antes  string
	Depois string
	Campos []string

	// Decide diz que esta mudança é, por si, o evento de segurança — e não
	// uma pista sobre ele.
	Decide bool

	// Alvos são os sujeitos que esta mudança responde: é por eles que o motor
	// liga a mudança aos achados que falam da mesma coisa.
	Alvos []string
}

// TemDrift diz se houve comparação. Sem ela, os checks de drift não têm o que
// responder e se declaram NÃO VERIFICADOS em vez de "nada encontrado".
func (f *Facts) TemDrift() bool {
	return f.DriftDados != nil
}
