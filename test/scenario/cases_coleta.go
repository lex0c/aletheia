package scenario

// A separação entre COLETAR e ANALISAR (§11.1).
//
// O que os testes unitários provam é a mecânica: ida e volta do artefato,
// recusa de esquema, âncora da janela, redação do argv. O que só o contêiner
// prova é o ciclo inteiro contra um /proc de verdade — coletar num host,
// analisar depois, e chegar à MESMA conclusão.
//
//	X1  o retrato leva o implante junto: coletado aqui, concluído depois
//	X2  a análise HERDA a cobertura da coleta, e não pode melhorá-la
//
// O X2 é o cenário que justifica os outros existirem. A tentação é óbvia — o
// `analyze` roda numa estação com root e seria trivial sondar o ambiente local
// e declarar cobertura cheia. O relatório sairia afirmando ter verificado coisas
// que ninguém olhou, sobre um host que talvez nem exista mais, e nada na saída
// denunciaria a troca: números maiores, veredito melhor, nenhum erro.

func init() {
	Register(Scenario{
		ID:     "X1-coleta-aqui-analise-depois",
		Desc:   "o implante entra no retrato: a coleta acontece no host e a conclusão acontece do lado limpo",
		Images: []string{"debian:12", "alpine:3.20"},
		Cmd:    "analyze",
		// Execução fileless: o binário nunca esteve em disco, e o que sobrevive
		// dele no artefato é o campo que diz isso. É o caso que separa um dump
		// de fatos de um `tar` de arquivos — nenhuma cópia de disco carregaria
		// esta informação.
		Plant: `/helper memfd /helper sleep 300 &
			sleep 0.5
			/aletheia collect --out /tmp/retrato.json`,
		Args: []string{"/tmp/retrato.json"},
		Expect: []Expect{
			{ID: "proc.memfd_exec", Sev: "CRITICAL"},
		},
		ExpectOutput: []string{
			// O relatório precisa dizer, antes de qualquer achado, que descreve um
			// RETRATO. Sem isto um `analyze` de três dias atrás é visualmente
			// idêntico a um `scan` de agora.
			"ANÁLISE DE COLETA",
			"nada foi olhado agora: os fatos e a COBERTURA são os da coleta",
			// E o `collect` precisa ter dito o que NÃO viu, enquanto ainda dava
			// tempo de recoletar: a máquina pode não existir depois.
			"O QUE ESTA COLETA NÃO VIU",
		},
		Exit: 2,
	})

	Register(Scenario{
		ID:     "X2-a-analise-nao-melhora-a-cobertura",
		Desc:   "coleta sem privilégio, análise COMO ROOT: o que ninguém olhou continua não olhado",
		Images: []string{"debian:12"},
		Cmd:    "analyze",
		// A assimetria é o teste. O `collect` roda como `nobody`; o `analyze`
		// roda como root, na mesma máquina, com tudo à mão. Se ele sondasse o
		// ambiente local, a cobertura subiria e o motivo registrado pela coleta
		// desapareceria do rodapé.
		// O `>&2` não é detalhe: com `--json -`, o stdout é JSONL puro e a
		// primeira linha de texto solto ali quebraria a agregação de frota —
		// que é a propriedade que o harness confere em toda execução.
		Plant: `su nobody -s /bin/sh -c '/aletheia collect --out /tmp/cego.json'
			echo "ANALISANDO COMO UID $(id -u)" >&2`,
		Args: []string{"-v", "/tmp/cego.json"},
		ExpectOutput: []string{
			// Quem analisa É root — sem esta linha o cenário não prova nada.
			"ANALISANDO COMO UID 0",
			// E o rodapé continua repetindo o motivo que a COLETA registrou.
			"não estamos como root",
		},
		MustBeIncomplete: true,
		// Um exit 0 aqui seria a mentira central da ferramenta, na versão que
		// atravessa o tempo: cobertura de uma máquina emprestada para outra.
		Exit: 1,
		// Medido: ZERO. Uma coleta cega não tem o que afirmar — e é essa a
		// questão. O silêncio aqui não é host limpo, é cobertura ausente, e
		// quem separa as duas coisas é o INCOMPLETE acima.
		MaxWarn: SemAvisos,
	})
}
