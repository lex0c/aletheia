package scenario

// Apagar log é das primeiras coisas que se faz depois de entrar, e das mais
// difíceis de acusar sem errar.
//
// A tentação é reportar arquivo VAZIO, e ela morre na primeira medição: numa
// debian:12 recém-criada, `wtmp`, `btmp`, `faillog` e `lastlog` estão TODOS com
// zero bytes. Vazio é o estado normal de sistema novo.
//
//	F1  buraco na rotação        o logrotate nunca apaga o do meio
//	F2  sessão sem registro      duas coisas que não podem ser verdade juntas
//	F3  a mesma forma, LEGÍTIMA  rotação do wtmp, que não pode virar achado

func init() {
	Register(Scenario{
		ID:   "F1-buraco-na-rotacao",
		Desc: "falta uma geração no meio da série de rotação: o logrotate nunca faz isso",
		// O logrotate produz sequência contígua e apaga o mais ANTIGO quando
		// passa do limite configurado. Faltar o fim é rotação funcionando;
		// faltar o meio é remoção manual.
		//
		// Não depende de julgar se o arquivo deveria ter conteúdo, e é por isso
		// que vale igual em host novo e em host de dez anos.
		Images: matriz,
		Plant:  buracoNaRotacao,
		Expect: []Expect{
			{ID: "antiforense.log_rotation_gap", Sev: "CRITICAL",
				Subject: "/var/log/auth.log"},
			{ID: "antiforense.log_rotation_gap", Evidence: "nunca o do meio"},
			// Log de autenticação é o que datava a entrada: perde mais que os outros.
			{ID: "antiforense.log_rotation_gap", Evidence: "datava a entrada"},
		},
		Exit: 2,
	})

	Register(Scenario{
		ID:   "F2-sessao-sem-registro",
		Desc: "sessão aberta agora e histórico de login vazio: as duas não podem ser verdade juntas",
		// Abrir sessão escreve nos dois arquivos. Se o histórico está vazio, ele
		// foi zerado DEPOIS que a sessão abriu.
		//
		// O cruzamento é o que torna isto utilizável: `wtmp` vazio sozinho é o
		// estado de toda instalação nova, e acusá-lo seria acusar todo contêiner
		// do mundo.
		Images: matriz,
		Plant:  sessaoSemHistorico,
		Expect: []Expect{
			{ID: "antiforense.wtmp_cleared", Sev: "CRITICAL", Subject: "wtmp"},
			{ID: "antiforense.wtmp_cleared", Evidence: "zerado depois que a sessão abriu"},
			// E o roteiro precisa dizer que a sessão viva é a única fonte que sobrou.
			{ID: "antiforense.wtmp_cleared", Evidence: "não é o logrotate"},
		},
		Exit: 2,
	})

	Register(Scenario{
		ID:   "F3-rotacao-do-wtmp-nao-eh-achado",
		Desc: "a MESMA forma, produzida pelo logrotate: arquivo vivo vazio com sessão aberta",
		// Várias distribuições rotacionam o wtmp. Logo depois disso o arquivo
		// vivo está vazio COM sessão aberta — exatamente a forma do F2, e
		// inteiramente legítima.
		//
		// O que separa os dois é o `wtmp.1` ao lado, e é por isso que ele é
		// procurado ANTES de acusar. Sem este cenário, o check acusaria todo
		// host logo depois da rotação semanal.
		Images: matriz,
		Plant:  rotacaoDoWtmp,
		Forbid: []string{"antiforense.wtmp_cleared"},
		Exit:   -1,
		// Orçamento de ruído MEDIDO: silêncio é o contrato deste cenário.
		MaxWarn: SemAvisos,
	})
}

// ---------------------------------------------------------------------------

const buracoNaRotacao = `
mkdir -p /var/log
echo linha > /var/log/auth.log
echo linha > /var/log/auth.log.1
echo linha > /var/log/auth.log.3.gz
`

const sessaoSemHistorico = `
mkdir -p /var/log /run
/helper utmp /run/utmp 7 root 10.0.0.9 1
: > /var/log/wtmp
`

// rotacaoDoWtmp é o F2 com a explicação ao lado.
const rotacaoDoWtmp = `
mkdir -p /var/log /run
/helper utmp /run/utmp 7 root 10.0.0.9 1
: > /var/log/wtmp
/helper utmp /var/log/wtmp.1 7 root 10.0.0.9 5
`
