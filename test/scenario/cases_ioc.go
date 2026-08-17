package scenario

// Indicadores DESTE incidente (SPEC 6.4, runbook §23).
//
// É o único check cuja fonte vem de FORA: todo o resto do catálogo codifica o
// que o autor pensou, e um indicador é conhecimento de terceiro. Por isso os
// três cenários cobrem os três desfechos que importam, e não só o positivo:
//
//	R1  a lista encontra          crítico, com a linha da lista citada
//	R2  a lista NÃO encontra      silêncio, e o relatório continua dizendo
//	                              quantos indicadores procurou
//	R3  a lista não tem indicador ERRO, alto: uma varredura que segue limpa
//	                              com uma lista vazia é a pior saída possível

func init() {
	Register(Scenario{
		ID:   "R1-indicador-encontrado",
		Desc: "o indicador do incidente aparece neste host: é a §23 respondida",
		// A cadeia é a de sempre — binário copiado para um diretório oculto e
		// posto para rodar —, mas o que está sob teste não é a heurística: é o
		// casamento com a lista que o operador trouxe do host anterior.
		Images: matriz,
		Plant: `mkdir -p /tmp/.cache
			cp /helper /tmp/.cache/agent
			chmod +x /tmp/.cache/agent
			/tmp/.cache/agent sleep 300 &
			printf 'paths: ["/tmp/.cache/*"]\nusers: [daemon]\n' > /ioc.yaml
			sleep 0.5`,
		Args: []string{"--ioc", "/ioc.yaml"},
		Expect: []Expect{
			{ID: "ioc.match", Sev: "CRITICAL", Evidence: "indicador de path"},
			{ID: "ioc.match", Evidence: "indicador de user"},
			// A linha da lista precisa estar citada: um achado que não diz de
			// onde veio o indicador não é auditável.
			{ID: "ioc.match", Evidence: "/ioc.yaml (linha"},
		},
		// E o relatório declara a lista, como declara a baseline: quem muda o
		// resultado da execução precisa ser examinável.
		ExpectOutput: []string{"INDICADORES", "1 path · 1 user"},
		Exit:         2,
	})

	Register(Scenario{
		ID:   "R2-indicador-ausente",
		Desc: "a mesma lista contra um host que não tem nada dela: silêncio, e a conta do que foi procurado",
		// A metade negativa, e ela é a que decide se o resultado vale: um
		// `ioc.match` que dispara sozinho não distingue host limpo de host
		// comprometido.
		//
		// E o cenário trava a outra metade do contrato: mesmo sem casar nada, o
		// relatório DIZ quantos indicadores entraram. Sem esse número, uma lista
		// mal escrita — dois indicadores lidos de quarenta linhas — produziria
		// exatamente esta mesma saída limpa.
		Images: matriz,
		Plant: `printf 'ips: [203.0.113.77]\npaths: ["/opt/naoexiste/*"]\nusers: [naoexiste]\n' > /ioc.yaml
			sleep 0.2`,
		Args:         []string{"--ioc", "/ioc.yaml"},
		Forbid:       []string{"ioc.match"},
		ExpectOutput: []string{"INDICADORES", "1 ip · 1 path · 1 user"},
		Exit:         -1,
		// Orçamento de ruído MEDIDO: silêncio é o contrato deste cenário.
		MaxWarn: SemAvisos,
	})

	Register(Scenario{
		ID:   "R3-lista-sem-indicador-falha-alto",
		Desc: "arquivo de indicadores que não produz indicador nenhum: erro, não varredura limpa",
		// O pior desfecho possível desta funcionalidade não é errar um
		// casamento: é o operador rodar com uma lista que a ferramenta não
		// entendeu, ler "nada encontrado" e concluir que o incidente não chegou
		// neste host. Por isso a lista vazia é ERRO de invocação, com exit 3, e
		// não uma execução que segue em silêncio.
		Images: []string{"debian:12"},
		Plant: `printf '# indicadores do incidente\n\n' > /ioc.yaml
			sleep 0.2`,
		Args:         []string{"--ioc", "/ioc.yaml"},
		ExpectOutput: []string{"a lista não trouxe indicador nenhum"},
		Exit:         3,
		// Orçamento de ruído MEDIDO: silêncio é o contrato deste cenário.
		MaxWarn: SemAvisos,
	})
}
