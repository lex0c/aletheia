package scenario

// Baseline: a pergunta que nenhum check faz sozinho.
//
// Os checks perguntam "isto é suspeito?" olhando forma, procedência e
// integridade — todas propriedades do ARTEFATO. Nenhum deles sabe que o rclone
// daquele servidor é o backup que roda desde 2023.
//
// A baseline traz essa história de fora, e por isso é a funcionalidade mais
// perigosa da ferramenta: se o host já estava comprometido na captura, o
// implante entra nela.
//
// Os três cenários daqui existem para provar as duas metades do contrato, e a
// segunda importa mais que a primeira:
//
//	B1  a baseline CALA o ruído conhecido e deixa o novo gritar
//	B2  ela NUNCA apaga: implante capturado junto continua impresso
//	B3  e ela se declara — de onde veio, de quando, com que cobertura

func init() {
	Register(Scenario{
		ID:   "B1-baseline-cala-o-conhecido",
		Desc: "servidor legítimo com baseline: o acúmulo de dois anos cala e o implante novo grita",
		// É o cenário 80 outra vez — o servidor de produção sem invasor —, agora
		// com a história dele em mãos.
		//
		// Sem baseline ele gasta seis avisos e um manual do orçamento de
		// atenção, e cada um é um achado CORRETO: binário sem dono de pacote É
		// um fato, CA fora do bundle É um fato. Com a baseline, os mesmos fatos
		// descem para informativo e o que sobra é só o que apareceu depois.
		//
		// O implante plantado DEPOIS da captura é o de sempre: nome de sistema,
		// caminho de sistema, setuid, unit e cron. A pergunta que este cenário
		// responde é se ele ainda grita através de uma baseline que calou tudo
		// o mais.
		Images: matriz,
		Plant:  baselineDepoisImplante,
		Args:   []string{"--baseline", "/base.json"},
		Expect: []Expect{
			// Dois mecanismos é AVISO — o salto para crítico é a partir de
			// três, e a distribuição entrega dois o tempo todo. Quem faz este
			// cenário sair crítico é o setuid, que não tem explicação legítima
			// num binário que nenhum pacote entregou.
			{ID: "correlate.persistence_redundant", Sev: "WARN",
				Subject: "/usr/local/sbin/systemd-oomd-helper"},
			{ID: "persist.suid_unowned", Sev: "CRITICAL"},
		},
		// O cabeçalho precisa declarar a autoridade que rebaixou achado.
		ExpectOutput: []string{
			"BASELINE",
			"estar na baseline diz que não é novo, não que é legítimo",
			// E o que apareceu DEPOIS precisa estar visivelmente marcado: é a
			// informação mais valiosa de uma execução com referência.
			//
			// Esta asserção é DELIBERADAMENTE sobre a renderização — "estar
			// visivelmente marcado" não é propriedade do dado, é do relatório.
			// A marca é "NEW" desde a reformulação; era "✳NOVO", e o ✳ só
			// sobreviveu na ressalva de achado sem chave estável.
			"NEW",
		},
		Exit: 2,
	})

	Register(Scenario{
		ID:   "B2-baseline-de-host-comprometido",
		Desc: "a captura foi feita com o implante JÁ instalado: ele desce de nível e NÃO desaparece",
		// ESTE É O CENÁRIO QUE JUSTIFICA O DESENHO INTEIRO.
		//
		// A tentação óbvia ao implementar baseline é suprimir o que já era
		// conhecido — é o que reduz ruído, e é o que a maioria das ferramentas
		// faz. O custo aparece exatamente aqui: se a captura pegou o host já
		// comprometido, suprimir abençoa o implante para sempre, e a ferramenta
		// passa a certificar como limpo o host que ela mesma deveria denunciar.
		//
		// Por isso casar com a baseline REBAIXA e nunca apaga: crítico vira
		// aviso, aviso vira informativo, e o piso é informativo. O achado
		// continua no relatório, com a data em que já estava lá, e com a frase
		// que separa "não é novo" de "é legítimo".
		//
		// O exit também não pode ir a zero: um host com implante conhecido não
		// é um host aprovado.
		Images: matriz,
		Plant:  baselineComImplante,
		Args:   []string{"--baseline", "/base.json"},
		Expect: []Expect{
			// Desceu de crítico para aviso, e continua lá.
			{ID: "persist.suid_unowned", Sev: "WARN",
				Subject: "/usr/local/sbin/systemd-oomd-helper"},
			{ID: "persist.suid_unowned", Evidence: "NÃO prova que é legítimo"},
		},
		ExpectOutput: []string{"estar na baseline diz que não é novo"},
		// 1 e não 0: implante conhecido não é implante aprovado.
		Exit: 1,
	})

	Register(Scenario{
		ID:   "B3-baseline-declara-a-si-mesma",
		Desc: "baseline capturada SEM privilégio: a execução seguinte diz que a referência é incompleta",
		// Uma baseline rebaixa achado, e autoridade que rebaixa precisa ser
		// examinável. A pior forma de erro aqui é silenciosa: uma referência
		// montada numa execução degradada descreve MENOS do que parece — o que
		// não foi olhado na captura não entrou nela, e depois aparece como novo
		// sem ter nascido.
		//
		// A captura é feita como usuário comum, de propósito, e o que este
		// cenário cobra é a execução seguinte DIZER isso em voz alta.
		Images: matriz,
		Plant:  baselineIncompleta,
		Args:   []string{"--baseline", "/base/ref.json"},
		ExpectOutput: []string{
			"BASELINE",
			"incompleta",
		},
		Exit: -1,
		// Orçamento de ruído MEDIDO: silêncio é o contrato deste cenário.
		MaxWarn: SemAvisos,
	})
}

// ---------------------------------------------------------------------------

// baselineDepoisImplante captura o servidor legítimo e só então planta.
const baselineDepoisImplante = servidorLegitimo + `
# a captura acontece com o host ainda íntegro
/aletheia baseline -o /base.json 2>/dev/null

# e o implante vem DEPOIS: é isto que precisa atravessar a baseline
mkdir -p /usr/local/sbin /etc/cron.d /etc/systemd/system
cp /helper /usr/local/sbin/systemd-oomd-helper
chmod 4755 /usr/local/sbin/systemd-oomd-helper
printf '@reboot root /usr/local/sbin/systemd-oomd-helper sleep 3600\n' > /etc/cron.d/oomd
printf '[Unit]\nDescription=OOMD Helper\n[Service]\nExecStart=/usr/local/sbin/systemd-oomd-helper sleep 3600\n[Install]\nWantedBy=multi-user.target\n' > /etc/systemd/system/systemd-oomd-helper.service
`

// baselineComImplante captura o host JÁ comprometido.
const baselineComImplante = `
mkdir -p /usr/local/sbin /etc/cron.d /etc/systemd/system
cp /helper /usr/local/sbin/systemd-oomd-helper
chmod 4755 /usr/local/sbin/systemd-oomd-helper
printf '@reboot root /usr/local/sbin/systemd-oomd-helper sleep 3600\n' > /etc/cron.d/oomd
printf '[Unit]\nDescription=OOMD Helper\n[Service]\nExecStart=/usr/local/sbin/systemd-oomd-helper sleep 3600\n[Install]\nWantedBy=multi-user.target\n' > /etc/systemd/system/systemd-oomd-helper.service

# a captura é feita ASSIM, com o implante dentro
/aletheia baseline -o /base.json 2>/dev/null
`

// baselineIncompleta captura sem privilégio, e o relatório seguinte precisa
// dizer que a referência viu menos do que devia.
// O plant é `set -e` e CONFIRMA o que produziu, e os dois vieram do mesmo bug.
//
// A versão anterior fazia `touch /base.json` para o usuário sem privilégio poder
// escrever — e o `baseline` RECUSA sobrescrever arquivo existente (é a trava que
// impede `scan --json /var/log/auth.log` de zerar um log do host). A captura
// saía com exit 3, o `|| true` engolia, e o arquivo ficava vazio: o scan seguinte
// morria em "unexpected end of JSON input", sem sequer imprimir linha de
// cobertura. O cenário reportava "o relatório não contém BASELINE" — a mensagem
// de um defeito de PRODUTO — quando o defeito era do plantio.
//
// A permissão vem do DIRETÓRIO, que é como se dá escrita sem criar o arquivo. E
// a linha final é a que fecha a classe: plantio que não produziu o que promete
// derruba o cenário ali, em vez de virar asserção enganosa três passos depois.
const baselineIncompleta = `
set -e
mkdir -p /usr/local/sbin
cp /helper /usr/local/sbin/agente

id -u nobody >/dev/null 2>&1 || adduser -D -u 1000 comum 2>/dev/null || useradd -u 1000 -m comum 2>/dev/null || true
mkdir -p /base && chmod 1777 /base
su nobody -s /bin/sh -c '/aletheia baseline -o /base/ref.json' 2>/dev/null || \
  su comum -s /bin/sh -c '/aletheia baseline -o /base/ref.json' 2>/dev/null || true
test -s /base/ref.json || { echo "PLANTIO FALHOU: baseline sem privilégio não escreveu /base/ref.json" >&2; exit 1; }
`
