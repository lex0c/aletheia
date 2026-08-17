package scenario

// Três fontes que faltavam, vindas de ler osquery, tracee e velociraptor.
//
//	D2  força bruta que entrou   o cruzamento entre wtmp e btmp
//
// A montagem que esconde e o hook de ftrace COMEÇARAM aqui, em contêiner com
// `--privileged` e `--cap-add SYS_ADMIN`. Foram para a VM (G3 e G4): contêiner
// privilegiado é uma concessão — não se parece com o servidor que se varre, e o
// runtime ainda mascara /sys por baixo. Manter as duas versões seria cobertura
// duplicada no pior dos dois ambientes.

func init() {
	Register(Scenario{
		ID:   "D2-forca-bruta-que-entrou",
		Desc: "a mesma origem que falhou dezenas de vezes conseguiu entrar",
		// É o achado que nenhuma das duas fontes dá sozinha, e é por isso que
		// vale existir:
		//
		//	btmp cheio de falhas    ruído de internet, todo host exposto tem
		//	wtmp com uma entrada    o host funcionando
		//	as duas na MESMA origem como o invasor chegou, com hora e endereço
		//
		// A ferramenta citava o wtmp em dezenas de evidências — "confira contra
		// o wtmp" — e nunca o lia. O formato nunca justificou a omissão: é
		// registro binário de tamanho fixo.
		Images: matriz,
		Plant:  forcaBrutaQueEntrou,
		Expect: []Expect{
			{ID: "auth.bruteforce_success", Sev: "CRITICAL", Subject: "203.0.113.9"},
			{ID: "auth.bruteforce_success", Evidence: "e depois ENTROU"},
			// E o inventário, que fecha o loop que a ferramenta apontava.
			{ID: "auth.login_inventory", Sev: "MANUAL", Subject: "root"},
		},
		// A origem legítima do time NÃO pode virar achado: ela entrou sem
		// falhar antes.
		Exit: 2,
	})

}

// ---------------------------------------------------------------------------

// forcaBrutaQueEntrou planta as duas metades: as falhas e a entrada.
const forcaBrutaQueEntrou = `
mkdir -p /var/log

# 25 tentativas recusadas da mesma origem — é o ruído que todo host exposto tem
/helper utmp /var/log/btmp 7 root 203.0.113.9 25

# e uma entrada bem-sucedida da MESMA origem: é o cruzamento que dá o sinal
/helper utmp /var/log/wtmp 7 root 203.0.113.9 1

# mais uma entrada legítima, de outra origem e SEM falhas antes: ela não pode
# virar achado, e é o que impede o check de acusar todo login que existe
/helper utmp /var/log/wtmp 7 deploy 10.0.0.15 3
chmod 600 /var/log/btmp
`
