package info

import "testing"

// O disfarce da §3.5 troca só o `argv`, e deixa o `comm` verdadeiro. Comparar
// com o comm faria a ferramenta calar exatamente sobre o que ela procura — foi
// o que a primeira versão fez, contra um processo que se dizia [kworker/0:9].
func TestDivergenciaOlhaOArgvContraOExecutavel(t *testing.T) {
	mente := map[string][2]string{
		"exec -a com nome de kthread": {"/helper", "[kworker/0:9]"},
		"nome de daemon conhecido":    {"/tmp/.x", "/usr/sbin/sshd"},
	}
	for nome, c := range mente {
		if mesmaCoisa(c[0], c[1]) {
			t.Errorf("%s: %q rodando %q precisa aparecer como divergência", nome, c[1], c[0])
		}
	}

	honesto := map[string][2]string{
		"shell de login":                       {"/usr/bin/bash", "-bash"},
		"caminho relativo":                     {"/usr/bin/node", "node"},
		"interpretador versionado":             {"/usr/bin/python3.11", "python3"},
		"argv reescrito pelo próprio processo": {"/usr/sbin/nginx", "nginx: master process"},
		"caminho absoluto igual":               {"/usr/sbin/sshd", "/usr/sbin/sshd"},
		"sem argv":                             {"/usr/bin/x", ""},
	}
	for nome, c := range honesto {
		if !mesmaCoisa(c[0], c[1]) {
			t.Errorf("%s: %q rodando %q NÃO é disfarce, e acusá-lo é ruído", nome, c[1], c[0])
		}
	}
}
