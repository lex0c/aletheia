package facts

import (
	"reflect"
	"testing"
)

// O formato do fdinfo é do kernel, e ele difere entre um descritor de PROGRAMA
// e um de LINK — o segundo cita os dois ids, e é por ele que se chega ao
// programa de um anexo moderno.
func TestIdsDoFdinfo(t *testing.T) {
	casos := []struct {
		nome       string
		texto      string
		prog, link uint32
	}{
		{
			nome: "descritor de programa",
			texto: "pos:\t0\nflags:\t02000002\nmnt_id:\t16\nino:\t1234\n" +
				"prog_type:\t2\nprog_jited:\t1\nprog_tag:\ta04f5eef06a7f555\n" +
				"memlock:\t4096\nprog_id:\t47\nrun_time_ns:\t0\nrun_cnt:\t0\n",
			prog: 47,
		},
		{
			nome:  "descritor de link",
			texto: "pos:\t0\nflags:\t02000000\nlink_type:\ttracing\nlink_id:\t3\nprog_id:\t12\n",
			prog:  12, link: 3,
		},
		{
			nome:  "descritor que não é bpf",
			texto: "pos:\t0\nflags:\t02\nmnt_id:\t9\n",
		},
	}
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			prog, link := idsDoTextoFdinfo(c.texto)
			if prog != c.prog || link != c.link {
				t.Errorf("prog=%d link=%d, queria prog=%d link=%d", prog, link, c.prog, c.link)
			}
		})
	}
}

// A visão cruzada compara CITADO com ENUMERADO. O id zero não conta: é o valor
// que um fdinfo sem prog_id devolve, e tratá-lo como citado inventaria um
// programa oculto em todo host.
func TestCitadosNaoEnumerados(t *testing.T) {
	citados := map[uint32]bool{0: true, 7: true, 9: true, 12: true}
	enumerados := map[uint32]bool{7: true, 12: true, 44: true}
	got := citadosNaoEnumerados(citados, enumerados)
	if !reflect.DeepEqual(got, []uint32{9}) {
		t.Errorf("faltantes = %v, queria [9]", got)
	}
	if n := citadosNaoEnumerados(map[uint32]bool{0: true}, nil); len(n) != 0 {
		t.Errorf("id zero não pode virar suspeito: %v", n)
	}
}

// Os quatro detentores valem o mesmo para a pergunta "alguém segura isto?".
// Esquecer um deles produziria achado em cima de programa perfeitamente
// explicado — o pin do cilium, o tail call do datapath.
func TestSemDonoVisivelConsideraOsQuatro(t *testing.T) {
	casos := []struct {
		nome string
		p    ProgramaBPF
		quer bool
	}{
		{"nada segura", ProgramaBPF{ID: 1}, true},
		{"descritor de processo", ProgramaBPF{ID: 2, Donos: []DonoBPF{{PID: 9}}}, false},
		{"pin no bpffs", ProgramaBPF{ID: 3, Pins: []string{"/sys/fs/bpf/x"}}, false},
		{"link", ProgramaBPF{ID: 4, Anexos: []string{"tracing"}}, false},
		{"tail call", ProgramaBPF{ID: 5, TailCall: true}, false},
	}
	for _, c := range casos {
		if got := c.p.SemDonoVisivel(); got != c.quer {
			t.Errorf("%s: SemDonoVisivel = %v, queria %v", c.nome, got, c.quer)
		}
	}
}
