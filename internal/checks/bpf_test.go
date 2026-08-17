package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
	"github.com/lex0c/aletheia/internal/kbpf"
)

func fatosBPF(progs ...facts.ProgramaBPF) *facts.Facts {
	return &facts.Facts{BPF: facts.BPF{Enumerado: true, Programas: progs}}
}

// O eixo do check é DONO, não existência. Um programa segurado por qualquer um
// dos quatro detentores legíveis é rotina — e é a esmagadora maioria do que se
// encontra num host moderno.
func TestBPFComDonoNaoViraAchado(t *testing.T) {
	f := fatosBPF(
		facts.ProgramaBPF{ID: 1, TipoNum: kbpf.ProgKprobe, Tipo: "kprobe",
			Donos: []facts.DonoBPF{{PID: 900, Comm: "bpftrace", Como: "descritor aberto"}}},
		facts.ProgramaBPF{ID: 2, TipoNum: kbpf.ProgTracing, Tipo: "tracing",
			Pins: []string{"/sys/fs/bpf/tetragon/prog"}},
		facts.ProgramaBPF{ID: 3, TipoNum: kbpf.ProgLSM, Tipo: "lsm",
			Anexos: []string{"tracing attach_type=27"}},
		facts.ProgramaBPF{ID: 4, TipoNum: kbpf.ProgKprobe, Tipo: "kprobe", TailCall: true},
	)
	r := bpfSemDono.Run(bpfSemDono, f, testEnv())
	if len(r.Findings) != 0 {
		t.Errorf("programa com dono visível não é achado: %v", r.Findings)
	}
}

// Sem dono nenhum, a severidade vem da FAMÍLIA do tipo: o que observa ou altera
// a execução do kernel é outra conversa que o que só computa.
func TestBPFSemDonoSeveridadePorFamilia(t *testing.T) {
	f := fatosBPF(
		facts.ProgramaBPF{ID: 7, TipoNum: kbpf.ProgKprobe, Tipo: "kprobe", Nome: "x"},
		facts.ProgramaBPF{ID: 8, TipoNum: kbpf.ProgSyscall, Tipo: "syscall"},
		facts.ProgramaBPF{ID: 9, TipoNum: kbpf.ProgSocketFilter, Tipo: "socket_filter"},
	)
	r := bpfSemDono.Run(bpfSemDono, f, testEnv())
	sev := map[string]check.Severity{}
	for _, fd := range r.Findings {
		sev[fd.Subject] = fd.Sev
	}
	if sev["bpf prog id=7"] != check.SevCritical {
		t.Error("kprobe órfão intercepta a execução do kernel: é crítico")
	}
	if sev["bpf prog id=8"] != check.SevWarn {
		t.Error("programa que não intercepta é aviso, não crítico")
	}
	if sev["bpf prog id=9"] != check.SevCritical {
		t.Error("filtro de socket órfão é a forma do BPFDoor: é crítico")
	}
	// A evidência do programa preso a socket precisa dizer POR QUE ninguém
	// aparece segurando — senão o operador procura um processo que não existe.
	for _, fd := range r.Findings {
		if fd.Subject != "bpf prog id=9" {
			continue
		}
		if !strings.Contains(strings.Join(fd.Evidence, " "), "SOCKET") {
			t.Errorf("evidência do socket_filter sem o mecanismo: %v", fd.Evidence)
		}
	}
	// eBPF só existe na memória do kernel: reiniciar apaga a única cópia.
	for _, fd := range r.Findings {
		if !fd.Irreversible {
			t.Errorf("%s precisa ser irreversível: o reboot apaga o programa", fd.Subject)
		}
	}
}

// O fio que fecha o achado do BPFDoor: quem segura um filtro de socket é um
// SOCKET, e a lista de quem tem socket de captura neste host agora é lida. O
// achado para de mandar procurar e passa a apontar.
func TestBPFSemDonoNomeiaCandidatos(t *testing.T) {
	f := fatosBPF(facts.ProgramaBPF{ID: 9, TipoNum: kbpf.ProgSocketFilter, Tipo: "socket_filter"})
	f.SocketsBrutos = []facts.SocketBruto{
		{Familia: "packet", Proto: "ETH_P_ALL (TODO o tráfego)", ProtoNum: 3, Inode: 5, PID: 812, Comm: "implante", Ativo: true},
	}
	r := bpfSemDono.Run(bpfSemDono, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %v", r.Findings)
	}
	junto := strings.Join(r.Findings[0].Evidence, " | ")
	if !strings.Contains(junto, "implante (pid=812)") {
		t.Errorf("o candidato precisa ser nomeado: %q", junto)
	}
	// E precisa dizer que é candidato: o kernel NÃO diz qual socket carrega
	// qual programa, e afirmar a ligação seria inventar o que falta.
	if !strings.Contains(junto, "não prova") {
		t.Errorf("candidato não pode ser apresentado como prova: %q", junto)
	}

	// Sem socket de captura nenhum, o achado diz isso em vez de calar.
	f.SocketsBrutos = nil
	r = bpfSemDono.Run(bpfSemDono, f, testEnv())
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "NÃO há socket de captura") {
		t.Errorf("a ausência de candidato também precisa ser dita: %v", r.Findings[0].Evidence)
	}

	// E candidato só faz sentido para quem é preso por socket: oferecer a
	// mesma lista num programa de kprobe apontaria para o lugar errado.
	f2 := fatosBPF(facts.ProgramaBPF{ID: 10, TipoNum: kbpf.ProgKprobe, Tipo: "kprobe"})
	f2.SocketsBrutos = []facts.SocketBruto{{Familia: "packet", Inode: 5, PID: 812, Comm: "implante", Ativo: true}}
	r2 := bpfSemDono.Run(bpfSemDono, f2, testEnv())
	if strings.Contains(strings.Join(r2.Findings[0].Evidence, " "), "candidatos a detentor") {
		t.Error("programa de kprobe não é preso por socket: não oferecer candidato")
	}
}

// O que a ferramenta NÃO sabe atribuir vira lacuna declarada, nunca achado. É a
// linha que impede um nó com cilium — dezenas de programas de tc e de cgroup —
// de virar dezenas de acusações.
func TestBPFTipoNaoAtribuivelViraLacunaNaoAchado(t *testing.T) {
	f := fatosBPF(
		facts.ProgramaBPF{ID: 11, TipoNum: kbpf.ProgSchedCls, Tipo: "sched_cls"},
		facts.ProgramaBPF{ID: 12, TipoNum: kbpf.ProgCgroupDevice, Tipo: "cgroup_device"},
		facts.ProgramaBPF{ID: 13, TipoNum: kbpf.ProgCgroupSkb, Tipo: "cgroup_skb"},
		facts.ProgramaBPF{ID: 14, TipoNum: 9999, Tipo: "tipo_9999"},
	)
	r := bpfSemDono.Run(bpfSemDono, f, testEnv())
	if len(r.Findings) != 0 {
		t.Fatalf("tipo que a ferramenta não sabe atribuir não pode virar achado: %v", r.Findings)
	}
	junto := strings.Join(r.Partial, " | ")
	for _, quer := range []string{"netlink", "cgroup", "não conhece"} {
		if !strings.Contains(junto, quer) {
			t.Errorf("a lacuna precisa dizer %q: %q", quer, junto)
		}
	}
	// Sem o número, "não verifiquei" não diz o tamanho do que ficou de fora.
	if !strings.Contains(junto, "2 programa(s)") {
		t.Errorf("a lacuna de cgroup precisa contar os dois: %q", junto)
	}
}

// O falso positivo medido, e o teste que ele não tinha.
//
// Num contêiner com SYS_ADMIN a bpf(2) responde — e o que ela enumera são os
// programas do HOST, porque o espaço de ids é global. Os processos que os
// seguram estão fora deste namespace de PID, então TODO programa do host sai
// sem dono. Na primeira medição isso deu um crítico contra um programa legítimo
// da máquina que rodava a suíte.
func TestBPFEmContainerNaoAcusa(t *testing.T) {
	f := fatosBPF(
		facts.ProgramaBPF{ID: 48, TipoNum: kbpf.ProgKprobe, Tipo: "kprobe"},
		facts.ProgramaBPF{ID: 49, TipoNum: kbpf.ProgSocketFilter, Tipo: "socket_filter"},
	)
	f.Host.EmContainer = true

	r := bpfSemDono.Run(bpfSemDono, f, testEnv())
	if len(r.Findings) != 0 {
		t.Fatalf("de dentro de contêiner os donos não são visíveis: nada pode ser "+
			"acusado. Achados: %v", r.Findings)
	}
	junto := strings.Join(r.Partial, " | ")
	if !strings.Contains(junto, "contêiner") || !strings.Contains(junto, "2 programa(s)") {
		t.Errorf("a lacuna precisa dizer que é contêiner e quantos ficaram: %q", junto)
	}
}

// Quando a enumeração não aconteceu, o check não pode dizer "nada encontrado".
// E a distinção entre lacuna e não-lacuna é a mesma do coletor.
func TestBPFNaoEnumeradoNaoViraSilencio(t *testing.T) {
	comLacuna := &facts.Facts{BPF: facts.BPF{
		Motivo: "sem CAP_BPF/CAP_SYS_ADMIN: os programas eBPF carregados não foram enumerados",
		Lacuna: true,
	}}
	r := bpfSemDono.Run(bpfSemDono, comLacuna, testEnv())
	if len(r.Partial) == 0 || !strings.Contains(r.Partial[0], "CAP_BPF") {
		t.Errorf("falta de privilégio precisa degradar a cobertura: %v", r.Partial)
	}

	// Em contêiner o kernel é do host: não é lacuna DESTA varredura, e mesmo
	// assim precisa ser dito em algum lugar — senão o operador acha que olhou.
	emContainer := &facts.Facts{BPF: facts.BPF{Motivo: "sem CAP_BPF", Lacuna: false}}
	r = bpfSemDono.Run(bpfSemDono, emContainer, testEnv())
	if len(r.Partial) != 0 {
		t.Errorf("dentro de contêiner isto não é lacuna de cobertura: %v", r.Partial)
	}
	r = bpfInventario.Run(bpfInventario, emContainer, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevInfo {
		t.Fatalf("o inventário precisa DIZER que não olhou: %v", r.Findings)
	}
}

// O inventário é UM achado, não um por programa: num nó de Kubernetes são
// dezenas, e dezenas de linhas afogam o relatório.
func TestBPFInventarioAgrega(t *testing.T) {
	var progs []facts.ProgramaBPF
	for i := 0; i < 12; i++ {
		progs = append(progs, facts.ProgramaBPF{
			ID: uint32(i + 1), TipoNum: kbpf.ProgCgroupSkb, Tipo: "cgroup_skb",
			Donos: []facts.DonoBPF{{PID: 1, Comm: "systemd", Como: "descritor aberto"}},
		})
	}
	progs = append(progs, facts.ProgramaBPF{
		ID: 99, TipoNum: kbpf.ProgKprobe, Tipo: "kprobe",
		Donos: []facts.DonoBPF{{PID: 800, Comm: "falco", Como: "descritor aberto"}},
	})
	r := bpfInventario.Run(bpfInventario, fatosBPF(progs...), testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("o inventário precisa sair como um achado só: %d", len(r.Findings))
	}
	fd := r.Findings[0]
	if fd.Sev != check.SevManual {
		t.Errorf("inventário não é acusação: sev = %v", fd.Sev)
	}
	junto := strings.Join(fd.Evidence, " | ")
	if !strings.Contains(junto, "systemd(12)") || !strings.Contains(junto, "falco(1)") {
		t.Errorf("quem segura precisa aparecer contado: %q", junto)
	}
	if !strings.Contains(junto, "13 programa(s)") {
		t.Errorf("o total precisa aparecer: %q", junto)
	}
}

// Host sem eBPF nenhum não produz inventário: uma linha dizendo "zero
// programas" seria ruído em todo servidor que não usa a tecnologia.
func TestBPFInventarioCalaEmHostSemEBPF(t *testing.T) {
	r := bpfInventario.Run(bpfInventario, fatosBPF(), testEnv())
	if len(r.Findings) != 0 {
		t.Errorf("sem programa carregado não há inventário: %v", r.Findings)
	}
}

// A visão cruzada: citado por descritor e ausente da lista, já confirmado pelo
// coletor.
func TestBPFOcultoEhCritico(t *testing.T) {
	f := &facts.Facts{BPF: facts.BPF{Enumerado: true, Ocultos: []uint32{42}}}
	r := bpfOculto.Run(bpfOculto, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("id citado e não listado é crítico: %v", r.Findings)
	}
	if !r.Findings[0].Irreversible {
		t.Error("a prova some no reboot: o achado é irreversível")
	}
}

// A segunda rota compara DUAS interfaces do kernel sobre o mesmo fato: o
// trampolim que o ftrace mostra e o programa que a bpf(2) deveria listar.
func TestBPFTrampolimSemPrograma(t *testing.T) {
	hooks := []facts.HookFtrace{
		{Simbolo: "__x64_sys_getdents64", Callback: "bpf_trampoline_6442516084+0x0/0xee"},
	}

	// Sem nenhum programa que use trampolim: alguém está sendo omitido.
	f := &facts.Facts{Ftrace: hooks, BPF: facts.BPF{Enumerado: true}}
	r := bpfOculto.Run(bpfOculto, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("trampolim sem programa é a divergência: %v", r.Findings)
	}

	// Com um programa de tracing carregado, o trampolim está explicado.
	f.BPF.Programas = []facts.ProgramaBPF{{ID: 3, TipoNum: kbpf.ProgTracing, Tipo: "tracing"}}
	if r := bpfOculto.Run(bpfOculto, f, testEnv()); len(r.Findings) != 0 {
		t.Errorf("programa de tracing explica o trampolim: %v", r.Findings)
	}

	// E struct_ops também usa trampolim — é o falso positivo declarado.
	f.BPF.Programas = []facts.ProgramaBPF{{ID: 4, TipoNum: kbpf.ProgStructOps, Tipo: "struct_ops"}}
	if r := bpfOculto.Run(bpfOculto, f, testEnv()); len(r.Findings) != 0 {
		t.Errorf("struct_ops explica o trampolim: %v", r.Findings)
	}

	// Trampolim de dispatcher de XDP não é o mesmo símbolo, e não conta.
	f.BPF.Programas = nil
	f.Ftrace = []facts.HookFtrace{{Simbolo: "x", Callback: "bpf_dispatcher_xdp+0x0/0x10"}}
	if r := bpfOculto.Run(bpfOculto, f, testEnv()); len(r.Findings) != 0 {
		t.Errorf("dispatcher não é trampolim de programa: %v", r.Findings)
	}
}
