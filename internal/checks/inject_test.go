package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/facts"
)

// --- proc.maps_rwx_anon ---

func TestMapsRWXExigeAnonimo(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		// rwx COM arquivo por trás: estranho, mas não é a assinatura de injeção
		{PID: 10, Comm: "app", Exe: "/usr/bin/app",
			MapsRWX: []string{"rwxp /usr/lib/libfoo.so"}},
		// rwx ANÔNIMO: código que nunca existiu em disco
		{PID: 11, Comm: "app2", Exe: "/usr/bin/app2",
			MapsRWX: []string{"rwxp (anônimo)"}},
	}}
	r := mapsRWXAnon.Run(mapsRWXAnon, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %d, quer 1 (só o anônimo)", len(r.Findings))
	}
	if r.Findings[0].Subject != "pid=11" {
		t.Errorf("achado em %s, quer pid=11", r.Findings[0].Subject)
	}
	if !r.Findings[0].Irreversible {
		t.Error("o código só existe nessa memória: matar destrói a única cópia")
	}
}

// Runtime com JIT usa rwx anônimo por projeto. Sem o descarte, todo host com
// Java ou Node vira uma parede de avisos — e parede de aviso é como um
// relatório inteiro passa a ser ignorado.
func TestMapsRWXPulaRuntimeComJIT(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 10, Comm: "java", Exe: "/usr/lib/jvm/java-21/bin/java",
			MapsRWX: []string{"rwxp (anônimo)"}},
		{PID: 11, Comm: "node", Exe: "/usr/bin/node", MapsRWX: []string{"rwxp (anônimo)"}},
	}}
	if r := mapsRWXAnon.Run(mapsRWXAnon, f, testEnv()); len(r.Findings) != 0 {
		t.Errorf("disparou em runtime com JIT: %v", r.Findings[0].Evidence)
	}
}

// A isenção é do BINÁRIO, não do nome: um "node" em /tmp não herda a reputação
// do node do sistema.
func TestMapsRWXNaoIsentaJITForaDeDiretorioDeSistema(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 10, Comm: "node", Exe: "/tmp/node", MapsRWX: []string{"rwxp (anônimo)"}},
	}}
	if r := mapsRWXAnon.Run(mapsRWXAnon, f, testEnv()); len(r.Findings) != 1 {
		t.Error("nome de runtime conhecido não pode isentar binário rodando de /tmp")
	}
}

func TestMapsIlegivelViraCoberturaParcial(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 10, MapsDenied: true},
		{PID: 11, MapsDenied: true},
	}}
	r := mapsRWXAnon.Run(mapsRWXAnon, f, testEnv())
	if len(r.Partial) == 0 {
		t.Fatal("maps ilegível precisa virar cobertura parcial")
	}
	if !strings.Contains(r.Partial[0], "2") {
		t.Errorf("a contagem precisa aparecer: %q", r.Partial[0])
	}
}

// --- proc.ns_divergent ---

func nsProc(pid int, cgroup string, ns map[string]string) facts.Process {
	return facts.Process{PID: pid, Comm: "x", Exe: "/usr/bin/x", Cgroup: cgroup, NS: ns}
}

var nsInit = map[string]string{
	"mnt": "mnt:[4026531840]", "net": "net:[4026531992]",
	"pid": "pid:[4026531836]", "user": "user:[4026531837]",
}

func nsOutro(kind, inode string) map[string]string {
	out := map[string]string{}
	for k, v := range nsInit {
		out[k] = v
	}
	out[kind] = inode
	return out
}

// Sem a linha de base do PID 1 não existe divergência a medir. Reportar
// "nenhum namespace divergente" sem tê-la lido seria inventar.
func TestNSSemLinhaDeBaseViraParcial(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		nsProc(500, "/user.slice/session-2.scope", nsOutro("mnt", "mnt:[4026999]")),
	}}
	r := nsDivergent.Run(nsDivergent, f, testEnv())
	if len(r.Findings) != 0 {
		t.Error("sem PID 1 não dá para afirmar divergência")
	}
	if len(r.Partial) == 0 {
		t.Error("e o silêncio precisa ser declarado como cobertura parcial")
	}
}

func TestNSDisparaForaDeUnitEDeContainer(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 1, Comm: "systemd", NS: nsInit},
		nsProc(500, "/user.slice/user-1000.slice/session-2.scope",
			nsOutro("net", "net:[4026532999]")),
	}}
	r := nsDivergent.Run(nsDivergent, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %d, quer 1", len(r.Findings))
	}
	ev := strings.Join(r.Findings[0].Evidence, " ")
	if !strings.Contains(ev, "net:[4026532999]") {
		t.Errorf("a evidência precisa do inode do namespace: %s", ev)
	}
	// O achado só serve se disser COMO olhar: o `find` da §8 e o `ss` da §2
	// rodam no namespace errado.
	if !strings.Contains(strings.Join(r.Findings[0].NextSteps, " "), "nsenter -t 500") {
		t.Errorf("o próximo passo precisa ser o nsenter no PID certo: %v", r.Findings[0].NextSteps)
	}
}

// Os dois descartes que decidem se o check é usável. Em desktop real, sem eles,
// eram 36 achados; com eles, 8 — todos sandbox de navegador, que é FP declarado.
func TestNSDescartaContainerEUnit(t *testing.T) {
	casos := map[string]string{
		"container docker":  "/system.slice/docker-abc123.scope",
		"kubepods":          "/kubepods/besteffort/pod123/abc",
		"unit simples":      "/system.slice/polkit.service",
		"unit com subgrupo": "/system.slice/systemd-udevd.service/udev",
	}
	for nome, cg := range casos {
		f := &facts.Facts{Processes: []facts.Process{
			{PID: 1, Comm: "systemd", NS: nsInit},
			nsProc(500, cg, nsOutro("mnt", "mnt:[4026999]")),
		}}
		if r := nsDivergent.Run(nsDivergent, f, testEnv()); len(r.Findings) != 0 {
			t.Errorf("%s (%s): namespace próprio aqui é configuração, não anomalia", nome, cg)
		}
	}
}

func TestNSNaoDisparaSemDivergencia(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 1, Comm: "systemd", NS: nsInit},
		nsProc(500, "/user.slice/session-2.scope", nsInit),
	}}
	if r := nsDivergent.Run(nsDivergent, f, testEnv()); len(r.Findings) != 0 {
		t.Error("mesmo namespace do PID 1 é o estado normal")
	}
}

func TestNSIlegivelViraCoberturaParcial(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 1, Comm: "systemd", NS: nsInit},
		{PID: 500, NSDenied: true},
		{PID: 501, NSDenied: true},
	}}
	r := nsDivergent.Run(nsDivergent, f, testEnv())
	if len(r.Partial) == 0 || !strings.Contains(r.Partial[0], "2") {
		t.Errorf("ns ilegível precisa virar cobertura parcial com contagem: %v", r.Partial)
	}
}
