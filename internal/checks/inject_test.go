package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
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

// Achado do guest de kernel 4.14: kdevtmpfs é thread de KERNEL e tem mount
// namespace próprio por design, em todo kernel. Disparar nela é acusar o
// kernel de esconder algo de si mesmo.
func TestNSNaoDisparaEmThreadDeKernel(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 1, Comm: "systemd", NS: nsInit},
		// Thread de kernel de verdade: CmdlineEmpty é FALSE nela, porque o
		// coletor só marca esse campo em processo que tem exe. Quem responde
		// aqui é o ExeMissing.
		{PID: 13, Comm: "kdevtmpfs", ExeErr: "não existe", ExeMissing: true,
			NS: nsOutro("mnt", "mnt:[4026531861]")},
	}}
	if r := nsDivergent.Run(nsDivergent, f, testEnv()); len(r.Findings) != 0 {
		t.Errorf("disparou em thread de kernel: %v", r.Findings[0].Evidence)
	}
}

// Mas "exe ilegível" NÃO é "exe inexistente": sem root, todo processo alheio
// parece thread de kernel, e a isenção apagaria o check inteiro em silêncio.
func TestNSNaoConfundeExeIlegivelComThreadDeKernel(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 1, Comm: "systemd", NS: nsInit},
		{PID: 500, Comm: "x", CmdlineEmpty: true, ExeErr: "sem permissão", ExeDenied: true,
			NS: nsOutro("net", "net:[4026532999]")},
	}}
	if r := nsDivergent.Run(nsDivergent, f, testEnv()); len(r.Findings) != 1 {
		t.Error("exe ilegível por permissão não é thread de kernel")
	}
}

// --- proc.maps_exec_anon ---

// A razão de o check existir: a região que passou pelo mprotect não é mais
// gravável, e o check irmão exige o 'w'. Se este também exigisse, os dois
// olhariam para a mesma metade.
func TestExecAnonDisparaSemGravavel(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 10, Comm: "app", Exe: "/usr/bin/app",
			MapsExecAnon: []string{"7f00-7f01 r-xp"}, MapsExecAnonN: 1},
		{PID: 11, Comm: "limpo", Exe: "/usr/bin/limpo"},
	}}
	r := mapsExecAnon.Run(mapsExecAnon, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Subject != "pid=10" {
		t.Fatalf("achados = %+v, quer só pid=10", r.Findings)
	}
	if !r.Findings[0].Irreversible {
		t.Error("o código só existe nessa memória: matar destrói a única cópia")
	}
}

// O runtime com JIT de kernel antigo não rotula região nenhuma, e o que ele
// gera é indistinguível de injeção. Sem a isenção, todo host com node vira
// parede de avisos — medido: um node ocioso tem 1 região r-x anônima.
func TestExecAnonPulaJITSemRotulo(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 10, Comm: "node", Exe: "/usr/bin/node",
			MapsExecAnon: []string{"7f00-7f01 r-xp"}, MapsExecAnonN: 1},
	}}
	r := mapsExecAnon.Run(mapsExecAnon, f, testEnv())
	if len(r.Findings) != 0 {
		t.Fatalf("achados = %+v, quer 0", r.Findings)
	}
	// Decisão de NÃO OLHAR se declara: supressão silenciosa é a cobertura
	// completa que esconde um ponto cego.
	if len(r.Partial) == 0 {
		t.Error("a isenção precisa chegar à cobertura")
	}
}

// O ganho sobre o check irmão, e o BLIND SPOT que ele declara e não cobre: o
// runtime que ROTULA as próprias regiões se autodenuncia como capaz de rotular.
// Nele, uma região sem rótulo não é explicada pelo que ele gera — e injeção
// DENTRO de um Firefox deixa de ser invisível.
func TestExecAnonNaoPulaJITQueRotulaAsProprias(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 10, Comm: "firefox", Exe: "/usr/lib/firefox/firefox",
			MapsExecAnon:  []string{"7f00-7f01 r-xp"},
			MapsExecAnonN: 1,
			MapsExecNomes: []string{"[anon:js-executable-memory]"}},
	}}
	r := mapsExecAnon.Run(mapsExecAnon, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %d, quer 1: este processo rotula o que gera, e esta "+
			"região não tem rótulo", len(r.Findings))
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "ROTULA") {
		t.Errorf("a evidência precisa dizer POR QUE o runtime não explica a região: %v",
			r.Findings[0].Evidence)
	}
}

// A isenção é do binário do PACOTE, não do nome. Um "node" em /tmp não herda a
// reputação do node.
func TestExecAnonNaoIsentaJITForaDeDiretorioDeSistema(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 10, Comm: "node", Exe: "/tmp/node",
			MapsExecAnon: []string{"7f00-7f01 r-xp"}, MapsExecAnonN: 1},
	}}
	if r := mapsExecAnon.Run(mapsExecAnon, f, testEnv()); len(r.Findings) != 1 {
		t.Fatalf("achados = %d, quer 1", len(r.Findings))
	}
}

// A correlação melhora a LEITURA, não a acusação (engine.go). Promover por
// conjunção aqui quebraria o exit code de toda frota que roda depurador — e
// tornaria este check mais grave que o irmão, que vê um sinal MAIS forte.
func TestExecAnonNaoPromovePorCorrelacao(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 10, Comm: "app", Exe: "/usr/bin/app", TracerPID: 999, ExeMemfd: true,
			MapsExecAnon: []string{"7f00-7f01 r-xp"}, MapsExecAnonN: 1},
	}}
	r := mapsExecAnon.Run(mapsExecAnon, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %d, quer 1", len(r.Findings))
	}
	if r.Findings[0].Sev != check.SevWarn {
		t.Errorf("severidade = %v, quer WARN", r.Findings[0].Sev)
	}
	ev := strings.Join(r.Findings[0].Evidence, " ")
	if !strings.Contains(ev, "ptrace") || !strings.Contains(ev, "memfd") {
		t.Errorf("as correlações são EVIDÊNCIA e precisam aparecer: %v", r.Findings[0].Evidence)
	}
}

// O teto da amostra não pode virar mentira de contagem.
func TestExecAnonRelataTotalQuandoAAmostraFoiCortada(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 10, Comm: "app", Exe: "/usr/bin/app",
			MapsExecAnon: []string{"7f00-7f01 r-xp"}, MapsExecAnonN: 900},
	}}
	r := mapsExecAnon.Run(mapsExecAnon, f, testEnv())
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "900") {
		t.Errorf("o total precisa aparecer: %v", r.Findings[0].Evidence)
	}
}

// --- proc.deleted_mapping ---

// Não existe atualização de pacote que entregue biblioteca em /tmp: ali a
// história legítima acabou.
func TestApagadoEmDiretorioGravavelECritico(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 10, Comm: "app", Exe: "/usr/bin/app", MapsApagados: []facts.MapaApagado{
			{Caminho: "/tmp/.x.so", Perms: "r-xp", Verificado: true},
		}},
	}}
	r := mapeamentoApagado.Run(mapeamentoApagado, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("achados = %+v, quer 1 CRITICAL", r.Findings)
	}
}

// Fora de diretório gravável, o mesmo fato tem uma história legítima —
// desinstalação com o serviço no ar — e vale um aviso, não uma acusação.
func TestApagadoForaDeDiretorioGravavelEAviso(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 10, Comm: "app", Exe: "/usr/bin/app", MapsApagados: []facts.MapaApagado{
			{Caminho: "/usr/lib/libfoo.so", Perms: "r-xp", Verificado: true},
		}},
	}}
	r := mapeamentoApagado.Run(mapeamentoApagado, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevWarn {
		t.Fatalf("achados = %+v, quer 1 WARN", r.Findings)
	}
}

// O caso comum de servidor: o caminho VOLTOU a existir porque o pacote foi
// atualizado. Um aviso por processo seria uma parede de centenas — e a parede
// enterraria os poucos que importam.
func TestApagadoRecriadoViraUmaLinhaInformativa(t *testing.T) {
	var ps []facts.Process
	for i := 0; i < 3; i++ {
		ps = append(ps, facts.Process{PID: 10 + i, Comm: "app", Exe: "/usr/bin/app",
			MapsApagados: []facts.MapaApagado{
				{Caminho: "/usr/lib/libc.so.6", Perms: "r-xp", Verificado: true, Recriado: true},
			}})
	}
	r := mapeamentoApagado.Run(mapeamentoApagado, &facts.Facts{Processes: ps}, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %d, quer 1 agregado para os 3 processos", len(r.Findings))
	}
	if r.Findings[0].Sev != check.SevInfo {
		t.Errorf("severidade = %v, quer INFO: reinício pendente não é incidente, e "+
			"não pode mexer no exit code de uma frota inteira", r.Findings[0].Sev)
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "3 mapeamento") {
		t.Errorf("a contagem precisa aparecer: %v", r.Findings[0].Evidence)
	}
}

// Sem o Verificado, "não perguntei" viraria "o arquivo sumiu" — e o achado
// afirmaria o que ninguém checou.
func TestApagadoSemVerificacaoDizQueNaoVerificou(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 10, Comm: "app", Exe: "/usr/bin/app", MapsApagados: []facts.MapaApagado{
			{Caminho: "/usr/lib/libfoo.so", Perms: "r-xp"},
		}},
	}}
	r := mapeamentoApagado.Run(mapeamentoApagado, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %d, quer 1", len(r.Findings))
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "não foi possível verificar") {
		t.Errorf("a evidência precisa declarar a dúvida: %v", r.Findings[0].Evidence)
	}
}

// Carregar código de memfd é operação normal de runtime com JIT; num processo
// que não é um, é código que nunca esteve em disco.
func TestMemfdMapeadoIsentaJITEAcusaOResto(t *testing.T) {
	m := []facts.MapaApagado{{Caminho: "/memfd:payload", Perms: "r-xp", Memfd: true}}
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 10, Comm: "node", Exe: "/usr/bin/node", MapsApagados: m},
		{PID: 11, Comm: "sshd", Exe: "/usr/sbin/sshd", MapsApagados: m},
	}}
	r := mapeamentoApagado.Run(mapeamentoApagado, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Subject != "pid=11" {
		t.Fatalf("achados = %+v, quer só pid=11", r.Findings)
	}
	if len(r.Partial) == 0 {
		t.Error("a isenção do JIT precisa chegar à cobertura")
	}
}

// O aperto que a matriz adversarial pediu: com a base de pacotes disponível, a
// isenção de JIT exige DONO DE PACOTE. Um payload copiado para /usr/bin/node
// casa nome e diretório mas não o dono, e deixa de sumir do check.
func TestJITExigeDonoDePacoteComBaseDisponivel(t *testing.T) {
	e := testEnv()
	e.Caps |= env.CapPkgDB

	// node de PACOTE: continua isento — sem isso, todo host com node vira parede.
	owned := &facts.Facts{
		Processes: []facts.Process{{PID: 10, Comm: "node", Exe: "/usr/bin/node",
			MapsRWX: []string{"rwxp (anônimo)"}}},
		Ownership: []facts.Ownership{{Path: "/usr/bin/node", Owned: true}},
	}
	if r := mapsRWXAnon.Run(mapsRWXAnon, owned, e); len(r.Findings) != 0 {
		t.Errorf("node de pacote tem de continuar isento: %v", r.Findings)
	}

	// payload rodando como /usr/bin/node, SEM dono: o bypass, agora fechado.
	fake := &facts.Facts{
		Processes: []facts.Process{{PID: 11, Comm: "node", Exe: "/usr/bin/node",
			MapsRWX: []string{"rwxp (anônimo)"}}},
		Ownership: []facts.Ownership{{Path: "/usr/bin/node", Owned: false}},
	}
	if r := mapsRWXAnon.Run(mapsRWXAnon, fake, e); len(r.Findings) != 1 {
		t.Fatalf("payload como /usr/bin/node SEM dono tem de disparar: %d achados", len(r.Findings))
	}
}

// O mesmo para o maps_exec_anon — foi ele que a matriz pegou.
func TestExecAnonJITFakeSemDonoDispara(t *testing.T) {
	e := testEnv()
	e.Caps |= env.CapPkgDB
	fake := &facts.Facts{
		Processes: []facts.Process{{PID: 11, Comm: "node", Exe: "/usr/bin/node",
			MapsExecAnon: []string{"7f00-7f01 r-xp"}, MapsExecAnonN: 1}},
		Ownership: []facts.Ownership{{Path: "/usr/bin/node", Owned: false}},
	}
	if r := mapsExecAnon.Run(mapsExecAnon, fake, e); len(r.Findings) != 1 {
		t.Fatalf("payload como /usr/bin/node sem dono tem de disparar: %d", len(r.Findings))
	}
}

// Sem a base de pacotes NÃO dá para distinguir node de payload, e a isenção
// continua — errar para "isenta" evita FP em JIT onde não se pode saber.
func TestJITSemBaseDePacotesMantemIsencao(t *testing.T) {
	e := testEnv() // sem CapPkgDB
	f := &facts.Facts{
		Processes: []facts.Process{{PID: 11, Comm: "node", Exe: "/usr/bin/node",
			MapsRWX: []string{"rwxp (anônimo)"}}},
		Ownership: []facts.Ownership{{Path: "/usr/bin/node", Owned: false}},
	}
	if r := mapsRWXAnon.Run(mapsRWXAnon, f, e); len(r.Findings) != 0 {
		t.Errorf("sem base de pacotes, a isenção continua: %v", r.Findings)
	}
}
