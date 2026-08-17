package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

// O FALSO POSITIVO QUE ORIGINOU ESTE CHECK, medido antes de escrever qualquer
// código: num Debian, um binário sob /var/lib/docker/overlay2/…/usr/sbin/nginx
// saía como "nenhum pacote reivindica". Num servidor com trinta contêineres
// isso são trinta avisos, e contêiner é a norma em produção.
//
// A base de pacotes do host está CERTA em não reivindicar — ela nunca entregou
// aquilo. A pergunta é que estava errada.

const overlayNginx = "/var/lib/docker/overlay2/9f3c1a2b4d5e/diff/usr/sbin/nginx"

func procDeContainer(pid int, exe string) facts.Process {
	return facts.Process{
		PID: pid, Exe: exe, Comm: "nginx",
		Cgroup:      "/system.slice/docker-2549dd25988f0f64c491475e481d0cd12b4b9399c7be55d24e3b670a6f235ced.scope",
		Container:   "docker",
		ContainerID: "2549dd25988f",
	}
}

func rodaFronteira(t *testing.T, f *facts.Facts) *check.Report {
	t.Helper()
	f.Index()
	return check.Run([]check.Check{fronteiraDeContainer}, f, testEnv())
}

// O normal: cgroup de contêiner + exe em camada de imagem. Não pode virar
// aviso, e o que sai é INVENTÁRIO — que dá tamanho ao que ficou de fora da
// pergunta de propriedade.
func TestContainerNormalNaoViraAviso(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		procDeContainer(101, overlayNginx),
		procDeContainer(102, overlayNginx),
	}}
	r := rodaFronteira(t, f)
	for _, fd := range r.Findings {
		if fd.Sev > check.SevInfo {
			t.Errorf("processo de contêiner normal virou %v: %s", fd.Sev, fd.Title)
		}
	}
	if len(r.Findings) == 0 {
		t.Fatal("o inventário tem que existir: sem ele, 'cobertura completa' com dois " +
			"binários não perguntados é meia verdade")
	}
	if !temEvidencia(r, "docker=2") {
		t.Errorf("o inventário tem que contar por runtime: %v", evidencias(r))
	}
}

// O CASO FORTE: conteúdo de imagem executado com o cgroup do HOST. Um binário
// só chega àquele caminho dentro de uma imagem; rodá-lo fora dela não tem
// caminho legítimo comum.
func TestConteudoDeImagemExecutadoForaDoContainer(t *testing.T) {
	f := &facts.Facts{Processes: []facts.Process{
		{PID: 200, Exe: overlayNginx, Comm: "nginx",
			Cgroup: "/user.slice/user-1000.slice/session-2.scope"}, // cgroup do HOST
	}}
	r := rodaFronteira(t, f)

	var achou bool
	for _, fd := range r.Findings {
		if fd.Sev == check.SevCritical && fd.Subject == "pid=200" {
			achou = true
		}
	}
	if !achou {
		t.Fatalf("executar conteúdo de imagem fora do contêiner é o achado forte: %v", r.Findings)
	}
	if !temEvidencia(r, "FORA do") {
		t.Errorf("a evidência tem que dizer o que aconteceu: %v", evidencias(r))
	}
}

// O caso fraco é INFORMATIVO, e o motivo está na evidência: volume montado é a
// forma normal de um processo de contêiner rodar binário fora de camada.
func TestProcessoDeContainerForaDeCamadaEhInformativo(t *testing.T) {
	p := procDeContainer(300, "/srv/app/server")
	f := &facts.Facts{Processes: []facts.Process{p}}
	r := rodaFronteira(t, f)
	for _, fd := range r.Findings {
		if fd.Sev > check.SevInfo {
			t.Errorf("volume montado é rotina e virou %v: %s", fd.Sev, fd.Title)
		}
	}
	if !temEvidencia(r, "VOLUME MONTADO") {
		t.Errorf("o falso positivo comum tem que estar na evidência: %v", evidencias(r))
	}
}

// De DENTRO de um contêiner não há fronteira a ver, e a resposta honesta é
// dizer isso em vez de calar.
//
// Mas NÃO é lacuna de cobertura, e a distinção custou uma regressão para ficar
// clara: marcar parcial fazia toda varredura feita dentro de contêiner sair
// incompleta e com exit 1, inclusive a de um contêiner limpo. "Não consegui
// olhar" e "não há o que olhar no escopo desta execução" são coisas diferentes,
// e só a primeira é lacuna.
func TestDeDentroDeContainerDizOEscopoSemInventarLacuna(t *testing.T) {
	f := &facts.Facts{
		Host:      facts.Host{EmContainer: true},
		Processes: []facts.Process{procDeContainer(400, overlayNginx)},
	}
	r := rodaFronteira(t, f)

	// O motor acrescenta um parcial por CapRoot ausente, e esse é dele. O que
	// não pode existir é lacuna vinda DESTE check.
	for _, p := range r.Coverage.Partial {
		for _, m := range p.Reasons {
			if strings.Contains(m, "contêiner") || strings.Contains(m, "fronteira") {
				t.Errorf("o check inventou uma lacuna que não existe: %q", m)
			}
		}
	}
	if len(r.Coverage.NotChecked) != 0 {
		t.Errorf("nada foi impedido de rodar: %v", r.Coverage.NotChecked)
	}
	var disse bool
	for _, fd := range r.Findings {
		if fd.Sev > check.SevInfo {
			t.Errorf("de dentro não há o que AFIRMAR: %v", fd)
		}
		if strings.Contains(strings.Join(fd.Evidence, " "), "não é visível daqui") {
			disse = true
		}
	}
	if !disse {
		t.Error("e o escopo tem que ser dito: silêncio aqui parece host limpo")
	}
}

func TestClassificacaoPorCgroup(t *testing.T) {
	casos := []struct{ cg, rt, id string }{
		{"/system.slice/docker-2549dd25988f0f64c491475e481d0cd12b4b9399c7be55d24e3b670a6f235ced.scope", "docker", "2549dd25988f"},
		{"/docker/abcdef0123456789abcdef", "docker", "abcdef012345"},
		{"/kubepods.slice/kubepods-burstable.slice/cri-containerd-9f3c1a2b4d5e6f70.scope", "kubernetes", "9f3c1a2b4d5e"},
		{"/machine.slice/libpod-1234567890abcdef.scope", "podman", "1234567890ab"},
		{"/lxc/meu-container", "lxc", "meu-container"},
		// host
		{"/user.slice/user-1000.slice/session-2.scope", "", ""},
		{"/system.slice/nginx.service", "", ""},
		{"/", "", ""},
		{"", "", ""},
	}
	for _, c := range casos {
		rt, id := facts.ContainerDoCgroup(c.cg)
		if rt != c.rt {
			t.Errorf("ContainerDoCgroup(%q) runtime = %q, queria %q", c.cg, rt, c.rt)
		}
		if rt != "" && id != c.id {
			t.Errorf("ContainerDoCgroup(%q) id = %q, queria %q", c.cg, id, c.id)
		}
	}
}

func TestCamadaDeImagem(t *testing.T) {
	dentro := []string{
		"/var/lib/docker/overlay2/9f3c/diff/usr/sbin/nginx",
		"/var/lib/containers/storage/overlay/abc/merged/bin/sh",
		"/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/x/fs/bin/sh",
	}
	fora := []string{"/usr/sbin/nginx", "/opt/app/server", "/var/lib/dockerx/y", "/srv/app"}
	for _, p := range dentro {
		if !facts.EmCamadaDeImagem(p) {
			t.Errorf("%q está em camada de imagem", p)
		}
	}
	for _, p := range fora {
		if facts.EmCamadaDeImagem(p) {
			t.Errorf("%q NÃO está em camada de imagem", p)
		}
	}
}

func evidencias(r *check.Report) []string {
	var out []string
	for _, fd := range r.Findings {
		out = append(out, fd.Evidence...)
	}
	return out
}

func temEvidencia(r *check.Report, sub string) bool {
	return strings.Contains(strings.Join(evidencias(r), "\n"), sub)
}
