//go:build scenarios

// Suíte de cenários. Roda a CLI de verdade, contra /proc de verdade, em
// distribuições de verdade — e afirma o que ela precisa DIZER.
//
//	make scenarios
//
// Fica atrás da tag `scenarios` porque exige docker e leva dezenas de segundos:
// `go test ./...` continua sendo rápido e sem dependência externa.
package test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lex0c/aletheia/internal/check"
	_ "github.com/lex0c/aletheia/internal/checks"
	"github.com/lex0c/aletheia/test/scenario"
)

const (
	binPath   = "../dist/aletheia"
	runFor    = 3 * time.Minute
	imageWait = 5 * time.Minute
)

// line é uma linha do JSONL. O contrato de asserção é o mesmo que a agregação
// de frota consome — testar por ele garante que o que a suíte valida é o que o
// operador realmente recebe.
type line struct {
	ID            string   `json:"id"`
	Ref           string   `json:"ref"`
	Sev           string   `json:"sev"`
	Subject       string   `json:"subject"`
	Evidence      []string `json:"evidence"`
	Total         int      `json:"total"`
	Complete      int      `json:"complete"`
	Verdict       string   `json:"verdict"`
	Exit          int      `json:"exit"`
	CollectorGaps []string `json:"collector_gaps"`
}

type result struct {
	findings []line
	coverage line
	exit     int
	stderr   string
}

func (r result) has(e scenario.Expect) bool {
	for _, f := range r.findings {
		if f.ID != e.ID {
			continue
		}
		if e.Sev != "" && f.Sev != e.Sev {
			continue
		}
		if e.Subject != "" && !strings.Contains(f.Subject, e.Subject) {
			continue
		}
		if e.Evidence != "" && !strings.Contains(strings.Join(f.Evidence, "\n"), e.Evidence) {
			continue
		}
		return true
	}
	return false
}

func (r result) ids() []string {
	var out []string
	for _, f := range r.findings {
		out = append(out, f.ID+"/"+f.Sev)
	}
	return out
}

func TestMain(m *testing.M) {
	if _, err := os.Stat(binPath); err != nil {
		println("dist/aletheia não existe — rode `make build` antes de `make scenarios`")
		os.Exit(3)
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		println("docker indisponível: a suíte de cenários exige um runtime de contêiner")
		os.Exit(3)
	}
	os.Exit(m.Run())
}

func TestCenarios(t *testing.T) {
	bin, err := filepath.Abs(binPath)
	if err != nil {
		t.Fatal(err)
	}

	for _, sc := range scenario.All() {
		if sc.Untestable != "" {
			t.Run(sc.ID, func(t *testing.T) {
				// Não é pulo silencioso: o motivo é o valor. Ele documenta o
				// limite do contêiner e o que exigiria VM.
				t.Skipf("fora do alcance do contêiner — %s", sc.Untestable)
			})
			continue
		}
		if sc.Mode == scenario.VM {
			t.Run(sc.ID+"/vm", func(t *testing.T) {
				t.Parallel()
				assertScenario(t, sc, runVM(t, sc))
			})
			continue
		}
		for _, img := range sc.Images {
			t.Run(sc.ID+"/"+sanitizeName(img), func(t *testing.T) {
				t.Parallel()
				var r result
				if sc.Mode == scenario.Image {
					r = runImage(t, bin, img, sc)
				} else {
					r = runLive(t, bin, img, sc)
				}
				assertScenario(t, sc, r)
			})
		}
	}
}

func assertScenario(t *testing.T, sc scenario.Scenario, r result) {
	t.Helper()

	for _, e := range sc.Expect {
		if !r.has(e) {
			t.Errorf("cenário %q: esperava %s/%s%s e não veio.\nachados: %v\nstderr:\n%s",
				sc.Desc, e.ID, e.Sev, evidenceHint(e), r.ids(), r.stderr)
		}
	}
	for _, id := range sc.Forbid {
		for _, f := range r.findings {
			if f.ID == id {
				t.Errorf("cenário %q: %s NÃO podia disparar (subject=%s)\nstderr:\n%s",
					sc.Desc, id, f.Subject, r.stderr)
			}
		}
	}
	if sc.Exit >= 0 && r.exit != sc.Exit {
		t.Errorf("exit = %d, quer %d — o exit code é o que a automação de frota lê\nstderr:\n%s",
			r.exit, sc.Exit, r.stderr)
	}

	// Os dois invariantes de cobertura. São o motivo de a ferramenta existir:
	// "não achei" nunca pode ser impresso igual a "não consegui olhar".
	if sc.MustBeIncomplete {
		if r.coverage.Verdict == "OK" {
			t.Errorf("veredito OK numa execução degradada — é exatamente a mentira " +
				"que a ferramenta existe para não cometer")
		}
		if r.coverage.Complete >= r.coverage.Total && len(r.coverage.CollectorGaps) == 0 {
			t.Errorf("cobertura %d/%d sem lacuna de coleta declarada",
				r.coverage.Complete, r.coverage.Total)
		}
	}
	if sc.MustBeComplete {
		if r.coverage.Complete != r.coverage.Total {
			t.Errorf("cobertura %d/%d: esperava completa neste cenário",
				r.coverage.Complete, r.coverage.Total)
		}
	}

	// A linha de cobertura é obrigatória em TODA execução: sem ela, a agregação
	// de frota mostra "host sem achados" escondendo que metade não rodou.
	if r.coverage.ID != "coverage" {
		t.Error("JSONL sem linha de cobertura")
	}
}

// runLive roda a CLI DENTRO do contêiner, vendo o /proc dele.
func runLive(t *testing.T, bin, img string, sc scenario.Scenario) result {
	t.Helper()

	script := sc.Plant + "\n/aletheia " + cmdOf(sc) + " --json -"
	if len(sc.Args) > 0 {
		script += " " + strings.Join(sc.Args, " ")
	}

	helper, err := filepath.Abs("../dist/helper")
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"run", "--rm",
		"-v", binFor(t, bin, sc) + ":/aletheia:ro",
		"-v", helper + ":/helper:ro"}
	if sc.NoNetwork {
		args = append(args, "--network=none")
	}
	for _, c := range sc.Caps {
		args = append(args, "--cap-add="+c)
	}
	if sc.User != "" {
		args = append(args, "-u", sc.User)
	}
	args = append(args, img, "sh", "-c", script)
	return dockerRun(t, args)
}

// runImage exporta o rootfs do contêiner e o varre DE FORA com --root — que é
// como se analisa um snapshot montado (runbook §35.6).
func runImage(t *testing.T, bin, img string, sc scenario.Scenario) result {
	t.Helper()
	dir := t.TempDir()

	name := "aletheia-scn-" + sanitizeName(sc.ID+"-"+img)
	_ = exec.Command("docker", "rm", "-f", name).Run()

	helper, err := filepath.Abs("../dist/helper")
	if err != nil {
		t.Fatal(err)
	}
	plant := sc.Plant
	if plant == "" {
		plant = "true"
	}
	if out, err := exec.Command("docker", "run", "--name", name,
		"-v", helper+":/helper:ro", img, "sh", "-c", plant).CombinedOutput(); err != nil {
		t.Fatalf("plantio falhou: %v\n%s", err, out)
	}
	defer exec.Command("docker", "rm", "-f", name).Run()

	// docker export | tar -x : o rootfs vira um diretório comum, exatamente
	// como um snapshot montado.
	rootfs := filepath.Join(dir, "rootfs")
	if err := os.MkdirAll(rootfs, 0o755); err != nil {
		t.Fatal(err)
	}
	exp := exec.Command("sh", "-c",
		"docker export "+name+" | tar -x -C "+rootfs+" 2>/dev/null || true")
	if out, err := exp.CombinedOutput(); err != nil {
		t.Fatalf("export falhou: %v\n%s", err, out)
	}

	args := append([]string{cmdOf(sc), "--root", rootfs, "--json", "-"}, sc.Args...)
	return localRun(t, bin, args)
}

// runVM sobe uma microVM com KERNEL PRÓPRIO. É o que contêiner não alcança:
// hidepid, ptrace_scope, sysctl, módulo, cgroup — tudo isso é do kernel, e
// contêiner usa o do host.
//
// Sem rede, sem disco compartilhado, sem SSH. O cenário entra pela linha de
// comando do kernel (base64, para aguentar aspas e espaço) e o resultado sai
// pelo console serial. Boot em ~0,5s: initramfs, sem bootloader e sem qcow2.
func runVM(t *testing.T, sc scenario.Scenario) result {
	t.Helper()

	// Arquitetura é um AMBIENTE inteiro, não só um binário: emulador, kernel e
	// initramfs precisam combinar. i686 legado tem kernel sem registrador de 64
	// bits formatando os campos de 64 bits do /proc.
	qemu, suffix := "qemu-system-x86_64", ""
	if sc.Arch == "386" {
		qemu, suffix = "qemu-system-i386", "-386"
	}
	if _, err := exec.LookPath(qemu); err != nil {
		t.Skipf("%s ausente: %v", qemu, err)
	}

	initramfs, err := filepath.Abs("../dist/vm/initramfs" + suffix + ".gz")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(initramfs); err != nil {
		t.Skipf("initramfs%s ausente — rode `make vm-image`: %v", suffix, err)
	}
	kernel := kernelFor(t, sc)

	logf := filepath.Join(t.TempDir(), "serial.log")
	appendArgs := "console=ttyS0 panic=1 loglevel=3" +
		" aletheia.setup=" + base64.StdEncoding.EncodeToString([]byte(sc.Setup))
	if sc.User != "" {
		appendArgs += " aletheia.user=" + sc.User
	}
	if len(sc.Args) > 0 {
		appendArgs += " aletheia.args=" + strings.Join(sc.Args, ",")
	}

	cmd := exec.Command(qemu,
		"-enable-kvm", "-no-reboot", "-m", "512", "-display", "none",
		// -nic none é obrigatório, não cosmético: sem ele o QEMU x86 acrescenta
		// uma placa de rede em modo usuário POR PADRÃO, e o guest sai com acesso
		// à internet através do host. O comentário que promete "sem rede"
		// precisa ser verdade — um cenário de resposta a incidente não pode dar
		// saída de rede a implante de teste nenhum.
		"-nic", "none",
		"-kernel", kernel, "-initrd", initramfs,
		"-append", appendArgs,
		"-serial", "file:"+logf)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("qemu falhou: %v\n%s", err, out)
	}

	raw, err := os.ReadFile(logf)
	if err != nil {
		t.Fatalf("console serial ilegível: %v", err)
	}
	return parseSerial(t, string(raw))
}

// kernelFor resolve o kernel do guest. Pular por ausência é aceitável; pular em
// SILÊNCIO não é — a mensagem diz exatamente o que rodar.
func kernelFor(t *testing.T, sc scenario.Scenario) string {
	t.Helper()
	if sc.Kernel == "" {
		return hostKernel(t)
	}
	name := sc.Kernel
	if sc.Arch == "386" {
		name += "-386"
	}
	p, err := filepath.Abs("../dist/vm/kernels/vmlinuz-" + name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Skipf("kernel %s ausente — rode `make vm-kernels` (exige rede): %v", name, err)
	}
	return p
}

// hostKernel usa o kernel do HOST. Ele cobre tudo que é opção de mount, sysctl,
// módulo e cgroup. O que ele NÃO cobre é o FORMATO antigo de procfs (2.6.32),
// que exigiria buscar um kernel de época — cenário à parte, e só quando houver
// check que dependa disso.
func hostKernel(t *testing.T) string {
	t.Helper()
	matches, _ := filepath.Glob("/boot/vmlinuz*")
	for _, m := range matches {
		if fi, err := os.Stat(m); err == nil && fi.Mode().IsRegular() {
			return m
		}
	}
	t.Skip("nenhum kernel em /boot/vmlinuz* — cenários de VM exigem um")
	return ""
}

// parseSerial extrai o JSONL do console. Os marcadores existem porque o kernel
// também escreve ali: sem delimitar, mensagem de driver entraria no parse.
func parseSerial(t *testing.T, out string) result {
	t.Helper()
	var r result
	var inJSON, inHuman bool
	var human strings.Builder

	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimRight(ln, "\r")
		switch {
		case strings.Contains(ln, "---ALETHEIA-BEGIN---"):
			inJSON = true
			continue
		case strings.Contains(ln, "---ALETHEIA-EXIT="):
			inJSON = false
			fmt.Sscanf(strings.TrimSpace(ln), "---ALETHEIA-EXIT=%d---", &r.exit)
			continue
		case strings.Contains(ln, "---HUMAN-BEGIN---"):
			inHuman = true
			continue
		case strings.Contains(ln, "---HUMAN-END---"):
			inHuman = false
			continue
		case strings.Contains(ln, "SETUP-FALHOU"):
			t.Fatalf("o setup do cenário falhou dentro do guest: %s", ln)
		}
		if inHuman {
			human.WriteString(ln + "\n")
			continue
		}
		if !inJSON || !strings.HasPrefix(strings.TrimSpace(ln), "{") {
			continue
		}
		var l line
		if err := json.Unmarshal([]byte(strings.TrimSpace(ln)), &l); err != nil {
			t.Fatalf("JSONL inválido vindo do guest: %v\nlinha: %q", err, ln)
		}
		if l.ID == "coverage" {
			r.coverage = l
		} else {
			r.findings = append(r.findings, l)
		}
	}
	r.stderr = human.String()
	return r
}

func evidenceHint(e scenario.Expect) string {
	if e.Evidence == "" {
		return ""
	}
	return " com evidência contendo " + strconv.Quote(e.Evidence)
}

// binFor escolhe o binário. Outra arquitetura é outro artefato, e um servidor
// legado de 32 bits é onde tamanho de int e número de syscall divergem.
func binFor(t *testing.T, bin string, sc scenario.Scenario) string {
	t.Helper()
	if sc.Arch == "" {
		return bin
	}
	p, err := filepath.Abs("../dist/aletheia-" + sc.Arch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Skipf("binário %s ausente — rode `make arches`: %v", sc.Arch, err)
	}
	return p
}

func cmdOf(sc scenario.Scenario) string {
	if sc.Cmd != "" {
		return sc.Cmd
	}
	return "scan"
}

func dockerRun(t *testing.T, args []string) result {
	t.Helper()
	return capture(t, exec.Command("docker", args...))
}

func localRun(t *testing.T, bin string, args []string) result {
	t.Helper()
	return capture(t, exec.Command(bin, args...))
}

func capture(t *testing.T, cmd *exec.Cmd) result {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	r := result{stderr: stderr.String()}
	if ee, ok := err.(*exec.ExitError); ok {
		r.exit = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("execução falhou: %v\nstderr:\n%s", err, r.stderr)
	}

	// stdout é JSONL puro: o relatório humano vai para stderr quando --json -.
	for _, ln := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
		if ln == "" {
			continue
		}
		var l line
		if err := json.Unmarshal([]byte(ln), &l); err != nil {
			t.Fatalf("stdout não é JSONL válido: %v\nlinha: %q", err, ln)
		}
		if l.ID == "coverage" {
			r.coverage = l
		} else {
			r.findings = append(r.findings, l)
		}
	}
	return r
}

// TestTodoCheckTemCenario fecha o ciclo: do mesmo jeito que Register recusa
// check sem FalsePositives, aqui se recusa check que ninguém provou disparar.
// Sem isto, dá para acrescentar um check e nunca demonstrar que ele funciona.
func TestTodoCheckTemCenario(t *testing.T) {
	coberto := scenario.CoveredCheckIDs()
	for _, c := range check.All() {
		if c.Mode == check.ModeManual {
			continue
		}
		if !coberto[c.ID] {
			t.Errorf("%s não aparece no Expect de nenhum cenário: ninguém demonstrou "+
				"que ele dispara contra um host real", c.ID)
		}
	}
}

// O binário estático é a propriedade que justificou escolher Go (SPEC 4).
// `file` diz que ele é estático; rodar em `scratch` — sem libc, sem shell, sem
// nada — PROVA.
func TestBinarioRodaEmScratch(t *testing.T) {
	bin, err := filepath.Abs(binPath)
	if err != nil {
		t.Fatal(err)
	}
	// `docker run scratch` não existe: scratch é nome reservado. Constrói-se
	// uma imagem cujo conteúdo é APENAS o binário — sem libc, sem shell, sem
	// coreutils. Se ele roda ali, a propriedade está provada em runtime, não
	// por inspeção do ELF.
	dir := t.TempDir()
	if err := copyFile(bin, filepath.Join(dir, "aletheia")); err != nil {
		t.Fatal(err)
	}
	df := "FROM scratch\nCOPY aletheia /aletheia\nENTRYPOINT [\"/aletheia\"]\n"
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(df), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("docker", "build", "-q", "-t", "aletheia-scratch:test", dir).CombinedOutput(); err != nil {
		t.Fatalf("build da imagem scratch falhou: %v\n%s", err, out)
	}
	defer exec.Command("docker", "rmi", "-f", "aletheia-scratch:test").Run()

	out, err := exec.Command("docker", "run", "--rm", "aletheia-scratch:test", "version").CombinedOutput()
	if err != nil {
		t.Fatalf("o binário NÃO roda em imagem vazia: a imunidade a userland "+
			"comprometido depende exatamente disso (SPEC 4).\n%v\n%s", err, out)
	}
	if !strings.Contains(string(out), "sha256=") {
		t.Errorf("saída inesperada em scratch: %s", out)
	}
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o755)
}

func sanitizeName(s string) string {
	r := strings.NewReplacer(":", "-", "/", "-", ".", "-")
	return r.Replace(s)
}
