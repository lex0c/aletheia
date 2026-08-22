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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	ID      string `json:"id"`
	Ref     string `json:"ref"`
	Sev     string `json:"sev"`
	Subject string `json:"subject"`
	// Title e NextSteps entram no contrato pelo mesmo motivo que Evidence já
	// estava: são CONTEÚDO do achado, e o lugar durável deles é o JSONL.
	//
	// Antes, cenário que precisava afirmar um deles usava ExpectOutput sobre o
	// relatório humano — e o relatório mudou de forma (o nível 0 virou decisão
	// compacta, com evidência só no -v). Dezenove asserções quebraram de uma vez
	// sem que nada no produto tivesse regredido: elas testavam a renderização
	// achando que testavam o achado.
	Title     string   `json:"title"`
	Evidence  []string `json:"evidence"`
	NextSteps []string `json:"next_steps"`

	Total    int    `json:"total"`
	Complete int    `json:"complete"`
	Verdict  string `json:"verdict"`
	Exit     int    `json:"exit"`
	// Partial são as lacunas por CHECK; CollectorGaps as do coletor. Um cenário
	// que cobra uma lacuna específica precisa das duas listas — ela pode estar
	// em qualquer uma, e qual das duas é detalhe de implementação do motor.
	Partial []partialJSON `json:"partial"`
	// NotChecked é a terceira forma de lacuna, e esquecê-la deixava o número
	// sem explicação: um check que NÃO RODOU some das duas listas acima e ainda
	// assim derruba a cobertura. Ver "104/106" com uma lacuna listada foi o que
	// denunciou a falta.
	NotChecked    []notCheckedJSON `json:"not_checked"`
	CollectorGaps []string         `json:"collector_gaps"`
}

type partialJSON struct {
	ID      string   `json:"id"`
	Reasons []string `json:"reasons"`
}

type notCheckedJSON struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
	// Escopo separa as DUAS coisas que moram em not_checked, e a distinção é a
	// mesma que o motor faz: lacuna é o que não rodou e devia; escopo é a
	// pergunta que não existe neste host — ela sai do DENOMINADOR e não derruba
	// a cobertura.
	//
	// O harness lia as duas como lacuna, e por muito tempo isso não custou nada
	// porque quase nada era escopo. Deixou de ser verdade quando os checks de
	// drift entraram: sem estado anterior informado eles são escopo puro, e todo
	// cenário de host limpo passou a "ter cinco lacunas" que a cobertura, na
	// mesma execução, contava como 109/109.
	Escopo bool `json:"out_of_scope"`
}

// lacunas devolve TODO motivo de lacuna declarado na execução, venha ele de um
// check ou do coletor.
func (r result) lacunas() []string {
	var out []string
	for _, p := range r.coverage.Partial {
		for _, m := range p.Reasons {
			out = append(out, p.ID+": "+m)
		}
	}
	for _, n := range r.coverage.NotChecked {
		if n.Escopo {
			// Fora de escopo não é lacuna — ver notCheckedJSON.Escopo.
			continue
		}
		out = append(out, n.ID+" NÃO RODOU: "+n.Reason)
	}
	return append(out, r.coverage.CollectorGaps...)
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
		if e.Title != "" && !strings.Contains(f.Title, e.Title) {
			continue
		}
		if e.NextStep != "" && !strings.Contains(strings.Join(f.NextSteps, "\n"), e.NextStep) {
			continue
		}
		return true
	}
	return false
}

// semArtefatoDoRig descarta o achado que a SUÍTE cria, não o cenário.
//
// O helper é montado em /helper e nenhum pacote o reivindica — o que é
// verdade, e o `integrity.no_package_owner` está certo em dizer. Mas isso é
// propriedade do rig, e deixá-lo contar faria todo cenário que usa o helper ter
// de mentir no exit code esperado.
//
// O filtro é DELIBERADAMENTE estreito: um só check, um só caminho. O helper
// copiado para outro lugar — /usr/bin/node no cenário 18,
// /usr/local/sbin/... no 66 — continua sendo avaliado, porque ali o caminho é
// escolha do cenário.
func (r result) semArtefatoDoRig() result {
	out := r
	out.findings = nil
	for _, f := range r.findings {
		if f.ID == "integrity.no_package_owner" && f.Subject == "/helper" {
			continue
		}
		out.findings = append(out.findings, f)
	}
	// O exit code vem do processo e não pode ser recalculado aqui; quando o
	// único achado era o artefato, o cenário declara Exit -1.
	return out
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
				exigeImagemLocal(t, img)
				// O modo MCP tem outro contrato de saída: JSON-RPC no
				// stdout, e a cobertura viajando DENTRO da resposta da tool em
				// vez de como linha própria.
				if sc.Cmd == "mcp" {
					assertMCP(t, sc, runMCP(t, bin, img, sc))
					return
				}
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
	r = r.semArtefatoDoRig()

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
	// ForbidFinding casa por ID+Subject/Sev/Evidence. Num cenário de LACUNA
	// CONHECIDA é a afirmação da ausência: se ela DISPARA, a lacuna fechou, e a
	// mensagem manda promover — é a catraca virando a favor.
	for _, ff := range sc.ForbidFinding {
		if r.has(ff) {
			if sc.KnownGap != "" {
				t.Errorf("cenário %q: a LACUNA CONHECIDA fechou — %s%s agora dispara. "+
					"Promova este ForbidFinding para Expect e remova KnownGap.\nlacuna: %s\nachados: %v",
					sc.Desc, ff.ID, subjectHint(ff), sc.KnownGap, r.ids())
			} else {
				t.Errorf("cenário %q: %s%s NÃO podia disparar\nachados: %v\nstderr:\n%s",
					sc.Desc, ff.ID, subjectHint(ff), r.ids(), r.stderr)
			}
		}
	}
	for _, want := range sc.ExpectOutput {
		if !strings.Contains(r.stderr, want) {
			t.Errorf("cenário %q: o relatório humano não contém %q.\nsaída:\n%s",
				sc.Desc, want, r.stderr)
		}
	}
	// As LACUNAS declaradas são contrato tanto quanto os achados: metade do que
	// esta ferramenta promete é dizer o que NÃO pôde olhar. Conferir isso pelo
	// texto do relatório não servia — o motivo da lacuna só sai com --coverage
	// ou -v, e um cenário sem essas flags cobrava um texto que nunca ia aparecer.
	anotarUsoDeAmbiente(sc, r.lacunas())

	if len(sc.ExpectGap) > 0 {
		lac := strings.Join(r.lacunas(), "\n")
		for _, quer := range sc.ExpectGap {
			if !strings.Contains(lac, quer) {
				t.Errorf("cenário %q: nenhuma lacuna declarada contém %q — a "+
					"ferramenta precisa DIZER o que não pôde olhar.\nlacunas: %v",
					sc.Desc, quer, r.lacunas())
			}
		}
	}

	for _, nao := range sc.ForbidGap {
		for _, l := range r.lacunas() {
			if strings.Contains(l, nao) {
				t.Errorf("cenário %q: havia uma lacuna contendo %q, e o que este "+
					"cenário afirma é o silêncio por CONHECIMENTO, não por cegueira"+
					"\nlacuna: %s", sc.Desc, nao, l)
			}
		}
	}

	for _, nao := range sc.ForbidOutput {
		if strings.Contains(r.stderr, nao) {
			t.Errorf("cenário %q: o relatório humano NÃO podia conter %q — a "+
				"negativa é o que está sendo protegido aqui.\nsaída:\n%s",
				sc.Desc, nao, r.stderr)
		}
	}
	// O orçamento de ruído. Num host legítimo a ferramenta tem coisas
	// verdadeiras a dizer, e cada uma delas gasta a atenção do operador.
	//
	// A contagem sai SEMPRE no log do teste, mesmo sem orçamento declarado: é
	// ela que permite escolher o teto de um cenário novo pela medição, em vez
	// de por opinião. `go test -tags scenarios -v` mostra.
	var avisos int
	var quais []string
	for _, f := range r.findings {
		if f.Sev == "WARN" {
			avisos++
			quais = append(quais, f.ID+"("+f.Subject+")")
		}
	}
	t.Logf("RUÍDO %s: %d aviso(s) %v", sc.ID, avisos, quais)

	if orcamento, declarado := sc.Orcamento(); declarado && avisos > orcamento {
		t.Errorf("cenário %q: %d avisos, orçamento é %d — num host legítimo o "+
			"excesso de ruído faz o operador ignorar a saída, e o achado que "+
			"importa se perde junto\navisos: %v",
			sc.Desc, avisos, orcamento, quais)
	}

	if sc.Exit >= 0 && r.exit != sc.Exit && !exitSoPorAmbiente(sc, r) {
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
		if fora := scenario.FiltraAmbientais(sc, r.lacunas()); len(fora) == 0 {
			// Cobertura completa A MENOS das lacunas que este ambiente impõe. É
			// o contrato que o cenário sempre quis: ele afirma coisas sobre o
			// host que MONTA, não sobre a máquina de quem roda a suíte.
		} else if r.coverage.Complete != r.coverage.Total {
			// As LACUNAS entram na mensagem porque sem elas o número sozinho não
			// diz o que fazer. "103/106" manda o leitor rodar a ferramenta à mão
			// e reproduzir o ambiente para descobrir quais três; a lista responde
			// na hora, e foi o que faltou durante toda uma investigação.
			t.Errorf("cobertura %d/%d: esperava completa neste cenário\nlacunas:\n  %s",
				r.coverage.Complete, r.coverage.Total,
				strings.Join(r.lacunas(), "\n  "))
		}
	}

	// A linha de cobertura é obrigatória em TODA execução: sem ela, a agregação
	// de frota mostra "host sem achados" escondendo que metade não rodou.
	//
	// A exceção é o exit 3, e ela prova a mesma regra pelo outro lado: exit 3 é
	// ERRO DE INVOCAÇÃO — argumento inválido, --root que não abre, lista de
	// indicadores que não trouxe indicador nenhum. Ali não houve varredura, e
	// justamente por isso não pode haver linha de cobertura: uma cobertura
	// impressa sem varredura seria a mentira que ela existe para impedir.
	//
	// O `preserve` é a outra exceção, e pelo mesmo motivo por outro caminho: ele
	// COPIA, não analisa. Não existe denominador — nenhum check rodou —, e uma
	// cobertura impressa ali afirmaria uma conclusão sobre o host que ninguém
	// tirou. O que ele deve à automação é o manifesto, não o veredito.
	switch {
	case !sc.Varredura():
		if r.coverage.ID == "coverage" {
			t.Error("preserve não varre, coleta: uma linha de cobertura aqui " +
				"afirmaria uma conclusão sobre o host que nenhum check tirou")
		}
	case sc.Exit != 3 && r.coverage.ID != "coverage":
		t.Error("JSONL sem linha de cobertura")
	case sc.Exit == 3 && r.coverage.ID == "coverage":
		t.Error("exit 3 é erro de invocação: não pode haver linha de cobertura, " +
			"porque varredura nenhuma aconteceu")
	}
}

// gapsAmbientaisUsados registra quais entradas da lista de ambiente casaram de
// verdade durante a execução da suíte. Ver TestGapsDoAmbienteSaoUsados.
var gapsAmbientaisUsados sync.Map

// vmRodou conta cenários que de fato subiram uma microVM. Zero significa tier
// de VM ausente (sem qemu), não suíte incompleta por defeito.
var vmRodou atomic.Int64

// kernelsRodados guarda os kernels que a execução chegou a bootar, pelo mesmo
// motivo do vmRodou: entrada recortada por kernel não pode ser cobrada por uma
// execução que nunca subiu aquele kernel.
var kernelsRodados sync.Map

func anotarUsoDeAmbiente(sc scenario.Scenario, lacunas []string) {
	kernelsRodados.Store(sc.Kernel, true)
	for _, l := range lacunas {
		for _, g := range scenario.GapsDoAmbiente {
			if g.ValeNoKernel(sc.Kernel) && strings.Contains(l, g.Contem) {
				gapsAmbientaisUsados.Store(g.Contem, true)
			}
		}
	}
}

// exitSoPorAmbiente permite o exit 1 onde o cenário pediu 0, e SÓ quando a
// única razão é uma lacuna que o ambiente da suíte impõe.
//
// O cenário diz "este host é limpo, logo exit 0". O exit 1 tem duas causas
// possíveis — achado que precisa de olho humano, ou cobertura incompleta — e
// esta função só perdoa a segunda, e só quando toda lacuna está na lista
// nomeada. Achado nenhum é perdoado: qualquer WARN ou pior faz a asserção
// valer como antes.
//
// Sem isso, `Exit: 0` dependia de o `udp_diag` estar carregado na máquina de
// quem roda a suíte. Com isso, ele volta a significar o que diz.
func exitSoPorAmbiente(sc scenario.Scenario, r result) bool {
	if sc.Exit != 0 || r.exit != 1 || r.coverage.Verdict != "INCOMPLETE" {
		return false
	}
	if len(scenario.FiltraAmbientais(sc, r.lacunas())) > 0 {
		return false
	}
	for _, f := range r.findings {
		if f.Sev == "WARN" || f.Sev == "CRITICAL" {
			return false
		}
	}
	return true
}

// runLive roda a CLI DENTRO do contêiner, vendo o /proc dele.
func runLive(t *testing.T, bin, img string, sc scenario.Scenario) result {
	t.Helper()

	script := sc.Plant + "\n/aletheia " + cmdOf(sc) + " --json -"
	if len(sc.Args) > 0 {
		script += " " + strings.Join(sc.Args, " ")
	}

	return dockerRun(t, append(argsDeDocker(t, bin, img, sc), img, "sh", "-c", script))
}

// argsDeDocker monta o ambiente do contêiner — volumes, cota, rede, caps,
// usuário. Extraído porque o modo MCP precisa do MESMO ambiente e de outro
// comando: duplicá-lo faria os dois divergirem no dia em que um ganhasse um
// flag novo, e a divergência apareceria como um cenário que passa por rodar num
// contêiner diferente do que ele diz rodar.
func argsDeDocker(t *testing.T, bin, img string, sc scenario.Scenario) []string {
	t.Helper()
	helper, err := filepath.Abs("../dist/helper")
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"run", "--rm",
		"-v", binFor(t, bin, sc) + ":/aletheia:ro",
		"-v", helper + ":/helper:ro"}
	if sc.CPUs != "" {
		args = append(args, "--cpus="+sc.CPUs)
	}
	if sc.NoNetwork {
		args = append(args, "--network=none")
	}
	for _, c := range sc.Caps {
		args = append(args, "--cap-add="+c)
	}
	if sc.User != "" {
		args = append(args, "-u", sc.User)
	}
	return args
}

// runImage exporta o rootfs do contêiner e o varre DE FORA com --root — que é
// como se analisa um snapshot montado (runbook §35.6).
func runImage(t *testing.T, bin, img string, sc scenario.Scenario) result {
	t.Helper()
	dir := t.TempDir()
	// O rootfs exportado carrega os modos ORIGINAIS, e é isso que faz o modo
	// imagem valer: o scan precisa ver a permissão como ela é no disco do alvo.
	//
	// A consequência aparece na limpeza: um rootfs de Rocky tem diretório sem
	// escrita para o dono, e o `RemoveAll` do TempDir falha ali — o teste passa
	// e o framework falha DEPOIS, com uma mensagem que não parece asserção.
	//
	// A ordem importa: o Cleanup é LIFO, então este afrouxa os modos ANTES da
	// remoção — e depois da varredura, que é o que precisava vê-los intactos.
	t.Cleanup(func() { _ = exec.Command("chmod", "-R", "u+rwX", dir).Run() })

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

	// O módulo de kernel do guest é preparado pelo `make vm-image` quando o host
	// tem um `dummy.ko` compatível. Sem ele o cenário não tem como existir — o
	// fato vem de /proc/modules, e plantar arquivo não carrega módulo nenhum.
	if sc.RequerModulo {
		marcador, _ := filepath.Abs("../dist/vm/modulo" + suffix + ".txt")
		if _, err := os.Stat(marcador); err != nil {
			t.Skipf("nenhum módulo de kernel foi preparado para o guest: o host " +
				"precisa ter dummy.ko para o kernel em execução, e uma ferramenta " +
				"para descomprimi-lo (zstd/xz/gzip). Rode `make vm-image` e veja a " +
				"mensagem dele")
		}
	}

	// Os módulos de ocultação são COMPILADOS (não levantados do host) e só entram
	// no initramfs quando o `make vm-modulos` correu antes do `make vm-image`. O
	// marcador prova que ESTE initramfs os contém; sem ele, pular com o motivo em
	// vez de bootar uma VM que não tem o que carregar.
	if sc.ModulosOcultacao {
		marcador, _ := filepath.Abs("../dist/vm/modulos-ocultacao" + suffix + ".txt")
		if _, err := os.Stat(marcador); err != nil {
			t.Skipf("os módulos de ocultação (socknd/modhide) não estão no " +
				"initramfs: eles são compilados contra o linux-lts do Alpine. " +
				"Rode `make vm-modulos` (exige docker) e depois `make vm-image`")
		}
	}

	initramfs, err := filepath.Abs("../dist/vm/initramfs" + suffix + ".gz")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(initramfs); err != nil {
		t.Skipf("initramfs%s ausente — rode `make vm-image`: %v", suffix, err)
	}
	conferirInitramfs(t, suffix)
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

	// Daqui em diante a VM sobe de verdade — os pulos por qemu ausente e por
	// initramfs sem módulo já passaram. É este ponto que o anti-apodrecimento
	// usa para saber se o tier de VM participou desta execução.
	vmRodou.Add(1)

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
// conferirInitramfs recusa rodar o tier de VM contra um initramfs que NÃO
// contém o binário desta árvore.
//
// # O verde mais caro que existe é o que testa outra coisa
//
// O initramfs é artefato de build, e nem `make scenarios` nem
// `make scenarios-container` o reconstroem: eles usam o que o último
// `make vm-image` deixou em dist/vm. O binário sob teste, então, é o que sobrou
// — e o resultado é uma suíte que sobe seis microVMs, passa, e não diz nada
// sobre o código que está na árvore.
//
// Não é hipótese. Foi medido nesta base: um initramfs de horas antes carregava
// um aletheia de SchemaVersion 6 enquanto a árvore já estava no 9, e o tier de
// VM vinha verde a sessão inteira sobre código que não existia mais. O que
// denunciou foi um acidente — uma comparação de drift recusou o dump por
// esquema incompatível.
//
// A recusa é PULO e não falha, pelo mesmo motivo dos outros guardas deste
// arquivo: initramfs desatualizado é condição de ambiente de quem roda, não
// defeito do código. E o pulo é alto — com motivo e com o comando que conserta.
// O anti-apodrecimento das lacunas ambientais já sabe distinguir "o tier de VM
// não participou" (vmRodou), então pular aqui não cobra ninguém por ausência.
func conferirInitramfs(t *testing.T, suffix string) {
	t.Helper()
	marcador, err := filepath.Abs("../dist/vm/binarios" + suffix + ".txt")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(marcador)
	if err != nil {
		t.Skipf("o initramfs%s não declara quais binários carrega (dist/vm/binarios%s.txt "+
			"ausente): ele é anterior a esta verificação e pode conter qualquer "+
			"versão. Rode `make vm-image`", suffix, suffix)
	}
	embutido := map[string]string{}
	for _, ln := range strings.Split(string(b), "\n") {
		if campos := strings.Fields(ln); len(campos) == 2 {
			embutido[campos[0]] = campos[1]
		}
	}
	for _, nome := range []string{"aletheia", "helper"} {
		atual, err := somaDoArquivo("../dist/" + nome + suffix)
		if err != nil {
			t.Skipf("dist/%s%s ilegível: %v", nome, suffix, err)
		}
		if embutido[nome] != atual {
			t.Skipf("o initramfs%s carrega um %s DIFERENTE do que está na árvore "+
				"(%s… no guest, %s… aqui): o tier de VM testaria outro binário e "+
				"passaria verde sobre código que não existe mais. Rode `make vm-image`",
				suffix, nome, primeiros(embutido[nome]), primeiros(atual))
		}
	}
}

func somaDoArquivo(caminho string) (string, error) {
	fh, err := os.Open(caminho)
	if err != nil {
		return "", err
	}
	defer fh.Close()
	h := sha256.New()
	if _, err := io.Copy(h, fh); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func primeiros(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	if s == "" {
		return "(ausente)"
	}
	return s
}

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
		// O linux-lts sai do `make vm-modulos` (junto dos módulos casados); os
		// kernels de época, do `make vm-kernels`. A mensagem aponta para o certo.
		alvo := "`make vm-kernels` (exige rede)"
		if name == "lts" {
			alvo = "`make vm-modulos` (exige docker)"
		}
		t.Skipf("kernel %s ausente — rode %s: %v", name, alvo, err)
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

// subjectHint descreve o alvo de um ForbidFinding na mensagem de falha.
func subjectHint(e scenario.Expect) string {
	s := ""
	if e.Subject != "" {
		s += " (subject=" + e.Subject + ")"
	}
	if e.Sev != "" {
		s += "/" + e.Sev
	}
	return s
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

// TestTodoCheckTemCenario mudou de casa: está em test/scenario/registro_test.go,
// SEM a tag `scenarios`.
//
// Ele nunca precisou de docker — compara dois registros em memória —, e atrás da
// tag só rodava para quem lembrasse de rodar a suíte inteira. Fora dela, roda no
// `go test ./...` e portanto na CI, que é onde um check novo sem cenário precisa
// falhar: antes do PR, não meses depois.

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

// TestCenarioNaoCitaCheckInexistente é SERIAL e roda sobre TODOS os cenários,
// inclusive os pulados. As duas coisas têm motivo.
//
// Serial: a versão anterior validava dentro de `assertScenario`, que roda em
// subteste com `t.Parallel()`, e montava um mapa global de forma preguiçosa —
// uma corrida de dados que o `-race` não pegou porque a suíte de cenários exige
// a tag de build e não entra no `go test -race ./internal/...`.
//
// Sobre os pulados: `UntestableChecks` só existe em cenário que NÃO executa, e
// validar dentro da execução nunca alcançava justamente esse campo. Um ID
// errado ali faria um check parecer coberto sem nunca ter sido demonstrado, que
// é a mesma armadilha que a ferramenta existe para evitar — "não apareceu"
// indistinguível de "não foi procurado", desta vez dentro da suíte.
func TestCenarioNaoCitaCheckInexistente(t *testing.T) {
	ids := map[string]bool{}
	for _, c := range check.All() {
		ids[c.ID] = true
	}
	for _, sc := range scenario.All() {
		for _, id := range sc.Forbid {
			if !ids[id] {
				t.Errorf("cenário %q proíbe %q, que não existe: um Forbid com ID "+
					"errado passa calado e não prova nada", sc.ID, id)
			}
		}
		for _, id := range sc.UntestableChecks {
			if !ids[id] {
				t.Errorf("cenário %q declara %q impossível, e ele não existe: "+
					"o check apareceria como coberto sem nunca ter sido demonstrado",
					sc.ID, id)
			}
		}
		for _, e := range sc.Expect {
			if !ids[e.ID] {
				t.Errorf("cenário %q espera %q, que não existe", sc.ID, e.ID)
			}
		}
		for _, e := range sc.ForbidFinding {
			if !ids[e.ID] {
				t.Errorf("cenário %q proíbe (ForbidFinding) %q, que não existe: um "+
					"ForbidFinding com ID errado passa calado e não prova nada", sc.ID, e.ID)
			}
		}
	}
}

// TestDividaDeCobertura imprime as LACUNAS CONHECIDAS — ataques que a suíte
// REPRODUZ e a ferramenta ainda perde. Não falha: é o inventário da dívida,
// impresso para não virar conhecimento tácito. Uma lacuna que FECHA falha em
// TestCenarios (a afirmação de ausência quebra), o que força a promoção para
// Expect. É por isso que a dívida aqui não pode crescer sem que alguém veja.
func TestDividaDeCobertura(t *testing.T) {
	n := 0
	for _, sc := range scenario.All() {
		if sc.KnownGap != "" {
			n++
			t.Logf("LACUNA CONHECIDA %s: %s", sc.ID, sc.KnownGap)
		}
	}
	t.Logf("%d lacuna(s) conhecida(s) — dívida de cobertura explícita e reproduzível", n)
}

// exigeImagemLocal pula com motivo quando uma imagem CONSTRUÍDA aqui não existe.
//
// As da matriz vêm do registro e o docker as busca sozinho. As de `aletheia-*`
// são construídas por `make images` e precisam de rede no build — num ambiente
// sem rede, o cenário tem que dizer que NÃO OLHOU, e não falhar com erro de
// docker nem passar calado. É a mesma regra que a ferramenta aplica a si mesma:
// "não encontrei" e "não consegui olhar" não podem sair iguais.
func exigeImagemLocal(t *testing.T, img string) {
	t.Helper()
	// As imagens construídas aqui — as de serviços e as de servidor de
	// referência — não vêm de registro público: sem elas o cenário é PULADO com
	// o comando na mensagem, nunca passa em silêncio.
	local := strings.HasPrefix(img, "aletheia-") || strings.HasPrefix(img, "servidor-")
	if !local {
		return
	}
	alvo := "make images"
	if strings.HasPrefix(img, "servidor-") {
		alvo = "make fixtures"
	}
	if err := exec.Command("docker", "image", "inspect", img).Run(); err != nil {
		t.Skipf("imagem %s ausente — rode `%s` (precisa de rede)", img, alvo)
	}
}

// TestGapsDoAmbienteSaoUsados impede que a lista de lacunas ambientais apodreça.
//
// Uma entrada que não casa com nada é pior que nenhuma: ela silencia uma classe
// de falha que talvez já não exista, e a suíte segue verde afirmando que
// tolerou algo que nunca aconteceu. Quando um módulo passa a vir carregado por
// padrão, ou quando um cenário muda, a entrada correspondente tem de SAIR — e
// este teste é quem lembra.
//
// Depende de a suíte inteira ter rodado, então ele vive aqui e não no pacote
// scenario: só depois de todos os cenários é que se sabe o que casou. Roda por
// último por ordem alfabética do arquivo? Não — o Go não garante ordem entre
// testes, e por isso ele PULA quando a execução foi filtrada por -run.
func TestGapsDoAmbienteSaoUsados(t *testing.T) {
	if testing.Short() {
		t.Skip("depende da suíte inteira")
	}
	total := 0
	gapsAmbientaisUsados.Range(func(any, any) bool { total++; return true })
	if total == 0 {
		t.Skip("nenhum cenário rodou nesta invocação (-run filtrou): sem base para julgar a lista")
	}
	semVM := vmRodou.Load() == 0
	for _, g := range scenario.GapsDoAmbiente {
		if g.SoEmVM && semVM {
			// O tier de VM não rodou (sem qemu): esta entrada não teve chance de
			// casar, e cobrá-la seria falhar por execução parcial.
			continue
		}
		if g.SoNoKernel != "" {
			if _, bootou := kernelsRodados.Load(g.SoNoKernel); !bootou {
				continue
			}
		}
		if _, ok := gapsAmbientaisUsados.Load(g.Contem); !ok {
			t.Errorf("a lacuna ambiental %q não apareceu em execução nenhuma da suíte.\n"+
				"Ou ela deixou de acontecer — e a entrada tem de SAIR, porque uma "+
				"tolerância que não tolera nada só esconde a próxima —, ou o texto "+
				"da lacuna mudou e a entrada parou de casar sem ninguém ver.\n"+
				"motivo registrado: %s", g.Contem, g.Porque)
		}
	}
}

// ---------------------------------------------------------------- modo MCP
//
// O servidor MCP não cabe no caminho dos outros cenários por três razões, e as
// três são de contrato e não de conveniência: ele não aceita `--json -`, lê a
// requisição do STDIN, e o que sai é JSON-RPC — cujo `id` é numérico, então a
// linha nem desserializa no tipo que o harness usa para achado.

// respostaMCP é uma resposta JSON-RPC já decodificada.
type respostaMCP struct {
	linha     string
	corpo     map[string]any
	resultado map[string]any // result, quando houve
	erro      map[string]any // error, quando houve
}

type resultadoMCP struct {
	porID  map[int]respostaMCP
	stdout string
	stderr string
	exit   int
}

// runMCP roda o servidor DENTRO do contêiner, com a transcrição na entrada
// padrão.
func runMCP(t *testing.T, bin, img string, sc scenario.Scenario) resultadoMCP {
	t.Helper()

	// O heredoc é NÃO citado de propósito: é o que permite ao cenário
	// substituir um valor descoberto no plantio — o pid do implante, que só
	// existe depois de ele subir. É o mesmo mecanismo que o campo `Args` já usa
	// com `$(cat /tmp/pid)`. A consequência: `$` e crase dentro da transcrição
	// são expandidos pelo shell, e nenhuma transcrição os usa por acaso.
	script := sc.Plant + `
cat > /tmp/mcp-entrada.jsonl <<FIM_DA_TRANSCRICAO
` + scenario.Transcricao(sc.MCP) + `FIM_DA_TRANSCRICAO
/aletheia mcp ` + strings.Join(sc.Args, " ") + ` < /tmp/mcp-entrada.jsonl`

	r := capturaCrua(t, exec.Command("docker",
		append(argsDeDocker(t, bin, img, sc), img, "sh", "-c", script)...))

	res := resultadoMCP{porID: map[int]respostaMCP{}, stdout: r.stdout, stderr: r.stderr, exit: r.exit}
	for _, ln := range strings.Split(strings.TrimSpace(r.stdout), "\n") {
		if ln == "" {
			continue
		}
		var corpo map[string]any
		if err := json.Unmarshal([]byte(ln), &corpo); err != nil {
			t.Fatalf("stdout do servidor MCP não é JSON-RPC válido: %v\nlinha: %q\n"+
				"stderr:\n%s", err, ln, r.stderr)
		}
		// O stdout é EXCLUSIVAMENTE protocolo — a spec é literal quanto a isso,
		// e é o que permite ao cliente parsear cada linha sem heurística. Uma
		// linha de diagnóstico vazando para cá quebraria todo cliente, e é
		// exatamente o tipo de regressão que ninguém percebe em desenvolvimento.
		if corpo["jsonrpc"] != "2.0" {
			t.Fatalf("linha no stdout que não é mensagem MCP: %q", ln)
		}
		resp := respostaMCP{linha: ln, corpo: corpo}
		resp.resultado, _ = corpo["result"].(map[string]any)
		resp.erro, _ = corpo["error"].(map[string]any)
		if id, ok := corpo["id"].(float64); ok {
			res.porID[int(id)] = resp
		}
	}
	return res
}

// capturaCrua roda o comando sem interpretar o stdout. O `capture` original
// exige JSONL de achados e aborta com t.Fatalf em qualquer outra coisa.
func capturaCrua(t *testing.T, cmd *exec.Cmd) struct {
	stdout, stderr string
	exit           int
} {
	t.Helper()
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	r := struct {
		stdout, stderr string
		exit           int
	}{stdout: out.String(), stderr: errb.String()}
	if ee, ok := err.(*exec.ExitError); ok {
		r.exit = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("execução falhou: %v\nstderr:\n%s", err, r.stderr)
	}
	return r
}

func assertMCP(t *testing.T, sc scenario.Scenario, r resultadoMCP) {
	t.Helper()

	if sc.Exit != -1 && r.exit != sc.Exit {
		t.Errorf("cenário %q: exit %d, esperava %d\nstderr:\n%s",
			sc.Desc, r.exit, sc.Exit, r.stderr)
	}
	// ExpectOutput/ForbidOutput, e não um par próprio: o caminho normal já
	// inspeciona exatamente o stderr do contêiner (ver assertScenario). Os
	// campos EsperaStderr/ProibeStderr que este modo tinha eram duplicata pura
	// — dois nomes para a mesma asserção, cada par sem efeito na outra metade
	// da suíte.
	for _, e := range sc.ExpectOutput {
		if !strings.Contains(r.stderr, e) {
			t.Errorf("cenário %q: a saída não trouxe %q\nstderr:\n%s", sc.Desc, e, r.stderr)
		}
	}
	for _, p := range sc.ForbidOutput {
		if strings.Contains(r.stderr, p) {
			t.Errorf("cenário %q: a saída trouxe o que NÃO podia (%q)\nstderr:\n%s",
				sc.Desc, p, r.stderr)
		}
	}

	for i, c := range sc.MCP {
		id := i + 1
		resp, ok := r.porID[id]
		if !ok {
			t.Errorf("cenário %q: %s (id %d) não foi respondida\nstdout:\n%s\nstderr:\n%s",
				sc.Desc, c.Rotulo(), id, r.stdout, r.stderr)
			continue
		}
		assertChamada(t, sc, c, resp)
	}
}

func assertChamada(t *testing.T, sc scenario.Scenario, c scenario.Chamada, resp respostaMCP) {
	t.Helper()
	ctx := fmt.Sprintf("cenário %q · %s", sc.Desc, c.Rotulo())

	if c.ErroCodigo != 0 {
		if resp.erro == nil {
			t.Errorf("%s: esperava erro %d e veio resultado\n%s", ctx, c.ErroCodigo, resp.linha)
			return
		}
		if cod, _ := resp.erro["code"].(float64); int(cod) != c.ErroCodigo {
			t.Errorf("%s: erro %v, esperava %d\n%s", ctx, resp.erro["code"], c.ErroCodigo, resp.linha)
		}
		return
	}
	if resp.erro != nil {
		t.Errorf("%s: erro inesperado: %v", ctx, resp.erro["message"])
		return
	}

	for _, e := range c.Espera {
		if !strings.Contains(resp.linha, e) {
			t.Errorf("%s: a resposta não trouxe %q\n%s", ctx, e, corta(resp.linha, 900))
		}
	}
	for _, p := range c.Proibe {
		if strings.Contains(resp.linha, p) {
			t.Errorf("%s: a resposta trouxe o que NÃO podia (%q)", ctx, p)
		}
	}

	// A FRONTEIRA DE INJEÇÃO, escrita como asserção.
	//
	// O texto do alvo precisa CHEGAR — escapar não é truncar, e a forense
	// precisa dos bytes que o atacante escolheu — e precisa chegar SÓ em `data`.
	//
	// A comparação é dentro de `structuredContent`, e não da linha inteira, e a
	// razão é do protocolo: `content` é a serialização do MESMO envelope em
	// texto, para o cliente que ainda não lê schema de saída. Cobrar ausência
	// ali cobraria que a resposta se contradissesse.
	if len(c.SoEmDados) > 0 {
		sc := resp.resultado["structuredContent"]
		dados, _ := json.Marshal(caminhoOuNil(sc, "data"))
		var fora []byte
		for _, campo := range []string{"provenance", "observability", "trust"} {
			b, _ := json.Marshal(caminhoOuNil(sc, campo))
			fora = append(fora, b...)
		}
		for _, agulha := range c.SoEmDados {
			if !strings.Contains(string(dados), agulha) {
				t.Errorf("%s: %q não chegou em `data` — escapar não é truncar",
					ctx, corta(agulha, 60))
			}
			if strings.Contains(string(fora), agulha) {
				t.Errorf("%s: %q VAZOU para fora de `data`: texto do alvo em "+
					"procedência, cobertura ou marca de confiança são afirmações da "+
					"FERRAMENTA, não evidência", ctx, corta(agulha, 60))
			}
		}
	}

	// A FORMA GERAL da fronteira: o texto aparece, e toda região onde ele
	// aparece está DECLARADA. É o que SoEmDados não alcança — um nome que entrou
	// numa lacuna de coleta chega a observability legitimamente, e o defeito não
	// seria ele estar lá, seria o caminho não estar dito.
	if len(c.TextoDoAlvo) > 0 {
		env, _ := resp.resultado["structuredContent"].(map[string]any)
		conf, _ := env["trust"].(map[string]any)
		declaradas := map[string]bool{}
		for _, r := range conf["host_supplied_paths"].([]any) {
			// A declaração é por PREFIXO: "observability" cobre
			// "observability.coverage.collector_gaps".
			declaradas[strings.Split(r.(string), ".")[0]] = true
		}
		for _, agulha := range c.TextoDoAlvo {
			achouEmAlguma := false
			for _, regiao := range []string{"data", "observability", "provenance", "trust"} {
				b, _ := json.Marshal(env[regiao])
				if !strings.Contains(string(b), agulha) {
					continue
				}
				achouEmAlguma = true
				if !declaradas[regiao] {
					t.Errorf("%s: texto do alvo em %q, e o caminho NÃO está em "+
						"trust.host_supplied_paths (%v) — a fronteira precisa ser "+
						"declarada, não presumida", ctx, regiao, conf["host_supplied_paths"])
				}
			}
			if !achouEmAlguma {
				t.Errorf("%s: %q não apareceu na resposta — o cenário não exercitou "+
					"o caminho que ele existe para provar", ctx, corta(agulha, 60))
			}
		}
	}

	// Os caminhos resolvem contra o ENVELOPE quando há um, e contra o result
	// cru quando não há (tools/list, server/discover). É o que deixa o cenário
	// escrever "observability.verdict" em vez de
	// "result.structuredContent.observability.verdict".
	base := resp.resultado
	if sc, ok := resp.resultado["structuredContent"].(map[string]any); ok {
		base = sc
	}
	for caminho, quero := range c.Campos {
		v, ok := valorNoCaminho(base, caminho)
		if !ok {
			t.Errorf("%s: caminho %q não existe na resposta\n%s", ctx, caminho, corta(resp.linha, 700))
			continue
		}
		if got := textoDe(v); got != quero {
			t.Errorf("%s: %s = %q, esperava %q", ctx, caminho, got, quero)
		}
	}
	for caminho, naoQuero := range c.CampoNao {
		v, ok := valorNoCaminho(base, caminho)
		if !ok {
			t.Errorf("%s: caminho %q não existe na resposta", ctx, caminho)
			continue
		}
		if got := textoDe(v); got == naoQuero {
			t.Errorf("%s: %s é %q, e não podia ser", ctx, caminho, got)
		}
	}

	if len(c.ProibeTool) > 0 || c.ExigeReadOnly {
		assertRegistry(t, ctx, c, resp)
	}
}

// assertRegistry cobra o que o registry NÃO oferece.
//
// A ausência de superfície de execução é a propriedade central deste servidor,
// e ela precisa ser afirmada pelo lado de fora: um teste que só verifica o que
// existe nunca percebe o dia em que passa a existir um `shell`.
func assertRegistry(t *testing.T, ctx string, c scenario.Chamada, resp respostaMCP) {
	t.Helper()
	tools, _ := resp.resultado["tools"].([]any)
	if len(tools) == 0 {
		t.Errorf("%s: tools/list veio vazio", ctx)
		return
	}
	for _, x := range tools {
		m, _ := x.(map[string]any)
		nome, _ := m["name"].(string)
		for _, proibido := range c.ProibeTool {
			if nome == proibido {
				t.Errorf("%s: a tool %q EXISTE. Este servidor concede observação, "+
					"não execução — e o que está no registry pode ser induzido por "+
					"texto plantado no alvo", ctx, nome)
			}
		}
		if !c.ExigeReadOnly {
			continue
		}
		an, _ := m["annotations"].(map[string]any)
		if an["readOnlyHint"] != true {
			t.Errorf("%s: a tool %q não se anota readOnlyHint", ctx, nome)
		}
		if an["destructiveHint"] != false {
			t.Errorf("%s: a tool %q não se anota destructiveHint:false", ctx, nome)
		}
	}
}

func caminhoOuNil(v any, campo string) any {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	return m[campo]
}

func valorNoCaminho(v any, caminho string) (any, bool) {
	for _, parte := range strings.Split(caminho, ".") {
		m, ok := v.(map[string]any)
		if !ok {
			return nil, false
		}
		v, ok = m[parte]
		if !ok {
			return nil, false
		}
	}
	return v, true
}

// textoDe normaliza o valor para comparação com o literal do cenário. O
// encoding/json entrega todo número como float64, e "0" é mais legível num
// cenário do que "0.000000".
func textoDe(v any) string {
	if f, ok := v.(float64); ok && f == float64(int64(f)) {
		return strconv.FormatInt(int64(f), 10)
	}
	return fmt.Sprint(v)
}

func corta(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
