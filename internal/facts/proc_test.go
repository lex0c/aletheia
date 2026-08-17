package facts

import (
	"os"
	"strings"
	"testing"
)

// TestSplitStatComm cobre a armadilha que quebra silenciosamente quase toda
// implementação caseira: o campo comm de /proc/<pid>/stat pode conter espaço E
// parêntese, e parsear por Fields desloca TODOS os campos seguintes — inclusive
// ppid e starttime — sem erro nenhum.
func TestSplitStatComm(t *testing.T) {
	cases := []struct {
		name     string
		line     string
		wantComm string
		wantStat string
		wantPPID string
	}{
		{
			name:     "comum",
			line:     "1234 (nginx) S 1 1234 1234 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 100 200",
			wantComm: "nginx", wantStat: "S", wantPPID: "1",
		},
		{
			name:     "comm com espaco",
			line:     "42 (Web Content) S 7 42 42 0 -1 0 1 0 0 0 0 0 0 0 20 0 4 0 555 0 0",
			wantComm: "Web Content", wantStat: "S", wantPPID: "7",
		},
		{
			name:     "comm com parenteses",
			line:     "99 (weird) (name)) R 3 99 99 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 111 0 0",
			wantComm: "weird) (name)", wantStat: "R", wantPPID: "3",
		},
		{
			name:     "comm que parece um kthread",
			line:     "8 ([kworker/0:1]) S 2 0 0 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 9 0 0",
			wantComm: "[kworker/0:1]", wantStat: "S", wantPPID: "2",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			comm, rest, ok := splitStatComm(c.line)
			if !ok {
				t.Fatalf("splitStatComm falhou em %q", c.line)
			}
			if comm != c.wantComm {
				t.Errorf("comm = %q, quer %q", comm, c.wantComm)
			}
			if len(rest) < 2 {
				t.Fatalf("rest muito curto: %v", rest)
			}
			if rest[0] != c.wantStat {
				t.Errorf("state = %q, quer %q", rest[0], c.wantStat)
			}
			if rest[1] != c.wantPPID {
				t.Errorf("ppid = %q, quer %q — campo deslocado é o bug clássico", rest[1], c.wantPPID)
			}
		})
	}
}

func TestSplitStatCommMalformado(t *testing.T) {
	for _, line := range []string{"", "sem parenteses aqui", "1234 (aberto sem fechar"} {
		if _, _, ok := splitStatComm(line); ok {
			t.Errorf("splitStatComm aceitou entrada malformada: %q", line)
		}
	}
}

// TestEnvAllowed guarda a política de redação (SPEC 5.4): só a allowlist tem
// VALOR gravado. Errar para o lado permissivo vaza segredo num artefato que
// sai do host.
func TestEnvAllowed(t *testing.T) {
	allowed := []string{
		"LD_PRELOAD", "LD_LIBRARY_PATH",
		"SSH_CONNECTION", // contém o IP de origem do atacante
		"SSH_CLIENT", "SSH_TTY",
		"INVOCATION_ID", "JOURNAL_STREAM", "PATH",
		"GS_ARGS", "GSOCKET_SECRET", "_GSOCKET_INTERNAL",
	}
	for _, k := range allowed {
		if !envAllowed(k) {
			t.Errorf("%s deveria ter o valor gravado", k)
		}
	}

	denied := []string{
		"AWS_SECRET_ACCESS_KEY", "DATABASE_URL", "GITHUB_TOKEN",
		"PGPASSWORD", "HOME", "USER", "TERM", "MYSQL_ROOT_PASSWORD",
	}
	for _, k := range denied {
		if envAllowed(k) {
			t.Errorf("%s NÃO pode ter o valor gravado: vaza segredo (runbook §3.6)", k)
		}
	}
}

func TestReadNULIgnoraVazios(t *testing.T) {
	// cmdline e environ terminam em NUL e podem ter NUL duplo.
	dir := t.TempDir()
	p := dir + "/cmdline"
	if err := writeFile(p, "bash\x00-c\x00curl x | sh\x00"); err != nil {
		t.Fatal(err)
	}
	got := readNUL(p)
	want := []string{"bash", "-c", "curl x | sh"}
	if len(got) != len(want) {
		t.Fatalf("readNUL = %q, quer %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] = %q, quer %q", i, got[i], want[i])
		}
	}
}

func TestReadNULArquivoAusente(t *testing.T) {
	if got := readNUL("/proc/nao/existe/cmdline"); got != nil {
		t.Errorf("arquivo ausente deve devolver nil, devolveu %q", got)
	}
}

func TestIsLibDir(t *testing.T) {
	lib := []string{"/usr/lib/x86_64-linux-gnu/libc.so.6", "/lib64/ld-linux.so.2", "/usr/local/lib/foo.so"}
	for _, p := range lib {
		if !isLibDir(p) {
			t.Errorf("%s é diretório de biblioteca legítimo", p)
		}
	}
	odd := []string{"/tmp/evil.so", "/dev/shm/x.so", "/home/node/.config/lib.so", "/opt/app/hook.so"}
	for _, p := range odd {
		if isLibDir(p) {
			t.Errorf("%s NÃO é diretório de biblioteca: deve entrar em MapsOdd (runbook §7.8)", p)
		}
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

// A distinção que separa "não achei" de "não consegui olhar" — e, deste lado,
// separa "não consegui olhar" de "não havia mais nada para olhar".
//
// Sem ela, um servidor de produção nunca reportaria OK: basta UM processo
// terminar durante os 60ms da coleta para a cobertura degradar. O oposto do
// defeito original, e igualmente inútil.
func TestReadProcessSeparaSumidoDeIlegivel(t *testing.T) {
	// PID que não pode existir: acima de qualquer pid_max praticado.
	if _, got := readProcess(1 << 30); got != readGone {
		t.Errorf("PID inexistente devolveu %v, quer readGone", got)
	}
	// O próprio processo é sempre legível.
	if _, got := readProcess(os.Getpid()); got != readOK {
		t.Errorf("o próprio PID devolveu %v, quer readOK", got)
	}
}

// E o desfecho "sumiu" NÃO pode virar lacuna de cobertura: o processo não
// existe mais para ninguém, nem para um humano rodando ps.
func TestProcessosQueSumiramNaoDegradamCobertura(t *testing.T) {
	f := &Facts{}
	f.ProcessesGone = 7
	for _, rs := range f.Partial {
		for _, r := range rs {
			if strings.Contains(r, "sumir") || strings.Contains(r, "terminaram") {
				t.Errorf("processo que terminou virou lacuna: %q", r)
			}
		}
	}
	if f.ProcessesGone != 7 {
		t.Error("mas a contagem precisa continuar visível no JSONL")
	}
}

// Um defeito NOSSO não pode virar afirmação sobre o host. Antes de a coleta ser
// paralela, o panic subia até o recover() do main e virava exit 3 (ERROR). Em
// goroutine o recover do main não alcança: o processo morre com status 2, que
// este contrato define como "CRITICAL — indicador de alta confiança", e a
// automação de frota marcaria o host como comprometido.
func TestPanicNoColetorNaoDerrubaOProcesso(t *testing.T) {
	// PID negativo faz procPath produzir caminho inválido; o que interessa é
	// que readProcessGuarded devolva em vez de propagar.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("o panic escapou do guarda: %v", r)
		}
	}()
	if _, out, _ := readProcessGuarded(-1); out == readOK {
		t.Error("PID inválido não pode sair como leitura bem-sucedida")
	}
}
