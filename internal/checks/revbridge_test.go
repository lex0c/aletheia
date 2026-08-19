package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

// --- correlate.revshell_bridge (runbook §17) ---

// pipeFD e sockFD montam os descritores de um processo.
func pipeFD(n int, inode uint64) facts.FD {
	return facts.FD{N: n, Pipe: true, PipeInode: inode, Target: "pipe:[x]"}
}

// cenarioPonte monta o par clássico: um shell cujo stdin vem de um pipe, e uma
// ponte que segura o mesmo pipe e tem um socket de saída público.
func cenarioPonte(pontePeerScope facts.Scope, ponteDir facts.Direction, ponteExe string) *facts.Facts {
	return &facts.Facts{
		Processes: []facts.Process{
			{PID: 100, Comm: "bash", Exe: "/usr/bin/bash", PPID: 50,
				FDs: []facts.FD{pipeFD(0, 700), pipeFD(1, 701)}},
			{PID: 101, Comm: baseComm(ponteExe), Exe: ponteExe, PPID: 50,
				FDs: []facts.FD{pipeFD(0, 701), pipeFD(1, 700),
					{N: 3, Socket: true, SocketInode: 900, Target: "socket:[x]"}}},
		},
		Sockets: []facts.Socket{sock(900, 101, ponteDir, pontePeerScope, "203.0.113.9")},
	}
}

func baseComm(exe string) string {
	if i := strings.LastIndex(exe, "/"); i >= 0 {
		return exe[i+1:]
	}
	return exe
}

// O caso central: shell lê de um pipe, a ponte segura o mesmo pipe e fala com um
// IP público. É a evasão do correlate.revshell, e tem de virar WARN.
func TestBridgeDisparaEmShellComPipeParaPonteComSaidaPublica(t *testing.T) {
	f := cenarioPonte(facts.ScopePublic, facts.DirOut, "/tmp/socat")
	r := revshellBridge.Run(revshellBridge, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %d, quer 1", len(r.Findings))
	}
	fd := r.Findings[0]
	if fd.Sev != check.SevWarn {
		t.Errorf("severidade = %s, quer WARN (a forma pura é que é CRITICAL)", fd.Sev)
	}
	if !fd.Irreversible {
		t.Error("o canal vive nos dois processos: matar um destrói a prova")
	}
	// os dois lados têm de ser preservados.
	passos := strings.Join(fd.NextSteps, " ")
	if !strings.Contains(passos, "100") || !strings.Contains(passos, "101") {
		t.Errorf("os dois PIDs precisam entrar na preservação: %v", fd.NextSteps)
	}
	// bidirecional foi detectado (stdout do shell volta pela ponte).
	if !strings.Contains(strings.Join(fd.Evidence, " "), "bidirecional") {
		t.Errorf("o canal de volta pelo pipe 700 devia ser notado: %v", fd.Evidence)
	}
}

// Um pipeline comum — `ps | grep` — tem pipe compartilhado, mas nenhum lado é
// shell lendo comando E o outro não tem socket de saída. Não pode disparar.
func TestBridgeNaoDisparaEmPipelineComum(t *testing.T) {
	f := &facts.Facts{
		Processes: []facts.Process{
			{PID: 200, Comm: "ps", Exe: "/usr/bin/ps", FDs: []facts.FD{pipeFD(1, 800)}},
			{PID: 201, Comm: "grep", Exe: "/usr/bin/grep", FDs: []facts.FD{pipeFD(0, 800)}},
		},
	}
	if r := revshellBridge.Run(revshellBridge, f, testEnv()); len(r.Findings) != 0 {
		t.Errorf("pipeline sem shell nem socket não é ponte: %+v", r.Findings)
	}
}

// `logger.sh | curl`: o shell ESCREVE no pipe (stdout), não LÊ dele (stdin).
// Não recebe comando de ninguém — não é reverse shell.
func TestBridgeNaoDisparaQuandoShellSoEscreveNoPipe(t *testing.T) {
	f := &facts.Facts{
		Processes: []facts.Process{
			// stdin do shell NÃO é pipe (é um arquivo/tty); só o stdout é.
			{PID: 300, Comm: "bash", Exe: "/usr/bin/bash", FDs: []facts.FD{pipeFD(1, 810)}},
			{PID: 301, Comm: "curl", Exe: "/usr/bin/curl",
				FDs: []facts.FD{pipeFD(0, 810), {N: 3, Socket: true, SocketInode: 910}}},
		},
		Sockets: []facts.Socket{sock(910, 301, facts.DirOut, facts.ScopePublic, "203.0.113.1")},
	}
	if r := revshellBridge.Run(revshellBridge, f, testEnv()); len(r.Findings) != 0 {
		t.Errorf("shell que só escreve no pipe não recebe comando: %+v", r.Findings)
	}
}

// Destino INTERNO não forma o achado: é a fronteira do check (declarada), e a
// ponte para serviço interno tem história legítima demais para WARN.
func TestBridgeExigeDestinoPublico(t *testing.T) {
	f := cenarioPonte(facts.ScopePrivate, facts.DirOut, "/tmp/socat")
	if r := revshellBridge.Run(revshellBridge, f, testEnv()); len(r.Findings) != 0 {
		t.Errorf("destino interno não forma o achado nesta fase: %+v", r.Findings)
	}
}

// Socket de ENTRADA na ponte não é canal com operador: é a ativação por socket,
// a mesma ressalva do correlate.revshell.
func TestBridgeIgnoraSocketDeEntrada(t *testing.T) {
	f := cenarioPonte(facts.ScopePublic, facts.DirIn, "/tmp/socat")
	if r := revshellBridge.Run(revshellBridge, f, testEnv()); len(r.Findings) != 0 {
		t.Errorf("socket de entrada é ativação por socket, não reverse shell: %+v", r.Findings)
	}
}

// A proveniência da ponte é o discriminador do FP. Um socat de /tmp grita; um
// agente com dono de pacote em /usr é anotado como possivelmente legítimo — o
// achado continua (trojan owned existe), mas a evidência muda a leitura.
func TestBridgeAnotaProvenienciaDaPonte(t *testing.T) {
	sujo := revshellBridge.Run(revshellBridge, cenarioPonte(facts.ScopePublic, facts.DirOut, "/tmp/socat"), testEnv())
	if !strings.Contains(strings.Join(sujo.Findings[0].Evidence, " "), "diretório") {
		t.Errorf("ponte em /tmp tem de ser apontada: %v", sujo.Findings[0].Evidence)
	}

	// binário com dono de pacote: Ownership marca /usr/bin/ssm-agent como owned.
	f := cenarioPonte(facts.ScopePublic, facts.DirOut, "/usr/bin/ssm-agent")
	f.Ownership = []facts.Ownership{{Path: "/usr/bin/ssm-agent", Owned: true}}
	limpo := revshellBridge.Run(revshellBridge, f, testEnv())
	if len(limpo.Findings) != 1 {
		t.Fatalf("achados = %d, quer 1", len(limpo.Findings))
	}
	if !strings.Contains(strings.Join(limpo.Findings[0].Evidence, " "), "acesso remoto legítimo") {
		t.Errorf("ponte com dono de pacote tem de ser anotada como possível agente: %v",
			limpo.Findings[0].Evidence)
	}
}

// A própria ferramenta não pode virar achado, dos dois lados.
func TestBridgeIgnoraSiMesmo(t *testing.T) {
	f := cenarioPonte(facts.ScopePublic, facts.DirOut, "/tmp/socat")
	f.Processes[0].Self = true
	if r := revshellBridge.Run(revshellBridge, f, testEnv()); len(r.Findings) != 0 {
		t.Errorf("o shell é a própria ferramenta: %+v", r.Findings)
	}
}

// Socket não ESTABELECIDO — um SYN-SENT que ainda não conectou — não é canal:
// exigir ESTAB evita disparar sobre uma tentativa de conexão que talvez nem
// complete.
func TestBridgeExigeSocketEstabelecido(t *testing.T) {
	f := cenarioPonte(facts.ScopePublic, facts.DirOut, "/tmp/socat")
	f.Sockets[0].State = "SYN-SENT"
	if r := revshellBridge.Run(revshellBridge, f, testEnv()); len(r.Findings) != 0 {
		t.Errorf("socket não estabelecido não é canal: %+v", r.Findings)
	}
}

// Um shell sozinho com o próprio socket de saída E stdin de pipe é a forma do
// correlate.revshell, não uma PONTE: não há segundo processo. Sem a guarda de
// bpid==self, o shell casaria consigo mesmo e este check roubaria o achado do
// outro, com severidade menor.
func TestBridgeNaoCasaShellConsigoMesmo(t *testing.T) {
	f := &facts.Facts{
		Processes: []facts.Process{
			{PID: 100, Comm: "bash", Exe: "/usr/bin/bash", FDs: []facts.FD{
				pipeFD(0, 700),
				{N: 3, Socket: true, SocketInode: 900, Target: "socket:[x]"},
			}},
		},
		Sockets: []facts.Socket{sock(900, 100, facts.DirOut, facts.ScopePublic, "203.0.113.9")},
	}
	if r := revshellBridge.Run(revshellBridge, f, testEnv()); len(r.Findings) != 0 {
		t.Errorf("shell sozinho é caso do correlate.revshell, não ponte: %+v", r.Findings)
	}
}
