package checks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
	"github.com/lex0c/aletheia/internal/ioc"
)

// envComIOC monta o ambiente com uma lista de verdade, carregada do arquivo:
// testar contra uma struct montada à mão pularia justamente a classificação,
// que é onde um indicador vira do tipo errado.
func envComIOC(t *testing.T, conteudo string) *env.Env {
	t.Helper()
	p := filepath.Join(t.TempDir(), "incidente.yaml")
	if err := os.WriteFile(p, []byte(conteudo), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := ioc.Carregar(p)
	if err != nil {
		t.Fatalf("carregar lista: %v", err)
	}
	e := testEnv()
	e.IOC = l
	return e
}

// Sem lista não há caça, e isso NÃO é lacuna: é a execução normal, sem --ioc.
func TestIOCSemListaNaoFazNada(t *testing.T) {
	f := &facts.Facts{Accounts: []facts.Account{{Name: "backup2", UID: 1001}}}
	r := indicadorDoIncidente.Run(indicadorDoIncidente, f, testEnv())
	if len(r.Findings) != 0 || len(r.Partial) != 0 {
		t.Errorf("sem lista o check não fala: %v / %v", r.Findings, r.Partial)
	}
}

// Cada tipo casa no lugar certo, e o achado é CRÍTICO — a SPEC é explícita:
// não é heurística, é o artefato confirmado deste incidente aparecendo aqui.
func TestIOCCasaCadaTipoNoSeuLugar(t *testing.T) {
	e := envComIOC(t, `ips:     [198.51.100.241]
paths:   ["*/htop/defunct"]
strings: [gs-netcat]
users:   [backup2]
hashes:  [d41d8cd98f00b204e9800998ecf8427e]
`)
	f := &facts.Facts{
		Processes: []facts.Process{{PID: 42, Comm: "x", Exe: "/home/n/.config/htop/defunct"}},
		Sockets: []facts.Socket{{
			Proto: "tcp", Dir: facts.DirOut, PID: 42, Comm: "x", Inode: 9,
			PeerIP: "198.51.100.241", PeerPort: 443, LocalIP: "10.0.0.5", LocalPort: 51204,
		}},
		Units: []facts.Unit{{
			Name: "api.service", Path: "/etc/systemd/system/api.service",
			Exec: []facts.ExecLine{{Key: "ExecStart", Cmd: "/usr/local/bin/gs-netcat -d"}},
		}},
		Accounts:  []facts.Account{{Name: "backup2", UID: 1001, Home: "/home/backup2"}},
		HashesIOC: []facts.ArquivoHash{{Path: "/tmp/.x", Algo: "md5", Hash: "d41d8cd98f00b204e9800998ecf8427e"}},
	}

	r := indicadorDoIncidente.Run(indicadorDoIncidente, f, e)
	tipos := map[string]bool{}
	for _, fd := range r.Findings {
		if fd.Sev != check.SevCritical {
			t.Errorf("%s: sev = %v, achado por indicador é CRÍTICO", fd.Subject, fd.Sev)
		}
		if !fd.Irreversible {
			t.Errorf("%s: achado por indicador precisa ser irreversível", fd.Subject)
		}
		for _, ev := range fd.Evidence {
			if pre, _, ok := strings.Cut(ev, ": "); ok && strings.HasPrefix(pre, "indicador de ") {
				tipos[strings.TrimPrefix(pre, "indicador de ")] = true
			}
		}
	}
	for _, quer := range []string{"ip", "path", "string", "user", "hash"} {
		if !tipos[quer] {
			t.Errorf("nenhum achado veio de indicador de %s: %v", quer, r.Findings)
		}
	}
}

// A chave casa por IMPRESSÃO DIGITAL, e é o que faz a mesma chave casar consigo
// mesma quando o invasor a colou com outro comentário e outras opções.
func TestIOCChaveCasaPorImpressaoDigital(t *testing.T) {
	// Blob VÁLIDO em base64: a impressão digital é o SHA-256 do conteúdo
	// decodificado, e uma chave de exemplo com tamanho quebrado não decodifica —
	// as duas pontas sairiam vazias e o teste passaria sem comparar nada.
	const blob = "AAAAC3NzaC1lZDI1NTE5AAAAIKenp6enp6enp6enp6enp6enp6enp6enp6enp6enp6en"
	e := envComIOC(t, "keys: [\"ssh-ed25519 "+blob+" atacante@vps\"]\n")
	f := &facts.Facts{SSHKeys: []facts.SSHKey{{
		File: "/root/.ssh/authorized_keys", Line: 3, Type: "ssh-ed25519",
		Fingerprint: facts.FingerprintSSH(blob),
		Comment:     "outro-comentario@qualquer",
		Options:     `command="/bin/sh"`,
	}}}
	r := indicadorDoIncidente.Run(indicadorDoIncidente, f, e)
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %v", r.Findings)
	}
	junto := strings.Join(r.Findings[0].Evidence, " | ")
	if !strings.Contains(junto, "chave autorizada em /root/.ssh/authorized_keys") {
		t.Errorf("evidência = %q", junto)
	}
	// E a impressão digital tem de ser derivável: se ela sair vazia, os dois
	// lados "casam" por serem vazios e o check vira ruído.
	if facts.FingerprintSSH(blob) == "" {
		t.Fatal("o blob do teste não decodifica: a comparação não estaria testando nada")
	}
}

// O mesmo indicador no mesmo lugar é UM achado.
//
// O caso real: um binário com bit setuid que TAMBÉM está em execução aparece
// duas vezes na varredura de arquivos — uma pela propriedade de pacote, outra
// pelo SUID —, e as duas com o mesmo sujeito. Sem a deduplicação o operador lê
// duas linhas idênticas e a frota conta dois achados onde há um.
//
// A primeira versão deste teste usava dois SUJEITOS diferentes e passava com a
// deduplicação removida: era decorativo, e foi uma mutação que mostrou.
func TestIOCNaoDuplicaOMesmoParIndicadorLugar(t *testing.T) {
	e := envComIOC(t, "paths: [\"/tmp/.x\"]\n")
	f := &facts.Facts{
		Ownership: []facts.Ownership{{Path: "/tmp/.x", Owned: false, Onde: []string{"processo pid=7"}}},
		Suid:      []facts.SuidFile{{Path: "/tmp/.x", Setuid: true}},
	}
	r := indicadorDoIncidente.Run(indicadorDoIncidente, f, e)
	n := 0
	for _, fd := range r.Findings {
		if fd.Subject == "/tmp/.x" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("o mesmo indicador no mesmo lugar saiu %d vezes: %v", n, r.Findings)
	}
}

// Chave que não decodifica NÃO pode casar.
//
// A impressão digital é o SHA-256 do blob decodificado; um blob quebrado — dos
// dois lados — devolve string vazia, e sem a guarda "vazio == vazio" faria a
// ferramenta acusar toda chave ilegível do host contra toda chave ilegível da
// lista. Também foi uma mutação sobrevivente que expôs a falta deste teste.
func TestIOCChaveIlegivelNaoCasa(t *testing.T) {
	e := envComIOC(t, "keys: [\"ssh-ed25519 AAAAnaoEhBase64Valido invasor@vps\"]\n")
	f := &facts.Facts{SSHKeys: []facts.SSHKey{{
		File: "/home/app/.ssh/authorized_keys", Line: 1,
		Fingerprint: "", // o coletor também não conseguiu derivar
	}}}
	if r := indicadorDoIncidente.Run(indicadorDoIncidente, f, e); len(r.Findings) != 0 {
		t.Errorf("chave sem impressão digital não pode casar com nada: %v", r.Findings)
	}
}

// Uma linha da lista que não foi entendida é um indicador que NINGUÉM procurou:
// ela degrada a cobertura deste check em vez de sumir.
func TestIOCAvisoDaListaDegradaCobertura(t *testing.T) {
	e := envComIOC(t, `ipss: [198.51.100.241]
users: [backup2]
`)
	r := indicadorDoIncidente.Run(indicadorDoIncidente, &facts.Facts{}, e)
	if len(r.Partial) == 0 || !strings.Contains(strings.Join(r.Partial, " "), "chave desconhecida") {
		t.Errorf("o que não foi entendido precisa aparecer na cobertura: %v", r.Partial)
	}
}

// O binário de um ExecStart vem com argumentos, e o indicador de CAMINHO é do
// binário. Sem separar o primeiro token, `paths: [/usr/local/bin/x]` nunca
// casaria com `ExecStart=/usr/local/bin/x --daemon`.
func TestPrimeiroTokenDeComando(t *testing.T) {
	casos := map[string]string{
		"/usr/local/bin/x --daemon":  "/usr/local/bin/x",
		"-/usr/bin/pre-script":       "/usr/bin/pre-script",
		"@/usr/bin/renomeado nome":   "/usr/bin/renomeado",
		"+/usr/bin/privilegiado a b": "/usr/bin/privilegiado",
		"":                           "",
	}
	for cmd, quer := range casos {
		if got := primeiroToken(cmd); got != quer {
			t.Errorf("primeiroToken(%q) = %q, queria %q", cmd, got, quer)
		}
	}
}

// A tag de um programa eBPF é o IOC de frota mais forte que existe para
// implante fileless: o kernel a calcula do bytecode, e ela não depende de nome,
// caminho, arquivo nem data — que é tudo o que um programa eBPF não tem.
func TestIOCCasaTagDeProgramaEBPF(t *testing.T) {
	e := envComIOC(t, "strings: [a04f5eef06a7f555]\n")
	f := &facts.Facts{BPF: facts.BPF{Enumerado: true, Programas: []facts.ProgramaBPF{
		{ID: 47, Tipo: "socket_filter", Nome: "implante", Tag: "a04f5eef06a7f555"},
	}}}
	r := indicadorDoIncidente.Run(indicadorDoIncidente, f, e)
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %v", r.Findings)
	}
	junto := strings.Join(r.Findings[0].Evidence, " | ")
	if !strings.Contains(junto, "tag do programa eBPF") {
		t.Errorf("evidência = %q", junto)
	}
	if r.Findings[0].Subject != "bpf prog id=47" {
		t.Errorf("subject = %q", r.Findings[0].Subject)
	}
}
