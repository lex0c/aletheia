package mcp

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

// servidorDeArquivo monta o perfil completo sobre uma imagem plantada, que é o
// modo em que a leitura direcionada dá para exercitar sem depender do host.
func servidorDeArquivo(t *testing.T, segredos bool) (*Servidor, string) {
	t.Helper()
	raiz := t.TempDir()
	for _, d := range []string{"etc", "tmp"} {
		if err := os.MkdirAll(filepath.Join(raiz, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(raiz, "etc/segredos.env"),
		[]byte("DB_PASSWORD=hunter2\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for alvo, nome := range map[string]string{
		"../etc":              "tmp/mau",
		"../etc/segredos.env": "tmp/atalho",
	} {
		if err := os.Symlink(alvo, filepath.Join(raiz, nome)); err != nil {
			t.Fatal(err)
		}
	}
	if err := syscall.Mkfifo(filepath.Join(raiz, "tmp/cano"), 0o644); err != nil {
		t.Skipf("sem mkfifo: %v", err)
	}

	a := NovoAcervo()
	a.Teto = 3
	pol := Policy{Modo: ModoImagem, Perfil: PerfilCompleto, PermitirSegredos: segredos}
	s := NovoServidor(pol, a, "teste", nil, func() (*env.Env, error) {
		e := env.Probe(env.Options{Root: raiz, Version: "teste"})
		e.Segredos = segredos
		return e, nil
	})
	t.Cleanup(func() {
		for _, r := range a.Todos() {
			_ = a.Liberar(r.ID)
		}
	})
	return s, raiz
}

func rodarTool(t *testing.T, s *Servidor, nome, args string) (map[string]any, *ErroRPC) {
	t.Helper()
	f, ok := s.porNome[nome]
	if !ok {
		t.Fatalf("%s não está no registry desta policy", nome)
	}
	out, er := f.Rodar(s, json.RawMessage(args))
	if er != nil {
		return nil, er
	}
	b, _ := json.Marshal(out)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m, nil
}

// OS DOIS PORTÕES DESTRAVAM COISAS DIFERENTES.
//
//	--profile full     ler o host por um caminho que o MODELO escolhe
//	--allow-secrets    os bytes crus saírem deste processo
//
// A separação é o que permite ao operador dizer "identifique o binário" sem
// dizer "mande o conteúdo do /etc/shadow para um modelo remoto". Um portão só
// obrigaria a escolher entre as duas.
func TestOsDoisPortoesDestravamConjuntosDiferentes(t *testing.T) {
	tem := func(s *Servidor, nome string) bool { _, ok := s.porNome[nome]; return ok }

	padrao := servidorVivo(t, ModoLive, "")
	completo, _ := servidorDeArquivo(t, false)
	comSegredo, _ := servidorDeArquivo(t, true)

	casos := []struct {
		tool                       string
		noPadrao, noFull, noSecret bool
	}{
		{"file.hash", false, true, true},
		{"file.capabilities", false, true, true},
		{"file.read", false, false, true},
		{"file.xattrs", false, false, true},
	}
	for _, c := range casos {
		if got := tem(padrao, c.tool); got != c.noPadrao {
			t.Errorf("%s no perfil padrão: %v, queria %v", c.tool, got, c.noPadrao)
		}
		if got := tem(completo, c.tool); got != c.noFull {
			t.Errorf("%s em --profile full: %v, queria %v — hash e capabilities "+
				"não emitem byte do alvo, read e xattrs emitem", c.tool, got, c.noFull)
		}
		if got := tem(comSegredo, c.tool); got != c.noSecret {
			t.Errorf("%s em full+secrets: %v, queria %v", c.tool, got, c.noSecret)
		}
	}

	// process.environ tem um terceiro eixo: ela pede FONTE live. Numa imagem
	// montada não há processo, e a pergunta não se aplica — some do callable
	// mesmo com as duas flags escritas.
	if tem(comSegredo, "process.environ") {
		t.Error("process.environ apareceu sobre uma IMAGEM: ali não há /proc, " +
			"e responder seria inventar processo")
	}
	vivoCompleto := servidorVivoCompleto(t)
	if !tem(vivoCompleto, "process.environ") {
		t.Error("process.environ tem de existir em live com as duas flags")
	}

	// E a ausência é DECLARADA, com o motivo — some do callable, não do
	// discurso.
	var motivo string
	for _, x := range completo.fora {
		if x.Nome == "file.read" {
			motivo = x.Motivo
		}
	}
	if !strings.Contains(motivo, "allow-secrets") {
		t.Errorf("a ausência de file.read precisa ensinar o caminho: %q", motivo)
	}
}

// O SYMLINK DO MEIO NÃO É BLOQUEADO POR NINGUÉM, e por isso é DITO.
//
// O_NOFOLLOW protege o último componente e mais nada; openat2 com
// RESOLVE_NO_SYMLINKS exigiria Linux 5.6 contra o piso de 3.2. Então a resposta
// carrega a cadeia e a identidade: o mesmo inode do arquivo real prova que o
// caminho pedido não é o arquivo lido.
func TestLeituraDizQualArquivoFoiRealmenteAberto(t *testing.T) {
	s, _ := servidorDeArquivo(t, true)

	direto, er := rodarTool(t, s, "file.read", `{"path":"/etc/segredos.env"}`)
	if er != nil {
		t.Fatalf("leitura direta: %v", er)
	}
	dd := direto["data"].(map[string]any)
	if !strings.Contains(dd["content"].(string), "hunter2") {
		t.Fatalf("o conteúdo CRU tem de chegar: %q", dd["content"])
	}
	if _, tem := dd["link_chain"]; tem {
		t.Error("caminho sem link não pode inventar cadeia")
	}

	pelaCadeia, er := rodarTool(t, s, "file.read", `{"path":"/tmp/mau/segredos.env"}`)
	if er != nil {
		t.Fatalf("pelo link intermediário: %v", er)
	}
	pd := pelaCadeia["data"].(map[string]any)
	if pd["inode"] != dd["inode"] {
		t.Fatalf("o link do meio devia levar ao MESMO inode: %v vs %v",
			pd["inode"], dd["inode"])
	}
	cadeia, _ := pd["link_chain"].([]any)
	if len(cadeia) != 1 || !strings.Contains(cadeia[0].(string), "/tmp/mau -> ../etc") {
		t.Errorf("a cadeia precisa NOMEAR o link atravessado: %v", pd["link_chain"])
	}
	if pd["resolved_path"] != "/etc/segredos.env" {
		t.Errorf("resolved_path=%v", pd["resolved_path"])
	}
}

// A RECUSA É RESPOSTA, e leva a evidência junto.
func TestRecusasDeLeituraCarregamAEvidencia(t *testing.T) {
	s, _ := servidorDeArquivo(t, true)

	casos := []struct{ nome, args, naMensagem, campo string }{
		{"symlink final", `{"path":"/tmp/atalho"}`, "symlink", "link_chain"},
		{"fifo", `{"path":"/tmp/cano"}`, "fifo", "type"},
		{"inexistente", `{"path":"/etc/nao-existe"}`, "não existe", ""},
		{"relativo", `{"path":"etc/passwd"}`, "ABSOLUTO", ""},
		{"não normalizado", `{"path":"/etc/../etc/passwd"}`, "redundantes", ""},
	}
	for _, c := range casos {
		_, er := rodarTool(t, s, "file.read", c.args)
		if er == nil {
			t.Errorf("%s: devia recusar", c.nome)
			continue
		}
		if !strings.Contains(er.Message, c.naMensagem) {
			t.Errorf("%s: a recusa precisa dizer por quê; falta %q em %q",
				c.nome, c.naMensagem, er.Message)
		}
		if c.campo == "" {
			continue
		}
		d, _ := er.Data.(map[string]any)
		if _, tem := d[c.campo]; !tem {
			t.Errorf("%s: a recusa jogou fora a evidência (falta %q em %v)",
				c.nome, c.campo, er.Data)
		}
	}

	// O symlink recusado é ATENDIDO quando o chamador pede.
	m, er := rodarTool(t, s, "file.read", `{"path":"/tmp/atalho","follow_symlinks":true}`)
	if er != nil {
		t.Fatalf("com follow_symlinks:true tinha de ler: %v", er)
	}
	if !strings.Contains(m["data"].(map[string]any)["content"].(string), "hunter2") {
		t.Error("seguiu o link e não trouxe o conteúdo")
	}
}

// ESTA FAMÍLIA NÃO RESPONDE SOBRE UM RETRATO, e o envelope diz isso.
//
// Todas as outras tools carregam `provenance` com snapshot_id, cobertura e
// veredito. Estas leem o host AGORA. Um modelo que correlacione "o processo do
// snap-X" com "o conteúdo deste arquivo" precisa saber que os dois instantes
// são diferentes, senão constrói uma narrativa que não aconteceu.
func TestFamiliaDeArquivoNaoFingeSerRetrato(t *testing.T) {
	s, _ := servidorDeArquivo(t, true)
	for _, tool := range []string{"file.read", "file.hash", "file.xattrs", "file.capabilities"} {
		m, er := rodarTool(t, s, tool, `{"path":"/etc/segredos.env"}`)
		if er != nil {
			t.Fatalf("%s: %v", tool, er)
		}
		if _, tem := m["provenance"]; tem {
			t.Errorf("%s carrega provenance: ela afirma um retrato que não "+
				"existe, com cobertura e veredito que ninguém calculou", tool)
		}
		leitura, ok := m["read"].(map[string]any)
		if !ok {
			t.Fatalf("%s não carrega o bloco read", tool)
		}
		if leitura["at"] == nil || leitura["source"] == nil {
			t.Errorf("%s: read incompleto: %v", tool, leitura)
		}
		if !strings.Contains(leitura["note"].(string), "NÃO faz parte de nenhum retrato") {
			t.Errorf("%s: a nota precisa dizer em prosa que isto não é um "+
				"retrato — é ela que o modelo lê", tool)
		}
	}
}

// process.environ RECUSA O RETRATO REDIGIDO em vez de devolver a allowlist.
//
// A meia-resposta é o perigo: um environ com oito chaves, forma de resposta
// completa, e nenhuma credencial — do qual se conclui que não havia credencial
// nenhuma. É a mesma mentira que a lista de achados vazia conta, por outra
// porta.
//
// O caminho normal do servidor não produz esse estado (com --allow-secrets toda
// captura é dispensada), e por isso o teste o constrói: uma guarda que nenhum
// teste consegue exercitar é pior que guarda nenhuma, e a forma de resolver isso
// é exercitá-la, não removê-la.
func TestEnvironRecusaRetratoRedigido(t *testing.T) {
	raiz := t.TempDir()
	a := NovoAcervo()
	s := NovoServidor(
		Policy{Modo: ModoLive, Perfil: PerfilCompleto, PermitirSegredos: true},
		a, "teste", nil, func() (*env.Env, error) {
			e := env.Probe(env.Options{Root: raiz, Version: "teste"})
			e.Segredos = false // a captura REDIGE, apesar da policy
			return e, nil
		})
	s.pol.Modo = ModoLive
	t.Cleanup(func() {
		for _, r := range a.Todos() {
			_ = a.Liberar(r.ID)
		}
	})

	e := env.Probe(env.Options{Version: "teste"})
	r, err := a.Capturar(e, EscopoVolatil)
	if err != nil {
		t.Fatal(err)
	}
	if r.SemRedacao() {
		t.Fatal("a captura sem consentimento tem de sair REDIGIDA")
	}

	_, er := rodarTool(t, s, "process.environ",
		fmt.Sprintf(`{"pid":%d,"snapshot_id":%q}`, os.Getpid(), r.ID))
	if er == nil {
		t.Fatal("um retrato redigido só tem o valor da allowlist: responder ali " +
			"devolve uma resposta parcial com forma de resposta completa")
	}
	if !strings.Contains(er.Message, "allowlist") {
		t.Errorf("a recusa precisa explicar o que faltaria: %s", er.Message)
	}
}

// O CARIMBO DIZ QUE A REDAÇÃO FOI DISPENSADA, e não que ela faltou.
//
// "não aplicada" e "dispensada" levam a leituras opostas: a primeira significa
// "desconfie da procedência deste arquivo"; a segunda, "a procedência é
// conhecida e isto aqui é segredo em claro".
func TestCarimboDistingueDispensadaDeAusente(t *testing.T) {
	comSegredo, _ := servidorDeArquivo(t, true)
	capturar(t, comSegredo, "complete")
	p := chamar(t, comSegredo, "host.overview", `{}`)["provenance"].(map[string]any)
	if p["redaction"] != "waived" {
		t.Errorf("com --allow-secrets a procedência tem de dizer waived: %v", p["redaction"])
	}

	semSegredo, _ := servidorDeArquivo(t, false)
	capturar(t, semSegredo, "complete")
	p2 := chamar(t, semSegredo, "host.overview", `{}`)["provenance"].(map[string]any)
	if p2["redaction"] != "applied" {
		t.Errorf("sem a flag, a captura continua redigindo: %v", p2["redaction"])
	}
}

// A LEITURA DIRECIONADA TAMBÉM É TRABALHO NO HOST, e também é cobrada.
//
// Um modelo paginando um arquivo grande (offset += 65536) faz muitas chamadas.
// Sem cobrança, o orçamento de coleta protegeria a captura e deixaria a porta
// aberta ao lado.
func TestLeituraDirecionadaCobraOOrcamento(t *testing.T) {
	s, _ := servidorDeArquivo(t, true)
	_, antes, _ := s.orcamentoDeColeta()

	if _, er := rodarTool(t, s, "file.hash", `{"path":"/etc/segredos.env"}`); er != nil {
		t.Fatal(er)
	}
	gasto, depois, _ := s.orcamentoDeColeta()
	if gasto == 0 || depois >= antes {
		t.Errorf("a leitura não cobrou nada: gasto=%s resta %s -> %s", gasto, antes, depois)
	}

	// E esgotado, ela é recusada como a captura.
	s.pol.OrcamentoDeColeta = 1
	if _, er := rodarTool(t, s, "file.read", `{"path":"/etc/segredos.env"}`); er == nil {
		t.Error("orçamento esgotado e a leitura passou")
	}
}

// servidorVivoCompleto é o perfil completo sobre o host VIVO — o único lugar
// onde process.environ existe.
func servidorVivoCompleto(t *testing.T) *Servidor {
	t.Helper()
	a := NovoAcervo()
	a.Teto = 2
	s := NovoServidor(
		Policy{Modo: ModoLive, Perfil: PerfilCompleto, PermitirSegredos: true},
		a, "teste", nil, func() (*env.Env, error) {
			e := env.Probe(env.Options{Version: "teste"})
			e.Segredos = true
			return e, nil
		})
	t.Cleanup(func() {
		for _, r := range a.Todos() {
			_ = a.Liberar(r.ID)
		}
	})
	return s
}

// O CONSENTIMENTO ATRAVESSA A COLETA, e não só o registry.
//
// --allow-secrets destrava a tool; readEnviron é quem decide se o VALOR entra
// no Facts. Sem esta catraca, desligar a segunda metade passava limpo: o
// servidor serviria process.environ com a allowlist de sempre, com forma de
// resposta completa. Medido — foi uma mutação que passou verde antes de este
// teste existir.
//
// O processo de apoio é real e recebe a variável no EXEC: /proc/<pid>/environ é
// o ambiente daquele instante, e um os.Setenv depois não aparece ali. Isso
// também foi medido, e é por isso que o teste não usa o próprio processo.
func TestConsentimentoChegaAoEnviron(t *testing.T) {
	const chave, valor = "ALETHEIA_SEGREDO_DE_TESTE", "hunter2-nao-esta-na-allowlist"

	iniciar := func() *exec.Cmd {
		cmd := exec.Command("sleep", "30")
		cmd.Env = append(os.Environ(), chave+"="+valor)
		if err := cmd.Start(); err != nil {
			t.Skipf("sem como criar processo de apoio: %v", err)
		}
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		})
		return cmd
	}

	alvo := iniciar()
	s := servidorVivoCompleto(t)
	capturar(t, s, "complete")

	m, er := rodarTool(t, s, "process.environ", fmt.Sprintf(`{"pid":%d}`, alvo.Process.Pid))
	if er != nil {
		t.Fatalf("process.environ: %v", er)
	}
	d := m["data"].(map[string]any)
	amb := d["env"].(map[string]any)
	if amb[chave] != valor {
		t.Fatalf("o consentimento não chegou à COLETA: %s=%v.\n"+
			"A flag destravou a tool e readEnviron continuou descartando o valor "+
			"— a resposta sai com a allowlist e forma de resposta completa, e a "+
			"ausência de credencial nela se leria como prova de que não havia "+
			"nenhuma.", chave, amb[chave])
	}
	if len(amb) < int(d["keys_total"].(float64)) {
		t.Errorf("faltam valores: %d de %v chaves", len(amb), d["keys_total"])
	}

	// E o outro lado: SEM consentimento, o valor não entra no Facts. É o que
	// torna o dump de rotina seguro para sair do host.
	semConsentimento := NovoAcervo()
	e := env.Probe(env.Options{Version: "teste"})
	r, err := semConsentimento.Capturar(e, EscopoCompleto)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = semConsentimento.Liberar(r.ID) })
	for i := range r.Fatos.Processes {
		p := &r.Fatos.Processes[i]
		if p.PID != alvo.Process.Pid {
			continue
		}
		if v, tem := p.Env[chave]; tem {
			t.Errorf("sem --allow-secrets o valor NÃO pode entrar no Facts: %s=%q",
				chave, v)
		}
		var temChave bool
		for _, k := range p.EnvKeys {
			if k == chave {
				temChave = true
			}
		}
		if !temChave {
			t.Error("a CHAVE continua sendo registrada: some-la esconderia que a " +
				"variável existe")
		}
		return
	}
	t.Fatalf("o processo de apoio %d não apareceu na captura", alvo.Process.Pid)
}
