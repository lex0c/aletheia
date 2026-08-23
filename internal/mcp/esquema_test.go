package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/dump"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

// Um validador de JSON Schema do subconjunto que estes schemas usam.
//
// Não é um validador geral, e não tenta ser: cobre `type`, `required`,
// `properties`, `additionalProperties:false`, `enum` e `items`, que é o dialeto
// inteiro de esquemas.go. Vale o pouco código porque o `outputSchema` é uma
// PROMESSA a um cliente que não tem como conferi-la a tempo — quando ele
// diverge da saída real, o modelo lê o documento errado sem que nada quebre.
func validarEsquema(caminho string, esq json.RawMessage, valor any) []string {
	var s map[string]any
	if err := json.Unmarshal(esq, &s); err != nil {
		return []string{fmt.Sprintf("%s: schema ilegível: %v", caminho, err)}
	}
	return conferirValor(caminho, s, valor)
}

func conferirValor(caminho string, s map[string]any, v any) []string {
	var falhas []string
	nome := func() string {
		if caminho == "" {
			return "(raiz)"
		}
		return caminho
	}

	if e, ok := s["enum"].([]any); ok {
		achou := false
		for _, opt := range e {
			if opt == v {
				achou = true
				break
			}
		}
		if !achou {
			falhas = append(falhas, fmt.Sprintf("%s: %#v não está no enum %v", nome(), v, e))
		}
	}

	tipo, _ := s["type"].(string)
	if tipo != "" && v != nil && !casaTipo(tipo, v) {
		return append(falhas, fmt.Sprintf("%s: schema diz %q, a saída tem %T",
			nome(), tipo, v))
	}

	switch tipo {
	case "object":
		m, ok := v.(map[string]any)
		if !ok {
			return falhas // nil: ausência é problema de `required`, tratado abaixo
		}
		props, _ := s["properties"].(map[string]any)
		if req, ok := s["required"].([]any); ok {
			for _, r := range req {
				k, _ := r.(string)
				if _, tem := m[k]; !tem {
					falhas = append(falhas, fmt.Sprintf(
						"%s: o schema exige %q e a saída não tem", nome(), k))
				}
			}
		}
		if add, ok := s["additionalProperties"].(bool); ok && !add {
			var extras []string
			for k := range m {
				if _, declarado := props[k]; !declarado {
					extras = append(extras, k)
				}
			}
			sort.Strings(extras)
			for _, k := range extras {
				falhas = append(falhas, fmt.Sprintf(
					"%s: %q não está declarado e additionalProperties é false", nome(), k))
			}
		}
		// E A DIREÇÃO CONTRÁRIA: toda chave da saída está DECLARADA.
		//
		// Satisfazer o schema não basta. Um campo novo no struct — `scope` na
		// procedência foi o caso real — passa por qualquer validação e não
		// aparece no contrato: o cliente recebe informação que não sabe existir,
		// e o modelo só a usa por acaso. Um campo que viaja e não é declarado é
		// um campo que não existe para quem lê o schema.
		//
		// A regra só vale onde o schema declara `properties`: `{"type":"object"}`
		// sem propriedade nenhuma é a forma deliberada de dizer "objeto opaco".
		if len(props) > 0 {
			var naoDeclaradas []string
			for k := range m {
				if _, ok := props[k]; !ok {
					naoDeclaradas = append(naoDeclaradas, k)
				}
			}
			sort.Strings(naoDeclaradas)
			for _, k := range naoDeclaradas {
				falhas = append(falhas, fmt.Sprintf(
					"%s: a saída traz %q e o schema não o declara", nome(), k))
			}
		}

		chaves := make([]string, 0, len(m))
		for k := range m {
			chaves = append(chaves, k)
		}
		sort.Strings(chaves)
		for _, k := range chaves {
			sub, ok := props[k].(map[string]any)
			if !ok {
				continue
			}
			falhas = append(falhas, conferirValor(caminho+"."+k, sub, m[k])...)
		}

	case "array":
		lista, ok := v.([]any)
		if !ok {
			return falhas
		}
		item, ok := s["items"].(map[string]any)
		if !ok {
			return falhas
		}
		for i, el := range lista {
			falhas = append(falhas, conferirValor(
				fmt.Sprintf("%s[%d]", caminho, i), item, el)...)
		}
	}
	return falhas
}

func casaTipo(tipo string, v any) bool {
	switch tipo {
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "string":
		_, ok := v.(string)
		return ok
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "number":
		_, ok := v.(float64)
		return ok
	case "integer":
		f, ok := v.(float64)
		return ok && f == math.Trunc(f)
	}
	return true
}

// paraJSON leva a saída da tool pelo MESMO caminho que o transporte usa —
// json.Marshal e de volta — porque é a forma pós-serialização que o cliente
// valida, e não a struct Go.
func paraJSON(v any) (any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func juntar(fs []string) string { return "\n  " + strings.Join(fs, "\n  ") }

// TODA TOOL SATISFAZ O PRÓPRIO outputSchema.
//
// O `outputSchema` é a única coisa que um cliente tem para saber ler a resposta,
// e ele é escrito à mão num arquivo separado do struct que produz a saída. As
// duas metades derivam sozinhas: o campo é renomeado, o struct ganha um novo, a
// obrigatoriedade muda — e nada quebra, porque nada compara os dois.
//
// Já derivaram. session.status declarava `redacted_at_source: boolean` e emitia
// `redaction` como lista de objetos: um cliente que confiasse no schema leria
// "não redigido" a partir de um campo que nunca chegou.
//
// A tabela de argumentos é parte da catraca. Uma tool nova que exija argumento e
// não apareça aqui falha pedindo a linha, porque uma tool que este teste não
// consegue chamar é uma tool que ele não valida — e o silêncio se leria como
// aprovação.
func TestTodaToolSatisfazOProprioOutputSchema(t *testing.T) {
	s, _ := servidorDeTeste(t, fatosComAchado())
	segundoRetrato(t, s)
	validarRegistry(t, s, argsDeTeste(t, s))
}

// snapshot.compare precisa de DOIS, e recusa comparar um retrato consigo mesmo.
func segundoRetrato(t *testing.T, s *Servidor) {
	t.Helper()
	f := fatosComAchado()
	f.CollectedAt = "2026-08-17T22:03:11Z"
	var buf bytes.Buffer
	if err := dump.De(ambienteDeTeste(), f).Escrever(&buf); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "depois.json")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.acervo.Carregar(p); err != nil {
		t.Fatal(err)
	}
}

// fatosDeTeste é deliberadamente LIMPO — é a fixture da catraca que trava
// "vazio não é limpo". Aqui é preciso o contrário: sem um achado, finding.get
// nunca roda, e um teste que não consegue chamar a tool passa por omissão.
//
// O gatilho é um processo rodando de /tmp, que é §3.x do próprio catálogo e não
// depende de nenhum outro fato colhido.
func fatosComAchado() *facts.Facts {
	f := fatosDeTeste()
	f.Processes = append(f.Processes, facts.Process{
		PID: 4021, PPID: 812, Comm: "sh", Exe: "/tmp/.cache/sh",
	})
	return f
}

// E o mesmo em modo live, onde vivem as duas tools que mudam estado — e onde os
// retratos nascem de captura, não de artefato.
func TestOutputSchemaTambemValeEmModoLive(t *testing.T) {
	s := servidorVivo(t, ModoLive, "")
	// Dois capturados aqui, mais o que a própria snapshot.capture tira quando
	// chega a vez dela no registry.
	s.acervo.Teto = 3
	// DOIS COMPLETOS, e não um completo mais dois voláteis.
	//
	// A versão anterior capturava um completo e dois voláteis, e parDeMesmoEscopo
	// achava o par volátil — de modo que a catraca de schema estava exercitando
	// justamente o caminho que snapshot.compare não devia aceitar. Ela validava
	// a forma de uma resposta que não devia existir.
	capturar(t, s, "complete")
	capturar(t, s, "complete")
	validarRegistry(t, s, argsDeTeste(t, s))
}

// E o perfil COMPLETO, que é onde vive a família file.* — a entrega 3.
//
// Sem este servidor, os schemas das cinco tools novas nunca seriam validados: os
// dois testes acima montam perfil padrão, onde elas nem entram no registry. Uma
// catraca que não alcança o código novo é uma catraca que aprova por omissão.
func TestOutputSchemaValeNoPerfilCompleto(t *testing.T) {
	s := servidorCompleto(t)
	// Dois completos: snapshot.compare exige os dois, e a captura da própria
	// tool no registry consome a terceira vaga.
	capturar(t, s, "complete")
	capturar(t, s, "complete")
	validarRegistry(t, s, argsDeTeste(t, s))
}

// servidorCompleto monta o servidor da entrega 3 com um alvo de verdade em
// disco: as tools de arquivo abrem descritor, e um caminho inventado só
// exercitaria o caminho de erro.
func servidorCompleto(t *testing.T) *Servidor {
	t.Helper()
	raiz := t.TempDir()
	if err := os.MkdirAll(filepath.Join(raiz, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(raiz, "etc/alvo.conf"),
		[]byte("token=hunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a := NovoAcervo()
	a.Teto = 3
	pol := Policy{Modo: ModoLive, Perfil: PerfilCompleto, PermitirSegredos: true}
	s := NovoServidor(pol, a, "teste", nil, func() (*env.Env, error) {
		e := env.Probe(env.Options{Version: "teste"})
		e.Segredos = true
		return e, nil
	})
	t.Cleanup(func() {
		for _, r := range a.Todos() {
			_ = a.Liberar(r.ID)
		}
	})
	t.Setenv("ALETHEIA_ALVO_DE_TESTE", filepath.Join(raiz, "etc/alvo.conf"))
	return s
}

func validarRegistry(t *testing.T, s *Servidor, args map[string]string) {
	t.Helper()
	for _, f := range s.ativas {
		a, declarado := args[f.Nome]
		if !declarado {
			a = `{}`
		}
		// Com mais de um retrato carregado, toda tool endereçada EXIGE o
		// snapshot_id — escolher um padrão responderia sobre o retrato errado
		// em silêncio. Quem precisa dele é o próprio inputSchema quem diz.
		a = comSnapshot(t, s, f, a)
		saida, er := f.Rodar(s, json.RawMessage(a))
		if er != nil {
			if !declarado && er.Code == CodInvalidParams {
				t.Errorf("%s exige argumento e não está na tabela de esquema_test.go: %s\n"+
					"Uma tool que este teste não consegue chamar é uma tool que ele "+
					"não valida.", f.Nome, er.Message)
				continue
			}
			t.Errorf("%s(%s): %s", f.Nome, a, er.Message)
			continue
		}
		v, err := paraJSON(saida)
		if err != nil {
			t.Errorf("%s: a saída não serializa: %v", f.Nome, err)
			continue
		}
		if falhas := validarEsquema("", f.Saida, v); len(falhas) > 0 {
			t.Errorf("%s: a saída não satisfaz o outputSchema que a própria tool "+
				"publica:%s", f.Nome, juntar(falhas))
		}
	}
}

// Os argumentos vêm do próprio servidor sempre que possível: um finding_ref
// literal envelhece junto com as fixtures e vira um teste que passa por não
// conseguir rodar.
func argsDeTeste(t *testing.T, s *Servidor) map[string]string {
	t.Helper()
	args := map[string]string{
		"process.get":  `{"pid":812}`,
		"process.tree": `{"pid":812}`,
		"net.ip":       `{"address":"127.0.0.1"}`,
		"net.port":     `{"port":22}`,
		"file.inspect": `{"path":"/etc/passwd"}`,
		// snapshot.capture cunha um retrato de verdade — por isso o teto do
		// acervo precisa de uma vaga a mais que o número de capturas do teste.
		"snapshot.capture": `{"scope":"volatile"}`,

		// A família file.* lê o host AGORA. O alvo é um arquivo que existe em
		// qualquer Linux e que este processo consegue abrir.
		"file.read":         `{"path":"/etc/hostname"}`,
		"file.hash":         `{"path":"/etc/hostname"}`,
		"file.xattrs":       `{"path":"/etc/hostname"}`,
		"file.capabilities": `{"path":"/etc/hostname"}`,
	}
	if _, tem := s.porNome["process.environ"]; tem {
		args["process.environ"] = fmt.Sprintf(`{"pid":%d}`, os.Getpid())
	}

	if _, tem := s.porNome["finding.get"]; tem {
		var completo string
		for _, r := range s.acervo.Todos() {
			if r.Escopo() == EscopoCompleto {
				completo = r.ID
				break
			}
		}
		lista := chamar(t, s, "findings.list",
			fmt.Sprintf(`{"limit":1,"snapshot_id":%q}`, completo))
		itens := lista["data"].(map[string]any)["items"].([]any)
		if len(itens) == 0 {
			t.Fatal("a fixture precisa produzir pelo menos um achado para " +
				"finding.get ser validada")
		}
		ref := itens[0].(map[string]any)["finding_ref"].(string)
		args["finding.get"] = fmt.Sprintf(
			`{"finding_ref":%q,"snapshot_id":%q}`, ref, completo)
	}
	if _, tem := s.porNome["snapshot.info"]; tem {
		args["snapshot.info"] = fmt.Sprintf(`{"snapshot_id":%q}`, s.acervo.Todos()[0].ID)
	}
	if _, tem := s.porNome["snapshot.compare"]; tem {
		antes, depois, ok := parDeCompletos(s)
		if !ok {
			t.Fatal("snapshot.compare precisa de dois retratos COMPLETOS")
		}
		args["snapshot.compare"] = fmt.Sprintf(
			`{"before_id":%q,"after_id":%q}`, antes, depois)
	}
	if _, tem := s.porNome["snapshot.release"]; tem {
		r := s.acervo.Todos()
		args["snapshot.release"] = fmt.Sprintf(`{"snapshot_id":%q}`, r[len(r)-1].ID)
	}
	return args
}

// comSnapshot injeta o snapshot_id quando o inputSchema da tool o declara, e
// escolhe um retrato de alcance suficiente para ela. É por reflexão sobre o
// schema, e não por lista: uma tool endereçada nova é coberta sem tocar aqui.
func comSnapshot(t *testing.T, s *Servidor, f Ferramenta, args string) string {
	t.Helper()
	var esq struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if json.Unmarshal(f.Entrada, &esq) != nil {
		return args
	}
	if _, quer := esq.Properties["snapshot_id"]; !quer {
		return args
	}
	var m map[string]any
	if json.Unmarshal([]byte(args), &m) != nil {
		return args
	}
	if _, ja := m["snapshot_id"]; ja {
		return args
	}
	for _, r := range s.acervo.Todos() {
		if f.EscopoMin == EscopoCompleto && r.Escopo() != EscopoCompleto {
			continue
		}
		m["snapshot_id"] = r.ID
		b, _ := json.Marshal(m)
		return string(b)
	}
	t.Fatalf("%s exige alcance %q e nenhum retrato carregado serve", f.Nome, f.EscopoMin)
	return args
}

// parDeCompletos escolhe o par que snapshot.compare aceita. O critério é
// COMPLETO, e não "mesmo alcance": dois voláteis têm o mesmo alcance e mesmo
// assim não sustentam comparação nenhuma.
func parDeCompletos(s *Servidor) (string, string, bool) {
	var ids []string
	for _, r := range s.acervo.Todos() {
		if r.Escopo() == EscopoCompleto {
			ids = append(ids, r.ID)
		}
	}
	if len(ids) < 2 {
		return "", "", false
	}
	return ids[0], ids[1], true
}
