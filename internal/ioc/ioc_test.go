package ioc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func escrever(t *testing.T, conteudo string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "incidente.yaml")
	if err := os.WriteFile(p, []byte(conteudo), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A forma da SPEC precisa carregar como está escrita lá — é o exemplo que o
// operador vai copiar.
func TestCarregarFormaDaSpec(t *testing.T) {
	p := escrever(t, `# incidente.yaml
ips:     [198.51.100.241]
hashes:  ["sha256:9f2c1b0a7d3e4f5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c"]
paths:   ["*/htop/defunct", "*.dat"]
strings: [GS_ARGS, gs-netcat, gsocket_dso]
keys:    ["ssh-rsa AAAAB3NzaC1yc2EAAAA user@atacante"]
users:   [backup2]
`)
	l, err := Carregar(p)
	if err != nil {
		t.Fatalf("carregar: %v", err)
	}
	if len(l.Avisos) != 0 {
		t.Errorf("a forma da SPEC não pode produzir aviso: %v", l.Avisos)
	}
	conta := map[Tipo]int{}
	for _, i := range l.Itens {
		conta[i.Tipo]++
	}
	quer := map[Tipo]int{IP: 1, Hash: 1, Caminho: 2, Texto: 3, Chave: 1, Usuario: 1}
	for tipo, n := range quer {
		if conta[tipo] != n {
			t.Errorf("%s: %d, queria %d (resumo: %s)", tipo, conta[tipo], n, l.Resumo())
		}
	}
	// A chave é guardada pelo BLOB: comparar a linha inteira faria a mesma
	// chave não casar consigo mesma quando o comentário muda.
	for _, i := range l.Itens {
		if i.Tipo == Chave && i.Valor != "AAAAB3NzaC1yc2EAAAA" {
			t.Errorf("blob da chave = %q", i.Valor)
		}
	}
}

// A forma em bloco é a outra que um arquivo YAML de verdade tem.
func TestCarregarFormaEmBloco(t *testing.T) {
	l, err := Carregar(escrever(t, `ips:
  - 198.51.100.241
  - 10.0.0.9
users:
  - backup2
`))
	if err != nil {
		t.Fatal(err)
	}
	if n := len(l.Do(IP)); n != 2 {
		t.Errorf("ips = %d, queria 2", n)
	}
	if n := len(l.Do(Usuario)); n != 1 {
		t.Errorf("users = %d, queria 1", n)
	}
}

// E a forma mais comum de todas no meio de um incidente: a lista colada, um
// indicador por linha, sem chave nenhuma. O tipo sai da FORMA.
func TestCarregarListaCrua(t *testing.T) {
	l, err := Carregar(escrever(t, `198.51.100.241
9f2c1b0a7d3e4f5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c
/usr/local/sbin/systemd-oomd-helper
gs-netcat
`))
	if err != nil {
		t.Fatal(err)
	}
	esperado := map[string]Tipo{
		"198.51.100.241": IP,
		"9f2c1b0a7d3e4f5a6b7c8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c": Hash,
		"/usr/local/sbin/systemd-oomd-helper":                              Caminho,
		"gs-netcat":                                                        Texto,
	}
	for _, i := range l.Itens {
		if quer := esperado[i.Bruto]; quer != i.Tipo {
			t.Errorf("%q classificado como %s, queria %s", i.Bruto, i.Tipo, quer)
		}
	}
	if len(l.Itens) != 4 {
		t.Errorf("itens = %d, queria 4", len(l.Itens))
	}
}

// O caso que decide o desenho: uma lista que carrega pela metade EM SILÊNCIO é
// pior que uma que falha. Chave escrita errada vira aviso visível, não item.
func TestChaveDesconhecidaViraAviso(t *testing.T) {
	l, err := Carregar(escrever(t, `ipss: [198.51.100.241]
users: [backup2]
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Itens) != 1 {
		t.Errorf("itens = %d: a chave errada não pode virar indicador solto", len(l.Itens))
	}
	if len(l.Avisos) != 1 || !strings.Contains(l.Avisos[0], "chave desconhecida") {
		t.Errorf("avisos = %v", l.Avisos)
	}
}

// Arquivo que existe, foi lido e não produziu indicador nenhum é o pior caso:
// a varredura seguiria limpa e o operador leria "nada encontrado" achando que
// procurou.
func TestListaVaziaEhErro(t *testing.T) {
	if _, err := Carregar(escrever(t, "# só comentário\n\n")); err != ErrVazia {
		t.Errorf("erro = %v, queria ErrVazia", err)
	}
}

func TestHashNormalizadoPorTamanho(t *testing.T) {
	l, err := Carregar(escrever(t, `hashes:
  - d41d8cd98f00b204e9800998ecf8427e
  - da39a3ee5e6b4b0d3255bfef95601890afd80709
  - SHA256:E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855
  - 1234
`))
	if err != nil {
		t.Fatal(err)
	}
	algos := map[string]bool{}
	for _, i := range l.Do(Hash) {
		algos[i.Algo] = true
		if i.Valor != strings.ToLower(i.Valor) {
			t.Errorf("hash não normalizado para minúsculas: %q", i.Valor)
		}
	}
	for _, a := range []string{"md5", "sha1", "sha256"} {
		if !algos[a] {
			t.Errorf("algoritmo %s não foi deduzido", a)
		}
	}
	// "1234" não é hash de nada, e vira aviso em vez de item silencioso.
	if len(l.Avisos) != 1 {
		t.Errorf("avisos = %v", l.Avisos)
	}
}

// O curinga ATRAVESSA a barra, e é uma diferença deliberada para o glob de
// shell: quem escreve `*/htop/defunct` não sabe em que home o arquivo está.
func TestCuringaAtravessaBarra(t *testing.T) {
	casos := []struct {
		padrao, valor string
		quer          bool
	}{
		{"*/htop/defunct", "/home/n/.config/htop/defunct", true},
		{"*/htop/defunct", "/home/n/.config/htop/outro", false},
		{"*.dat", "/var/tmp/coleta.dat", true},
		{"/tmp/*", "/tmp/x/y/z", true},
		{"/usr/bin/ssh?", "/usr/bin/sshd", true},
		{"/usr/bin/ssh?", "/usr/bin/ssh", false},
		{"/etc/passwd", "/etc/passwd", true},
		{"/etc/passwd", "/etc/passwd-", false},
		{"*a*b*c*", "xxaxxbxxcxx", true},
		{"*a*b*c*", "xxaxxcxxbxx", false},
	}
	for _, c := range casos {
		if got := casaCuringa(c.padrao, c.valor); got != c.quer {
			t.Errorf("casaCuringa(%q, %q) = %v, queria %v", c.padrao, c.valor, got, c.quer)
		}
	}
}

// A comparação é do TIPO, não de quem chama: texto casa por conteúdo, IP casa
// exato. Trocar as duas produziria falso positivo em massa de um lado e
// silêncio do outro.
func TestSemanticaPorTipo(t *testing.T) {
	l, err := Carregar(escrever(t, `ips: [10.0.0.9]
strings: [gs-netcat]
paths: ["/tmp/*"]
`))
	if err != nil {
		t.Fatal(err)
	}
	if n := len(l.Casar(Texto, "/usr/local/bin/gs-netcat --daemon")); n != 1 {
		t.Errorf("texto deveria casar por CONTEÚDO: %d", n)
	}
	if n := len(l.Casar(IP, "10.0.0.99")); n != 0 {
		t.Errorf("IP casa EXATO: 10.0.0.99 não é 10.0.0.9")
	}
	if n := len(l.Casar(Caminho, "/tmp/.x/implante")); n != 1 {
		t.Errorf("caminho deveria casar por curinga: %d", n)
	}
	// E tipo errado não casa: um indicador de IP não é procurado em caminho.
	if n := len(l.Casar(Caminho, "10.0.0.9")); n != 0 {
		t.Errorf("indicador de IP não pode casar como caminho")
	}
}

func TestTemEAlgoritmos(t *testing.T) {
	l, err := Carregar(escrever(t, "users: [backup2]\n"))
	if err != nil {
		t.Fatal(err)
	}
	// Sem hash na lista, o coletor não paga custo nenhum — é o Tem que decide.
	if l.Tem(Hash) {
		t.Error("Tem(Hash) precisa ser falso: a lista não tem hash")
	}
	if !l.Tem(Usuario) {
		t.Error("Tem(Usuario) precisa ser verdadeiro")
	}
	if n := len(l.Algoritmos()); n != 0 {
		t.Errorf("algoritmos = %d, queria 0", n)
	}
}

// O "#" colado no valor é PARTE do valor.
//
// O corte era em qualquer cerquilha, e truncava o indicador em silêncio: um
// caminho como /tmp/.cache#1 virava /tmp/.cache e deixava de casar. É um falso
// negativo no único lugar do programa onde o operador disse, com todas as
// letras, o que procurar — e ele não recebia aviso nenhum.
func TestCerquilhaColadaNaoEhComentario(t *testing.T) {
	p := escrever(t, "# lista do incidente\n"+
		"path: /tmp/.cache#1\n"+
		"path: /opt/app/x   # este É comentário\n"+
		"string: sessao#4821\n")
	l, err := Carregar(p)
	if err != nil {
		t.Fatal(err)
	}
	quer := map[string]Tipo{
		"/tmp/.cache#1": Caminho,
		"/opt/app/x":    Caminho,
		"sessao#4821":   Texto,
	}
	visto := map[string]bool{}
	for _, it := range l.Itens {
		tipo, ok := quer[it.Valor]
		if !ok {
			t.Errorf("indicador truncado ou inesperado: %q", it.Valor)
			continue
		}
		if it.Tipo != tipo {
			t.Errorf("%q veio como %q", it.Valor, it.Tipo)
		}
		visto[it.Valor] = true
	}
	for v := range quer {
		if !visto[v] {
			t.Errorf("indicador perdido: %q", v)
		}
	}
}
