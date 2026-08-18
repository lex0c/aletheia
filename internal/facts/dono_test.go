package facts

import "testing"

// O resumo por diretório precisa DEDUPLICAR: cem arquivos do mesmo dono são uma
// entrada com contagem cem, não cem entradas. Sem isso o merge global receberia
// uma entrada por arquivo e o lock da varredura viraria fila.
func TestResumoAgrupaPorDono(t *testing.T) {
	var r resumoDeDonos
	for i := 0; i < 100; i++ {
		r.ver(false, 1000, false, false, "/home/lex/a")
	}
	r.ver(false, 0, true, true, "/usr/bin/ls")
	if len(r.itens) != 2 {
		t.Fatalf("itens = %d, queria 2", len(r.itens))
	}
	if r.itens[0].Arquivos != 100 {
		t.Errorf("arquivos = %d", r.itens[0].Arquivos)
	}
	if r.itens[1].Executaveis != 1 || r.itens[1].EmSistema != 1 {
		t.Errorf("o executável em árvore de sistema se perdeu: %+v", r.itens[1])
	}
}

// Os exemplos são limitados, mas o executável e o caminho de sistema NÃO podem
// depender de caber na amostra: num dono com 400 mil arquivos de dados, o único
// executável nunca cairia nos três primeiros — e é ele que decide a gravidade.
func TestExemploDeExecutavelSobreviveAoTeto(t *testing.T) {
	var r resumoDeDonos
	for i := 0; i < 50; i++ {
		r.ver(false, 1005, false, false, "/srv/dados/x")
	}
	r.ver(false, 1005, true, true, "/usr/bin/.sysupd")
	d := r.itens[0]
	if len(d.Exemplos) != maxExemplosDono {
		t.Errorf("exemplos = %d, queria o teto %d", len(d.Exemplos), maxExemplosDono)
	}
	if d.ExemploExec != "/usr/bin/.sysupd" || d.ExemploSistema != "/usr/bin/.sysupd" {
		t.Errorf("o executável precisa ser guardado à parte: %+v", d)
	}
}

// O merge soma e preserva. Um dono visto em dois diretórios por dois
// trabalhadores diferentes é UM dono.
func TestAcumuladorFundeEPreservaOsExemplos(t *testing.T) {
	a := novoAcumuladorDeDonos()
	a.juntar([]DonoDeArquivo{{ID: 7, Arquivos: 3, Exemplos: []string{"/a"}}})
	a.juntar([]DonoDeArquivo{{ID: 7, Arquivos: 4, Executaveis: 1,
		ExemploExec: "/usr/bin/z", EmSistema: 1, ExemploSistema: "/usr/bin/z"}})
	out := consolidarDonos(a)
	if len(out) != 1 {
		t.Fatalf("donos = %+v", out)
	}
	if out[0].Arquivos != 7 || out[0].Executaveis != 1 {
		t.Errorf("soma errada: %+v", out[0])
	}
	if out[0].ExemploExec != "/usr/bin/z" {
		t.Errorf("o exemplo do segundo lote se perdeu: %+v", out[0])
	}
}

// uid e gid com o MESMO número são donos diferentes. No host onde isto foi
// medido o uid 999 era órfão e o gid 999 se chamava `adm` — juntar os dois teria
// escondido o achado atrás de um nome que pertence à outra tabela.
func TestUidEGidComOMesmoNumeroNaoSeMisturam(t *testing.T) {
	var r resumoDeDonos
	r.ver(false, 999, false, false, "/srv/a")
	r.ver(true, 999, false, false, "/srv/a")
	if len(r.itens) != 2 {
		t.Fatalf("uid 999 e gid 999 são dois donos: %+v", r.itens)
	}
	a := novoAcumuladorDeDonos()
	a.juntar(r.itens)
	out := consolidarDonos(a)
	if len(out) != 2 || out[0].Grupo || !out[1].Grupo {
		t.Errorf("a ordem é uid antes de gid, e estável: %+v", out)
	}
}

// Estourar o teto de identidades não pode passar em silêncio: um dono sem conta
// pode estar entre as descartadas, e aí "não achei" sairia igual a "parei de
// contar".
func TestTetoDeIdentidadesEhDeclarado(t *testing.T) {
	a := novoAcumuladorDeDonos()
	for i := 0; i < maxDonosDistintos+5; i++ {
		a.juntar([]DonoDeArquivo{{ID: i, Arquivos: 1}})
	}
	if !a.estourou {
		t.Error("o teto foi ultrapassado e o acumulador não marcou")
	}
	if n := len(consolidarDonos(a)); n != maxDonosDistintos {
		t.Errorf("guardados = %d, queria o teto %d", n, maxDonosDistintos)
	}
}

// A árvore de sistema é prefixo de CAMINHO, e precisa não pegar vizinho: /usrX
// não é /usr, e /home/usr/bin também não.
func TestArvoreDeSistemaNaoPegaVizinho(t *testing.T) {
	sim := []string{"/usr/bin/ls", "/etc/passwd", "/opt/app/run", "/lib64/x.so"}
	nao := []string{"/usrlocal/x", "/home/lex/usr/bin/y", "/var/tmp/z", "/srv/etc/a"}
	for _, p := range sim {
		if !ehArvoreDeSistema(p) {
			t.Errorf("%s devia ser árvore de sistema", p)
		}
	}
	for _, p := range nao {
		if ehArvoreDeSistema(p) {
			t.Errorf("%s NÃO é árvore de sistema", p)
		}
	}
}
