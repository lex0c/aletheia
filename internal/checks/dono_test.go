package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

// tabelaNormal é o passwd/group de um host qualquer: root, um usuário de
// sistema e um humano.
// O `root` com a maior parte dos arquivos não é enfeite: é a forma de qualquer
// host, e sem ele todo dono órfão da fixture responderia por 100% da varredura
// e cairia na regra de dominância. Fixture irreal esconde a regra que importa.
func tabelaNormal() *facts.Facts {
	return &facts.Facts{
		Donos: []facts.DonoDeArquivo{{ID: 0, Arquivos: 400000, Executaveis: 9000}},
		Accounts: []facts.Account{
			{Name: "root", UID: 0}, {Name: "daemon", UID: 1}, {Name: "lex", UID: 1000},
		},
		Grupos: []facts.Grupo{
			{Name: "root", GID: 0}, {Name: "daemon", GID: 1}, {Name: "lex", GID: 1000},
		},
	}
}

// A trava mais importante do check, e a que justifica ele existir com cuidado.
//
// Sem /etc/passwd legível o conjunto de conhecidos vem vazio, e a regra ingênua
// — "não está no mapa, logo é órfão" — acusaria TODO arquivo do host. Um
// relatório assim não é um relatório com falso positivo: é um relatório
// inutilizável, e sai exatamente igual num host limpo e num host invadido.
func TestSemTabelaDeContasNadaEhAvaliado(t *testing.T) {
	f := &facts.Facts{
		Donos: []facts.DonoDeArquivo{
			{ID: 0, Arquivos: 40000, Executaveis: 900, EmSistema: 900,
				ExemploSistema: "/usr/bin/ls", ExemploExec: "/usr/bin/ls"},
			{ID: 1000, Arquivos: 5000},
		},
	}
	r := donoSemConta.Run(donoSemConta, f, testEnv())
	if len(r.Findings) != 0 {
		t.Fatalf("sem passwd lido, NENHUM dono pode ser acusado — o host inteiro "+
			"viraria achado: %v", r.Findings)
	}
	if len(r.Partial) == 0 {
		t.Error("e o silêncio precisa ser DECLARADO: sem a lacuna, 'não achei' " +
			"sai igual a 'não consegui olhar'")
	}
}

// O caso duro: um programa dentro de árvore de distribuição pertencendo a
// ninguém. /usr/bin tem um dono esperado — o gerenciador de pacotes, como root.
func TestExecutavelEmArvoreDeSistemaEhCritico(t *testing.T) {
	f := tabelaNormal()
	f.Donos = append(f.Donos, facts.DonoDeArquivo{
		ID: 1005, Arquivos: 2, Executaveis: 1, EmSistema: 2,
		ExemploExec: "/usr/bin/.sysupd", ExemploSistema: "/usr/bin/.sysupd",
		Exemplos: []string{"/usr/bin/.sysupd", "/usr/lib/x.so"},
	})
	r := donoSemConta.Run(donoSemConta, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %v", r.Findings)
	}
	if r.Findings[0].Sev != check.SevCritical {
		t.Errorf("sev = %v, queria crítico", r.Findings[0].Sev)
	}
	if r.Findings[0].Subject != "uid 1005" {
		t.Errorf("subject = %q: é o número que o operador vai procurar", r.Findings[0].Subject)
	}
	// O caminho precisa sair: sem ele o achado manda procurar sem dizer onde.
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "/usr/bin/.sysupd") {
		t.Error("o executável precisa aparecer na evidência")
	}
}

// E o caso medido no host real: um volume de contêiner, só dado, zero
// executável. Ele TEM que sair como observação — como achado, gastaria a
// atenção do operador e mudaria o exit code de um host limpo.
func TestDonoSoDeDadoEhObservacaoENaoAchado(t *testing.T) {
	f := tabelaNormal()
	f.Donos = append(f.Donos, facts.DonoDeArquivo{
		ID: 999, Arquivos: 1,
		Exemplos: []string{"/home/lex/proj/data/redis/dump.rdb"},
	})
	r := donoSemConta.Run(donoSemConta, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %v", r.Findings)
	}
	if r.Findings[0].Sev != check.SevInfo {
		t.Errorf("sev = %v: sem executável a forma é de dado copiado, e SevInfo "+
			"é o que NÃO move o exit code de um host limpo", r.Findings[0].Sev)
	}
}

// gid órfão não escala para crítico nem com executável: dono de GRUPO não
// confere a identidade do jeito que o uid confere. Tratar os dois igual
// inflaria a gravidade de uma tabela de grupos desalinhada.
func TestGidOrfaoNaoChegaACritico(t *testing.T) {
	f := tabelaNormal()
	f.Donos = append(f.Donos, facts.DonoDeArquivo{
		ID: 5000, Grupo: true, Arquivos: 3, Executaveis: 3, EmSistema: 3,
		ExemploExec: "/usr/bin/algo", ExemploSistema: "/usr/bin/algo",
	})
	r := donoSemConta.Run(donoSemConta, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev == check.SevCritical {
		t.Fatalf("achados = %v", r.Findings)
	}
	if r.Findings[0].Subject != "gid 5000" {
		t.Errorf("subject = %q", r.Findings[0].Subject)
	}
}

// Dono conhecido é silêncio. Num host normal isto cobre 100% dos arquivos, e é
// a condição para o check não ser ruído permanente.
func TestDonoConhecidoNaoDispara(t *testing.T) {
	f := tabelaNormal()
	f.Donos = []facts.DonoDeArquivo{
		{ID: 0, Arquivos: 300000, Executaveis: 9000, EmSistema: 300000},
		{ID: 1000, Arquivos: 400000, Executaveis: 500},
		{ID: 0, Grupo: true, Arquivos: 300000},
		{ID: 1000, Grupo: true, Arquivos: 400000},
	}
	if r := donoSemConta.Run(donoSemConta, f, testEnv()); len(r.Findings) != 0 {
		t.Errorf("dono conhecido não é achado: %v", r.Findings)
	}
}

// O volume inverte a leitura, e isso precisa estar ESCRITO no achado: uma
// árvore inteira com dono único veio pronta de outro lugar. Sem a frase, o
// operador lê "400 mil arquivos de um dono desconhecido" como o pior caso,
// quando é o mais provavelmente benigno.
func TestVolumeGrandeExplicaQueEhArvoreImportada(t *testing.T) {
	f := tabelaNormal()
	f.Donos = append(f.Donos, facts.DonoDeArquivo{ID: 100000, Arquivos: 240000})
	r := donoSemConta.Run(donoSemConta, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %v", r.Findings)
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "árvore importada") {
		t.Errorf("a leitura invertida precisa sair: %v", r.Findings[0].Evidence)
	}
}

// O passo seguinte precisa nomear a tabela CERTA. `getent passwd` num gid
// responde outra coisa ou nada, e um passo que não resolve manda o operador
// concluir "não existe" a partir de uma pergunta errada.
//
// Este defeito era real: a linha estava fixa em `passwd` para os dois casos, e
// apareceu ao mutar a regra do gid — não ao escrever o teste.
func TestPassoSeguinteUsaATabelaCerta(t *testing.T) {
	f := tabelaNormal()
	f.Donos = append(f.Donos,
		facts.DonoDeArquivo{ID: 4000, Arquivos: 1},
		facts.DonoDeArquivo{ID: 5000, Grupo: true, Arquivos: 1})
	r := donoSemConta.Run(donoSemConta, f, testEnv())
	if len(r.Findings) != 2 {
		t.Fatalf("achados = %v", r.Findings)
	}
	for _, fd := range r.Findings {
		passos := strings.Join(fd.NextSteps, " ")
		quer := "getent passwd 4000"
		if strings.HasPrefix(fd.Subject, "gid") {
			quer = "getent group 5000"
		}
		if !strings.Contains(passos, quer) {
			t.Errorf("%s: queria %q nos passos, veio %q", fd.Subject, quer, passos)
		}
	}
}

// `chown 1337:1337` — a forma que uma conta apagada deixa — produz uid E gid
// órfãos apontando para o MESMO arquivo. Dois achados para um arquivo não
// acrescentam nada: diluem o crítico num aviso ao lado, e o operador lê dois
// problemas onde há um.
//
// Este defeito saiu do cenário J2, não da revisão de código.
func TestGidGemeoNaoViraAchadoSeparado(t *testing.T) {
	f := tabelaNormal()
	f.Donos = append(f.Donos,
		facts.DonoDeArquivo{ID: 1337, Arquivos: 1, Executaveis: 1, EmSistema: 1,
			ExemploExec: "/usr/bin/.sysupd", ExemploSistema: "/usr/bin/.sysupd"},
		facts.DonoDeArquivo{ID: 1337, Grupo: true, Arquivos: 1, Executaveis: 1,
			EmSistema: 1, ExemploExec: "/usr/bin/.sysupd",
			ExemploSistema: "/usr/bin/.sysupd"})
	r := donoSemConta.Run(donoSemConta, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("um arquivo, um achado: %v", r.Findings)
	}
	if r.Findings[0].Sev != check.SevCritical || r.Findings[0].Subject != "uid 1337" {
		t.Errorf("o que sobra é o do uid, e crítico: %+v", r.Findings[0])
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "grupo privado") {
		t.Error("mas o gid órfão precisa ser DITO dentro dele: dobrar não é omitir")
	}
}

// E o gid órfão SOZINHO — sem uid órfão de mesmo número — continua sendo
// achado. A dobra é para o gêmeo, não para a classe inteira.
func TestGidOrfaoSozinhoContinuaSendoAchado(t *testing.T) {
	f := tabelaNormal()
	f.Donos = []facts.DonoDeArquivo{
		{ID: 1000, Arquivos: 10},             // uid conhecido
		{ID: 7777, Grupo: true, Arquivos: 4}, // gid órfão, sem uid gêmeo
	}
	r := donoSemConta.Run(donoSemConta, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Subject != "gid 7777" {
		t.Fatalf("achados = %v", r.Findings)
	}
}

// Modo imagem NÃO acusa. Exportar um rootfs para diretório reescreve o dono de
// cada arquivo para quem rodou o `tar` — e aí a imagem inteira aparece com um
// dono que o passwd dela não tem. Uma imagem montada de disco de verdade
// preserva os uids originais, e daqui não dá para saber qual dos dois se está
// olhando.
//
// Este é o defeito que os três cenários de modo imagem pegaram: cada um passou
// a sair com um crítico, todos o mesmo uid do extrator. Nenhuma revisão de
// código tinha visto.
func TestModoImagemRelataMasNaoAcusa(t *testing.T) {
	f := tabelaNormal()
	// uid 2000 e NÃO dominante de propósito: se o extrator possuísse a árvore
	// toda, a regra de dominância também daria INFO e o teste passaria pelo
	// motivo errado. Aqui só a regra de modo imagem pode explicar o resultado.
	f.Donos = append(f.Donos, facts.DonoDeArquivo{
		ID: 2000, Arquivos: 12, Executaveis: 12, EmSistema: 12,
		ExemploExec: "/usr/bin/ls", ExemploSistema: "/usr/bin/ls",
	})
	e := testEnv()
	e.Source = env.SourceImage
	r := donoSemConta.Run(donoSemConta, f, e)
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %v", r.Findings)
	}
	if r.Findings[0].Sev != check.SevInfo {
		t.Errorf("sev = %v: em modo imagem o dono pode ser o de quem extraiu, e "+
			"acusar por isso faria TODA imagem sair com crítico", r.Findings[0].Sev)
	}
	if len(r.Partial) == 0 {
		t.Error("e o motivo precisa estar na cobertura, não só na evidência")
	}
	// O mesmo dado em modo LIVE continua sendo crítico: a diferença é a fonte.
	if r2 := donoSemConta.Run(donoSemConta, f, testEnv()); r2.Findings[0].Sev != check.SevCritical {
		t.Errorf("em modo live o mesmo dono é crítico, e veio %v", r2.Findings[0].Sev)
	}
}

// Dono que responde pela MAIORIA dos arquivos não largou nada aqui: a árvore
// chegou pronta com ele. É a forma de contêiner rootless e de rootfs extraído,
// e é o oposto da leitura ingênua — quanto MAIS arquivos, menos parece implante.
func TestDonoDominanteNaoEhImplante(t *testing.T) {
	f := tabelaNormal()
	f.Donos = append(f.Donos, facts.DonoDeArquivo{
		ID: 100000, Arquivos: 900000, Executaveis: 30000, EmSistema: 40000,
		ExemploExec: "/usr/bin/bash", ExemploSistema: "/usr/bin/bash",
	})
	r := donoSemConta.Run(donoSemConta, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("achados = %v", r.Findings)
	}
	if r.Findings[0].Sev != check.SevInfo {
		t.Errorf("sev = %v: 900 mil arquivos de um dono só é árvore importada",
			r.Findings[0].Sev)
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "chegou pronta") {
		t.Error("e a leitura invertida precisa estar escrita")
	}
}

// Mas a proporção só vale com amostra: "1 de 1 arquivo" não é dominância, é uma
// varredura que mal começou. Sem o piso, um host onde a varredura foi negada
// quase inteira classificaria o pouco que viu como árvore importada — e o
// implante sairia como observação.
func TestProporcaoNaoValeSobreAmostraMinuscula(t *testing.T) {
	f := &facts.Facts{
		Accounts: []facts.Account{{Name: "root", UID: 0}},
		Grupos:   []facts.Grupo{{Name: "root", GID: 0}},
		Donos: []facts.DonoDeArquivo{{
			ID: 1337, Arquivos: 2, Executaveis: 1, EmSistema: 2,
			ExemploExec: "/usr/bin/.x", ExemploSistema: "/usr/bin/.x",
		}},
	}
	r := donoSemConta.Run(donoSemConta, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("dois arquivos são 100%% de uma amostra de dois, e isso não é "+
			"dominância: %v", r.Findings)
	}
}
