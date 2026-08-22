package drift

import (
	"testing"

	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

// OS QUATRO DEFEITOS DE OBSERVABILIDADE POR FONTE, cada um em teste próprio.
//
// A forma é sempre a mesma, e é a que sobreviveu a todas as catracas
// anteriores: a fonte de UMA família falha (ou nem existe naquele modo de
// coleta), e a família AO LADO — que leu perfeitamente o que compara — perde a
// comparação, ou pior, ganha uma mudança que ninguém fez.
//
// A catraca do commit anterior impede duas FAMÍLIAS de dividirem uma chave de
// lacuna. O que ela não alcança é uma chave (ou um fato de completude) com dois
// ESCRITORES de significados diferentes, nem uma fonte que não existe naquele
// modo. Estes quatro testes são a versão executável dessa lição.

func mudancasDe(d facts.Drift, tipo string) []facts.MudancaDrift {
	var out []facts.MudancaDrift
	for _, m := range d.Mudancas {
		if m.Tipo == tipo {
			out = append(out, m)
		}
	}
	return out
}

func coberturaDe(t *testing.T, d facts.Drift, tipo string) facts.CoberturaDrift {
	t.Helper()
	for _, c := range d.Cobertura {
		if c.Tipo == tipo {
			return c
		}
	}
	t.Fatalf("a família %q precisa aparecer na cobertura", tipo)
	return facts.CoberturaDrift{}
}

// HELPER1: o retrato de IMAGEM não tem /proc, e a lista de helpers sai vazia
// porque o coletor nem roda. Isso não é helper removido.
//
// A CLI compara qualquer par de dumps — confere ordem temporal, não modo de
// coleta —, e um `core_pattern` que some é exatamente o que um implante faria
// depois de usá-lo. Inventar esse achado é pior que não ter a família.
func TestHELPER1RetratoDeImagemNaoRemoveHelper(t *testing.T) {
	vivo := &facts.Facts{
		HelpersLidos: true,
		Helpers: []facts.HelperDoKernel{{
			Nome: "core_pattern", Fonte: "/proc/sys/kernel/core_pattern",
			Valor: "|/usr/lib/systemd/systemd-coredump",
			Alvo:  "/usr/lib/systemd/systemd-coredump",
		}},
	}
	// Modo image: sem procfs, sem coletor, sem fato.
	imagem := &facts.Facts{}

	d := Comparar(
		lado(vivo, tudoVisivel|env.CapProcfs),
		Lado{F: imagem, Caps: env.CapFilesystem | env.CapRoot, Host: "h",
			Quando: "2026-01-02T00:00:00Z"})

	for _, m := range mudancasDe(d, "kernel.helper") {
		t.Errorf("o retrato de imagem inventou uma mudança de helper: %s %s %s",
			m.Kind, m.ID, m.Campo)
	}
	if c := coberturaDe(t, d, "kernel.helper"); c.Simetrico || !c.SemSumiu {
		t.Errorf("a cobertura tinha de cair, e do lado do que SUMIU: %+v", c)
	}
}

// MODCONF1: uma subárvore de /lib/modules ilegível NÃO pode suprimir a
// comparação de um modprobe.d que foi lido inteiro.
//
// As duas escrevem a chave `modprobe`, e são perguntas diferentes: o que o boot
// manda carregar, e quais .ko existem em disco. Enquanto a família dependia da
// chave, carregar um implante de kernel numa árvore sem permissão apagava a
// comparação que o denunciaria.
func TestMODCONF1ArvoreDeModulosIlegivelNaoCalaModprobeD(t *testing.T) {
	conf := func(cmd string) facts.ModuleConf {
		return facts.ModuleConf{File: "/etc/modprobe.d/x.conf", Kind: "install",
			Module: "foo", Cmd: cmd}
	}
	antes := &facts.Facts{ModuleConfigCompleto: true, Modules: []facts.ModuleConf{conf("/bin/true")}}
	depois := &facts.Facts{ModuleConfigCompleto: true, Modules: []facts.ModuleConf{conf("/tmp/.x")}}
	// A lacuna é da OUTRA fonte: /lib/modules, na mesma chave.
	depois.PersistDenied = map[string][]string{
		"modprobe": {"/lib/modules/6.6.0/kernel/net (sob /lib/modules) não pôde ser listado"},
	}

	d := Comparar(lado(antes, tudoVisivel),
		Lado{F: depois, Caps: tudoVisivel, Host: "h", Quando: "2026-01-02T00:00:00Z"})

	var achou bool
	for _, m := range mudancasDe(d, "module.config") {
		if m.Campo == "cmd" {
			achou = true
		}
	}
	if !achou {
		t.Fatalf("o `install foo` passou a rodar /tmp/.x e a comparação calou "+
			"por causa de uma subárvore de /lib/modules: %+v", d.Mudancas)
	}
}

// CA1: um certificado que fica ILEGÍVEL entre dois retratos não pode virar
// mudança de confiança.
//
// Aqui só a metade de cima: dado o fato de completude correto, a família se
// cala. Que o COLETOR produza esse fato — o defeito real — é o
// TestCAIlegivelDerrubaACompletude, no pacote facts.
//
// `emissor` e `auto_assinado` decidem, e o vazio deles é indistinguível de "a
// autoridade trocou". No lugar onde um falso positivo custa mais caro — a
// pergunta é "alguém plantou uma CA raiz?" —, ler ilegível como estado é o
// oposto do que esta ferramenta promete.
func TestCA1CertificadoIlegivelNaoViraTrocaDeAutoridade(t *testing.T) {
	lido := facts.CACert{
		File: "/etc/ssl/certs/empresa.pem", Subject: "CN=Empresa CA",
		Issuer: "CN=Empresa CA", AutoAssinado: true, SPKI: "SHA256:aaa",
		Fingerprint: "SHA256:bbb",
	}
	// O MESMO arquivo, agora sem permissão de leitura.
	ilegivel := facts.CACert{File: "/etc/ssl/certs/empresa.pem", Erro: "permission denied"}

	antes := &facts.Facts{CACertsCompleto: true, CACerts: []facts.CACert{lido}}
	depois := &facts.Facts{CACertsCompleto: false, CACerts: []facts.CACert{ilegivel}}
	depois.PersistDenied = map[string][]string{
		"trust": {"a âncora de confiança /etc/ssl/certs/empresa.pem foi listada e NÃO pôde ser lida"},
	}

	d := Comparar(lado(antes, tudoVisivel),
		Lado{F: depois, Caps: tudoVisivel, Host: "h", Quando: "2026-01-02T00:00:00Z"})

	for _, m := range mudancasDe(d, "ca") {
		t.Errorf("um certificado ilegível virou drift de confiança: %s %s %s",
			m.Kind, m.ID, m.Campo)
	}
	if c := coberturaDe(t, d, "ca"); c.Simetrico {
		t.Errorf("a cobertura de confiança tinha de cair: %+v", c)
	}
}

// LOADER2: os MESMOS diretórios, a ORDEM trocada.
//
// Quem resolve soname é o loader, e ele para no primeiro que casar. Mover
// /opt/.lib para a frente de /usr/lib sequestra toda biblioteca do host sem
// acrescentar nem remover diretório nenhum — e enquanto a família identificava
// cada entidade pelo próprio caminho, isso era zero drift.
func TestLOADER2ReordenarACadeiaEhMudanca(t *testing.T) {
	cadeia := func(ds ...string) *facts.Facts {
		f := &facts.Facts{LoaderPathCompleto: true, LoaderEnvCompleto: true}
		for _, d := range ds {
			f.Loader.SearchDirs = append(f.Loader.SearchDirs,
				facts.LoaderDir{Dir: d, From: "/etc/ld.so.conf.d/x.conf", Exists: true})
		}
		return f
	}
	d := Comparar(
		lado(cadeia("/usr/lib", "/opt/.lib"), tudoVisivel),
		Lado{F: cadeia("/opt/.lib", "/usr/lib"), Caps: tudoVisivel, Host: "h",
			Quando: "2026-01-02T00:00:00Z"})

	var achou bool
	for _, m := range mudancasDe(d, "loader.order") {
		if m.Campo == "cadeia" {
			achou = true
		}
	}
	if !achou {
		t.Fatalf("reordenar a cadeia troca quem responde primeiro por soname: %+v",
			d.Mudancas)
	}
	// E a família POR DIRETÓRIO tem de continuar calada: nada surgiu nem sumiu,
	// e emitir ali seria a mesma mudança contada duas vezes.
	for _, m := range mudancasDe(d, "loader.path") {
		t.Errorf("a família por diretório não podia falar de uma reordenação: %s %s",
			m.Kind, m.ID)
	}
}
