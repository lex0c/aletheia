package facts

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

// A COMPLETUDE É DA FONTE, e três coletores a tratavam como se fosse do
// SUBSISTEMA.
//
// O sintoma é sempre o mesmo e sempre silencioso: uma fonte falha e o fato que
// outra fonte usa é derrubado junto. Quem lê o fato — a família de drift —
// recusa uma comparação que estava perfeitamente lida, ou pior, aceita uma que
// não estava.
//
// Os três casos abaixo são as três formas, e cada um confere as DUAS pontas: a
// flag que tem de cair e a que NÃO pode cair.

// travar deixa o caminho ilegível e devolve o destravamento para o t.Cleanup —
// sem ele o TempDir não some.
func travar(t *testing.T, p string) {
	t.Helper()
	if err := os.Chmod(p, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(p, 0o644) })
}

// pam_env.conf ilegível degrada o ENV do loader, e não o caminho de busca.
//
// São superfícies diferentes dentro do mesmo struct: /etc/environment e
// pam_env.conf alimentam EnvVars; SearchDirs vem do ld.so.conf. Enquanto os
// dois derrubavam a mesma flag, um pam_env.conf 0600 (que é o normal em host
// endurecido) apagava a comparação de um /opt/.lib recém-injetado no
// ld.so.conf.d — a mudança que a família existe para pegar.
func TestPamEnvIlegivelNaoDegradaOCaminhoDeBusca(t *testing.T) {
	raiz := t.TempDir()
	os.MkdirAll(filepath.Join(raiz, "etc/ld.so.conf.d"), 0o755)
	os.MkdirAll(filepath.Join(raiz, "etc/security"), 0o755)
	os.WriteFile(filepath.Join(raiz, "etc/ld.so.conf"), []byte("include /etc/ld.so.conf.d/*.conf\n"), 0o644)
	os.WriteFile(filepath.Join(raiz, "etc/ld.so.conf.d/x.conf"), []byte("/opt/.lib\n"), 0o644)
	os.WriteFile(filepath.Join(raiz, "etc/environment"), []byte("PATH=/usr/bin\n"), 0o644)
	pam := filepath.Join(raiz, "etc/security/pam_env.conf")
	os.WriteFile(pam, []byte("LD_PRELOAD DEFAULT=/tmp/.so\n"), 0o644)
	travar(t, pam)

	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	t.Cleanup(func() { e.Close() })
	f := &Facts{}
	collectLoader(f, e)

	if !f.LoaderPathCompleto {
		t.Error("o pam_env.conf ilegível derrubou LoaderPathCompleto: um diretório " +
			"de busca NOVO deixaria de ser comparado por causa de outro arquivo, " +
			"de outra superfície")
	}
	if f.LoaderEnvCompleto {
		t.Error("o pam_env.conf não abriu e LoaderEnvCompleto continuou verdadeiro: " +
			"um LD_PRELOAD declarado ali sairia como inexistente")
	}
	if !f.LoaderPreloadLido {
		t.Error("nada aconteceu com o /etc/ld.so.preload nesta raiz")
	}
	var achou bool
	for _, d := range f.Loader.SearchDirs {
		if d.Dir == "/opt/.lib" {
			achou = true
		}
	}
	if !achou {
		t.Errorf("o diretório do ld.so.conf.d nem foi lido: %+v", f.Loader.SearchDirs)
	}
}

// Uma subárvore de /lib/modules ilegível degrada o ÍNDICE DE MÓDULOS EM DISCO,
// e não a configuração de módulo.
//
// As duas escrevem a chave `modprobe` — que continua servindo ao operador —,
// mas são perguntas diferentes: "o que o boot manda carregar" e "quais .ko
// existem". Enquanto a família de drift dependia da chave, um /lib/modules sem
// permissão calava a comparação de um modprobe.d perfeitamente lido.
func TestArvoreDeModulosIlegivelNaoDegradaAConfigDeModulo(t *testing.T) {
	raiz := t.TempDir()
	os.MkdirAll(filepath.Join(raiz, "etc/modprobe.d"), 0o755)
	os.WriteFile(filepath.Join(raiz, "etc/modprobe.d/x.conf"),
		[]byte("install foo /bin/true\n"), 0o644)
	sub := filepath.Join(raiz, "lib/modules/6.6.0/kernel/net")
	os.MkdirAll(sub, 0o755)
	travar(t, sub)

	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	t.Cleanup(func() { e.Close() })
	f := &Facts{}
	collectModprobe(f, e)

	if !f.ModuleConfigCompleto {
		t.Error("uma subárvore de /lib/modules ilegível derrubou " +
			"ModuleConfigCompleto: um `install` novo no modprobe.d deixaria de " +
			"ser comparado por causa de outra fonte")
	}
	var temLacuna bool
	for _, l := range f.PersistDenied["modprobe"] {
		if len(l) > 0 {
			temLacuna = true
		}
	}
	if !temLacuna {
		t.Error("a subárvore ilegível precisa continuar declarando lacuna para o operador")
	}
	if len(f.Modules) == 0 {
		t.Errorf("o modprobe.d nem foi lido: %+v", f.Modules)
	}
}

// Um certificado LISTADO e ilegível é lacuna, e o coletor não a declarava.
//
// `CACertsCompleto` só caía quando o DIRETÓRIO não listava. Depois de listar,
// um arquivo sem permissão virava um CACert com Erro e nada mais — e como
// `emissor` e `auto_assinado` decidem na família, o vazio deles saía como
// autoridade trocada. Um drift de confiança inventado, no lugar onde o falso
// positivo custa mais caro.
//
// LIDO e inválido é outra coisa, e continua sendo estado comparável: um arquivo
// estranho no diretório de âncoras é fato do host, não cegueira da ferramenta.
func TestCAIlegivelDerrubaACompletude(t *testing.T) {
	raiz := t.TempDir()
	dir := filepath.Join(raiz, "usr/local/share/ca-certificates")
	os.MkdirAll(dir, 0o755)
	ilegivel := filepath.Join(dir, "empresa.pem")
	os.WriteFile(ilegivel, []byte("-----BEGIN CERTIFICATE-----\n"), 0o644)
	travar(t, ilegivel)

	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	t.Cleanup(func() { e.Close() })
	f := &Facts{}
	collectTrust(f, e)

	if f.CACertsCompleto {
		t.Error("uma âncora de confiança listada e ILEGÍVEL não derrubou " +
			"CACertsCompleto: emissor e auto_assinado vazios sairiam como " +
			"autoridade trocada")
	}
	if !f.HostsLido || !f.ResolverLido || !f.HostTrustCompleto {
		t.Error("um certificado ilegível não pode degradar as outras três " +
			"superfícies de confiança")
	}
}

// E a outra metade da mesma regra: PEM inválido é ESTADO, não lacuna.
func TestCAInvalidaNaoEhLacuna(t *testing.T) {
	raiz := t.TempDir()
	dir := filepath.Join(raiz, "usr/local/share/ca-certificates")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "lixo.pem"), []byte("não é PEM nenhum\n"), 0o644)

	e := env.Probe(env.Options{Root: raiz, Version: "test"})
	t.Cleanup(func() { e.Close() })
	f := &Facts{}
	collectTrust(f, e)

	if !f.CACertsCompleto {
		t.Error("um arquivo LIDO e inválido virou lacuna: ele é fato do host — " +
			"alguém deixou um arquivo estranho no diretório de âncoras —, e " +
			"tratá-lo como cegueira suprime a comparação que o mostraria")
	}
	if len(f.CACerts) != 1 || f.CACerts[0].Erro == "" {
		t.Errorf("o arquivo inválido precisa entrar na lista com o erro: %+v", f.CACerts)
	}
}
