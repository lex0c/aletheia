package facts

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/env"
)

// As linhas do maps, na grafia exata do kernel. O caminho vem depois de cinco
// campos fixos e pode ser vazio (anônimo), um rótulo entre colchetes, ou um
// arquivo com o sufixo " (deleted)".
const (
	anonRX    = "7f0000000000-7f0000001000 r-xp 00000000 00:00 0 \n"
	anonRWX   = "7f0000001000-7f0000002000 rwxp 00000000 00:00 0 \n"
	anonRW    = "7f0000002000-7f0000003000 rw-p 00000000 00:00 0 \n"
	nomeadaRX = "7f0000003000-7f0000004000 r-xp 00000000 00:00 0      [anon:js-executable-memory]\n"
	apagadaRX = "7f0000004000-7f0000005000 r-xp 00000000 08:01 123    /tmp/.x.so (deleted)\n"
	apagadaRW = "7f0000005000-7f0000006000 rw-p 00000000 08:01 124    /etc/ld.so.cache (deleted)\n"
	memfdRX   = "7f0000006000-7f0000007000 r-xp 00000000 00:01 125    /memfd:payload (deleted)\n"
	vdso      = "7f0000007000-7f0000008000 r-xp 00000000 00:00 0      [vdso]\n"
)

func lerMapsDe(t *testing.T, texto string) *Process {
	t.Helper()
	p := &Process{PID: 1}
	lerMaps(p, strings.NewReader(texto))
	return p
}

// A injeção que respeita W^X não deixa 'w' e 'x' ligados ao mesmo tempo:
// mmap(RW) → write → mprotect(RX). Se a classificação exigir o 'w' — que é o
// que o MapsRWX faz —, o retrato não guarda nada e o check nasce cego.
func TestLerMapsSeparaExecutavelAnonimoDoRWX(t *testing.T) {
	p := lerMapsDe(t, anonRX+anonRWX+anonRW+vdso)

	if p.MapsExecAnonN != 1 {
		t.Errorf("MapsExecAnonN = %d, quer 1: só a r-xp anônima entra — a rwxp é do "+
			"check irmão, a rw-p não executa e o vdso tem rótulo", p.MapsExecAnonN)
	}
	if len(p.MapsExecAnon) != 1 || !strings.HasPrefix(p.MapsExecAnon[0], "7f0000000000-7f0000001000") {
		t.Errorf("MapsExecAnon = %v, quer o ENDEREÇO da região: sem ele N regiões "+
			"viram N cópias de \"r-xp\" e o operador não sabe onde olhar", p.MapsExecAnon)
	}
	// Regressão: o MapsRWX continua sendo o dono da região gravável.
	if len(p.MapsRWX) != 1 {
		t.Errorf("MapsRWX = %v, quer a rwxp anônima: o check irmão depende dela", p.MapsRWX)
	}
}

// O rótulo de região (PR_SET_VMA_ANON_NAME) é o que o JIT moderno usa para
// declarar o próprio código. Contá-lo como anônimo faria todo Firefox virar
// achado; ignorá-lo por completo apagaria a evidência de que aquele processo
// SABE rotular — e é ela que torna uma região sem rótulo inexplicável.
func TestLerMapsGuardaRotuloSemContarComoAnonimo(t *testing.T) {
	p := lerMapsDe(t, nomeadaRX)

	if p.MapsExecAnonN != 0 {
		t.Errorf("MapsExecAnonN = %d, quer 0: região ROTULADA não é anônima sem nome", p.MapsExecAnonN)
	}
	if len(p.MapsExecNomes) != 1 || p.MapsExecNomes[0] != "[anon:js-executable-memory]" {
		t.Errorf("MapsExecNomes = %v, quer o rótulo: é ele que diz que este "+
			"processo declara o código que gera", p.MapsExecNomes)
	}
}

// O filtro que decide o check inteiro. Medido num desktop: 713 mapeamentos
// apagados NÃO executáveis e ZERO executáveis. Sem exigir o 'x', o retrato
// carrega memfd de IPC, ld.so.cache e dconf, e o check afoga na estreia.
func TestLerMapsSoGuardaApagadoExecutavel(t *testing.T) {
	p := lerMapsDe(t, apagadaRX+apagadaRW+memfdRX)

	if len(p.MapsApagados) != 2 {
		t.Fatalf("MapsApagados = %+v, quer 2: a rw-p apagada é ruído de rotina", p.MapsApagados)
	}
	if p.MapsApagados[0].Caminho != "/tmp/.x.so" {
		t.Errorf("caminho = %q, quer /tmp/.x.so sem o sufixo \" (deleted)\": é por "+
			"ele que se pergunta se o arquivo voltou", p.MapsApagados[0].Caminho)
	}
	if p.MapsApagados[0].Memfd {
		t.Error("/tmp/.x.so é arquivo apagado, não memfd")
	}
	// memfd NUNCA esteve em disco. Tratá-lo como arquivo apagado manda o
	// operador procurar em disco o que só existe naquela memória.
	if !p.MapsApagados[1].Memfd {
		t.Errorf("%q devia estar marcado como memfd", p.MapsApagados[1].Caminho)
	}
}

// A mesma biblioteca aparece em vários segmentos do maps. Sem deduplicar, um
// achado vira quatro e a contagem do relatório deixa de significar processos.
func TestLerMapsDeduplicaApagadoRepetido(t *testing.T) {
	repetido := apagadaRX + "7f0000009000-7f000000a000 r-xp 00001000 08:01 123    /tmp/.x.so (deleted)\n"
	if p := lerMapsDe(t, repetido); len(p.MapsApagados) != 1 {
		t.Errorf("MapsApagados = %d, quer 1: são dois segmentos do MESMO arquivo", len(p.MapsApagados))
	}
}

// Teto e contagem são coisas diferentes. Um runtime com milhares de regiões não
// pode encher o retrato — e o relatório não pode dizer "16 regiões" onde há 40.
func TestLerMapsLimitaAmostraSemPerderOTotal(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 40; i++ {
		e := strconv.FormatInt(int64(0x7f0000000000+i*0x1000), 16)
		f := strconv.FormatInt(int64(0x7f0000000000+(i+1)*0x1000), 16)
		b.WriteString(e + "-" + f + " r-xp 00000000 00:00 0 \n")
	}
	p := lerMapsDe(t, b.String())

	if len(p.MapsExecAnon) != maxMapsExecAnon {
		t.Errorf("amostra = %d, quer o teto de %d", len(p.MapsExecAnon), maxMapsExecAnon)
	}
	if p.MapsExecAnonN != 40 {
		t.Errorf("total = %d, quer 40: o teto corta a AMOSTRA, não a contagem", p.MapsExecAnonN)
	}
}

// A pergunta que separa atualização de pacote de payload apagado. Errá-la
// transforma o estado que o needrestart reporta em incidente — ou o contrário.
func TestResolverMapasApagadosDistingueRecriadoDeSumido(t *testing.T) {
	dir := t.TempDir()
	vivo := filepath.Join(dir, "libsubstituida.so")
	if err := os.WriteFile(vivo, []byte("novo"), 0o755); err != nil {
		t.Fatal(err)
	}
	sumido := filepath.Join(dir, "payload.so")

	f := &Facts{Processes: []Process{{PID: 1, MapsApagados: []MapaApagado{
		{Caminho: vivo},
		{Caminho: sumido},
		{Caminho: "/memfd:payload", Memfd: true},
	}}}}
	resolverMapasApagados(f, &env.Env{})

	m := f.Processes[0].MapsApagados
	if !m[0].Verificado || !m[0].Recriado {
		t.Errorf("%+v: o caminho VOLTOU a existir — é a forma de uma atualização de pacote", m[0])
	}
	if !m[1].Verificado || m[1].Recriado {
		t.Errorf("%+v: o caminho não existe mais para ninguém", m[1])
	}
	// memfd não tem caminho a verificar. Marcá-lo como "verificado e não
	// recriado" afirmaria que houve um arquivo, e nunca houve.
	if m[2].Verificado {
		t.Errorf("%+v: memfd nunca esteve em disco, não há o que perguntar", m[2])
	}
}

// "não recriado" e "não perguntei" são conclusões opostas. Sem o Verificado, um
// retrato antigo — de antes deste campo — faria todo mapeamento apagado parecer
// payload sumido.
func TestMapaApagadoNaoVerificadoNaoAfirmaAusencia(t *testing.T) {
	var m MapaApagado
	if m.Verificado {
		t.Fatal("o zero de MapaApagado não pode afirmar que a pergunta foi feita")
	}
}

// O endereço é o primeiro campo da linha, e é o que o operador usa para achar a
// região com gdb. Devolver as permissões no lugar dele passaria despercebido:
// as duas são strings curtas.
func TestSplitMapLineDevolveEndereco(t *testing.T) {
	addr, perms, path, ok := splitMapLineBytes([]byte(strings.TrimSuffix(apagadaRX, "\n")))
	if !ok {
		t.Fatal("linha não foi entendida")
	}
	if string(addr) != "7f0000004000-7f0000005000" {
		t.Errorf("addr = %q", addr)
	}
	if string(perms) != "r-xp" {
		t.Errorf("perms = %q", perms)
	}
	if string(path) != "/tmp/.x.so (deleted)" {
		t.Errorf("path = %q", path)
	}
}
