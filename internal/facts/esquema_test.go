package facts

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// A CATRACA do SchemaVersion, porque a regra sozinha não bastou.
//
// A regra está escrita em facts.go e é clara: sobe quando um fato serializado
// novo, ou uma mudança de semântica de um existente, puder alterar a conclusão
// de quem analisar o dump depois. Ela foi ampliada num dia e violada duas vezes
// nesse mesmo dia, por quem a escreveu. Antes disso, três commits seguidos a
// tinham furado na versão estreita.
//
// O padrão é o mesmo que esta base já reconheceu na suíte de cenários: regra que
// depende de alguém lembrar é regra que vai ser esquecida. O conserto é uma
// catraca, não mais disciplina.
//
// # O que esta catraca pega, e o que NÃO pega
//
// Pega a metade mecânica: campo serializado novo, renomeado, removido, ou com o
// tipo trocado. É a classe de 3 das 5 omissões históricas, e a única que dá para
// detectar por construção.
//
// NÃO pega mudança de SEMÂNTICA com o mesmo campo — a tolerância que passou a
// permitir 60s no PIDReciclado não muda campo nenhum. Essa metade continua sendo
// disciplina de revisão, e fingir que o teste resolve seria pior que não ter o
// teste: daria uma sensação de cobertura que não existe.
func TestImpressaoDoEsquema(t *testing.T) {
	const (
		esquemaEsperado = 23
		// Atualizada sem subir o SchemaVersion, e a razão fica aqui porque a
		// catraca manda escrevê-la.
		//
		// Process.EnvLido/EnvCortado/EnvErro separam "o ambiente está vazio" de
		// "não consegui ler o ambiente". Num dump v17 anterior a eles, EnvLido
		// sai false — e a pergunta da regra é se esse vazio significa algo para
		// algum CHECK. Não significa: nenhum check lê os três.
		//
		// O único consumidor é a tool process.environ, e ela não alcança dump
		// nenhum: exige --profile full, que é recusado em modo snapshot, e
		// declara fonte live. Os retratos que ela vê nascem de snapshot.capture,
		// deste binário.
		//
		// E o valor padrão é o CONSERVADOR: false faz a tool recusar responder,
		// não afirmar ambiente vazio. Um dump velho produziria recusa, que é
		// lacuna declarada — nunca a leitura tranquilizadora.
		// Atualizada de novo, e pelo mesmo raciocínio: Process.EnvBruto guarda
		// as entradas do environ como o kernel as expôs. Nenhum CHECK a lê — o
		// único consumidor é process.environ, que exige --profile full e não
		// alcança dump nenhum —, e a ausência num dump anterior é o estado
		// conservador: sem entradas cruas, a tool responde pela projeção e diz
		// que a projeção é o que ela é.
		// Subida de novo, e desta vez o SchemaVersion SOBE junto (17→18). O
		// CrossView passou a carregar o estado de LEITURA de cada testemunha —
		// ProcListLida/N, ModProcLido, ModSysLido, ModFtraceLido,
		// SocketProtos. Diferente do EnvBruto acima, aqui a
		// regra do SchemaVersion MANDA subir: o consumidor é crossview.get, e ao
		// contrário de process.environ ele ALCANÇA dump (fonte live servida em
		// modo snapshot). Um dump v17, lido por este binário sem a subida, traria
		// esses bits vazios — e a tool renderizaria "not_compared" para uma
		// comparação que de fato aconteceu, ou pior, "agree" com uma testemunha
		// marcada como não lida. A subida faz o loader RECUSAR o dump antigo em
		// vez de respondê-lo torto. É o mesmo "vazio ≠ ilegível" que o resto do
		// Aletheia sustenta, agora atravessando a fronteira MCP.
		// Sobe de novo (21→22), e desta vez a regra manda subir por DOIS
		// campos, com o mesmo argumento nos dois: ambos são lidos por CHECK, e
		// ambos vêm zerados num dump v21 afirmando o oposto do que a coleta
		// nova sabe dizer.
		//
		// ProgramaBPF.UIDDesconhecido — lido por kernel.bpf_unowned, que é
		// CRITICAL e irreversível. Zerado significa "o kernel informou o
		// autor", e a evidência volta a imprimir "carregado por uid 0" sobre um
		// 4.13, que nunca informou nada: dado inventado dentro de uma acusação.
		//
		// ArquivoDeLog.Datada — lido por antiforense.wtmp_cleared (a guarda que
		// separa logrotate de antiforense) e por log_rotation_gap. Zerado
		// significa "esta rotação é por contador", e é exatamente a leitura que
		// fazia o wtmp_cleared acusar toda a família RHEL.
		// Sobe de novo (22→23), e aqui a regra manda subir pelo motivo mais
		// direto de todos: os fatos novos descrevem ATÉ ONDE DO PASSADO alguém
		// olhou, e num dump v22 eles vêm no zero-value.
		//
		// EventosDeLog vazia é indistinguível de "este host não fez nada".
		// FontesDeLog vazia apaga a diferença entre arquivo ilegível, formato
		// desconhecido, cauda curta e host tranquilo — quatro conclusões, um só
		// JSON. E LogJanelaEfetiva vazia faz um `analyze --since 30d` sobre uma
		// coleta de 7 dias ler 23 dias que ninguém abriu como dias sem evento.
		//
		// LogEstado é o único cujo zero-value é seguro por desenho: "" significa
		// DESCONHECIDO, e nenhum check conclui a partir dele.
		//
		// Atualizada DENTRO do 23, sem subir para 24, e a razão é a que a regra
		// manda perguntar: existe dump v23 no mundo? Não — o 23 nasceu nesta
		// branch e ela não foi mergeada. FonteDeLog.Lacuna entra na MESMA
		// estrutura que o 23 introduziu, e nenhum artefato anterior a ela
		// existe para ser lido torto. Subir para 24 aqui carimbaria uma
		// incompatibilidade com um formato que ninguém tem.
		//
		// Atualizada de novo, pelo mesmo motivo e ainda dentro do 23:
		// AtInferido virou DOIS bits (ano e fuso, que erram em escalas
		// diferentes) e FonteDeLog ganhou a confiança das datas da COBERTURA.
		// Tudo dentro de estruturas que o 23 introduziu, e nenhum artefato
		// anterior a elas existe.
		impressaoGravada = "e2d7b644746c7da6"
	)
	if SchemaVersion != esquemaEsperado {
		t.Fatalf("SchemaVersion=%d e este teste conhece o %d: atualize os dois "+
			"JUNTOS, que é o ponto dele", SchemaVersion, esquemaEsperado)
	}
	got := impressaoDeEsquema(reflect.TypeOf(Facts{}))
	if got != impressaoGravada {
		t.Errorf(`a forma serializada de Facts MUDOU.

impressão gravada: %s
impressão atual:   %s

Pergunte-se o que a regra do SchemaVersion manda perguntar: um dump da versão
ANTERIOR, lido por este binário, traria o campo novo vazio — e vazio significa
alguma coisa para algum check? Se sim, suba o SchemaVersion.

Se a resposta for não (campo puramente informativo, que nenhum check lê), a
impressão pode ser atualizada sozinha — mas escreva no commit por que não subiu.`,
			impressaoGravada, got)
	}
}

// impressaoDeEsquema resume a forma SERIALIZADA de um tipo: nomes de campo JSON
// e seus tipos, recursivamente, em ordem estável.
//
// Só o que sai no dump entra: campo com `json:"-"` ou não exportado é interno à
// coleta e não pode ser lido por binário nenhum depois.
func impressaoDeEsquema(t reflect.Type) string {
	h := sha256.New()
	h.Write([]byte(descreveTipo(t, map[reflect.Type]bool{})))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func descreveTipo(t reflect.Type, visto map[reflect.Type]bool) string {
	switch t.Kind() {
	case reflect.Ptr, reflect.Slice, reflect.Array:
		return t.Kind().String() + "<" + descreveTipo(t.Elem(), visto) + ">"
	case reflect.Map:
		return "map<" + descreveTipo(t.Key(), visto) + "," + descreveTipo(t.Elem(), visto) + ">"
	case reflect.Struct:
		if visto[t] {
			return "…" // ciclo: já descrito acima
		}
		visto[t] = true
		defer delete(visto, t)
		var campos []string
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if f.PkgPath != "" {
				continue // não exportado: não vai para o dump
			}
			nome, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if nome == "-" {
				continue
			}
			if nome == "" {
				nome = f.Name
			}
			campos = append(campos, nome+":"+descreveTipo(f.Type, visto))
		}
		sort.Strings(campos)
		return "{" + strings.Join(campos, ";") + "}"
	default:
		return t.Kind().String()
	}
}
