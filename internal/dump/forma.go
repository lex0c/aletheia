package dump

import (
	"errors"
	"fmt"
)

// O ORÇAMENTO DE FORMA, que é o que MaxDump não é.
//
// # O teto de bytes protegia a coisa errada
//
// MaxDump limita o JSON SERIALIZADO. A memória que o processo gasta é a da
// estrutura DECODIFICADA, e as duas não têm relação fixa: quem escreve o
// arquivo escolhe a razão entre elas.
//
//	{"schema":2,"facts":{"schema_version":24,"processes":[{},{},{}, ... ]}}
//
// Cada `{}` custa 3 bytes no arquivo e vira um facts.Process inteiro na
// memória — 600 bytes de struct, com string, []string, []FD, []Map e mapas
// dentro. Medido neste projeto: um arquivo de 0,86 MiB com 300 mil objetos
// vazios produziu 600 MiB de heap vivo e 1 GiB alocado no total. Amplificação
// de 699×.
//
// Levando isso ao teto de 512 MiB, o analisador precisaria de centenas de
// gigabytes. Ou seja: MaxDump nunca chega a disparar — o OOM chega antes, e o
// processo morre com `fatal error: out of memory` e status 2, que o contrato
// desta ferramenta lê como "CRITICAL: indicador de alta confiança". O teto que
// existia para impedir isso protegia um número que o atacante não precisa
// exceder.
//
// # O que basta contar
//
// ABERTURAS DE CONTÊINER — `{` e `[` —, e só elas.
//
// O raciocínio fecha: toda string decodificada custa, no máximo, os bytes que
// ela ocupa na entrada, e a entrada já tem teto. Número e booleano não alocam.
// O único custo que NÃO é proporcional à entrada é o de um contêiner: `{}` são
// 2 bytes de entrada e um struct de tamanho arbitrário na saída. Contar
// aberturas é portanto necessário E suficiente.
//
// É também o que separa o ataque do artefato real, com folga de uma a duas
// ordens de grandeza. Medido em três alvos deliberadamente diferentes, porque
// um só não diz qual é a faixa:
//
//	workstation, host vivo    1,97 MiB   12.465 aberturas   166 B/abertura
//	raiz mínima (--root)      3,5 KiB        36 aberturas   100 B/abertura
//	rootfs de contêiner      17,1 KiB       244 aberturas    72 B/abertura
//	ATAQUE                    0,86 MiB  300.003 aberturas     3 B/abertura
//
// O alvo mais POBRE é o mais denso: um contêiner Alpine não tem processo,
// socket nem log para diluir a estrutura fixa do retrato. É esse que define a
// margem, e não a workstation.
//
// # Dois tetos, porque um só não fecha
//
// O teto ABSOLUTO limita a memória de um arquivo grande. Sozinho ele tem de ser
// generoso o bastante para o maior dump legítimo, e aí um arquivo PEQUENO ainda
// amplifica à vontade abaixo dele.
//
// A razão MÍNIMA de bytes por abertura fecha essa brecha. Ela só é consultada
// acima de um piso de aberturas, e o piso não é conveniência: é o que garante
// que ela nunca recuse um artefato pequeno e denso, que é justamente o alvo
// pobre da tabela acima. Abaixo do piso não há o que proteger — dez mil
// contêineres custam seis megabytes, e nenhum analisador morre disso.
//
// Os dois são conferidos SEPARADAMENTE, e não pelo menor dos dois, porque
// afirmam coisas diferentes — ver o comentário dentro de medirForma.
//
// # O que sobra depois deles
//
// Um teto, e não a ausência de um. O pior artefato que ainda PASSA foi medido:
// 53 MiB, um milhão de objetos, 3,2 GiB alocados no decode e 731 MiB de heap
// vivo. É muito, e é finito — antes disto o mesmo ataque em 0,86 MiB já custava
// 1 GiB, e nada impedia os 512 MiB de MaxDump de custarem centenas.
const (
	// MaxAberturas é o teto absoluto. Ele sai do maior coletor: um proxy com
	// `tcp_max_tw_buckets` cheio produz as 400 mil linhas de socket que
	// maxLinhasSocket admite, e todo o resto do retrato junto não chega perto
	// disso de novo. Um milhão é o dobro do maior dump legítimo concebível e
	// oitenta vezes o dump real medido acima.
	MaxAberturas = 1_000_000

	// MinBytesPorAbertura é a razão abaixo da qual o arquivo não descreve um
	// host: ele descreve um pedido de alocação. Oito bytes é 9× abaixo do
	// artefato legítimo mais denso que medi, porque a margem tem de ficar do
	// lado de NÃO recusar um artefato verdadeiro no meio de um incidente.
	MinBytesPorAbertura = 8

	// MinAberturasParaRazao é o piso a partir do qual a razão passa a ser
	// consultada.
	//
	// Sem ele a razão vale desde o primeiro byte, e aí o artefato mais denso é
	// o que corre risco de recusa — que é exatamente o retrato de um alvo
	// POBRE, sem processo nem log para diluir a estrutura fixa. Um contêiner
	// Alpine mede 72 bytes por abertura; um alvo ainda mais vazio mede menos, e
	// nenhum deles é uma ameaça: dez mil contêineres decodificam em cerca de
	// seis megabytes.
	//
	// O piso não abre brecha porque o ataque precisa de VOLUME para valer a
	// pena. Abaixo dele o teto de memória é o próprio piso vezes o maior
	// registro dos fatos, e isso é um número pequeno e fixo.
	MinAberturasParaRazao = 10_000

	// MaxProfundidade freia o aninhamento. O decodificador do Go é recursivo e
	// tem limite próprio (10 mil), mas um `[[[[...]]]]` chega lá com 10 KB de
	// entrada, e o erro que sai de lá fala de recursão em vez de falar do
	// artefato. Um dump real mede 7.
	MaxProfundidade = 64
)

// ErrForma recusa um artefato cuja FORMA não cabe no orçamento, antes de a
// decodificação alocar por ela.
var ErrForma = errors.New("a forma do dump não cabe no orçamento do analisador")

// varrer percorre os bytes UMA vez e chama aoAbrir em cada `{` e `[` fora de
// string, com o total acumulado e a profundidade corrente.
//
// # Ela não valida JSON, e isso é de propósito
//
// Validar é trabalho do json.Unmarshal que vem depois, e duplicá-lo aqui
// criaria duas gramáticas que precisam concordar — a que diverge é a que
// ninguém está olhando. Esta função responde UMA pergunta: "decodificar isto
// pode alocar mais do que o orçamento?". Para respondê-la basta contar `{` e
// `[` fora de string.
//
// Fora de STRING é a única sutileza que importa, e é onde a guarda falharia em
// silêncio: um `{"cmd":"awk '{print $1}'"}` tem chaves que não abrem nada, e
// contá-las recusaria artefato legítimo — mas ACREDITAR estar dentro de uma
// string quando não está some com as aberturas de verdade, e aí o artefato
// hostil passa sem sintoma nenhum. O escape entra junto: `"\\"` termina a
// string, `"\""` não. FuzzFormaConcordaComOParser prova a equivalência contra
// o encoding/json sobre toda entrada que ele aceita.
//
// Um byte por vez, sem alocar nada. Medido em 1 GB/s: 1,9 ms num dump real de
// 1,97 MiB, contra 24 ms do Unmarshal que vem depois.
func varrer(b []byte, aoAbrir func(aberturas, prof int) error) (int, error) {
	var aberturas, prof int
	for i := 0; i < len(b); i++ {
		switch b[i] {
		case '"':
			// Pula a string inteira. O laço interno avança dois bytes no
			// escape, então uma barra invertida nunca esconde a aspa de
			// fechamento nem a consome.
			for i++; i < len(b); i++ {
				if b[i] == '\\' {
					i++
					continue
				}
				if b[i] == '"' {
					break
				}
			}
		case '{', '[':
			aberturas++
			prof++
			if err := aoAbrir(aberturas, prof); err != nil {
				return aberturas, err
			}
		case '}', ']':
			prof--
		}
	}
	return aberturas, nil
}

// contarAberturas é a varredura sem orçamento, para o fuzz diferencial poder
// comparar o contador com o encoding/json.
//
// Ele e medirForma são a MESMA varredura de propósito: dois laços com a mesma
// regra de escape divergiriam, e o teste passaria a provar a correção de um
// código que não é o que roda.
func contarAberturas(b []byte) int {
	n, _ := varrer(b, func(int, int) error { return nil })
	return n
}

// medirForma aplica o orçamento sobre a varredura, e PARA no primeiro estouro.
func medirForma(b []byte) error {
	// OS DOIS TETOS DIZEM COISAS DIFERENTES, e por isso são conferidos
	// separadamente em vez de pelo menor dos dois.
	//
	// Estourar a RAZÃO é uma afirmação sobre o arquivo: ele não descreve um
	// host. Estourar o teto ABSOLUTO é uma afirmação sobre o analisador: o
	// orçamento dele acabou, e o artefato pode ser um host grande de verdade.
	// Uma mensagem só, acusando malícia nos dois casos, mandaria o operador
	// procurar um atacante onde há um proxy com muito TIME-WAIT.
	razao := len(b) / MinBytesPorAbertura

	_, err := varrer(b, func(aberturas, prof int) error {
		switch {
		case aberturas > MinAberturasParaRazao && aberturas > razao:
			return fmt.Errorf("%w: %d byte(s) abrindo mais de %d contêiner(es) JSON.\n"+
				"Isto não é um retrato de host: um dump real gasta cerca de 166 "+
				"bytes por objeto, e este gasta menos de %d. Um `{}` custa 3 "+
				"bytes no disco e um registro INTEIRO na memória — decodificar "+
				"este arquivo esgotaria a memória do analisador antes de "+
				"qualquer erro controlado.",
				ErrForma, len(b), razao, MinBytesPorAbertura)

		case aberturas > MaxAberturas:
			return fmt.Errorf("%w: passa de %d contêineres JSON, que é o "+
				"orçamento de decodificação deste binário.\n"+
				"A proporção do arquivo é plausível, então ele pode ser um host "+
				"GRANDE de verdade — um proxy com centenas de milhares de "+
				"sockets chega perto disto. Recusar é o lado seguro: decodificar "+
				"além daqui derruba o analisador por falta de memória, e um "+
				"processo morto com status 2 é lido pela automação de frota como "+
				"CRITICAL.\n"+
				"Recolete com --no-logs ou com escopo menor, ou analise num "+
				"host com mais memória.",
				ErrForma, MaxAberturas)

		case prof > MaxProfundidade:
			// Este teto quase nunca é o que morde: uma bomba de aninhamento
			// CRUA é toda abertura e nenhum byte, então a razão a pega antes.
			// Ele existe para a bomba ACOLCHOADA, que tem recheio suficiente
			// para parecer proporcional.
			return fmt.Errorf("%w: aninhamento passa de %d níveis.\n"+
				"Um dump real mede 7. Este nível de aninhamento não vem de um "+
				"retrato de host — vem de um arquivo escrito para fazer o "+
				"decodificador recursivo do Go estourar a pilha.",
				ErrForma, MaxProfundidade)
		}
		return nil
	})
	return err
}
