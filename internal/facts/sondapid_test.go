package facts

import (
	"os"
	"os/exec"
	"testing"
	"time"
)

// A varredura por sinal é a metade da sondagem que cobre a faixa INTEIRA de
// pid_max, e é ela que decidiu deixar de existir a lacuna constante que fazia
// `cross.hidden_pid` nunca fechar em host com pid_max de 4194304.
//
// Dois comportamentos precisam de teste, e o segundo é o que ninguém olha:
// achar o que existe, e DIZER CERTO até onde foi quando não deu para ir até o
// fim.

// TestVarrerPorSinalAchaOQueNaoEstaNaListagem usa um processo de verdade.
//
// O `visiveis` de propósito NÃO o contém: é essa a situação que a sondagem
// existe para pegar — algo que responde ao kernel e não aparece na listagem.
// Simular com PID inventado não serviria, porque o que está sob teste é
// justamente a resposta do kernel.
func TestVarrerPorSinalAchaOQueNaoEstaNaListagem(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skipf("sem como criar processo de apoio: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	alvo := cmd.Process.Pid

	// O TETO DA FUNÇÃO ENTRA NA EXPECTATIVA, e a razão é de host, não de
	// desenho: varrerPorSinal grampeia o limite em pidMaxLimite, e num host de
	// uptime longo o pid corrente chega a menos de um sondaBloco do teto —
	// aqui, 4.134.053 num pid_max de 4.194.304. Aí `alvo + sondaBloco` passa do
	// teto, a varredura para no teto (certo) e a expectativa crua falha.
	//
	// Era um teste que ficava vermelho conforme o uptime da máquina, o que é a
	// pior forma de teste frágil: ele não falha em quem escreveu a mudança,
	// falha em quem estiver com a máquina ligada há mais tempo.
	limite := alvo + sondaBloco
	esperado := min(limite, pidMaxLimite)
	cand, ate := varrerPorSinal(limite, map[int]bool{}, time.Now().Add(time.Minute))

	if ate != esperado {
		t.Errorf("varreu até %d, queria %d: sem corte, o alcance é a faixa inteira "+
			"(limite pedido %d, teto da função %d)", ate, esperado, limite, pidMaxLimite)
	}
	if _, ok := cand[alvo]; !ok {
		t.Errorf("o pid %d existe e não estava na listagem, e a varredura não o "+
			"devolveu — é exatamente o caso que ela existe para achar", alvo)
	}

	// E o outro lado: o que ESTÁ na listagem não é candidato. Sem isto a
	// sondagem devolveria o host inteiro.
	cand2, _ := varrerPorSinal(limite, map[int]bool{alvo: true}, time.Now().Add(time.Minute))
	if _, ok := cand2[alvo]; ok {
		t.Error("pid listado virou candidato: a sondagem procura o que NÃO está na listagem")
	}
}

// TestVarrerPorSinalNaoDevolveOProprioProcesso confirma o filtro pelo caminho
// mais curto que existe: o PID deste teste está vivo, e passá-lo como visível
// tem que bastar para ele não aparecer.
func TestVarrerPorSinalNaoDevolveOProprioProcesso(t *testing.T) {
	eu := os.Getpid()
	cand, _ := varrerPorSinal(eu+16, map[int]bool{eu: true}, time.Now().Add(time.Minute))
	if _, ok := cand[eu]; ok {
		t.Error("o próprio processo apareceu como oculto")
	}
}

// TestVarrerPorSinalCortadaDizAteOndeFoi é o teste do PARA-QUEDAS.
//
// Com o prazo já vencido, nenhum bloco é concluído e o alcance precisa ser 0 —
// não o limite pedido. É a diferença entre "sondei tudo e não achei" e "não
// sondei", que é a distinção que esta ferramenta inteira existe para manter: um
// alcance otimista aqui faria a cobertura afirmar completude sobre uma faixa
// que ninguém olhou.
func TestVarrerPorSinalCortadaDizAteOndeFoi(t *testing.T) {
	vencido := time.Now().Add(-time.Second)
	cand, ate := varrerPorSinal(8*sondaBloco, map[int]bool{}, vencido)
	if ate != 0 {
		t.Errorf("prazo vencido e o alcance saiu %d: nenhum bloco foi concluído, "+
			"e afirmar alcance é afirmar que se olhou", ate)
	}
	if len(cand) != 0 {
		t.Errorf("prazo vencido e vieram %d candidatos", len(cand))
	}
}

// TestSondaAteEhPrefixoContiguo trava a regra de contagem.
//
// Os blocos são entregues em ordem a N workers, então o que se conclui quando o
// prazo corta é um prefixo com no máximo N-1 buracos no fim. O número publicado
// tem que ser o último prefixo CONTÍGUO — publicar o bloco mais alto concluído
// afirmaria cobertura sobre os buracos abaixo dele.
func TestSondaAteEhPrefixoContiguo(t *testing.T) {
	// Faixa pequena e prazo largo: todos os blocos entram, e o alcance é o
	// limite exato, inclusive quando ele não fecha um bloco redondo.
	limite := 3*sondaBloco + 7
	_, ate := varrerPorSinal(limite, map[int]bool{}, time.Now().Add(time.Minute))
	if ate != limite {
		t.Errorf("alcance %d, queria %d: o último bloco é parcial e ainda assim "+
			"foi concluído até o limite", ate, limite)
	}
}

// pid_max vem do HOST SOB INVESTIGAÇÃO, e a primeira linha deste arquivo diz que
// o host pode mentir. Um valor perto de MaxInt32 estourava a conta de blocos num
// build de 386 — `(limite + 65535)` dá negativo em int de 32 bits — e o make()
// saía com tamanho negativo: pânico no coletor, e o scan inteiro junto.
//
// A sondagem antiga não tinha esse risco porque nunca passava de 65536. Foi a
// cobertura da faixa inteira que o criou, então é ela que tem de se defender.
func TestVarrerPorSinalNaoEstouraComPidMaxAbsurdo(t *testing.T) {
	for _, limite := range []int{1 << 30, 1<<31 - 1, -5, 0} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("limite=%d derrubou o coletor: %v", limite, r)
				}
			}()
			// Prazo vencido: o que está sob teste é o dimensionamento, não a
			// varredura — sem isso o caso de 4 milhões levaria segundos.
			_, ate := varrerPorSinal(limite, map[int]bool{}, time.Now().Add(-time.Second))
			if ate < 0 {
				t.Errorf("limite=%d devolveu alcance negativo (%d)", limite, ate)
			}
		}()
	}
}
