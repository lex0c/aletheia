package scenario

// A captura de tráfego (§12.3).
//
// Os testes unitários provam o formato do arquivo e o filtro contra pacotes
// sintéticos. O que só o contêiner prova é o resto do caminho: abrir AF_PACKET,
// amarrar na interface, receber quadro de verdade do kernel e escrever um pcap
// que fecha.
//
//	Y1  o filtro CASA      tráfego na porta pedida entra no arquivo
//	Y2  o filtro EXCLUI    o mesmo tráfego, filtro em outra porta: zero gravados
//
// O par é o teste. Um filtro largo demais grava conversa de terceiros que não
// são parte do incidente; estreito demais devolve arquivo vazio com cara de
// resposta. Sozinho, cada cenário deixa passar um dos dois erros.

func init() {
	Register(Scenario{
		ID:     "Y1-captura-o-que-foi-pedido",
		Desc:   "captura de tráfego sem tcpdump: o que casa o filtro entra no arquivo",
		Images: []string{"debian:12", "alpine:3.20"},
		Cmd:    "preserve",
		// O tráfego precisa acontecer DURANTE a captura: o plantio deixa a
		// conexão marcada para meio segundo depois, quando o preserve já está
		// escutando.
		Plant: `mkdir -p /ir
			/helper listen 127.0.0.1:9999 &
			sleep 0.3
			( sleep 0.5; exec /helper connect 127.0.0.1:9999 ) &`,
		Args: []string{"--out", "/ir", "--pcap", "--iface", "lo",
			"--port", "9999", "--duration", "2s"},
		ExpectOutput: []string{
			"CAPTURANDO em lo",
			"filtro: porta 9999",
			// O aviso é obrigatório e diz o que a captura NÃO prova.
			"ESTA CAPTURA MENTE",
			"espelhamento FORA desta máquina",
			// E que a própria ferramenta vira o que ela mesma sinaliza.
			"um scan neste host vê um socket AF_PACKET",
			// TRÊS, e o número é o teste. O handshake TCP na loopback é SYN,
			// SYN-ACK, ACK — e o AF_PACKET entrega cada um deles duas vezes, na
			// transmissão e na recepção. Gravar seis foi o que esta implementação
			// fazia até ser medida contra o tcpdump, que grava três.
			"3 gravados",
			"cópia(s) de transmissão descartadas",
		},
		// Se nada tivesse entrado, estas frases apareceriam — e a ausência delas
		// é o que prova que o handshake foi parar no arquivo.
		ForbidOutput: []string{"ZERO pacotes casaram", "NENHUM pacote passou"},
		Exit:         0,
	})

	Register(Scenario{
		ID:     "Y2-o-filtro-exclui-e-diz-que-excluiu",
		Desc:   "mesmo tráfego, filtro em outra porta: zero gravados, e a diferença entre 'não casou' e 'não houve' fica dita",
		Images: []string{"debian:12"},
		Cmd:    "preserve",
		Plant: `mkdir -p /ir
			/helper listen 127.0.0.1:9999 &
			sleep 0.3
			( sleep 0.5; exec /helper connect 127.0.0.1:9999 ) &`,
		Args: []string{"--out", "/ir", "--pcap", "--iface", "lo",
			"--port", "8888", "--duration", "2s"},
		ExpectOutput: []string{
			// A frase inteira é o ponto do cenário: um arquivo de 24 bytes lido
			// com pressa vira "capturei e não houve tráfego", que é uma
			// afirmação que ninguém fez.
			"ZERO pacotes casaram o filtro",
			"NÃO é 'não houve tráfego'",
			"é resultado — não falha",
		},
		// Captura vazia é RESULTADO: o socket abriu, o prazo correu, nada casou.
		// Sair diferente de zero aqui transformaria resposta em erro.
		Exit: 0,
	})
}
