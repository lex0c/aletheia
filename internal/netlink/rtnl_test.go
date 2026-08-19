package netlink

import (
	"syscall"
	"testing"
)

// attr monta um TLV como o kernel o escreve: comprimento SEM o padding,
// conteúdo, e o alinhamento de quatro bytes por fora.
func attr(tipo uint16, dados []byte) []byte {
	tam := 4 + len(dados)
	b := make([]byte, tam)
	ordemNativa.PutUint16(b[0:2], uint16(tam))
	ordemNativa.PutUint16(b[2:4], tipo)
	copy(b[4:], dados)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func u32(v uint32) []byte {
	b := make([]byte, 4)
	ordemNativa.PutUint32(b, v)
	return b
}

// O alinhamento é a armadilha desta codificação: o comprimento declarado NÃO
// inclui o padding. Avançar por ele desalinha a leitura no PRIMEIRO atributo de
// tamanho ímpar — e dali em diante todo atributo é lido a partir do byte
// errado, sem erro e com dados plausíveis.
func TestAtributosRespeitamOAlinhamentoDeQuatro(t *testing.T) {
	// "eth0" tem 5 bytes com o NUL: o atributo tem 9, e o próximo começa em 12.
	b := append(attr(syscall.IFLA_IFNAME, []byte("eth0\x00")), attr(iflaXDP, u32(7))...)
	as := atributos(b)
	if len(as) != 2 {
		t.Fatalf("atributos = %d, quer 2 (o segundo se perde sem o alinhamento)", len(as))
	}
	if nome, _ := atributo(as, syscall.IFLA_IFNAME); stringDe(nome) != "eth0" {
		t.Errorf("nome = %q", stringDe(nome))
	}
	if as[1].Tipo != iflaXDP {
		t.Errorf("segundo atributo = %d, quer %d", as[1].Tipo, iflaXDP)
	}
}

// Os dois bits altos do tipo são marcadores — aninhado e ordem de rede —, não
// fazem parte do número. Sem a máscara, um bloco aninhado (0x8000|tipo) nunca
// casaria com o tipo procurado.
func TestAtributosTiramOsBitsDeMarcacaoDoTipo(t *testing.T) {
	const aninhado = 0x8000
	as := atributos(attr(aninhado|tcaOptions, u32(1)))
	if len(as) != 1 || as[0].Tipo != tcaOptions {
		t.Errorf("tipo = %#x, quer %#x", as[0].Tipo, tcaOptions)
	}
}

// Comprimento absurdo é resposta truncada ou corrompida. Seguir em frente
// leria memória de outro atributo como se fosse conteúdo.
func TestAtributosParamEmComprimentoInvalido(t *testing.T) {
	b := []byte{0x02, 0x00, 0x03, 0x00} // tam=2, menor que o próprio cabeçalho
	if as := atributos(b); len(as) != 0 {
		t.Errorf("atributos = %+v, quer nenhum", as)
	}
}

func linkFalso(indice int32, nome string, xdpProgID uint32) []byte {
	b := make([]byte, tamIfInfomsg)
	ordemNativa.PutUint32(b[4:8], uint32(indice))
	b = append(b, attr(syscall.IFLA_IFNAME, []byte(nome+"\x00"))...)
	if xdpProgID != 0 {
		b = append(b, attr(iflaXDP, attr(iflaXDPProgID, u32(xdpProgID)))...)
	}
	return b
}

// O XDP vem num bloco ANINHADO. Ler o bloco como se fosse plano devolveria o
// primeiro atributo de dentro — o modo de anexação — no lugar do id do
// programa, e a atribuição apontaria para o programa errado.
func TestDecodificarLinkLeOXDPDeDentroDoBlocoAninhado(t *testing.T) {
	i, ok := decodificarLink(linkFalso(3, "eth0", 42))
	if !ok {
		t.Fatal("link não decodificado")
	}
	if i.Indice != 3 || i.Nome != "eth0" {
		t.Errorf("link = %+v", i)
	}
	if i.XDPProgID != 42 {
		t.Errorf("xdp = %d, quer 42", i.XDPProgID)
	}
}

// Interface sem XDP é o normal, e precisa sair com ZERO — não com lixo do
// campo, que viraria atribuição inventada para um programa que existe.
func TestDecodificarLinkSemXDPFicaEmZero(t *testing.T) {
	i, _ := decodificarLink(linkFalso(1, "lo", 0))
	if i.XDPProgID != 0 {
		t.Errorf("xdp = %d, quer 0", i.XDPProgID)
	}
}

func filtroFalso(pai uint32, kind string, progID uint32, nome string) []byte {
	b := make([]byte, tamTcmsg)
	ordemNativa.PutUint32(b[12:16], pai)
	b = append(b, attr(tcaKind, []byte(kind+"\x00"))...)
	var opts []byte
	if progID != 0 {
		opts = append(opts, attr(tcaBPFID, u32(progID))...)
	}
	if nome != "" {
		opts = append(opts, attr(tcaBPFName, []byte(nome+"\x00"))...)
	}
	return append(b, attr(tcaOptions, opts)...)
}

// A DIREÇÃO sai do pai, e ela decide o que o programa consegue fazer: no
// ingress ele vê o que CHEGA — onde mora um gatilho de C2 —, no egress vê o que
// sai.
func TestDecodificarFiltroLeIdENomeEDirecao(t *testing.T) {
	f, ok := decodificarFiltro(filtroFalso(pariIngress, "bpf", 77, "cil_from_netdev"), "eth0")
	if !ok {
		t.Fatal("filtro bpf não foi reconhecido")
	}
	if f.ProgID != 77 || f.Nome != "cil_from_netdev" {
		t.Errorf("filtro = %+v", f)
	}
	if f.Direcao != "ingress" {
		t.Errorf("direção = %q, quer ingress", f.Direcao)
	}
	if g, _ := decodificarFiltro(filtroFalso(pariEgress, "bpf", 78, ""), "eth0"); g.Direcao != "egress" {
		t.Errorf("direção = %q, quer egress", g.Direcao)
	}
}

// Um dispositivo tem filtros de todo tipo, e os outros classificadores não
// carregam programa nenhum. Aceitá-los produziria atribuição a partir de bytes
// que significam outra coisa.
func TestDecodificarFiltroIgnoraClassificadorQueNaoEBPF(t *testing.T) {
	if _, ok := decodificarFiltro(filtroFalso(pariIngress, "u32", 77, ""), "eth0"); ok {
		t.Error("u32 não é cls_bpf")
	}
}

// O filtro da forma ANTIGA leva o bytecode embutido e não tem id no espaço de
// programas. Atribuí-lo ao programa de id zero ligaria todos eles entre si.
func TestDecodificarFiltroSemIdNaoAtribuiNada(t *testing.T) {
	if _, ok := decodificarFiltro(filtroFalso(pariIngress, "bpf", 0, "legado"), "eth0"); ok {
		t.Error("sem id não há programa a que atribuir")
	}
}

// Pai desconhecido não pode virar "ingress" por descuido: a grafia crua diz ao
// operador que aquele ponto de anexação é outro.
func TestDirecaoDeParentDesconhecidoSaiCru(t *testing.T) {
	if got := direcaoDoPai(0x12345678); got != "parent=12345678" {
		t.Errorf("direção = %q", got)
	}
}

// A ação de tc (act_bpf) vem aninhada: TCA_ACT_KIND="bpf" + TCA_ACT_OPTIONS.
//
// As opções são montadas na ordem REAL do kernel, com números LITERAIS (não o
// símbolo tcaActBPFID), pondo ISCAS nos vizinhos do id: FLAGS(7) e o TAG(8) de 8
// bytes ladeiam o ID(9). Ler o id do atributo errado devolve o flags, ou os 4
// primeiros bytes do tag — e o teste falha. É de propósito: o teste antigo
// montava o id no MESMO símbolo que decodificava, então passava com a constante
// certa OU errada. Foi esse ponto cego que deixou o id escorregar (lido no 7,
// TCA_ACT_BPF_FLAGS; depois no 8, o TAG) até a matriz pegar contra o kernel real.
func TestDecodificarAcaoBPF(t *testing.T) {
	// TCA_ACT_BPF_*: PARMS=2, NAME=6, FLAGS=7, TAG=8, ID=9.
	opts := attr(2, make([]byte, 20))                               // PARMS (struct tc_act_bpf)
	opts = append(opts, attr(6, []byte("cil_xdp\x00"))...)          // NAME
	opts = append(opts, attr(7, u32(1))...)                         // FLAGS (isca)
	opts = append(opts, attr(8, []byte{9, 8, 7, 6, 5, 4, 3, 2})...) // TAG de 8 bytes (isca)
	opts = append(opts, attr(9, u32(88))...)                        // ID (o certo)
	acao := append(attr(tcaActKind, []byte("bpf\x00")), attr(tcaActOptions, opts)...)

	ac, ok := decodificarAcaoBPF(acao)
	if !ok {
		t.Fatal("ação bpf válida não foi reconhecida")
	}
	if ac.ProgID != 88 {
		t.Errorf("prog id = %d, quer 88 (id lido do atributo errado?)", ac.ProgID)
	}
	if ac.Nome != "cil_xdp" {
		t.Errorf("nome = %q", ac.Nome)
	}
}

// Ação de OUTRO tipo (mirred, gact) não carrega programa: não pode virar
// atribuição a partir de bytes que significam outra coisa.
func TestDecodificarAcaoBPFIgnoraOutroKind(t *testing.T) {
	acao := append(attr(tcaActKind, []byte("mirred\x00")), attr(tcaActOptions, u32(1))...)
	if _, ok := decodificarAcaoBPF(acao); ok {
		t.Error("mirred não é act_bpf")
	}
}

// Ação bpf sem id (bytecode embutido, forma antiga) não tem programa no espaço
// de ids a que atribuir.
func TestDecodificarAcaoBPFSemIDNaoAtribui(t *testing.T) {
	acao := append(attr(tcaActKind, []byte("bpf\x00")),
		attr(tcaActOptions, attr(tcaActBPFName, []byte("x\x00")))...)
	if _, ok := decodificarAcaoBPF(acao); ok {
		t.Error("ação bpf sem id não pode atribuir")
	}
}

// O construtor de nlattr é o espelho do parser: o que ele monta, atributos()
// tem de reler. Alinhamento a 4 incluído.
func TestNlattrIdaEVolta(t *testing.T) {
	b := nlattr(tcaActKind, []byte("bpf\x00"))
	as := atributos(b)
	if len(as) != 1 || as[0].Tipo != tcaActKind || stringDe(as[0].Dados) != "bpf" {
		t.Errorf("nlattr/atributos não fecham: %+v", as)
	}
	// payload de tamanho ímpar precisa do padding para o próximo atributo casar.
	dois := append(nlattr(1, []byte("ab")), nlattr(2, u32(9))...)
	if a := atributos(dois); len(a) != 2 || a[1].Tipo != 2 {
		t.Errorf("padding quebrou o segundo atributo: %+v", a)
	}
}
