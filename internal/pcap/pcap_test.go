package pcap

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
	"time"
)

// quadro monta um pacote ethernet + IPv4 + TCP/UDP com o que os testes precisam.
func quadro(src, dst [4]byte, proto byte, sp, dp int) []byte {
	p := make([]byte, 14+20+8)
	p[12], p[13] = 0x08, 0x00 // EtherType IPv4
	ip := p[14:]
	ip[0] = 0x45 // versão 4, IHL 5
	ip[9] = proto
	copy(ip[12:16], src[:])
	copy(ip[16:20], dst[:])
	tr := p[34:]
	binary.BigEndian.PutUint16(tr[0:], uint16(sp))
	binary.BigEndian.PutUint16(tr[2:], uint16(dp))
	return p
}

var (
	alvo  = [4]byte{198, 51, 100, 241}
	local = [4]byte{10, 0, 0, 5}
	outro = [4]byte{8, 8, 8, 8}
)

// O leitor independente. Escrever e ler com o mesmo código provaria só que ele
// concorda consigo mesmo; este parser segue o formato do libpcap como está
// documentado, e é ele que diz se um Wireshark conseguiria abrir o arquivo.
type lido struct {
	magic, snaplen, enlace uint32
	versao                 [2]uint16
	pacotes                []pacoteLido
}

type pacoteLido struct {
	ts             time.Time
	dados          []byte
	tamanhoOrignal int
}

func ler(t *testing.T, b []byte) lido {
	t.Helper()
	if len(b) < 24 {
		t.Fatalf("arquivo com %d bytes: nem o cabeçalho global cabe", len(b))
	}
	le := binary.LittleEndian
	out := lido{
		magic:   le.Uint32(b[0:]),
		versao:  [2]uint16{le.Uint16(b[4:]), le.Uint16(b[6:])},
		snaplen: le.Uint32(b[16:]),
		enlace:  le.Uint32(b[20:]),
	}
	for off := 24; off < len(b); {
		if off+16 > len(b) {
			t.Fatalf("cabeçalho de pacote truncado em %d", off)
		}
		seg, usec := le.Uint32(b[off:]), le.Uint32(b[off+4:])
		incl, orig := le.Uint32(b[off+8:]), le.Uint32(b[off+12:])
		off += 16
		if off+int(incl) > len(b) {
			t.Fatalf("pacote truncado em %d: diz %d bytes e o arquivo acabou", off, incl)
		}
		out.pacotes = append(out.pacotes, pacoteLido{
			ts:             time.Unix(int64(seg), int64(usec)*1000).UTC(),
			dados:          b[off : off+int(incl)],
			tamanhoOrignal: int(orig),
		})
		off += int(incl)
	}
	return out
}

func TestArquivoTemOFormatoDoLibpcap(t *testing.T) {
	var buf bytes.Buffer
	h := sha256.New()
	e, err := NovoEscritor(&buf, h, 65535, LinkEthernet)
	if err != nil {
		t.Fatal(err)
	}
	q := quadro(alvo, local, protoTCP, 443, 51000)
	quando := time.Date(2026, 8, 17, 21, 3, 11, 123456000, time.UTC)
	if err := e.Pacote(quando, q, len(q)); err != nil {
		t.Fatal(err)
	}
	// Um pacote CORTADO pelo snaplen: o tamanho original é o que separa
	// "pacote pequeno" de "pacote truncado", e sem ele a análise conclui errado.
	if err := e.Pacote(quando, q[:20], 1514); err != nil {
		t.Fatal(err)
	}

	r := ler(t, buf.Bytes())
	if r.magic != magicMicro {
		// uint32 explícito: a constante não tipada vira `int` ao entrar num
		// `any`, e 0xa1b2c3d4 estoura o int de 32 bits — o teste não compilava
		// em i686, que é justamente a arquitetura onde o socketcall e este
		// escritor nunca tinham sido exercitados.
		t.Errorf("magic = %08x, queria %08x", r.magic, uint32(magicMicro))
	}
	if r.versao != [2]uint16{2, 4} {
		t.Errorf("versão = %v, queria 2.4", r.versao)
	}
	if r.snaplen != 65535 || r.enlace != LinkEthernet {
		t.Errorf("snaplen=%d enlace=%d", r.snaplen, r.enlace)
	}
	if len(r.pacotes) != 2 {
		t.Fatalf("%d pacotes lidos, queria 2", len(r.pacotes))
	}
	if !r.pacotes[0].ts.Equal(quando) {
		t.Errorf("ts = %v, queria %v (microssegundo é a resolução do formato)",
			r.pacotes[0].ts, quando)
	}
	if !bytes.Equal(r.pacotes[0].dados, q) {
		t.Error("os bytes do pacote não voltaram iguais")
	}
	if r.pacotes[1].tamanhoOrignal != 1514 || len(r.pacotes[1].dados) != 20 {
		t.Errorf("o corte do snaplen se perdeu: incl=%d orig=%d",
			len(r.pacotes[1].dados), r.pacotes[1].tamanhoOrignal)
	}

	// O hash acompanha a escrita: é a cadeia de custódia de uma peça que não
	// tem original para comparar — a origem é o fio, e ele não volta.
	soma := sha256.Sum256(buf.Bytes())
	if hex.EncodeToString(h.Sum(nil)) != hex.EncodeToString(soma[:]) {
		t.Error("o hash calculado durante a escrita não bate com o arquivo")
	}
	if e.Bytes != int64(buf.Len()) || e.Pacotes != 2 {
		t.Errorf("contagem = %d bytes / %d pacotes", e.Bytes, e.Pacotes)
	}
}

// Um arquivo sem pacote nenhum ainda precisa ser um pcap VÁLIDO: zero pacote é
// resultado, e um arquivo que não abre transformaria resultado em falha.
func TestCapturaVaziaAindaEhUmPcapValido(t *testing.T) {
	var buf bytes.Buffer
	if _, err := NovoEscritor(&buf, nil, 262144, LinkRaw); err != nil {
		t.Fatal(err)
	}
	r := ler(t, buf.Bytes())
	if r.magic != magicMicro || r.enlace != LinkRaw || len(r.pacotes) != 0 {
		t.Errorf("cabeçalho inválido: %+v", r)
	}
	if buf.Len() != 24 {
		t.Errorf("%d bytes, queria 24", buf.Len())
	}
}
