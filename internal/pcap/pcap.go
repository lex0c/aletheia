// Package pcap captura tráfego sem tcpdump e sem libpcap.
//
// # Por que existe
//
// O runbook manda capturar em vários pontos, e num host suspeito isso esbarra
// em duas paredes: em imagem mínima o `tcpdump` não está instalado, e instalá-lo
// mexe na base de pacotes — que é justamente a evidência da §24. Compilar com
// libpcap exigiria cgo, e cgo mata o binário estático que faz esta ferramenta
// rodar em userland comprometido (SPEC 4).
//
// O que sobra é o que o kernel oferece direto: AF_PACKET, e um formato de
// arquivo que cabe em 24 bytes de cabeçalho global mais 16 por pacote.
//
// # O que esta captura NÃO prova
//
// Um eBPF hostil em `xdp` ou `tc` esconde o pacote ANTES de ele chegar ao
// socket. Uma captura limpa neste host não é prova de que não há tráfego: é
// prova de que nada chegou até aqui. Captura confiável é espelhamento FORA da
// máquina (§2.6, §35.4), e o comando diz isso em voz alta toda vez.
//
// # O filtro é de espaço de usuário, de propósito
//
// A alternativa era `SO_ATTACH_FILTER`: montar um programa BPF clássico à mão e
// deixar o kernel descartar antes de copiar. É mais eficiente e tem um modo de
// falha inaceitável aqui — um filtro sutilmente errado descarta o que você
// pediu, e a captura sai LEGITIMAMENTE vazia. Ninguém revisa um arquivo vazio.
//
// Filtrando em espaço de usuário, um erro meu só pode escrever pacote demais —
// nunca perder o que foi pedido em silêncio. O preço é o kernel entregar tudo, e
// esse preço é MEDIDO: o contador de descartes do próprio kernel entra no
// relatório, e uma captura que perdeu pacote é declarada incompleta.
package pcap

import (
	"encoding/binary"
	"hash"
	"io"
	"time"
)

// Os tipos de enlace que este escritor sabe rotular. Escrever um pcap com o
// rótulo errado é pior que não escrever: o Wireshark decodifica com confiança
// total a partir do byte errado, e a conclusão sai limpa e falsa.
const (
	LinkEthernet = 1   // DLT_EN10MB — ethernet e também o loopback do Linux
	LinkRaw      = 101 // DLT_RAW — tun/ppp: o pacote começa no IP
)

// Escritor emite o formato clássico do libpcap, em little-endian.
//
// O hash é calculado ENQUANTO se escreve. Não há um "original" para comparar —
// a origem é o fio, e ele não volta —, mas a cadeia de custódia ainda vale:
// releitura do arquivo contra este hash detecta corrupção na escrita e qualquer
// alteração posterior.
type Escritor struct {
	w       io.Writer
	h       hash.Hash
	Bytes   int64
	Pacotes int
	// reg é o buffer de UM registro (cabeçalho + payload), reusado entre
	// pacotes. Ver Pacote.
	reg []byte
}

const (
	magicMicro = 0xa1b2c3d4
	versaoMaj  = 2
	versaoMin  = 4
)

// NovoEscritor escreve o cabeçalho global.
func NovoEscritor(w io.Writer, h hash.Hash, snaplen uint32, tipoEnlace uint32) (*Escritor, error) {
	e := &Escritor{w: w, h: h}
	var hdr [24]byte
	le := binary.LittleEndian
	le.PutUint32(hdr[0:], magicMicro)
	le.PutUint16(hdr[4:], versaoMaj)
	le.PutUint16(hdr[6:], versaoMin)
	le.PutUint32(hdr[8:], 0) // fuso: sempre GMT, como a ferramenta inteira
	le.PutUint32(hdr[12:], 0)
	le.PutUint32(hdr[16:], snaplen)
	le.PutUint32(hdr[20:], tipoEnlace)
	return e, e.escrever(hdr[:])
}

// Pacote grava um quadro. `original` é o tamanho que ele TINHA no fio: quando o
// snaplen corta, é esse número que diz que o corte aconteceu — e sem ele um
// pacote truncado passa por pacote pequeno.
func (e *Escritor) Pacote(quando time.Time, dados []byte, original int) error {
	// UMA escrita por pacote, não duas.
	//
	// Cabeçalho e payload saíam em write(2) separados sobre um *os.File cru: 2
	// syscalls e 2 sha256.Write por quadro. A ~50k pps o laço de leitura ficava
	// atrás do ring do AF_PACKET e o tp_drops subia — e esse é justamente o
	// número que o pacote usa para declarar a captura incompleta. A lentidão do
	// escritor virava "evidência" de perda no fio.
	if cap(e.reg) < 16+len(dados) {
		e.reg = make([]byte, 16+len(dados)+2048)
	}
	reg := e.reg[:16+len(dados)]
	le := binary.LittleEndian
	le.PutUint32(reg[0:], uint32(quando.Unix()))
	le.PutUint32(reg[4:], uint32(quando.Nanosecond()/1000))
	le.PutUint32(reg[8:], uint32(len(dados)))
	le.PutUint32(reg[12:], uint32(original))
	copy(reg[16:], dados)
	if err := e.escrever(reg); err != nil {
		return err
	}
	e.Pacotes++
	return nil
}

func (e *Escritor) escrever(b []byte) error {
	n, err := e.w.Write(b)
	e.Bytes += int64(n)
	if e.h != nil && n > 0 {
		e.h.Write(b[:n])
	}
	return err
}
