// plant monta UMA técnica de ataque no próprio processo e dorme, para a
// aletheia escaneá-lo. É material de TESTE da matriz adversarial — não é
// malicioso: cada técnica é a forma estrutural que um check afirma pegar (ou
// que se quer provar como ponto cego), montada de propósito para ser detectada.
//
// SEGURANÇA: tudo é userspace e local. Nada carrega módulo, nada conecta na
// internet (os cenários de rede usam TEST-NET-3, 203.0.113.0/24, que nunca é
// roteada), nada escreve fora de /tmp. Roda no contêiner descartável da matriz.
package main

import (
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"
)

func must(err error, o string) {
	if err != nil {
		fmt.Fprintln(os.Stderr, o+":", err)
		os.Exit(1)
	}
}

// nomearVMA dá um rótulo a uma região anônima (PR_SET_VMA_ANON_NAME, 5.17+).
// É o que o JIT moderno faz — e o que um payload pode COPIAR para se esconder
// do proc.maps_exec_anon, que só conta região SEM rótulo. O kernel exibe o nome
// como "[anon:NOME]" e REJEITA colchetes no argumento: passa-se só o NOME.
func nomearVMA(b []byte, nome string) {
	const prSetVMA = 0x53564d41
	n := append([]byte(nome), 0)
	syscall.Syscall6(syscall.SYS_PRCTL, prSetVMA, 0,
		uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), uintptr(unsafe.Pointer(&n[0])), 0)
}

func mmapAnon(prot int) []byte {
	b, err := syscall.Mmap(-1, 0, 4096, prot, syscall.MAP_PRIVATE|syscall.MAP_ANON)
	must(err, "mmap anon")
	copy(b, []byte{0x90, 0x90, 0xc3})
	return b
}

// mapDeArquivo mapeia um arquivo e opcionalmente o apaga (deixando o mapeamento
// "(deleted)"). É a lib aberta com dlopen e removida em seguida.
func mapDeArquivo(path string, prot int, apagar bool) []byte {
	must(os.WriteFile(path, make([]byte, 8192), 0o755), "write "+path)
	fh, err := os.Open(path)
	must(err, "open "+path)
	b, err := syscall.Mmap(int(fh.Fd()), 0, 8192, prot, syscall.MAP_PRIVATE)
	must(err, "mmap "+path)
	if apagar {
		os.Remove(path)
	}
	return b
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "uso: plant <tecnica>")
		os.Exit(2)
	}
	var manter [][]byte
	switch os.Args[1] {
	// --- REGRESSÃO: cada uma é o que um check afirma pegar ---
	case "rwx-anon": // proc.maps_rwx_anon
		manter = append(manter, mmapAnon(syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC))
	case "rx-anon": // proc.maps_exec_anon (W^X: mmap RW -> mprotect RX)
		b := mmapAnon(syscall.PROT_READ | syscall.PROT_WRITE)
		must(syscall.Mprotect(b, syscall.PROT_READ|syscall.PROT_EXEC), "mprotect")
		manter = append(manter, b)
	case "deleted-exec": // proc.deleted_mapping (CRITICAL, /tmp)
		manter = append(manter, mapDeArquivo("/tmp/.plant.so", syscall.PROT_READ|syscall.PROT_EXEC, true))

	// --- PONTO CEGO: técnicas que se quer medir se passam sem sinal ---
	case "rx-anon-rotulada": // maps_exec_anon só conta SEM rótulo: rótulo spoofado esconde
		b := mmapAnon(syscall.PROT_READ | syscall.PROT_WRITE)
		must(syscall.Mprotect(b, syscall.PROT_READ|syscall.PROT_EXEC), "mprotect")
		nomearVMA(b, "js-executable-memory")
		manter = append(manter, b)
	case "deleted-data": // deleted_mapping exige EXECUTÁVEL: segmento de dado apagado passa
		manter = append(manter, mapDeArquivo("/tmp/.plantd.so", syscall.PROT_READ|syscall.PROT_WRITE, true))

	default:
		fmt.Fprintln(os.Stderr, "técnica desconhecida:", os.Args[1])
		os.Exit(2)
	}
	_ = manter
	fmt.Printf("PLANT pid=%d tech=%s\n", os.Getpid(), os.Args[1])
	os.Stdout.Sync()
	time.Sleep(120 * time.Second)
}
