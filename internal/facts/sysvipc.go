package facts

import (
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/env"
)

// SysVShmSeg é um segmento de memória compartilhada System V, lido de
// /proc/sysvipc/shm.
//
// Por que importa: SysV SHM é um canal IPC que não aparece em socket, em fd de
// arquivo nem em conexão de rede. É o canal que o Ebury usa entre o sshd
// trojanizado e o componente de exfiltração — a credencial roubada passa pela
// memória compartilhada, invisível para quem só olha rede e disco. Nenhuma
// outra parte da ferramenta o enxerga.
type SysVShmSeg struct {
	Key    int    `json:"key"`
	ShmID  int    `json:"shmid"`
	Perms  int    `json:"perms"` // octal: 0600, 0666…
	Size   uint64 `json:"size"`
	CPID   int    `json:"cpid"` // quem CRIOU o segmento
	LPID   int    `json:"lpid"` // último que operou nele
	NAttch int    `json:"nattch"`
	UID    int    `json:"uid"`
	// Criador é o comm do processo CPID, quando ele ainda vive. Vazio quando o
	// criador já saiu — o segmento sobrevive à morte de quem o criou.
	Criador string `json:"creator_comm,omitempty"`
}

// collectSysVShm lê /proc/sysvipc/shm e correlaciona o criador (cpid) com a
// lista de processos. Precisa rodar DEPOIS de collectProcesses.
func collectSysVShm(f *Facts, e *env.Env) {
	b, err := e.ReadFile("/proc/sysvipc/shm")
	if err != nil {
		// Ausência aqui não é lacuna: um kernel sem CONFIG_SYSVIPC não tem o
		// arquivo, e um host sem segmento nenhum tem só o cabeçalho. As duas
		// respostas são "não há canal SysV", e é isso que interessa.
		return
	}
	for i, ln := range strings.Split(string(b), "\n") {
		fs := strings.Fields(ln)
		// Cabeçalho (i==0, começa por "key") e linha curta: fora.
		if i == 0 || len(fs) < 8 {
			continue
		}
		seg := SysVShmSeg{
			Key:    atoiSeg(fs[0]),
			ShmID:  atoiSeg(fs[1]),
			Perms:  atoiOctal(fs[2]),
			Size:   atou64Seg(fs[3]),
			CPID:   atoiSeg(fs[4]),
			LPID:   atoiSeg(fs[5]),
			NAttch: atoiSeg(fs[6]),
			UID:    atoiSeg(fs[7]),
		}
		if p := f.ProcessByPID(seg.CPID); p != nil {
			seg.Criador = p.Comm
		}
		f.SysVShm = append(f.SysVShm, seg)
	}
}

func atoiSeg(s string) int      { n, _ := strconv.Atoi(s); return n }
func atou64Seg(s string) uint64 { n, _ := strconv.ParseUint(s, 10, 64); return n }

// atoiOctal lê a coluna de permissão, que o kernel imprime em OCTAL (%o): "666"
// é 0666. Interpretar como decimal daria 666 e quebraria toda a lógica de bit.
func atoiOctal(s string) int { n, _ := strconv.ParseInt(s, 8, 32); return int(n) }
