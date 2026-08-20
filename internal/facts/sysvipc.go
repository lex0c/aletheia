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
	// CriadorEmRede diz que o criador tem SOCKET DE ESCUTA — é um daemon de rede.
	// É o discriminador que pega o Ebury MODERNO: a versão 1.3.5 trocou a
	// permissão do segmento para 0600 justamente para derrotar o IOC de
	// permissão, mas o CANAL continua sendo criado por um daemon de rede (o
	// sshd), e é isso que não muda.
	CriadorEmRede bool `json:"creator_networked,omitempty"`
}

// collectSysVShm lê /proc/sysvipc/shm e correlaciona o criador (cpid) com a
// lista de processos e com os sockets de escuta. Precisa rodar DEPOIS de
// collectProcesses e collectSockets.
func collectSysVShm(f *Facts, e *env.Env) {
	b, err := e.ReadFile("/proc/sysvipc/shm")
	if err != nil {
		// ENOENT (kernel sem CONFIG_SYSVIPC) é "mecanismo não existe", uma
		// resposta completa. Permissão/IO é o oposto: EXISTE e não pude ler — e
		// aí a ausência de achado é lacuna, não limpeza.
		if env.EhLacuna(err) {
			f.partial("sysvipc", "/proc/sysvipc/shm existe e não pôde ser lido ("+
				env.MotivoDoErro(err)+"): segmento SysV suspeito NÃO entrou na varredura")
		}
		return
	}

	// Quem tem socket de escuta é daemon de rede — o par do canal do Ebury.
	emRede := map[int]bool{}
	for i := range f.Sockets {
		if f.Sockets[i].State == "LISTEN" && f.Sockets[i].PID != 0 {
			emRede[f.Sockets[i].PID] = true
		}
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
		seg.CriadorEmRede = emRede[seg.CPID]
		f.SysVShm = append(f.SysVShm, seg)
	}

	lacunaDeIPCNS(f, e)
}

// lacunaDeIPCNS declara que /proc/sysvipc/shm é POR IPC NAMESPACE: um segmento
// criado em outro IPC ns (contêiner com CLONE_NEWIPC) não aparece nesta leitura.
// Espelha lacunaDeNetns — a mesma honestidade sobre o que ficou fora do alcance.
func lacunaDeIPCNS(f *Facts, e *env.Env) {
	if !e.Has(env.CapProcfs) {
		return
	}
	meu, ok := inodeDeNS("/proc/self/ns/ipc")
	if !ok {
		return
	}
	pids, err := e.ReadDirNamesErr("/proc")
	if err != nil {
		return // não listar /proc já é lacuna do coletor de proc
	}
	outros := map[uint64]bool{}
	for _, pid := range pids {
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		if ino, ok := inodeDeNS("/proc/" + pid + "/ns/ipc"); ok && ino != meu {
			outros[ino] = true
		}
	}
	if len(outros) == 0 {
		return // um IPC ns só: não há segmento fora do que /proc/sysvipc/shm mostra
	}
	f.partial("sysvipc", strconv.Itoa(len(outros))+" outro(s) IPC namespace(s) presente(s) "+
		"(contêiner/serviço com CLONE_NEWIPC): segmento SysV SHM criado DENTRO deles "+
		"NÃO aparece em /proc/sysvipc/shm desta execução — entrar em cada IPC ns por "+
		"setns() não é feito.")
}

func atoiSeg(s string) int      { n, _ := strconv.Atoi(s); return n }
func atou64Seg(s string) uint64 { n, _ := strconv.ParseUint(s, 10, 64); return n }

// atoiOctal lê a coluna de permissão, que o kernel imprime em OCTAL (%o): "666"
// é 0666. Interpretar como decimal daria 666 e quebraria toda a lógica de bit.
func atoiOctal(s string) int { n, _ := strconv.ParseInt(s, 8, 32); return int(n) }
