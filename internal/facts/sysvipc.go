package facts

import (
	"strconv"
	"strings"
	"time"

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
	// CriadoEm é o ctime do segmento (epoch). É a âncora temporal que prova, ou
	// desmente, que o processo de CPID é mesmo o criador.
	CriadoEm int `json:"created_at,omitempty"`
	// PIDReciclado marca que existe processo com o CPID e ele começou DEPOIS do
	// segmento: o número foi reaproveitado, e aquele processo não é o criador.
	PIDReciclado bool `json:"pid_recycled,omitempty"`
	// CriadorNaoConfirmado é o caso honesto do meio — não deu para comparar as
	// datas. A atribuição não é usada para subir severidade.
	CriadorNaoConfirmado bool `json:"creator_unconfirmed,omitempty"`
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
		// O ctime do segmento é a coluna 14 do /proc/sysvipc/shm, e é ele que
		// separa o criador de verdade de um PID reciclado.
		if len(fs) >= 14 {
			seg.CriadoEm = atoiSeg(fs[13])
		}
		// PID RECICLADO NÃO É O CRIADOR, e casar por número era suficiente para
		// inventar um.
		//
		// O próprio comentário deste coletor já dizia que o segmento SOBREVIVE à
		// morte do criador. O PID some junto, e o kernel o reaproveita: horas
		// depois, um processo novo com o mesmo número abre um socket de escuta e
		// o segmento órfão de 3 MiB vira "canal do Ebury" — CRITICAL, direto,
		// sem atacante nenhum. Em servidor com uptime longo isso é questão de
		// tempo, e CRITICAL falso é o que ensina o operador a ignorar o próximo.
		//
		// A prova é temporal: processo que começou DEPOIS do segmento não pode
		// tê-lo criado. Onde não dá para comparar — sem ctime ou sem hora de
		// início — a atribuição fica NÃO CONFIRMADA, e o check não a usa para
		// subir a severidade. Preferir o aviso ao crítico inventado.
		if p := f.ProcessByPID(seg.CPID); p != nil {
			seg.Criador = p.Comm
			switch depois, ok := processoComecouDepois(p, seg.CriadoEm); {
			case !ok:
				seg.CriadorNaoConfirmado = true
			case depois:
				seg.CriadorNaoConfirmado = true
				seg.Criador = ""
				seg.PIDReciclado = true
			}
		}
		seg.CriadorEmRede = emRede[seg.CPID] && !seg.CriadorNaoConfirmado
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

// processoComecouDepois diz se o processo começou DEPOIS do instante dado.
//
// O segundo retorno é "deu para comparar": sem hora de início do processo ou
// sem ctime do segmento não há prova em direção nenhuma, e inventar uma seria
// pior que não ter.
//
// A TOLERÂNCIA não é frouxidão: é o erro da própria medida, e ignorá-la
// suprimia uma detecção real.
//
// O início do processo não é lido, é DERIVADO — btime do /proc/stat (segundo
// inteiro) mais o campo 22 do /proc/<pid>/stat dividido pelo USER_HZ. As duas
// pontas arredondam, e o resultado pode cair DEPOIS do instante verdadeiro.
// Medido no cenário SV3, onde o helper cria o segmento no primeiro instante de
// vida: ctime 07:35:51, início derivado 07:35:52. Com comparação estrita, o
// criador legítimo era acusado de PID reciclado e o CRITICAL do Ebury sumia —
// trocar um falso positivo por um falso negativo no ponto mais forte do
// catálogo é péssimo negócio.
//
// O viés é deliberado e assimétrico: errar para "não é reciclagem" devolve o FP
// que este guarda existe para tirar; errar para "é reciclagem" APAGA uma
// detecção. Entre os dois, prefira o primeiro.
//
// 60s é folga enorme sobre os ~2s de erro da medida. O que ela custa: num host
// onde o espaço de PID dá a volta em menos de um minuto — servidor de build com
// pid_max pequeno e milhares de forks por segundo — uma reciclagem dentro dessa
// janela passa despercebida, e ali o resultado é o comportamento antigo, não
// algo pior.
const toleranciaCriacaoSHM = 60

func processoComecouDepois(p *Process, criadoEm int) (bool, bool) {
	if p.StartUTC == "" || criadoEm <= 0 {
		return false, false
	}
	t, err := time.Parse(time.RFC3339, p.StartUTC)
	if err != nil {
		return false, false
	}
	return t.Unix() > int64(criadoEm)+toleranciaCriacaoSHM, true
}
