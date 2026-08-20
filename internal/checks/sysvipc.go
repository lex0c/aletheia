package checks

import (
	"strconv"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() {
	check.Register(sysvShmChannel)
}

// sysvShmChannel — runbook §7.12.
//
// Um segmento de memória compartilhada System V que QUALQUER usuário lê ou
// escreve. SysV SHM é o canal do Ebury: a credencial roubada passa pela memória
// compartilhada entre o sshd trojanizado e o exfil, sem tocar em socket, fd de
// arquivo nem conexão de rede — invisível para quem só olha rede e disco.
//
// O discriminador é a PERMISSÃO, não a existência. SysV SHM legítimo (banco de
// dados, HPC) é 0600 ou 0660 restrito a um grupo. Bit de OUTRO (r/w para o mundo)
// num segmento é a marca do canal aberto: qualquer processo entra nele. Quando é
// gravável pelo mundo E pertence a root, qualquer um injeta no canal de root.
var sysvShmChannel = check.Check{
	ID:       "persist.sysv_shm_channel",
	Ref:      "7.12",
	Title:    "memória compartilhada System V aberta ao mundo",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive, // /proc/sysvipc é do kernel VIVO; não existe em imagem
	Requires: env.CapProcfs,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"SysV SHM legítimo é restrito: banco de dados (PostgreSQL, Oracle) e HPC " +
			"criam segmento 0600 ou 0660 de grupo. Só o bit de OUTRO (mundo lê/" +
			"escreve) vira achado — 0640/0660 de grupo não dispara",
		"segmento gravável pelo mundo mas de usuário comum (não root) é aviso, " +
			"não crítico: o canal existe, mas não é o de root que o Ebury usa",
		"o criador (cpid) pode já ter saído — o segmento sobrevive a ele. A " +
			"ausência do nome do criador NÃO invalida o achado; a permissão é o sinal",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for _, s := range f.SysVShm {
			outroLe := s.Perms&0o004 != 0
			outroEscreve := s.Perms&0o002 != 0
			if !outroLe && !outroEscreve {
				continue // restrito a dono/grupo: é a forma legítima
			}

			ev := []string{
				"shmid=" + strconv.Itoa(s.ShmID) + " key=" + strconv.Itoa(s.Key) +
					" perms=0" + strconv.FormatInt(int64(s.Perms), 8) +
					" tamanho=" + strconv.FormatUint(s.Size, 10) + " bytes",
				"SysV SHM é canal IPC que não aparece em socket, fd de arquivo nem " +
					"conexão — é por ele que o Ebury passa credencial entre sshd e exfil",
			}
			if s.Criador != "" {
				ev = append(ev, "criado pelo processo "+s.Criador+" (pid "+
					strconv.Itoa(s.CPID)+")")
			} else {
				ev = append(ev, "o criador (pid "+strconv.Itoa(s.CPID)+") já saiu; "+
					"o segmento sobreviveu a ele")
			}
			if s.NAttch > 0 {
				ev = append(ev, strconv.Itoa(s.NAttch)+" processo(s) anexado(s) agora")
			}

			// Gravável pelo mundo E de root é o pior: qualquer usuário injeta no
			// canal de root. Mundo só lê, ou dono comum, é aviso.
			sev := check.SevWarn
			if outroEscreve && s.UID == 0 {
				sev = check.SevCritical
				ev = append(ev, "gravável por QUALQUER usuário e pertence a root: "+
					"qualquer um injeta neste canal privilegiado")
			}

			fd := self.F(sev, "shmid="+strconv.Itoa(s.ShmID), "", ev...)
			fd.NextSteps = []string{
				"veja quem está anexado: sudo ls -l /proc/*/maps | grep -l SYSV " +
					"2>/dev/null; ou `ipcs -m -i " + strconv.Itoa(s.ShmID) + "`",
				"o criador é o par do canal: se for sshd ou daemon de rede, é a " +
					"forma do Ebury — preserve o processo antes de tocar",
			}
			r.Findings = append(r.Findings, fd)
		}
		return r
	},
}
