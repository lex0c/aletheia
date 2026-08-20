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
// Dois discriminadores, porque o Ebury tem duas eras.
//
//	PERMISSÃO   SysV SHM legítimo (banco, HPC) é 0600/0660 restrito a dono/grupo.
//	            Bit de OUTRO (r/w para o mundo) é o canal aberto; gravável pelo
//	            mundo E de root, qualquer um injeta no canal de root — o Ebury antigo.
//	CRIADOR     o Ebury 1.3.5 trocou para 0600 justamente para derrotar o IOC de
//	            permissão. O que não mudou: o canal é GRANDE e criado por um
//	            DAEMON DE REDE (o sshd). Segmento >= 3 MiB de um criador com socket
//	            de escuta é crítico mesmo restrito — o tamanho separa do interlock
//	            minúsculo (bytes) que o PostgreSQL cria.
var sysvShmChannel = check.Check{
	ID:       "persist.sysv_shm_channel",
	Ref:      "7.12",
	Title:    "memória compartilhada System V: canal aberto ou perfil do Ebury",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive, // /proc/sysvipc é do kernel VIVO; não existe em imagem
	Requires: env.CapProcfs,
	Optional: env.CapRoot,
	Wtf:      true,
	FalsePositives: []string{
		"SysV SHM legítimo é restrito: banco de dados (PostgreSQL, Oracle) e HPC " +
			"criam segmento 0600 ou 0660 de grupo. 0640/0660 de grupo não dispara",
		"o interlock do PostgreSQL é 0600 e criado por um daemon de rede, mas é " +
			"MINÚSCULO (bytes): o piso de 3 MiB do critério de criador-de-rede o " +
			"deixa de fora. Só o segmento GRANDE de daemon de rede vira crítico",
		"segmento gravável pelo mundo mas de usuário comum (não root) é aviso, " +
			"não crítico: o canal existe, mas não é o de root que o Ebury usa",
		"o criador (cpid) pode já ter saído — o segmento sobrevive a ele. A " +
			"ausência do nome do criador NÃO invalida o achado por permissão",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for _, s := range f.SysVShm {
			outroLe := s.Perms&0o004 != 0
			outroEscreve := s.Perms&0o002 != 0
			aberto := outroLe || outroEscreve
			// O Ebury MODERNO trocou a permissão para 0600 justamente para
			// derrotar o IOC de permissão. O que não mudou: o canal é GRANDE e
			// criado por um DAEMON DE REDE (o sshd). O tamanho separa isso do
			// interlock minúsculo (bytes) que o PostgreSQL cria — nada de banco
			// se aproxima do piso de MiB.
			ebury := s.CriadorEmRede && s.Size >= 3*1024*1024
			if !aberto && !ebury {
				continue // restrito a dono/grupo e criador comum: a forma legítima
			}

			ev := []string{
				"shmid=" + strconv.Itoa(s.ShmID) + " key=" + strconv.Itoa(s.Key) +
					" perms=0" + strconv.FormatInt(int64(s.Perms), 8) +
					" tamanho=" + strconv.FormatUint(s.Size, 10) + " bytes",
				"SysV SHM é canal IPC que não aparece em socket, fd de arquivo nem " +
					"conexão — é por ele que o Ebury passa credencial entre sshd e exfil",
			}
			if s.Criador != "" {
				dr := ""
				if s.CriadorEmRede {
					dr = " — que é DAEMON DE REDE (tem socket de escuta)"
				}
				ev = append(ev, "criado pelo processo "+s.Criador+" (pid "+
					strconv.Itoa(s.CPID)+")"+dr)
			} else {
				ev = append(ev, "o criador (pid "+strconv.Itoa(s.CPID)+") já saiu; "+
					"o segmento sobreviveu a ele")
			}
			if s.NAttch > 0 {
				ev = append(ev, strconv.Itoa(s.NAttch)+" processo(s) anexado(s) agora")
			}

			sev := check.SevWarn
			switch {
			case ebury:
				// Um segmento grande criado por daemon de rede é o perfil do
				// canal do Ebury, mesmo restrito a 0600 — o IOC que a permissão
				// sozinha perde.
				sev = check.SevCritical
				ev = append(ev, "segmento GRANDE criado por daemon de rede: é o "+
					"perfil do canal do Ebury, e a permissão restrita (0600) é "+
					"justamente a evasão do IOC antigo")
			case outroEscreve && s.UID == 0:
				// Gravável pelo mundo E de root: qualquer usuário injeta no canal
				// de root.
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
		r.Partial = append(r.Partial, f.Partial["sysvipc"]...)
		return r
	},
}
