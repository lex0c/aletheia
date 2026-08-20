//go:build scenarios

package scenario

// Memória compartilhada System V como canal — a forma do Ebury. A credencial
// roubada passa pela memória entre o sshd trojanizado e o exfil, sem tocar em
// socket, fd de arquivo nem conexão. Nenhuma outra parte da ferramenta enxerga
// esse canal; este check lê /proc/sysvipc/shm.
//
// O par prova o discriminador: a PERMISSÃO, não a existência. SysV SHM legítimo
// (banco de dados) é restrito a dono/grupo; o bit de OUTRO é a marca do canal
// aberto. Sem o negativo, o check seria uma parede sobre todo host com Postgres.
func init() {
	Register(Scenario{
		ID:     "SV1-sysv-shm-mundo",
		Desc:   "segmento SysV SHM gravável por qualquer usuário e de root: o canal aberto do Ebury",
		Images: matriz,
		Plant: `/helper shm 666 &
sleep 0.5`,
		Expect: []Expect{
			{ID: "persist.sysv_shm_channel", Sev: "CRITICAL"},
			{ID: "persist.sysv_shm_channel", Evidence: "qualquer um injeta neste canal privilegiado"},
			{ID: "persist.sysv_shm_channel", Evidence: "não aparece em socket"},
		},
		Exit: 2,
	})

	Register(Scenario{
		ID:     "SV2-sysv-shm-restrito",
		Desc:   "o MESMO segmento a 0600 (a forma do banco de dados): restrito, não é canal aberto",
		Images: matriz,
		Plant: `/helper shm 600 &
sleep 0.5`,
		// O segmento restrito a dono NÃO pode virar achado: é a forma legítima do
		// PostgreSQL/Oracle. Se um dia disparar, o check virou parede e este
		// cenário falha.
		ForbidFinding: []Expect{
			{ID: "persist.sysv_shm_channel"},
		},
		MaxWarn: SemAvisos,
		// Exit não é a asserção aqui: a imagem-base pode ter achados próprios
		// (INFO, manual) que mexem no código. O que este cenário prova é o
		// silêncio DESTE check sobre o segmento restrito, e zero avisos.
		Exit: -1,
	})
}
