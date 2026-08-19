package scenario

// Injeção em memória: código que roda sem nunca ter sido um arquivo íntegro no
// disco, ou que apagou o arquivo depois de mapeá-lo. São as formas que passam
// por "compare o hash do binário com o do pacote" — não há binário a comparar.
//
// Os dois checks já eram provados no test/matrix (tier de contêiner), mas o
// harness Go — que roda a CLI contra /proc real, com orçamento de ruído e exit
// code — não os via. Aqui eles ganham cenário: a mesma técnica, medida contra
// o binário de verdade.
//
//	M1  W^X: mmap RW, grava, mprotect RX   nunca foi RWX, e o check pega mesmo assim
//	M3  lib mapeada executável e apagada   o exe principal fica íntegro, a lib some

func init() {
	Register(Scenario{
		ID:   "M1-injecao-rx-anon",
		Desc: "injeção W^X: no retrato a região é r-xp anônima e NUNCA foi gravável-e-executável",
		// A forma que escapa de quem só procura RWX simultâneo (o maps_rwx_anon do
		// helper rwx). O implante grava numa região RW e a promove a RX com
		// mprotect: no instante da varredura ela é executável, anônima e sem
		// arquivo por trás — e nunca teve W e X ao mesmo tempo. É a diferença
		// entre pegar a assinatura preguiçosa e pegar a técnica.
		Images: matriz,
		Plant: `/helper rx-anon &
			sleep 1`,
		Expect: []Expect{
			{ID: "proc.maps_exec_anon", Sev: "WARN", Evidence: "executáveis anônimas sem arquivo"},
			{ID: "proc.maps_exec_anon", Evidence: "nenhum pacote reivindica"},
		},
		Exit: 1,
	})

	Register(Scenario{
		ID:   "M3-mapeamento-apagado",
		Desc: "biblioteca mapeada EXECUTÁVEL e apagada: o exe principal fica íntegro, a lib some do disco",
		// A lib aberta com dlopen e removida em seguida: o mapeamento fica
		// "(deleted)" em /proc/<pid>/maps, ainda executável, ainda na memória. O
		// exe principal do processo continua com hash correto — quem só verifica
		// o /proc/<pid>/exe não vê nada. É crítico porque veio de diretório
		// gravável por qualquer usuário e já não existe para ser periciado.
		Images: matriz,
		Plant: `/helper deleted-exec /tmp/.libx.so &
			sleep 1`,
		Expect: []Expect{
			{ID: "proc.deleted_mapping", Sev: "CRITICAL", Evidence: "(deleted)"},
			{ID: "proc.deleted_mapping", Evidence: "gravável por qualquer usuário"},
		},
		Exit: 2,
	})
}
