package scenario

// Persistência na GERAÇÃO do boot — o que roda como root antes do userland, e
// que nenhuma unit, cron ou log registra. Três formas, três arquivos em disco:
//
//	GB1 interpretador de binfmt sem dono   systemd-binfmt o recria no boot
//	GB2 hook de initramfs sem dono         roda como root antes de tudo
//	GB3 cmdline de boot enfraquecido       desliga confinamento desde o boot
//
// Os três checks liam disco (Sources Live|Image) e já eram provados no
// test/matrix, mas o harness Go não os via. Aqui ganham cenário: o arquivo
// plantado, a CLI de verdade, o dono resolvido contra a base do dpkg.

func init() {
	Register(Scenario{
		ID:   "GB1-binfmt-interpretador-sem-dono",
		Desc: "config de binfmt aponta para um interpretador sem dono: o systemd-binfmt o recria no boot",
		// O registro vivo de binfmt some no reboot; o que persiste é o .conf em
		// /etc/binfmt.d, que o systemd-binfmt reaplica. O sinal não é o hook em
		// si — qemu-user-static entrega os seus com dono de pacote —, é o
		// interpretador SEM dono que o kernel passa a invocar.
		Images: []string{"debian:12"},
		Plant: `mkdir -p /etc/binfmt.d /usr/local/sbin
			cp /helper /usr/local/sbin/emul-helper
			printf ':emul:E::exz::/usr/local/sbin/emul-helper:\n' > /etc/binfmt.d/emul.conf`,
		Expect: []Expect{
			{ID: "persist.binfmt_config", Sev: "WARN", Evidence: "nenhum pacote reivindica o interpretador"},
		},
		Exit: 1,
	})

	Register(Scenario{
		ID:   "GB2-initramfs-hook-sem-dono",
		Desc: "script de geração do initramfs sem dono de pacote: roda como root ANTES do userland",
		// O initramfs roda antes de tudo, como root, e nada de unit/cron/log
		// registra o que acontece ali. Um módulo do dracut em /usr/lib — onde
		// tudo deveria vir de pacote — sem dono é sinal forte: CRITICAL pela
		// escada do §24 (diretório de pacote), diferente de um hook em /etc que o
		// admin escreveu.
		Images: []string{"debian:12"},
		Plant: `mkdir -p /usr/lib/dracut/modules.d/99evil
			printf '#!/bin/bash\ninstall() { :; }\n' > /usr/lib/dracut/modules.d/99evil/module-setup.sh
			chmod +x /usr/lib/dracut/modules.d/99evil/module-setup.sh`,
		Expect: []Expect{
			{ID: "persist.initramfs_hook", Sev: "CRITICAL", Evidence: "hook executável"},
		},
		Exit: 2,
	})

	Register(Scenario{
		ID:   "GB3-cmdline-enfraquecido",
		Desc: "GRUB_CMDLINE_LINUX desliga o confinamento: enfraquece a defesa desde o próximo boot",
		// A linha de comando do kernel na CONFIGURAÇÃO (ainda não na que está
		// rodando): apparmor=0 desliga o AppArmor no próximo boot. É WARN porque
		// ainda não vale — mas passa a valer no reboot, e é exatamente onde um
		// implante garante que nenhum perfil o confine.
		Images: []string{"debian:12"},
		Plant:  `mkdir -p /etc/default && printf 'GRUB_CMDLINE_LINUX="root=UUID=1 apparmor=0"\n' > /etc/default/grub`,
		Expect: []Expect{
			{ID: "persist.kernel_cmdline_weakening", Sev: "WARN", Evidence: "desliga o AppArmor"},
		},
		Exit: 1,
	})

	Register(Scenario{
		ID:   "GB4-binfmt-registro-vivo",
		Desc: "interpretador de binfmt REGISTRADO no kernel vivo, apontando para /tmp gravável",
		// O irmão VIVO do GB1: não a configuração em disco, mas o registro que já
		// está no kernel — /proc/sys/fs/binfmt_misc. É o que roteia execução AGORA
		// para um interpretador em diretório gravável, sem casar ELF nativo: o
		// kernel passa a invocá-lo, e isso é CRITICAL. Precisa de VM porque exige
		// montar binfmt_misc e escrever no register do kernel de verdade.
		Mode: VM,
		Setup: `mount -t binfmt_misc none /proc/sys/fs/binfmt_misc 2>/dev/null || true
			printf '#!/bin/sh\n' > /tmp/.evilbin
			chmod +x /tmp/.evilbin
			echo ':evilm:E::evx::/tmp/.evilbin:' > /proc/sys/fs/binfmt_misc/register`,
		Expect: []Expect{
			{ID: "kernel.binfmt_interpreter", Sev: "CRITICAL"},
		},
		Exit: 2,
	})
}
