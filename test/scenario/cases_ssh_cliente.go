//go:build scenarios

package scenario

// Config do CLIENTE ssh que executa comando — a persistência de usuário que o
// inventário do sshd (chaves, ForceCommand) não alcança. Quem escreve o
// ~/.ssh/config da vítima roda código toda vez que ela dá `ssh`, sem tocar em
// nada com dono root.
//
// Dois cenários, e o par é o ponto: o ProxyCommand é legítimo e comum (jump
// host), então o check tem de separar a FORMA do comando — um em /tmp acusa, um
// `ssh -W` inventaria. Sem o negativo, o check seria uma parede.
func init() {
	Register(Scenario{
		ID:     "SC1-proxycommand-backdoor",
		Desc:   "ProxyCommand do ~/.ssh/config aponta para binário em /tmp: roda a cada ssh",
		Images: matriz,
		Plant: `mkdir -p /root/.ssh
cat > /root/.ssh/config <<'CFG'
Host alvo
    ProxyCommand /tmp/.beacon %h %p
CFG`,
		Expect: []Expect{
			{ID: "persist.ssh_client_exec", Sev: "CRITICAL"},
			{ID: "persist.ssh_client_exec", Evidence: "gravável por qualquer usuário"},
			{ID: "persist.ssh_client_exec", Evidence: "ProxyCommand: /tmp/.beacon"},
		},
		Exit: 2,
	})

	Register(Scenario{
		ID:     "SC2-proxycommand-legitimo",
		Desc:   "o MESMO ProxyCommand, mas `ssh -W` para um bastion: inventariado, não acusado",
		Images: matriz,
		Plant: `mkdir -p /root/.ssh
cat > /root/.ssh/config <<'CFG'
Host interno
    ProxyCommand ssh -W %h:%p bastion
CFG`,
		Expect: []Expect{
			// Aparece no inventário — o operador vê que há um ProxyCommand —, mas
			// como INFO: a forma é a canônica do jump host.
			{ID: "persist.ssh_client_exec", Sev: "INFO"},
		},
		// A prova de que não vira parede: o jump host legítimo NÃO pode subir
		// para aviso nem crítico. Se um dia subir, este cenário falha e obriga a
		// rever o discriminador.
		ForbidFinding: []Expect{
			{ID: "persist.ssh_client_exec", Sev: "WARN"},
			{ID: "persist.ssh_client_exec", Sev: "CRITICAL"},
		},
		Exit: -1,
	})

	// O Include é seguido, inclusive para FORA de ~/.ssh, com expansão de `~`. Um
	// ProxyCommand escondido no arquivo incluído é a evasão que motivou o parser
	// de config efetivo — e o achado aponta para o arquivo INCLUÍDO, não para o
	// que fez o Include.
	Register(Scenario{
		ID:     "SC3-proxycommand-em-include",
		Desc:   "ProxyCommand escondido num arquivo que o ~/.ssh/config inclui fora de ~/.ssh",
		Images: matriz,
		Plant: `mkdir -p /root/.ssh /root/.config
cat > /root/.ssh/config <<'CFG'
Include ~/.config/ssh-extra
CFG
cat > /root/.config/ssh-extra <<'EXTRA'
Host alvo
    ProxyCommand /tmp/.implant %h
EXTRA`,
		Expect: []Expect{
			{ID: "persist.ssh_client_exec", Sev: "CRITICAL"},
			// O achado aponta para o arquivo INCLUÍDO — a prova de que o Include
			// foi seguido, não o config principal.
			{ID: "persist.ssh_client_exec", Evidence: "/root/.config/ssh-extra"},
		},
		Exit: 2,
	})
}
