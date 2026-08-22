package facts

import (
	"strings"

	"github.com/lex0c/aletheia/internal/env"
)

// Controle de acesso obrigatório (runbook §21).
//
// Desligar o MAC é passo comum depois de entrar: com SELinux em permissivo, o
// implante roda sem confinamento e nada é negado nem registrado.
//
// O problema de acusar isso é que **estado de fábrica não é ataque**. Metade
// dos servidores roda com SELinux permissivo de propósito, e um host meu tem
// 158 perfis de AppArmor com o módulo desligado — que é como o Manjaro entrega.
// Um check baseado em "MAC não está ativo" acusaria todos eles.
//
// O que é objetivo é a CONTRADIÇÃO entre duas fontes:
//
//	/etc/selinux/config    diz o que o administrador quis
//	/sys/fs/selinux/enforce diz o que está valendo AGORA
//
// Um sistema não se instala em estado auto-contraditório. Config pedindo
// enforcing com o kernel em permissivo significa que alguém rodou `setenforce
// 0` depois do boot — e isso não sobrevive a um reboot, o que o torna decisão
// recente por definição.
//
// É a mesma forma dos checks de visão cruzada: duas fontes para o mesmo fato, e
// o achado mora na divergência.

// MAC descreve o estado do controle de acesso obrigatório.
type MAC struct {
	// Configurado é o que o /etc/selinux/config pede: enforcing, permissive
	// ou disabled. Vazio quando não há configuração.
	Configurado string `json:"configured,omitempty"`

	// Ativo é o que o kernel reporta agora: "1" enforcing, "0" permissivo.
	// Vazio quando o selinuxfs não está montado.
	Ativo string `json:"active,omitempty"`

	// FSPresente diz se o selinuxfs existe. Ausente num contêiner é o runtime
	// mascarando, e não SELinux desligado.
	FSPresente bool `json:"selinuxfs,omitempty"`

	// ConfigLido e RuntimeLido separam as DUAS fontes desta struct.
	//
	// `Configurado` vem do /etc/selinux/config e vale no próximo boot;
	// `Ativo` vem do securityfs e vale agora. São leituras independentes, com
	// permissões diferentes, e enquanto a comparação de drift tinha um estado
	// só para as duas o securityfs ilegível calava a mudança PERSISTENTE no
	// arquivo — `enforcing -> permissive`, que é o achado.
	//
	// Falso não é "não há": é "não olhei". A diferença é a regra desta base, e
	// aqui ela desceu ao nível do CAMPO.
	ConfigLido  bool `json:"config_read,omitempty"`
	RuntimeLido bool `json:"runtime_read,omitempty"`
}

func collectMAC(f *Facts, e *env.Env) {
	// MAC ilegível não é MAC ausente, e a diferença decide um achado: o
	// antiforense.mac_downgraded pergunta se alguém desligou o SELinux/AppArmor,
	// e um /etc/selinux/config sem permissão de leitura fazia a resposta sair
	// como "não há configuração" — indistinguível de host que nunca teve MAC.
	// DOIS fatos, porque são DUAS leituras independentes na mesma entidade: o
	// arquivo diz o que vale no próximo boot, o securityfs diz o que vale
	// agora. Enquanto a comparação tinha um estado só para as duas, o
	// securityfs ilegível suprimia a comparação do ARQUIVO — e é o arquivo que
	// carrega a mudança PERSISTENTE, que é a que interessa.
	f.MAC.ConfigLido = true
	f.MAC.RuntimeLido = true

	b, err := e.ReadFile("/etc/selinux/config")
	if env.EhLacuna(err) {
		f.MAC.ConfigLido = false
		f.partial("mac", "/etc/selinux/config não pôde ser lido ("+
			env.MotivoDoErro(err)+"): o modo configurado do SELinux NÃO foi lido, "+
			"e ausência de configuração não pode ser afirmada")
	}
	if err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			ln = strings.TrimSpace(ln)
			if v, ok := strings.CutPrefix(ln, "SELINUX="); ok {
				f.MAC.Configurado = strings.ToLower(strings.TrimSpace(v))
				break
			}
		}
	}
	f.MAC.FSPresente = e.IsDir("/sys/fs/selinux")
	ativo, err := e.ReadFile("/sys/fs/selinux/enforce")
	if env.EhLacuna(err) {
		f.MAC.RuntimeLido = false
		f.partial("mac", "/sys/fs/selinux/enforce não pôde ser lido ("+
			env.MotivoDoErro(err)+"): o modo EM VIGOR não foi lido")
	}
	if err == nil {
		f.MAC.Ativo = strings.TrimSpace(string(ativo))
	}
}
