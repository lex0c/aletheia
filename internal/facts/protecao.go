package facts

import (
	"strings"

	"github.com/lex0c/aletheia/internal/env"
)

// O que o kernel deixa acontecer com ele mesmo.
//
// Estes valores não são achado: são o CONTEXTO que muda o peso de todos os
// achados de kernel. Um módulo sem arquivo num host que exige assinatura é uma
// afirmação muito mais forte que o mesmo módulo num host sem trava nenhuma — no
// primeiro, alguém desligou uma proteção ou contornou uma verificação.
//
// É também a entrada do `readiness` (SPEC 13.2): a pergunta "este host está
// preparado para o próximo incidente?" começa aqui.
type ProtecaoKernel struct {
	// SecurityFS diz se /sys/kernel/security está montado. Sem ele, lockdown e
	// IMA não são legíveis — e esta ferramenta NÃO monta nada para descobrir.
	SecurityFS bool `json:"securityfs"`

	// Lockdown é "none", "integrity" ou "confidentiality". Vazio = não lido.
	Lockdown string `json:"lockdown,omitempty"`
	// SigEnforce é "Y" quando o kernel recusa módulo sem assinatura válida.
	SigEnforce string `json:"module_sig_enforce,omitempty"`
	// ModulesDisabled em "1" tranca o carregamento de módulo até o próximo boot.
	ModulesDisabled string `json:"modules_disabled,omitempty"`
	// SecureBoot vem do efivar. Vazio quando não há EFI ou não se pôde ler.
	SecureBoot string `json:"secure_boot,omitempty"`
	// IMA diz se a medição de integridade está presente.
	IMA bool `json:"ima,omitempty"`

	// Os sysctl que decidem o que um processo sem privilégio enxerga do kernel.
	KptrRestrict  string `json:"kptr_restrict,omitempty"`
	DmesgRestrict string `json:"dmesg_restrict,omitempty"`
	UnprivBPF     string `json:"unprivileged_bpf_disabled,omitempty"`
	PtraceScope   string `json:"ptrace_scope,omitempty"`

	// NaoLidos são os caminhos que existiam e não abriram, com o motivo. O que
	// não existe NÃO entra aqui: ausência de arquivo é ausência de recurso, e
	// confundir as duas faria todo kernel sem lockdown parecer ilegível.
	NaoLidos []string `json:"unreadable,omitempty"`
}

// Lido diz se ALGUMA coisa pôde ser lida. Um inventário em que tudo é
// "não determinado" não é contexto: é lacuna, e sai como lacuna — seis linhas
// dizendo "não sei" gastam a atenção do operador sem entregar nada.
func (p ProtecaoKernel) Lido() bool {
	return p.SecurityFS || p.IMA ||
		p.Lockdown != "" || p.SigEnforce != "" || p.ModulesDisabled != "" ||
		p.SecureBoot != "" || p.KptrRestrict != "" || p.DmesgRestrict != "" ||
		p.UnprivBPF != "" || p.PtraceScope != ""
}

// TrancaModulo diz se este kernel impede carregar módulo agora. É o contexto que
// transforma "há um módulo estranho" em "alguém carregou isto ANTES da tranca".
func (p ProtecaoKernel) TrancaModulo() bool {
	return p.ModulesDisabled == "1" || p.SigEnforce == "Y"
}

func collectProtecaoKernel(f *Facts, e *env.Env) {
	p := &f.Protecao
	p.SecurityFS = e.IsDir("/sys/kernel/security")

	// Lockdown e IMA moram no securityfs. Não montá-lo é decisão: a ferramenta
	// é read-only, e montar filesystem para responder uma pergunta é alterar o
	// host — exatamente o que ela promete não fazer.
	if p.SecurityFS {
		p.Lockdown = valorEntreColchetes(leOuRegistra(f, e, "/sys/kernel/security/lockdown"))
		p.IMA = e.IsDir("/sys/kernel/security/ima")
	}

	p.SigEnforce = leOuRegistra(f, e, "/sys/module/module/parameters/sig_enforce")
	p.ModulesDisabled = leOuRegistra(f, e, "/proc/sys/kernel/modules_disabled")
	p.KptrRestrict = leOuRegistra(f, e, "/proc/sys/kernel/kptr_restrict")
	p.DmesgRestrict = leOuRegistra(f, e, "/proc/sys/kernel/dmesg_restrict")
	p.UnprivBPF = leOuRegistra(f, e, "/proc/sys/kernel/unprivileged_bpf_disabled")
	p.PtraceScope = leOuRegistra(f, e, "/proc/sys/kernel/yama/ptrace_scope")
	p.SecureBoot = lerSecureBoot(e)
}

// leOuRegistra devolve o conteúdo, e registra a falha SÓ quando o arquivo
// existe e não abre. Arquivo ausente é recurso ausente, não lacuna de leitura.
func leOuRegistra(f *Facts, e *env.Env, p string) string {
	if !e.Exists(p) {
		return ""
	}
	b, err := e.ReadFile(p)
	if err != nil {
		f.Protecao.NaoLidos = append(f.Protecao.NaoLidos, p+": "+err.Error())
		return ""
	}
	return strings.TrimSpace(string(b))
}

// valorEntreColchetes extrai a opção ATIVA de uma lista do kernel:
// "none [integrity] confidentiality" → "integrity".
func valorEntreColchetes(s string) string {
	i := strings.Index(s, "[")
	j := strings.Index(s, "]")
	if i < 0 || j < i {
		return s
	}
	return s[i+1 : j]
}

// lerSecureBoot lê o efivar. O valor é o último byte de cinco: os quatro
// primeiros são os atributos da variável EFI, e ler só o primeiro byte — que é
// o erro fácil aqui — devolveria o atributo, não a resposta.
func lerSecureBoot(e *env.Env) string {
	const nome = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
	b, err := e.ReadFile(nome)
	if err != nil || len(b) < 5 {
		return ""
	}
	if b[4] == 1 {
		return "on"
	}
	return "off"
}
