package facts

import (
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/env"
)

// A linha de comando do kernel (runbook §35.7).
//
// # Por que ela é uma superfície de persistência
//
// Todo o resto da §7 pergunta "o que faz este host EXECUTAR alguma coisa?". A
// linha de boot responde uma pergunta anterior e mais forte: com que regras o
// kernel sobe. Um parâmetro ali decide se o kernel exige assinatura em módulo,
// se o LSM confina alguém, se a auditoria grava e qual programa vira o PID 1 —
// e nada disso passa por unit, cron ou perfil de shell.
//
//	module.sig_enforce=0   módulo sem assinatura passa a carregar
//	selinux=0 apparmor=0   nenhum confinamento
//	audit=0                a auditoria não grava desde o boot
//	init=/caminho          o kernel executa AQUILO como PID 1
//
// É também o que EXPLICA o contexto que a ferramenta já coleta: um
// `kernel.protection_context` dizendo "sig_enforce=N" não diz por quê. A linha
// de boot diz.
//
// # Duas fontes, e a diferença entre elas é o achado
//
//	/proc/cmdline    com o que este kernel SUBIU
//	bootloader       com o que o PRÓXIMO boot vai subir
//
// Elas não são a mesma pergunta. Um parâmetro presente só na primeira não
// sobrevive a um reboot — alguém subiu este kernel assim, na mão. Um parâmetro
// presente só na segunda ainda não está valendo — e vai valer no próximo boot,
// que é persistência à espera.
//
// A configuração vem de ARQUIVO, então existe também em modo image, onde o
// kernel é o do analista (§35.6). O /proc/cmdline não.

// LinhaDeBoot é uma linha de comando de kernel, com a origem dela.
//
// O Valor fica CRU, como o argv de um processo fica: quem redige é a camada de
// saída (SPEC 5.4). A linha pode carregar segredo — `rd.luks.key=`,
// `systemd.setenv=TOKEN=` —, e por isso o check nunca imprime a linha inteira:
// ele imprime o parâmetro que casou.
type LinhaDeBoot struct {
	Fonte string `json:"source"`
	Valor string `json:"value"`
	// Rodando marca a linha com que este kernel subiu. As demais são
	// configuração — o que o bootloader entregaria no próximo boot.
	Rodando bool `json:"running,omitempty"`
}

// TokenDeBoot é um parâmetro da linha, já separado.
type TokenDeBoot struct {
	Chave string
	Valor string
	// TemValor distingue `audit=0` de `audit`. São coisas diferentes: o token
	// solto liga o mecanismo, e tratar os dois igual faria `audit` sozinho —
	// que é o oposto de desligar — casar com a regra de desligamento.
	TemValor bool
}

// maxLinhasDeBoot limita as linhas guardadas. Um host com oito kernels
// instalados tem dezesseis entradas no grub, quase todas com a MESMA linha —
// a deduplicação resolve o caso normal, e o teto existe para o patológico.
const maxLinhasDeBoot = 32

// TokensDeBoot separa a linha em parâmetros.
//
// O kernel separa por espaço e honra ASPAS: `systemd.setenv="A B"` é UM
// parâmetro. Um `strings.Fields` quebraria ali e produziria um token `B"`, que
// não casa com nada e some — silenciosamente, que é a pior forma.
func TokensDeBoot(s string) []TokenDeBoot {
	var out []TokenDeBoot
	var atual strings.Builder
	emAspas := false
	solta := func() {
		t := atual.String()
		atual.Reset()
		if t == "" {
			return
		}
		if k, v, ok := strings.Cut(t, "="); ok {
			out = append(out, TokenDeBoot{Chave: k, Valor: strings.Trim(v, `"`), TemValor: true})
			return
		}
		out = append(out, TokenDeBoot{Chave: t})
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"':
			emAspas = !emAspas
			atual.WriteByte(c)
		case (c == ' ' || c == '\t' || c == '\n') && !emAspas:
			solta()
		default:
			atual.WriteByte(c)
		}
	}
	solta()
	return out
}

// ValorDeBoot devolve o valor da última ocorrência de uma chave. É a ÚLTIMA
// porque é assim que o kernel resolve repetição: quem vem depois vence, e um
// `selinux=1 … selinux=0` acrescentado no fim desliga.
func ValorDeBoot(linha, chave string) (string, bool) {
	valor, achou := "", false
	for _, t := range TokensDeBoot(linha) {
		if t.Chave == chave {
			valor, achou = t.Valor, true
		}
	}
	return valor, achou
}

func collectBoot(f *Facts, e *env.Env) {
	var descartadas int
	add := func(fonte, valor string, rodando bool) {
		valor = strings.TrimSpace(valor)
		if valor == "" {
			return
		}
		for _, b := range f.Boot {
			if b.Fonte == fonte && b.Valor == valor {
				return
			}
		}
		if len(f.Boot) >= maxLinhasDeBoot {
			descartadas++
			return
		}
		f.Boot = append(f.Boot, LinhaDeBoot{Fonte: fonte, Valor: valor, Rodando: rodando})
	}

	// A linha com que este kernel SUBIU. Não existe em imagem montada: lá o
	// kernel é o do analista, e o do host está desligado.
	if e.Source == env.SourceLive {
		v, err := readTrimErr("/proc/cmdline")
		switch {
		case err != nil:
			f.denyPersist("boot", "/proc/cmdline ilegível ("+err.Error()+"): a linha "+
				"com que este kernel subiu não pôde ser lida")
		case v != "":
			add("/proc/cmdline", v, true)
		}
	}

	lerDefaultGrub(f, e, add)
	lerGrubCfg(f, e, add)
	lerEntradasDeLoader(f, e, add)
	lerCmdlineSolta(f, e, add)

	if descartadas > 0 {
		f.partial("boot", strconv.Itoa(descartadas)+" linhas de boot distintas além do "+
			"teto de "+strconv.Itoa(maxLinhasDeBoot)+" NÃO entraram no retrato")
	}
}

type adicionaBoot func(fonte, valor string, rodando bool)

// lerDefaultGrub lê a variável que o `grub-mkconfig` transforma em menu. É o
// que o administrador edita, e por isso é onde uma alteração persistente
// costuma aparecer primeiro — inclusive antes de existir no grub.cfg.
func lerDefaultGrub(f *Facts, e *env.Env, add adicionaBoot) {
	for _, p := range []string{"/etc/default/grub", "/etc/sysconfig/grub"} {
		b, err := e.ReadFile(p)
		if err != nil {
			if env.EhLacuna(err) {
				f.denyPersist("boot", p+" existe e não pôde ser lido ("+
					env.MotivoDoErro(err)+"): uma linha de comando de kernel "+
					"enfraquecida ou um init substituído aqui NÃO foi avaliado")
			}
			continue
		}
		f.BootConfigLido = true
		for _, ln := range strings.Split(string(b), "\n") {
			// O arquivo é SOURCED por shell, e `export GRUB_CMDLINE_LINUX=…` é
			// tão válido quanto a atribuição nua — o mesmo TrimPrefix que a
			// leitura de perfil de shell já faz. Sem ele, um host que escreve
			// assim saía com "nenhuma configuração enfraquecida", que é a forma
			// de falso negativo que esta ferramenta existe para não cometer.
			//
			// Linha COMENTADA não precisa de guarda: a comparação é ancorada no
			// começo da linha já aparada, e `#GRUB_CMDLINE_LINUX=` não começa
			// com `GRUB_CMDLINE_LINUX=`.
			ln = strings.TrimPrefix(strings.TrimSpace(ln), "export ")
			for _, chave := range []string{"GRUB_CMDLINE_LINUX", "GRUB_CMDLINE_LINUX_DEFAULT"} {
				v, ok := strings.CutPrefix(ln, chave+"=")
				if !ok {
					continue
				}
				add(p+":"+chave, strings.Trim(strings.TrimSpace(v), `"'`), false)
			}
		}
	}
}

// lerGrubCfg lê o arquivo que o boot realmente consulta. Ele é GERADO, e a
// diferença entre ele e o /etc/default/grub é informação: quem edita só o
// gerado não deixa rastro na fonte, e quem edita só a fonte ainda não aplicou.
func lerGrubCfg(f *Facts, e *env.Env, add adicionaBoot) {
	caminhos := []string{"/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"}
	// A partição EFI tem o seu, com o nome da distribuição no meio.
	for _, dir := range []string{"/boot/efi/EFI", "/efi/EFI"} {
		nomes, err := e.ReadDirNamesErr(dir)
		if env.EhLacuna(err) {
			// EACCES/EIO num diretório EFI é LACUNA, não ausência: o grub.cfg
			// da partição do próximo boot NÃO foi procurado, e calar isso
			// converteria "não olhei" em "nada aqui".
			f.denyPersist("boot", dir+" não pôde ser listado ("+env.MotivoDoErro(err)+
				"): o grub.cfg da partição EFI NÃO foi procurado")
			continue
		}
		for _, nome := range nomes {
			caminhos = append(caminhos, dir+"/"+nome+"/grub.cfg")
		}
	}
	for _, p := range caminhos {
		b, err := e.ReadFile(p)
		if err != nil {
			// Existe e não abriu é LACUNA; não existir é resposta.
			if e.Exists(p) {
				f.denyPersist("boot", p+" ilegível ("+err.Error()+"): a linha de "+
					"comando do próximo boot não pôde ser lida")
			}
			continue
		}
		f.BootConfigLido = true
		for _, ln := range strings.Split(string(b), "\n") {
			if v, ok := cmdlineDoGrub(ln); ok {
				add(p, v, false)
			}
		}
	}
}

// cmdlineDoGrub extrai a linha de comando de uma diretiva de carga do grub:
//
//	linux /vmlinuz-6.1.0 root=UUID=… ro quiet
//
// O primeiro campo é o comando e o segundo é a IMAGEM; o resto é a linha de
// comando. Incluir a imagem faria o caminho do kernel virar um parâmetro.
func cmdlineDoGrub(ln string) (string, bool) {
	campos := strings.Fields(strings.TrimSpace(ln))
	if len(campos) < 3 {
		return "", false
	}
	switch campos[0] {
	case "linux", "linux16", "linuxefi":
		return strings.Join(campos[2:], " "), true
	}
	return "", false
}

// lerEntradasDeLoader lê as entradas do systemd-boot, onde a linha mora numa
// diretiva `options`. É o formato de Arch e Fedora com boot por UEFI direto —
// hosts em que grub.cfg não existe, e onde não olhar aqui seria não olhar.
func lerEntradasDeLoader(f *Facts, e *env.Env, add adicionaBoot) {
	for _, dir := range []string{
		"/boot/loader/entries", "/efi/loader/entries", "/boot/efi/loader/entries",
	} {
		nomes, err := e.ReadDirNamesErr(dir)
		if env.EhLacuna(err) {
			f.denyPersist("boot", dir+" não pôde ser listado ("+env.MotivoDoErro(err)+
				"): as entradas do systemd-boot NÃO foram lidas")
			continue
		}
		for _, nome := range nomes {
			if !strings.HasSuffix(nome, ".conf") {
				continue
			}
			p := dir + "/" + nome
			b, err := e.ReadFile(p)
			if err != nil {
				f.denyPersist("boot", p+" ilegível ("+err.Error()+")")
				continue
			}
			f.BootConfigLido = true
			for _, ln := range strings.Split(string(b), "\n") {
				if v, ok := strings.CutPrefix(strings.TrimSpace(ln), "options "); ok {
					add(p, v, false)
				}
			}
		}
	}
}

// lerCmdlineSolta lê os arquivos que carregam a linha inteira, usados por
// imagem unificada de kernel (UKI) e por dracut. Num host que boota por UKI não
// há grub.cfg NEM entrada de loader: é aqui, ou em lugar nenhum.
// A leitura aqui distingue NÃO EXISTE de NÃO ABRIU, e isso passou a importar
// mais do que importava.
//
// Enquanto o check de cmdline marcava lacuna sempre que NENHUMA configuração
// era lida, um EACCES nestes arquivos ainda produzia — por acidente, e com o
// texto errado — alguma degradação de cobertura. Com aquela lacuna removida (ela
// disparava em contêiner, VM e kexec, onde configuração de bootloader não
// existe), o acidente sumiu junto: num host onde /etc/kernel/cmdline é a única
// fonte e está ilegível, o silêncio seria total.
//
// As outras fontes já faziam isto. Estas duas eram as que faltavam.
func lerCmdlineSolta(f *Facts, e *env.Env, add adicionaBoot) {
	for _, p := range []string{"/etc/kernel/cmdline", "/usr/lib/kernel/cmdline"} {
		b, err := e.ReadFile(p)
		if err != nil {
			if env.EhLacuna(err) {
				f.denyPersist("boot", p+" existe e não pôde ser lido ("+
					env.MotivoDoErro(err)+"): a linha de comando do próximo boot "+
					"NÃO foi avaliada por esta fonte")
			}
			continue
		}
		f.BootConfigLido = true
		add(p, linhaUnica(string(b)), false)
	}
	nomes, err := e.ReadDirNamesErr("/etc/cmdline.d")
	if env.EhLacuna(err) {
		f.denyPersist("boot", "/etc/cmdline.d não pôde ser listado ("+env.MotivoDoErro(err)+
			"): a linha de comando por dropin NÃO foi lida")
	}
	for _, nome := range nomes {
		if !strings.HasSuffix(nome, ".conf") {
			continue
		}
		p := "/etc/cmdline.d/" + nome
		b, err := e.ReadFile(p)
		if err != nil {
			if env.EhLacuna(err) {
				f.denyPersist("boot", p+" existe e não pôde ser lido ("+
					env.MotivoDoErro(err)+"): este dropin de linha de comando NÃO foi avaliado")
			}
			continue
		}
		f.BootConfigLido = true
		add(p, linhaUnica(string(b)), false)
	}
}

// linhaUnica junta as linhas do arquivo num parâmetro por espaço, que é como o
// kernel-install e o dracut as concatenam.
func linhaUnica(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
