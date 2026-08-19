package checks

import (
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() { check.Register(initramfsHook) }

// initramfsHook — runbook §7.12.
//
// # Persistência antes do userland
//
// O initramfs roda como root ANTES de o sistema de arquivos raiz assumir —
// antes de unit, cron ou perfil de shell existirem. O que ele contém é montado
// por scripts de GERAÇÃO em disco: hooks do initramfs-tools, módulos do dracut,
// hooks do mkinitcpio, drop-ins do kernel-install. E há dois caminhos para pôr
// código lá:
//
//	hook executável        um script no diretório de geração roda ao gerar a
//	                       imagem, e o que ele copiar para dentro roda no boot
//	arquivo referenciado   install_items (dracut) e FILES (mkinitcpio) embutem
//	                       um caminho literal na imagem, sem hook nenhum
//
// # O discriminador
//
// Admin acrescenta hook legitimamente — LUKS, hardware incomum. O que separa
// isso de um implante é o de sempre: de onde vem o arquivo. Sem dono de pacote
// num diretório de PACOTE é forte; em /etc é território do administrador, e vale
// um aviso. Em diretório gravável, não há leitura inocente.
//
// Pega em disco, então vale em modo image. O parser da imagem COMPACTADA é outra
// pergunta, mais cara, e está declarada como não feita.
var initramfsHook = check.Check{
	ID:       "persist.initramfs_hook",
	Ref:      "7.12",
	Title:    "script ou arquivo que entra na geração do initramfs sem dono de pacote",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Optional: env.CapRoot | env.CapPkgDB,
	Wtf:      true,
	FalsePositives: []string{
		"ADMIN acrescenta hook de initramfs legitimamente — setup de LUKS, driver " +
			"de hardware incomum, splash. Em /etc isso é território do administrador, " +
			"e o achado é um aviso para reconhecer, não uma acusação",
		"o que dá sinal é a AUSÊNCIA de dono de pacote e o caminho — não a " +
			"presença de um hook. Um script de /usr/lib/dracut sem dono é forte; " +
			"um de /etc/initramfs-tools/hooks que você escreveu, não",
		"sem a base de pacotes legível a pergunta de propriedade não tem resposta, " +
			"e o que degrada é a cobertura",
		"LIMITE declarado: isto lê os MECANISMOS de geração em disco. A imagem do " +
			"initramfs já COMPACTADA não é aberta — um payload embutido só nela, sem " +
			"rastro nos scripts de geração, NÃO é visto por este check",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		semDono := caminhosSemDono(f)
		for i := range f.Initramfs {
			a := &f.Initramfs[i]
			sev, nota, acusa := pesoDoInitramfs(a, semDono)
			if !acusa {
				continue
			}
			ev := []string{
				a.Path + " — " + a.Como + " (" + a.Mecanismo + ")",
				"o initramfs roda como root ANTES do userland: nada de unit, cron ou " +
					"log registra o que acontece aqui",
				nota,
			}
			fd := self.F(sev, a.Path, "", ev...)
			fd.Irreversible = true
			fd.NextSteps = []string{
				"guarde o arquivo antes de mexer: sudo cp " + check.Arg(a.Path) + " \"$IR/\"",
				"compare com outro host da frota: o mesmo hook em vários é " +
					"provisionamento; em um só, é alteração (runbook §23)",
				"e confira a IMAGEM já gerada — este check lê os scripts de geração, " +
					"não o initramfs compactado (runbook §29)",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.PersistDenied["initramfs"]...)
		return r
	},
}

// pesoDoInitramfs decide, e a distinção que importa é HOOK versus arquivo
// REFERENCIADO.
//
// Um hook é CÓDIGO que roda na geração: sem dono é sinal forte, com a escada do
// §24 (diretório de pacote CRITICAL, /etc — território do admin — WARN).
//
// Um arquivo referenciado por install_items/FILES é DADO embutido: uma keyfile
// LUKS é o caso legítimo canônico, sem dono de pacote em toda máquina com disco
// cifrado. Julgar isso por propriedade encheria de FP todo host com LUKS. Por
// isso, para o referenciado, só diretório GRAVÁVEL é sinal — não há razão
// legítima para embutir um arquivo de /tmp no initramfs.
func pesoDoInitramfs(a *facts.ArtefatoInitramfs, semDono map[string]bool) (check.Severity, string, bool) {
	if motivo, gravavel := suspectDir(a.Path); gravavel {
		return check.SevCritical, "e o arquivo está " + motivo +
			": nada se instala ali de propósito, muito menos no initramfs", true
	}
	// Discrimina pelo TIPO, nunca pelo texto de apresentação.
	//
	// Enquanto isto comparava a.Como com "hook executável", o module-setup.sh
	// do dracut — que a coleta passou a reconhecer sem exigir +x, porque o
	// dracut o SOURCEIA — entrava no Facts e era descartado aqui em silêncio.
	// A metade do bypass que a coleta fechou ficava aberta um andar acima, e o
	// discriminador quebrou porque alguém acrescentou uma frase nova.
	if a.Tipo != facts.InitramfsCodigo {
		// Arquivo referenciado fora de diretório gravável: dado de admin
		// (keyfile) é legítimo e comum, e propriedade não o distingue de payload.
		return check.SevInfo, "", false
	}
	if !semDono[a.Path] {
		return check.SevInfo, "", false // hook com dono de pacote: é o normal
	}
	if strings.HasPrefix(a.Path, "/etc/") {
		return check.SevWarn, "e nenhum pacote o reivindica — em /etc é território do " +
			"administrador, e o sinal é você NÃO reconhecer este hook", true
	}
	return check.SevCritical, "e nenhum pacote o reivindica, num diretório onde tudo " +
		"deveria vir de pacote", true
}
