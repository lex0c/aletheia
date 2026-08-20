package checks

import (
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() { check.Register(montagemSobreSistema) }

// montagemSobreSistema — runbook §35.
//
// Montar algo POR CIMA de um diretório de sistema esconde o conteúdo real sem
// tocar em nenhum arquivo. O que estava lá continua no disco, intacto, e some
// da visão de todo processo — inclusive da desta ferramenta, que lê o
// filesystem como qualquer outro.
//
// É ocultação sem rootkit: não precisa de módulo, não precisa de LD_PRELOAD,
// não deixa arquivo novo. E some no reboot sem deixar rastro nenhum, o que a
// torna atraente para quem quer trabalhar e sumir.
//
// O que a denuncia é a tabela de montagem, que é a única fonte que ainda mostra
// as duas camadas: o ponto montado e o que ele cobre.
var montagemSobreSistema = check.Check{
	ID:      "kernel.mount_over_system",
	Ref:     "35",
	Title:   "montagem por cima de diretório de sistema: esconde o que está embaixo",
	Group:   "kernel",
	Mode:    check.ModeAuto,
	Sources: env.SourceLive,
	// CapFilesystem e não CapProcfs, e a diferença tem motivo.
	//
	// O invariante de registro exige que todo check de CapProcfs declare
	// CapRoot, porque ler /proc de processo ALHEIO sem privilégio devolve quase
	// nada e a cobertura sairia completa mentindo. Aqui não se lê processo
	// nenhum: /proc/self/mountinfo é a tabela do próprio processo, legível por
	// qualquer usuário e COMPLETA sem root.
	//
	// Declarar CapRoot para satisfazer o invariante degradaria toda varredura
	// sem privilégio por uma dependência que não existe — foi o que o
	// `Optional: CapSystemd` fez uma vez, e derrubou treze de dezesseis
	// execuções em contêiner.
	//
	// A lacuna real — /proc não montado — é declarada pelo COLETOR, que é mais
	// preciso que qualquer capability: ele sabe se a leitura falhou.
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"CONTÊINER faz isto de fábrica: o runtime monta /etc/hosts, /etc/hostname " +
			"e /etc/resolv.conf individualmente em todo contêiner que existe. " +
			"Esses três são exemplos conhecidos e não entram",
		"volume montado em /opt ou /srv é operação normal, e essas árvores não " +
			"são consideradas aqui — só as que a distribuição possui",
		"sistema de arquivos em overlay (contêiner, imagem imutável, live CD) " +
			"monta a raiz inteira por desenho, e a raiz não é considerada",
		"PARTIÇÃO é operação normal e não entra: /boot/efi em vfat vindo de um " +
			"disco é a partição EFI de toda máquina UEFI. Só bind e filesystem " +
			"de memória são considerados, porque são a forma da técnica",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		for i := range f.Mounts {
			m := &f.Mounts[i]
			if !cobreDiretorioDeSistema(m.Ponto) || montagemDeContainer(m.Ponto) {
				continue
			}
			// PARTIÇÃO NORMAL NÃO É OCULTAÇÃO.
			//
			// /boot/efi vindo de /dev/nvme0n1p1 em vfat é a partição EFI de toda
			// máquina UEFI, e /boot separado é igualmente comum — foi o falso
			// positivo que apareceu no primeiro host real.
			//
			// A técnica de esconder tem forma própria: ou é BIND — um pedaço de
			// outra árvore montado por cima —, ou é filesystem de MEMÓRIA, que
			// não vem de disco nenhum e some no reboot. Montar um disco de
			// verdade num ponto de montagem de verdade é particionamento.
			como, esconde := formaDeOcultacao(m)
			if !esconde {
				continue
			}

			ev := []string{
				m.Ponto + " está coberto por uma montagem de " + m.Tipo + " — " + como,
				"o que estava nesse caminho continua no disco e sumiu da visão de " +
					"TODO processo, esta ferramenta inclusive",
				"origem: " + nz(m.Origem, "?") + " · opções: " + m.Opcoes,
			}
			ev = append(ev, "não deixa arquivo novo e some no reboot: a tabela de "+
				"montagem é a única fonte que ainda mostra as duas camadas")

			fd := self.F(check.SevCritical, m.Ponto, "", ev...)
			fd.Irreversible = true
			fd.NextSteps = []string{
				"o conteúdo REAL continua embaixo: monte a origem em outro ponto e " +
					"compare, em vez de desmontar (desmontar destrói a evidência da " +
					"montagem)",
				"`cat /proc/self/mountinfo` guardado agora é a prova: ela some no reboot",
				"a partir daqui, listagem de arquivo deste caminho não vale como " +
					"prova",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.PersistDenied["mounts"]...)
		return r
	},
}

// arvoresDeSistema são as que a DISTRIBUIÇÃO possui. Montar sobre elas não é
// operação: /opt e /srv existem para receber volume, e por isso ficam fora.
var arvoresDeSistema = []string{
	"/etc", "/bin", "/sbin", "/lib", "/lib64",
	"/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib64", "/usr/libexec",
	"/boot", "/root",
}

func cobreDiretorioDeSistema(ponto string) bool {
	for _, d := range arvoresDeSistema {
		if ponto == d || strings.HasPrefix(ponto, d+"/") {
			return true
		}
	}
	return false
}

// montagemDeContainer reconhece os três arquivos que TODO runtime de contêiner
// monta individualmente. Sem esta exclusão, cada contêiner varrido produziria
// três críticos idênticos.
var arquivosDeContainer = map[string]bool{
	"/etc/hosts": true, "/etc/hostname": true, "/etc/resolv.conf": true,
	"/etc/mtab": true,
}

func montagemDeContainer(ponto string) bool { return arquivosDeContainer[ponto] }

// filesystemsDeMemoria não vêm de disco nenhum: o conteúdo nasce vazio, vive na
// RAM e some no reboot. Montar um deles sobre diretório de sistema é esconder o
// que está embaixo sem deixar rastro em disco.
var filesystemsDeMemoria = map[string]bool{
	"tmpfs": true, "ramfs": true, "overlay": true, "overlayfs": true,
	"aufs": true, "squashfs": true, "devtmpfs": true,
}

// formaDeOcultacao diz se a montagem tem a forma da TÉCNICA, e qual é.
//
// Devolve falso para particionamento comum — disco real, filesystem real, raiz
// inteira —, que é o que /boot/efi e /home em partição própria são.
func formaDeOcultacao(m *facts.Montagem) (string, bool) {
	if m.Raiz != "" && m.Raiz != "/" {
		return "BIND de " + m.Raiz + ", um pedaço de outra árvore aparecendo aqui " +
			"sem criar filesystem nenhum", true
	}
	if filesystemsDeMemoria[m.Tipo] {
		return "filesystem de MEMÓRIA, que nasce vazio e some no reboot sem " +
			"deixar rastro em disco", true
	}
	return "", false
}
