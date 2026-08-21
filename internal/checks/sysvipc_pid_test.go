package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

// O CRITICAL do perfil Ebury não pode nascer de PID reciclado.
//
// O segmento sobrevive a quem o criou, o PID some junto e o kernel o
// reaproveita. Sem prova temporal, um segmento órfão de 3 MiB mais um processo
// novo qualquer com socket de escuta bastavam para o salto a CRITICAL — sem
// atacante nenhum, e num servidor com uptime longo é questão de tempo.
func TestEburyNaoNasceDePIDReciclado(t *testing.T) {
	base := facts.SysVShmSeg{
		ShmID: 7, Key: 42, Perms: 0o600, Size: 4 * 1024 * 1024, CPID: 420,
	}

	// (a) autoria PROVADA: o daemon de rede criou mesmo. CRITICAL é correto.
	provado := base
	provado.Criador, provado.CriadorEmRede = "sshd", true
	r := sysvShmChannel.Run(sysvShmChannel, &facts.Facts{SysVShm: []facts.SysVShmSeg{provado}}, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("autoria provada + daemon de rede + 4 MiB é o perfil do Ebury: %+v", r.Findings)
	}

	// (b) PID RECICLADO: o coletor já não afirma autoria, e sem ela o segmento
	// 0600 não é nem aberto nem Ebury — não há achado a fazer.
	recic := base
	recic.PIDReciclado, recic.CriadorNaoConfirmado = true, true
	r = sysvShmChannel.Run(sysvShmChannel, &facts.Facts{SysVShm: []facts.SysVShmSeg{recic}}, testEnv())
	for _, fd := range r.Findings {
		if fd.Sev == check.SevCritical {
			t.Errorf("PID reciclado não sustenta CRITICAL: %+v", fd)
		}
	}

	// (c) NÃO CONFIRMADO (sem data para comparar) também não sustenta o salto,
	// mas o segmento aberto continua sendo dito — e o relatório precisa
	// explicar por que não afirmou a autoria.
	naoConf := base
	// 0604 e não 0666: gravável-por-todos de root é CRITICAL por conta própria,
	// e misturaria as duas razões. Aqui só a leitura é aberta, então o que
	// decide a severidade é a atribuição de autoria — a variável sob teste.
	naoConf.Perms, naoConf.Criador, naoConf.CriadorNaoConfirmado = 0o604, "algo", true
	r = sysvShmChannel.Run(sysvShmChannel, &facts.Facts{SysVShm: []facts.SysVShmSeg{naoConf}}, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("segmento aberto a todos continua sendo achado: %+v", r.Findings)
	}
	if r.Findings[0].Sev == check.SevCritical {
		t.Errorf("autoria não confirmada não sustenta CRITICAL: %+v", r.Findings[0])
	}
	if !strings.Contains(strings.Join(r.Findings[0].Evidence, " "), "NÃO pôde ser confirmada") {
		t.Errorf("a evidência precisa dizer que a autoria não foi provada: %v", r.Findings[0].Evidence)
	}
}
