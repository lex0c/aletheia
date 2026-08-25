package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

// fatosDeLog monta um retrato COM conteúdo de log coletado e uma família de
// auth observada de forma contínua. É o piso de que todos os checks precisam:
// sem cobertura declarada, nenhum deles pode afirmar coisa alguma.
func fatosDeLog(evs ...facts.EventoDeLog) *facts.Facts {
	return &facts.Facts{
		LogEstado:         facts.LogColetado,
		SSHChavesCompleto: true,
		FusoDoAlvoLido:    true,
		FontesDeLog: []facts.FonteDeLog{{
			Path: "/var/log/auth.log", Familias: []string{"auth"}, Estado: facts.FonteLida,
			CobertoDesde: "2026-08-17T00:00:00Z", CobertoAte: "2026-08-24T12:00:00Z",
		}},
		EventosDeLog: evs,
	}
}

func rodaLog(t *testing.T, c check.Check, f *facts.Facts) *check.Report {
	t.Helper()
	f.Index()
	return check.Run([]check.Check{c}, f, testEnv())
}

// ---------------------------------------------------------------------------

// O fingerprint é a coisa que SÓ o log tem: o wtmp registra que alguém entrou,
// não com o quê.
func TestChaveUsadaQueNaoEstaMaisNoAuthorizedKeys(t *testing.T) {
	f := fatosDeLog(facts.EventoDeLog{
		Kind: "auth.accepted", At: "2026-08-24T03:00:00Z", AtKnown: true,
		User: "deploy", RemoteIP: "185.10.2.4", Metodo: "publickey",
		Fingerprint: "SHA256:AAA", File: "/var/log/auth.log",
	})
	f.SSHKeys = []facts.SSHKey{{File: "/root/.ssh/authorized_keys", Fingerprint: "SHA256:BBB"}}

	r := rodaLog(t, chaveForaDasLocais, f)
	if len(r.Findings) != 1 {
		t.Fatalf("%d achados: %+v", len(r.Findings), r.Findings)
	}
	fd := r.Findings[0]
	// MANUAL, e não aviso: desligamento de conta e rotação de chave deixam
	// exatamente esta forma, e a ferramenta não separa uma da outra. Foi o T1 —
	// o servidor de produção de referência — que cobrou a decisão.
	if fd.Sev != check.SevManual {
		t.Errorf("Sev = %v, quer MANUAL", fd.Sev)
	}
	if fd.Subject != "SHA256:AAA" {
		t.Errorf("Subject = %q", fd.Subject)
	}
	// O horizonte precisa estar na evidência: sem ele o achado carrega uma
	// afirmação implícita e falsa sobre tudo o que não apareceu.
	if !contemEvidencia(fd, "observado de forma contínua") {
		t.Errorf("faltou o horizonte na evidência: %v", fd.Evidence)
	}
}

// A chave que AINDA está autorizada não é achado: é o funcionamento normal.
func TestChaveQueContinuaAutorizadaNaoAcusa(t *testing.T) {
	f := fatosDeLog(facts.EventoDeLog{
		Kind: "auth.accepted", Metodo: "publickey", Fingerprint: "SHA256:AAA",
		User: "deploy", File: "/var/log/auth.log",
	})
	f.SSHKeys = []facts.SSHKey{{Fingerprint: "SHA256:AAA"}}

	if r := rodaLog(t, chaveForaDasLocais, f); len(r.Findings) != 0 {
		t.Errorf("chave autorizada não é achado: %+v", r.Findings)
	}
}

// A AFIRMAÇÃO É SOBRE UMA AUSÊNCIA, e ausência só vale quando a fonte foi
// olhada inteira. Sem root o authorized_keys alheio é ilegível — e acusar ali
// seria acusar a partir de cegueira.
func TestInventarioDeChavesIncompletoNaoAcusa(t *testing.T) {
	f := fatosDeLog(facts.EventoDeLog{
		Kind: "auth.accepted", Metodo: "publickey", Fingerprint: "SHA256:AAA",
		User: "deploy", File: "/var/log/auth.log",
	})
	f.SSHChavesCompleto = false

	r := rodaLog(t, chaveForaDasLocais, f)
	if len(r.Findings) != 0 {
		t.Errorf("sem inventário completo não se afirma ausência: %+v", r.Findings)
	}
	if len(r.Coverage.Partial) == 0 {
		t.Error("e a cobertura precisa CAIR: a pergunta cabia e ficou sem resposta")
	}
}

// ---------------------------------------------------------------------------

func TestSudoParaTmpAcusa(t *testing.T) {
	f := fatosDeLog(facts.EventoDeLog{
		Kind: "auth.sudo", At: "2026-08-24T02:11:03Z", AtKnown: true,
		User: "deploy", Alvos: []string{"/tmp/.upd"}, File: "/var/log/auth.log",
	})
	r := rodaLog(t, sudoParaAlvoIncomum, f)
	if len(r.Findings) != 1 || r.Findings[0].Subject != "/tmp/.upd" {
		t.Fatalf("%+v", r.Findings)
	}
	if r.Findings[0].Sev != check.SevWarn {
		t.Errorf("Sev = %v", r.Findings[0].Sev)
	}
}

// UM achado com contagem, nunca N achados iguais. 427 execuções da mesma coisa
// são uma linha no relatório.
func TestSudoRepetidoViraUmAchadoComContagem(t *testing.T) {
	var evs []facts.EventoDeLog
	for i := 0; i < 37; i++ {
		evs = append(evs, facts.EventoDeLog{
			Kind: "auth.sudo", At: "2026-08-24T02:11:0" + string(rune('0'+i%10)) + "Z",
			AtKnown: true, User: "deploy", Alvos: []string{"/tmp/.upd"},
			File: "/var/log/auth.log",
		})
	}
	r := rodaLog(t, sudoParaAlvoIncomum, fatosDeLog(evs...))
	if len(r.Findings) != 1 {
		t.Fatalf("%d achados, quer 1 agregado", len(r.Findings))
	}
	if !contemEvidencia(r.Findings[0], "37 execução") {
		t.Errorf("a contagem precisa estar na evidência: %v", r.Findings[0].Evidence)
	}
}

// O sudo para caminho de sistema é a rotina de todo servidor: acusá-lo seria
// descrever o clima.
func TestSudoParaCaminhoDeSistemaNaoAcusa(t *testing.T) {
	f := fatosDeLog(facts.EventoDeLog{
		Kind: "auth.sudo", User: "deploy", Alvos: []string{"/usr/bin/systemctl"},
		File: "/var/log/auth.log",
	})
	if r := rodaLog(t, sudoParaAlvoIncomum, f); len(r.Findings) != 0 {
		t.Errorf("%+v", r.Findings)
	}
}

// ---------------------------------------------------------------------------

// PERDA é aviso; PARADA LIMPA é manual. Confundir as duas gritaria em toda
// frota que mantém o auditd atualizado — uma atualização de pacote para o
// daemon, e isso não é evasão.
func TestPerdaDeRegistroEAvisoMasParadaLimpaEhManual(t *testing.T) {
	base := func(evs ...facts.EventoDeLog) *facts.Facts {
		f := fatosDeLog(evs...)
		f.Audit.Instalada = true
		f.FontesDeLog = append(f.FontesDeLog, facts.FonteDeLog{
			Path: "/var/log/audit/audit.log", Familias: []string{"audit"},
			Estado: facts.FonteLida, CobertoDesde: "2026-08-23T00:00:00Z",
			CobertoAte: "2026-08-24T12:00:00Z",
		})
		return f
	}

	r := rodaLog(t, trilhaDeAuditoriaComBuraco, base(facts.EventoDeLog{
		Kind: "audit.lost", At: "2026-08-24T05:00:00Z", AtKnown: true,
		Process: "kernel", Trecho: "audit: audit_lost=42", File: "/var/log/kern.log",
	}))
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevWarn {
		t.Fatalf("perda de registro é aviso: %+v", r.Findings)
	}

	r = rodaLog(t, trilhaDeAuditoriaComBuraco, base(facts.EventoDeLog{
		Kind: "audit.lost", At: "2026-08-24T05:00:00Z", AtKnown: true,
		Process: "auditd", Metodo: "end", File: "/var/log/audit/audit.log",
	}))
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevManual {
		t.Fatalf("parada limpa sozinha é MANUAL: %+v", r.Findings)
	}
}

// Host sem auditoria instalada: a pergunta não cabe, e sai do DENOMINADOR.
// Auditoria não é padrão em quase nenhuma distribuição — como lacuna, isto
// derrubaria a cobertura de quase toda varredura do mundo.
func TestSemAuditdAPerguntaNaoCabe(t *testing.T) {
	f := fatosDeLog()
	r := rodaLog(t, trilhaDeAuditoriaComBuraco, f)

	lacunas, escopo := r.Coverage.NaoVerificados()
	if len(escopo) != 1 {
		t.Fatalf("quer 1 fora de escopo, tem %d (lacunas: %d)", len(escopo), len(lacunas))
	}
	if r.Coverage.Incomplete() {
		t.Error("escopo NÃO pode derrubar a cobertura")
	}
}

// ---------------------------------------------------------------------------

func TestVaoEntreGeracoesEhManual(t *testing.T) {
	f := fatosDeLog()
	f.FontesDeLog = []facts.FonteDeLog{
		{Path: "/var/log/auth.log", Familias: []string{"auth"}, Estado: facts.FonteLida,
			CobertoDesde: "2026-08-22T08:00:00Z", CobertoAte: "2026-08-24T12:00:00Z"},
		{Path: "/var/log/auth.log.1", Familias: []string{"auth"}, Estado: facts.FonteLida,
			CobertoDesde: "2026-08-18T00:00:00Z", CobertoAte: "2026-08-20T12:30:00Z"},
	}
	r := rodaLog(t, buracoTemporalNoLog, f)
	if len(r.Findings) != 1 {
		t.Fatalf("%d achados: %+v", len(r.Findings), r.Findings)
	}
	fd := r.Findings[0]
	// MANUAL, e não aviso: ausência de linha não prova remoção. Host desligado e
	// servidor ocioso produzem a mesma forma, e a promoção pertence à correlação
	// com o wtmp, que tem testemunha independente.
	if fd.Sev != check.SevManual {
		t.Errorf("Sev = %v, quer MANUAL", fd.Sev)
	}
	if !contemEvidencia(fd, "1 dia") && !contemEvidencia(fd, "2 dia") {
		t.Errorf("o tamanho do vão precisa estar dito: %v", fd.Evidence)
	}
}

// O ARQUIVO LIDO EM DUAS PONTAS tem um vão que é NOSSO — o miolo não foi lido
// por causa do teto. Acusar o host por isso seria acusá-lo do limite da
// ferramenta.
func TestVaoDeLeituraTruncadaNaoViraAchado(t *testing.T) {
	f := fatosDeLog()
	f.FontesDeLog = []facts.FonteDeLog{
		{Path: "/var/log/auth.log", Familias: []string{"auth"}, Estado: facts.FonteTruncada,
			LeituraDescontinua: true,
			CobertoDesde:       "2026-08-24T10:00:00Z", CobertoAte: "2026-08-24T12:00:00Z"},
		{Path: "/var/log/auth.log.1", Familias: []string{"auth"}, Estado: facts.FonteLida,
			CobertoDesde: "2026-08-01T00:00:00Z", CobertoAte: "2026-08-02T00:00:00Z"},
	}
	if r := rodaLog(t, buracoTemporalNoLog, f); len(r.Findings) != 0 {
		t.Errorf("o vão é do teto da ferramenta, não do host: %+v", r.Findings)
	}
}

// ---------------------------------------------------------------------------

// journald-only: INFO, e a cobertura NÃO cai. É o precedente do `dateext`.
func TestHostSemLogEmTextoSaiComoInformacaoENaoLacuna(t *testing.T) {
	f := &facts.Facts{LogEstado: facts.LogForaDeEscopo}
	r := rodaLog(t, coberturaDeLog, f)

	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevInfo {
		t.Fatalf("%+v", r.Findings)
	}
	if !contemEvidencia(r.Findings[0], "journal") {
		t.Errorf("a evidência precisa dizer onde ESTÁ o log: %v", r.Findings[0].Evidence)
	}
	if r.Coverage.Incomplete() {
		t.Error("escopo não derruba a cobertura")
	}
}

// O horizonte EFETIVO sai no relatório: é ele que diz até onde do passado a
// coleta chegou, e a coleta não tem mais janela temporal — ela lê da geração
// mais nova para a mais antiga até um teto morder.
func TestCoberturaDizOHorizonteAlcancado(t *testing.T) {
	f := fatosDeLog(facts.EventoDeLog{Kind: "auth.accepted", File: "/var/log/auth.log"})

	r := rodaLog(t, coberturaDeLog, f)
	if len(r.Findings) != 1 {
		t.Fatalf("%+v", r.Findings)
	}
	if !contemEvidencia(r.Findings[0], "2026-08-17") {
		t.Errorf("o horizonte ALCANÇADO precisa aparecer: %v", r.Findings[0].Evidence)
	}
	if !contemEvidencia(r.Findings[0], "NÃO tem janela temporal") {
		t.Errorf("e o relatório precisa dizer COMO a coleta parou: %v", r.Findings[0].Evidence)
	}
}

// --no-logs não é "não achei": é "não olhei", e a cobertura tem que dizer isso.
func TestColetaDesligadaViraLacunaENaoSilencio(t *testing.T) {
	f := &facts.Facts{LogEstado: facts.LogDesativado}
	for _, c := range []check.Check{chaveForaDasLocais, sudoParaAlvoIncomum, coberturaDeLog} {
		r := rodaLog(t, c, f)
		if len(r.Findings) != 0 {
			t.Errorf("%s: nada pode ser afirmado: %+v", c.ID, r.Findings)
		}
		if len(r.Coverage.Partial) == 0 {
			t.Errorf("%s: desligado precisa DERRUBAR a cobertura", c.ID)
		}
	}
}

// A lacuna do COLETOR precisa chegar ao relatório por algum check — senão o
// motor conta o check como completo sobre uma fonte que ninguém leu.
func TestLacunaDoColetorChegaAoRelatorio(t *testing.T) {
	f := fatosDeLog()
	f.Partial = map[string][]string{
		"logeventos": {"/var/log/auth.log não pôde ser lido (permissão negada)"},
	}
	r := rodaLog(t, coberturaDeLog, f)
	if len(r.Coverage.Partial) == 0 {
		t.Fatal("a lacuna do coletor não chegou à cobertura")
	}
	if !strings.Contains(strings.Join(r.Coverage.Partial[0].Reasons, " "), "auth.log") {
		t.Errorf("motivo = %v", r.Coverage.Partial[0].Reasons)
	}
}

func contemEvidencia(fd check.Finding, s string) bool {
	for _, e := range fd.Evidence {
		if strings.Contains(e, s) {
			return true
		}
	}
	return false
}

// CHAVE SEM FINGERPRINT sai do conjunto de comparação, e o conjunto é o que
// sustenta a afirmação de ausência.
//
// O achado continua saindo — suprimi-lo deixaria uma linha malformada em
// qualquer authorized_keys desligar o check inteiro, que é barato demais. O que
// muda é a cobertura: ela deixa de dizer que a pergunta foi respondida.
func TestChaveSemFingerprintDerrubaACoberturaSemCalarOAchado(t *testing.T) {
	f := fatosDeLog(facts.EventoDeLog{
		Kind: "auth.accepted", Metodo: "publickey", Fingerprint: "SHA256:AAA",
		User: "deploy", File: "/var/log/auth.log",
	})
	f.SSHKeys = []facts.SSHKey{
		{File: "/root/.ssh/authorized_keys", Type: "ssh-ed25519"}, // sem Fingerprint
	}

	r := rodaLog(t, chaveForaDasLocais, f)
	if len(r.Findings) != 1 {
		t.Fatalf("o achado não pode ser calado por uma linha malformada: %+v", r.Findings)
	}
	if !contemEvidencia(r.Findings[0], "ficaram fora da comparação") {
		t.Errorf("a ressalva precisa estar na EVIDÊNCIA, não só no rodapé: %v",
			r.Findings[0].Evidence)
	}
	if len(r.Coverage.Partial) == 0 {
		t.Error("comparação contra conjunto incompleto não é pergunta respondida")
	}
}

// SUDO CUJO ALVO NÃO PÔDE SER RESOLVIDO fica sem resposta, e o silêncio sobre
// ele precisa ser dito.
//
// `sudo sh -c 'eval "$CMD"'` executa algo que o resolvedor não segue. Sem a
// lacuna, aquelas execuções saem do relatório como se tivessem sido avaliadas e
// aprovadas — "olhei e está bem" e "não consegui olhar" colapsando no mesmo
// silêncio, dentro de um check.
func TestSudoComAlvoIndeterminadoDeclaraLacuna(t *testing.T) {
	f := fatosDeLog(facts.EventoDeLog{
		Kind: "auth.sudo", User: "deploy", AlvoIndeterminado: true,
		File: "/var/log/auth.log", Trecho: `deploy : ... COMMAND=/bin/sh -c eval "$CMD"`,
	})
	r := rodaLog(t, sudoParaAlvoIncomum, f)
	if len(r.Findings) != 0 {
		t.Errorf("não há alvo para acusar: %+v", r.Findings)
	}
	if len(r.Coverage.Partial) == 0 {
		t.Fatal("a pergunta ficou sem resposta e a cobertura não caiu")
	}
	if !strings.Contains(strings.Join(r.Coverage.Partial[0].Reasons, " "), "não foi avaliado") {
		t.Errorf("motivo = %v", r.Coverage.Partial[0].Reasons)
	}
}

// AuthorizedKeysCommand tira a AUTORIDADE dos arquivos locais: quem responde
// "esta chave está autorizada?" é um programa, e o authorized_keys em disco é
// vazio por construção. Sem esta guarda, o check falaria em TODO login
// bem-sucedido de um host de frota grande — continuamente, não por acidente.
func TestAuthorizedKeysCommandTiraOCheckDeEscopo(t *testing.T) {
	f := fatosDeLog(facts.EventoDeLog{
		Kind: "auth.accepted", Metodo: "publickey", Fingerprint: "SHA256:AAA",
		User: "deploy", File: "/var/log/auth.log",
	})
	f.SSH.AuthorizedKeysCommand = "/usr/bin/sss_ssh_authorizedkeys"

	r := rodaLog(t, chaveForaDasLocais, f)
	lacunas, escopo := r.Coverage.NaoVerificados()
	if len(escopo) != 1 {
		t.Fatalf("quer 1 fora de escopo, tem %d (lacunas: %d)", len(escopo), len(lacunas))
	}
	if r.Coverage.Incomplete() {
		t.Error("escopo NÃO derruba a cobertura")
	}
}

// A LACUNA É POR FAMÍLIA, e não da coleta inteira.
//
// A primeira versão despejava Partial["logeventos"] dentro de todo check, e um
// audit.log ilegível tornava parcial o check de chave SSH — que só lê `auth`.
// Seguro contra falso limpo, e ruidoso do jeito que faz a cobertura incompleta
// virar papel de parede: quem vê tudo parcial para de ler a linha.
func TestLacunaDeUmaFamiliaNaoContaminaOutra(t *testing.T) {
	f := fatosDeLog(facts.EventoDeLog{
		Kind: "auth.accepted", Metodo: "publickey", Fingerprint: "SHA256:AAA",
		User: "deploy", File: "/var/log/auth.log",
	})
	f.Audit.Instalada = true
	f.FontesDeLog = append(f.FontesDeLog, facts.FonteDeLog{
		Path: "/var/log/audit/audit.log", Familias: []string{"audit"},
		Estado: facts.FonteIlegivel,
		Lacuna: "/var/log/audit/audit.log não pôde ser lido (permission denied)",
	})

	// O check de chave SSH lê `auth`, que está intacta: nada de parcial.
	r := rodaLog(t, chaveForaDasLocais, f)
	if len(r.Coverage.Partial) != 0 {
		t.Errorf("a lacuna do audit não pode tornar parcial um check de auth: %+v",
			r.Coverage.Partial)
	}
	if len(r.Findings) != 1 {
		t.Errorf("e o achado continua saindo: %+v", r.Findings)
	}

	// Já o check da trilha de auditoria depende dela, e TEM que cair.
	r = rodaLog(t, trilhaDeAuditoriaComBuraco, f)
	if len(r.Coverage.Partial) == 0 {
		t.Error("o check que depende de `audit` precisa declarar a lacuna dela")
	}
}
