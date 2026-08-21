package facts

import (
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"github.com/lex0c/aletheia/internal/env"
)

// Registros de login (runbook §13).
//
// A ferramenta cita o wtmp em dezenas de evidências — "confira contra o wtmp",
// "compare com o horário de trabalho" — e nunca o leu. Mandar o operador a uma
// fonte é útil; ir até ela é melhor, e o formato não justifica a omissão: é
// registro binário de tamanho FIXO, sem parser nenhum envolvido.
//
// Três arquivos, e cada um responde uma pergunta diferente:
//
//	/var/log/wtmp   quem entrou, de onde e quando        (legível por todos)
//	/var/log/btmp   quem TENTOU e falhou                 (root)
//	/run/utmp       quem está logado AGORA               (legível por todos)
//
// O btmp é o que dá o sinal mais forte quando cruzado com o wtmp: dezenas de
// falhas da mesma origem seguidas de um sucesso da MESMA origem é força bruta
// que funcionou, e nenhuma das duas metades diz isso sozinha.

const (
	// Os DOIS tamanhos de `struct utmp` que existem em Linux.
	//
	// O de 384 bytes é o do x86 com glibc, onde `ut_session` é int32 e o
	// `ut_tv` é um par de int32 — mantidos assim de propósito, para compat
	// binária com o utmp de 32 bits. É o que se mede compilando em x86_64 e
	// também com -m32, e foi por isso que 384 passou por universal aqui.
	//
	// Ele NÃO é universal. Em arquitetura sem esse legado (arm64, e qualquer
	// uma com __WORDSIZE_TIME64_COMPAT32 == 0) e na musl inteira, `ut_session`
	// é long e o `ut_tv` é um `struct timeval` de verdade: 400 bytes, com o
	// segundo do timestamp no offset 344 e 64 bits de largura.
	//
	// Ler um wtmp de 400 com passo de 384 não falha: produz registros
	// desalinhados, com usuário vindo do meio de outro campo e timestamp
	// sempre zero — e como o ReadFile teve sucesso, nenhuma lacuna é
	// declarada. Um servidor arm64 ou Alpine reportava inventário de login
	// inventado, silenciosamente.
	tamUtmp32 = 384
	tamUtmp64 = 400

	// maxRegistrosLogin limita a leitura aos mais RECENTES. Um wtmp de servidor
	// antigo tem centenas de milhares de registros, e o que interessa a uma
	// triagem é o fim do arquivo.
	maxRegistrosLogin = 2000
)

// Tipos de registro do utmp que interessam. Exportados porque quem decide o
// que cada um significa é o check, não o coletor.
const (
	// TipoBoot marca o início de um boot. O campo de origem dele carrega a
	// VERSÃO DO KERNEL, não um endereço — quem confundir os dois passa a tratar
	// texto de kernel como origem de conexão.
	TipoBoot = 2

	// TipoLoginUsuario é a entrada de fato — o que `last` mostra.
	TipoLoginUsuario = 7
	// TipoSaida é o encerramento da sessão.
	TipoSaida = 8
)

// Login é um registro de entrada, saída ou tentativa.
type Login struct {
	Tipo    int    `json:"type"`
	User    string `json:"user,omitempty"`
	Linha   string `json:"line,omitempty"`
	Origem  string `json:"host,omitempty"`
	PID     int    `json:"pid,omitempty"`
	QuandoU string `json:"when_utc,omitempty"`

	// Falhou distingue o que veio do btmp. O formato é o mesmo; o arquivo é
	// que diz se aquilo foi uma entrada ou uma tentativa recusada.
	Falhou bool `json:"failed,omitempty"`

	// Agora marca o que veio de /run/utmp — sessão ABERTA neste instante, e não
	// histórico. A distinção sustenta um cruzamento que nenhuma das duas fontes
	// faz sozinha: alguém logado agora com o histórico vazio.
	Agora bool `json:"current,omitempty"`
}

func collectLogins(f *Facts, e *env.Env) {
	// O wtmp costuma ser legível por todos, mas o CIS Benchmark manda pôr 0640
	// nele, e essa recomendação é seguida. Quando ela foi seguida, uma
	// varredura sem root lia zero registro — e zero registro de login com
	// sessão aberta agora é a forma EXATA do achado antiforense de histórico
	// zerado. A ferramenta fabricava um CRITICAL irreversível de permissão
	// negada: acusava o defensor endurecido de ter apagado o próprio rastro.
	if f.HistoricoDeLoginLido = lerUtmp(f, e, "/var/log/wtmp", false, false); !f.HistoricoDeLoginLido {
		f.denyPersist("login", "/var/log/wtmp não pôde ser lido: o HISTÓRICO de "+
			"login não foi examinado, e sem ele não se pode afirmar nada sobre "+
			"ele estar vazio")
	}
	if !lerUtmp(f, e, "/run/utmp", false, true) {
		f.denyPersist("login", "/run/utmp não pôde ser lido: as sessões ABERTAS "+
			"agora não foram examinadas")
	}

	// btmp é 0600 de root em toda distribuição, e a diferença precisa aparecer
	// como lacuna quando a varredura roda sem privilégio — sem isso, "nenhuma
	// força bruta" sairia igual a "não pude olhar as tentativas".
	if !lerUtmp(f, e, "/var/log/btmp", true, false) {
		f.denyPersist("login", "/var/log/btmp ilegível (é 0600 de root): "+
			"tentativas de login RECUSADAS não foram examinadas, e força bruta "+
			"não pode ser distinguida de ausência dela")
	}
}

// lerUtmp lê os registros mais recentes. Devolve falso quando o arquivo existe
// e não pôde ser lido — que é diferente de não existir.
//
// A leitura é do FIM do arquivo, por duas razões que se somam: numa triagem o
// que interessa é o recente, e o wtmp de um servidor de anos passa do teto de
// leitura do env — o que devolveria zero registro com cara de histórico
// zerado, que é precisamente o achado que este arquivo alimenta.
func lerUtmp(f *Facts, e *env.Env, caminho string, falhou, agora bool) bool {
	fi, err := e.Lstat(caminho)
	if err != nil {
		// Só a AUSÊNCIA é ausência de fonte. Qualquer outro erro — e o que
		// acontece na prática é EACCES, com /var/log em 0750 root:adm — é
		// lacuna, e devolver true aqui marcaria HistoricoDeLoginLido sem ter
		// lido um byte. Como /run/utmp (0644) continua entregando as sessões
		// abertas, o resultado era "sessão aberta e histórico vazio": o
		// CRITICAL irreversível de histórico zerado, fabricado a partir de
		// permissão negada. É o mesmo falso positivo que collectLogins
		// descreve acima, reintroduzido uma camada abaixo dele.
		return errors.Is(err, os.ErrNotExist)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		if fi, err = e.Stat(caminho); err != nil {
			return false
		}
	}

	tam, ok := tamanhoDoRegistroCom(fi.Size(), nativoDeUtmp(f.Host.Libc))
	if !ok {
		// Nem 384 nem 400 dividem o arquivo: é outro layout, ou o arquivo está
		// truncado. Adivinhar aqui produziria um inventário de login inventado,
		// que é pior que nenhum.
		f.denyPersist("login", baseNome(caminho)+" tem "+itoa(int(fi.Size()))+
			" bytes, que não é múltiplo de nenhum dos dois tamanhos conhecidos "+
			"de registro utmp (384 e 400): o arquivo NÃO foi interpretado")
		// false, e não true: a lacuna acima diz que o arquivo não foi
		// interpretado, e devolver true marcaria HistoricoDeLoginLido como
		// testemunha de uma leitura que não houve. Com um wtmp truncado (corte
		// de disco, escrita interrompida) o resultado era f.Logins vazio COM a
		// testemunha ligada — que atravessa o guarda de antiforense.wtmp_cleared
		// e produz o CRITICAL irreversível de "histórico zerado" a partir de um
		// arquivo que ninguém leu. É o mesmo falso positivo que o ramo do Lstat
		// acima descreve, pela porta do tamanho.
		return false
	}

	n := int(fi.Size() / int64(tam))
	pular := 0
	if n > maxRegistrosLogin {
		pular = n - maxRegistrosLogin
		n = maxRegistrosLogin
		f.denyPersist("login", baseNome(caminho)+" tem mais de "+
			itoa(maxRegistrosLogin)+" registros e foram lidos os "+
			itoa(maxRegistrosLogin)+" mais recentes: o que veio antes NÃO foi "+
			"examinado")
	}
	b, err := lerFatia(e, caminho, int64(pular)*int64(tam), n*tam)
	if err != nil {
		return false
	}
	n = len(b) / tam // o arquivo pode ter encolhido entre o stat e a leitura

	for i := 0; i < n; i++ {
		r := b[i*tam : (i+1)*tam]
		l := Login{
			Tipo:   int(int16(le16(r[0:]))),
			PID:    int(int32(le32(r[4:]))),
			Linha:  cstr(r[8:40]),
			User:   cstr(r[44:76]),
			Origem: cstr(r[76:332]),
			Falhou: falhou,
			Agora:  agora,
		}
		// O segundo do timestamp muda de lugar E de largura entre os dois
		// layouts: 32 bits no offset 340, 64 bits no 344.
		if sec := segundoDoRegistro(r, tam); sec > 0 {
			l.QuandoU = time.Unix(sec, 0).UTC().Format("2006-01-02T15:04:05Z")
		}
		if l.User == "" && l.Tipo != TipoBoot {
			continue
		}
		f.Logins = append(f.Logins, l)
	}
	return true
}

// lerFatia lê `quanto` bytes a partir de `de`. Existe porque o utmp é o único
// formato aqui em que a parte que interessa está no FIM e o começo pode ser
// grande demais para caber no teto de leitura.
func lerFatia(e *env.Env, caminho string, de int64, quanto int) ([]byte, error) {
	rc, err := e.Open(caminho)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	if de > 0 {
		s, ok := rc.(io.Seeker)
		if !ok {
			return nil, errSemSeek
		}
		if _, err := s.Seek(de, io.SeekStart); err != nil {
			return nil, err
		}
	}
	b := make([]byte, quanto)
	lidos, err := io.ReadFull(rc, b)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, err
	}
	return b[:lidos], nil
}

var errSemSeek = errors.New("o arquivo não aceita posicionamento: a cauda não " +
	"pôde ser lida")

// cstr corta a string no primeiro NUL. Os campos do utmp são buffers de
// tamanho fixo preenchidos com zero, e usar o buffer inteiro traria lixo do
// registro anterior para dentro da evidência.
func cstr(b []byte) string {
	if i := indexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return strings.TrimSpace(string(b))
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

func le16(b []byte) uint16 { return uint16(b[0]) | uint16(b[1])<<8 }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d [20]byte
	i := len(d)
	for n > 0 {
		i--
		d[i] = byte('0' + n%10)
		n /= 10
	}
	return string(d[i:])
}

// nativoDeUtmp escolhe o layout DESTE host, pela arquitetura e pela LIBC.
//
// A build tag sozinha errava, e o comentário do próprio arquivo irmão já dizia
// por quê: ele afirma "e da musl em qualquer arquitetura", enquanto a tag
// `!amd64 && !386` exclui justamente a arquitetura em que o Alpine mais roda.
// Na musl x86_64 o `struct utmpx` tem `ut_tv` como `struct timeval` de verdade
// — tv_sec de 64 bits no deslocamento 344 — e o registro tem 400 bytes, igual
// ao arm64 com glibc.
//
// O efeito em Alpine x86_64: sempre que o tamanho do arquivo dividisse os dois
// (múltiplo de 9600, ou seja 24 registros musl), o desempate escolhia 384 e o
// inventário de login saía lido do byte errado — nome de usuário vindo do meio
// de outro campo, timestamp zero — SEM lacuna declarada. Um inventário de login
// inventado é pior que nenhum, que é o que o resto deste arquivo já diz.
func nativoDeUtmp(libc string) int {
	if libc == "musl" {
		return tamUtmp64
	}
	return tamanhoNativoDeUtmp
}

// tamanhoDoRegistro descobre o layout pelo tamanho do arquivo, para o host em
// que este binário roda.
func tamanhoDoRegistro(tamanho int64) (int, bool) {
	return tamanhoDoRegistroCom(tamanho, tamanhoNativoDeUtmp)
}

// tamanhoDoRegistroCom é a mesma decisão com o layout nativo INFORMADO.
//
// O utmp é uma sequência de registros de tamanho fixo, sem cabeçalho: o único
// jeito de saber qual dos dois layouts está em uso é a divisibilidade. Quando os
// dois dividem — arquivo vazio, ou um múltiplo comum como 2400 bytes — vence o
// nativo, que é a resposta certa em todo host que não teve o arquivo copiado de
// outra máquina.
func tamanhoDoRegistroCom(tamanho int64, nativo int) (int, bool) {
	if tamanho < 0 {
		return 0, false
	}
	// Arquivo VAZIO divide os dois e vence o nativo, com ok: wtmp zerado é o
	// estado de toda instalação nova e de todo contêiner. Chamar isso de
	// formato desconhecido poria uma lacuna em cada varredura do mundo.
	c32 := tamanho%tamUtmp32 == 0
	c64 := tamanho%tamUtmp64 == 0
	switch {
	case c32 && c64:
		return nativo, true
	case c64:
		return tamUtmp64, true
	case c32:
		return tamUtmp32, true
	}
	return 0, false
}

// segundoDoRegistro lê o timestamp no lugar certo de cada layout.
func segundoDoRegistro(r []byte, tam int) int64 {
	if tam == tamUtmp64 {
		if len(r) < 352 {
			return 0
		}
		return int64(le64(r[344:]))
	}
	if len(r) < 344 {
		return 0
	}
	return int64(le32(r[340:]))
}

// le64 lê um inteiro de 64 bits little-endian. Existe aqui porque só o layout
// de 400 bytes usa essa largura no campo de tempo.
func le64(b []byte) uint64 {
	if len(b) < 8 {
		return 0
	}
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}
