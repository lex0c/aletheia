package facts

import (
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
	// tamRegistroUtmp é fixo e igual em 32 e 64 bits: os campos de tempo e
	// sessão são int32 por compatibilidade, de propósito, então a estrutura
	// não muda de tamanho com a arquitetura.
	tamRegistroUtmp = 384

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
	// wtmp é legível por todos; btmp é 0600 de root, e a diferença precisa
	// aparecer como lacuna quando a varredura roda sem privilégio — sem isso,
	// "nenhuma força bruta" sairia igual a "não pude olhar as tentativas".
	lerUtmp(f, e, "/var/log/wtmp", false, false)
	lerUtmp(f, e, "/run/utmp", false, true)

	if !lerUtmp(f, e, "/var/log/btmp", true, false) {
		f.denyPersist("login", "/var/log/btmp ilegível (é 0600 de root): "+
			"tentativas de login RECUSADAS não foram examinadas, e força bruta "+
			"não pode ser distinguida de ausência dela")
	}
}

// lerUtmp lê os registros mais recentes. Devolve falso quando o arquivo existe
// e não pôde ser lido — que é diferente de não existir.
func lerUtmp(f *Facts, e *env.Env, caminho string, falhou, agora bool) bool {
	if _, err := e.Lstat(caminho); err != nil {
		return true // não existe: não é lacuna, é ausência de fonte
	}
	b, err := e.ReadFile(caminho)
	if err != nil {
		return false
	}

	// Do FIM para o começo: o interessante numa triagem é o mais recente, e
	// ler o arquivo inteiro de um servidor antigo é desperdício.
	n := len(b) / tamRegistroUtmp
	inicio := 0
	if n > maxRegistrosLogin {
		inicio = n - maxRegistrosLogin
		f.denyPersist("login", baseNome(caminho)+" tem "+itoa(n)+
			" registros e foram lidos os "+itoa(maxRegistrosLogin)+
			" mais recentes: o que veio antes NÃO foi examinado")
	}
	for i := inicio; i < n; i++ {
		r := b[i*tamRegistroUtmp : (i+1)*tamRegistroUtmp]
		l := Login{
			Tipo:   int(int16(le16(r[0:]))),
			PID:    int(int32(le32(r[4:]))),
			Linha:  cstr(r[8:40]),
			User:   cstr(r[44:76]),
			Origem: cstr(r[76:332]),
			Falhou: falhou,
			Agora:  agora,
		}
		if sec := le32(r[340:]); sec > 0 {
			l.QuandoU = time.Unix(int64(sec), 0).UTC().Format("2006-01-02T15:04:05Z")
		}
		if l.User == "" && l.Tipo != TipoBoot {
			continue
		}
		f.Logins = append(f.Logins, l)
	}
	return true
}

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
