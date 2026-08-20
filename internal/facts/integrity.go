package facts

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"io"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/lex0c/aletheia/internal/env"
)

// Integridade por hash (runbook §24, fase 7).
//
// A pergunta de propriedade responde "veio de um pacote?". Esta responde a
// seguinte, que é a que faltava:
//
//	e continua sendo o que o pacote entregou?
//
// A diferença é a distância inteira entre ver e não ver o Ebury. Ele substitui
// `libkeyutils.so.1` no lugar dela: caminho legítimo, nome certo, dono de
// pacote em ordem — e conteúdo trocado. Todos os checks de propriedade dizem
// "sim, veio de um pacote", e todos estão certos e cegos ao mesmo tempo.
//
// As três bases guardam o hash NATIVAMENTE, o que mantém a regra da ferramenta
// de não chamar binário do host:
//
//	dpkg     /var/lib/dpkg/info/<pkg>.md5sums   texto, "hash  caminho"
//	apk      linha Z: no installed              SHA1 em base64, prefixo Q1
//	pacman   <pkg>/mtree                        gzip, sha256digest= por linha
//
// O ESCOPO é estreito de propósito. Verificar a árvore inteira custaria minutos
// e não acrescenta sinal: o que interessa é o que já é candidato — exe de
// processo, alvo de persistência, SUID, módulo, alvo de gatilho. São algumas
// centenas de arquivos, e as fontes de hash lidas são só as dos pacotes que
// entregaram algum deles.

const (
	// Teto por arquivo. Um binário de centenas de megabytes existe (bancos de
	// dados, runtimes de ML) e hashear tudo travaria a varredura. O que passar
	// disso vira lacuna DECLARADA, nunca silêncio.
	maxHashBytes = 256 << 20

	// Teto de trabalhadores. O mesmo do coletor de processos: acima disso a
	// disputa por I/O passa a custar mais do que o paralelismo rende.
	maxHashWorkers = 8

	// Teto TOTAL de bytes hasheados. Sem ele o custo cresce com o host: um
	// servidor com dois mil mapeamentos distintos de biblioteca levaria a
	// varredura a dezenas de segundos.
	//
	// O que ficar de fora vira lacuna DECLARADA. É a mesma regra de todo limite
	// desta ferramenta: truncar em silêncio diria "confere" sobre o que não foi
	// nem lido.
	maxHashTotal = 1 << 30
)

// HashDivergente é um arquivo que o pacote entregou e que MUDOU desde então.
type HashDivergente struct {
	Path     string `json:"path"`
	Pacote   string `json:"package"`
	Algo     string `json:"algo"`
	Esperado string `json:"expected"`
	Obtido   string `json:"got"`

	// Config marca arquivo que o pacote entrega para ser EDITADO. A divergência
	// ali é o trabalho normal do administrador — o que muda é o peso, não o
	// fato.
	Config bool `json:"config,omitempty"`
}

// verificarHashes compara o que está em disco com o que o pacote declarou.
//
// Recebe o mapa caminho -> pacote produzido pela resposta de propriedade: é ele
// que torna a verificação barata, restringindo a leitura às fontes de hash dos
// pacotes efetivamente envolvidos.
func verificarHashes(f *Facts, e *env.Env, donos map[string]string) {
	// Pacote -> caminhos dele que nos interessam.
	porPacote := map[string][]string{}
	for caminho, pkg := range donos {
		if pkg != "" {
			porPacote[pkg] = append(porPacote[pkg], caminho)
		}
	}
	if len(porPacote) == 0 {
		return
	}

	var esperados map[string]hashRef
	desviados := map[string]bool{}
	switch f.Pkg.Kind {
	case "dpkg":
		esperados = hashesDpkg(f, e, porPacote)
		// Os conffiles ficam FORA dos .md5sums — o dpkg os guarda no status,
		// num campo próprio, porque são feitos para o administrador editar.
		//
		// Sem lê-los, dezoito arquivos por host ficavam "sem hash declarado" e
		// a cobertura saía degradada em toda varredura de Debian. Pior: são
		// justamente /etc/init.d, /etc/pam.d e /etc/cron.* — os gatilhos de
		// execução, que é onde a modificação importa.
		conffilesDpkg(f, e, esperados, donos)
		// DIVERSÃO é o mecanismo pelo qual um pacote move o arquivo de outro,
		// de propósito e COM REGISTRO. O arquivo no caminho original passa a ser
		// de outro pacote, e o hash do original nunca mais confere — é legítimo,
		// e sem isto todo host com `dash` como /bin/sh acusaria. A imagem oficial
		// do Ubuntu 14.04 desvia o /sbin/initctl exatamente assim.
		desviados = removerDesviados(e, esperados)
	case "apk":
		esperados = hashesApk(f, e, porPacote)
	case "pacman":
		esperados = hashesPacman(f, e, porPacote)
	default:
		return
	}

	// A comparação é PARALELA, e a razão é medida: com as bibliotecas entrando
	// na lista, o `wtf` no host saltou de 1,1s para 3,3s — e o contrato do
	// subcomando é responder em torno de um segundo. Hashear é I/O mais CPU,
	// que é exatamente o que reparte bem.
	// O tamanho entra na tarefa em vez de ser consultado depois.
	//
	// A primeira versão chamava `tamanhoDe` dentro do comparador do sort — uma
	// syscall por COMPARAÇÃO, O(n log n) delas — e mais uma por arquivo no
	// laço. Pior que o custo: um comparador que faz I/O não define ordem
	// consistente se um arquivo sumir no meio, e ordenação com comparador
	// inconsistente não tem resultado definido.
	type tarefa struct {
		caminho, pkg string
		tam          int64
	}
	fila := make([]tarefa, 0, len(donos))
	var semHash []string
	for caminho, pkg := range donos {
		if pkg == "" {
			continue
		}
		if desviados[caminho] {
			// Caminho DESVIADO não é lacuna: é um mecanismo com registro, e o
			// registro é justamente a explicação. Contá-lo como "não pude
			// comparar" deixaria toda imagem do Ubuntu permanentemente
			// degradada — e um parcial que nunca sai gasta o sinal de cobertura,
			// que é o que separa "não achei" de "não consegui olhar".
			continue
		}
		// SYMLINK não tem conteúdo próprio, e comparar o hash do alvo com o que
		// a base declara para o link daria divergência em todo caminho ligado —
		// /bin/sh, /sbin/modprobe e os `*-restore` do iptables são todos links.
		//
		// Não é lacuna: o que importa é o arquivo apontado, e ele é candidato
		// por si quando alguém o executa ou o carrega.
		if fi, err := e.Lstat(caminho); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if _, ok := esperados[caminho]; !ok {
			// O pacote reivindica o arquivo e NÃO declara hash para ele. Precisa
			// aparecer como lacuna, não como "confere".
			semHash = append(semHash, caminho)
			continue
		}
		fila = append(fila, tarefa{caminho: caminho, pkg: pkg, tam: tamanhoDe(e, caminho)})
	}

	// Os menores primeiro: sob o teto de bytes, isso maximiza quantos arquivos
	// cabem antes do corte. O desempate por caminho torna a ordem determinística
	// — sem ele, dois arquivos do mesmo tamanho trocam de lugar entre execuções
	// e o corte do orçamento cai em arquivos diferentes.
	sort.Slice(fila, func(i, j int) bool {
		if fila[i].tam != fila[j].tam {
			return fila[i].tam < fila[j].tam
		}
		return fila[i].caminho < fila[j].caminho
	})

	var mu sync.Mutex
	var wg sync.WaitGroup
	var prox int64
	var gastos int64
	n := e.Workers(maxHashWorkers)
	for w := 0; w < n; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(atomic.AddInt64(&prox, 1)) - 1
				if i >= len(fila) {
					return
				}
				t := fila[i]
				// Soma ANTES de decidir: verificar e depois somar deixaria N
				// trabalhadores passarem juntos pelo teto.
				if atomic.AddInt64(&gastos, t.tam) > maxHashTotal {
					mu.Lock()
					semHash = append(semHash, t.caminho)
					mu.Unlock()
					continue
				}
				ref := esperados[t.caminho]
				obtido, err := hashDoArquivo(e, t.caminho, ref.algo)
				mu.Lock()
				switch {
				case err != nil:
					semHash = append(semHash, t.caminho)
				case !strings.EqualFold(obtido, ref.hash):
					f.HashDiff = append(f.HashDiff, HashDivergente{
						Path: t.caminho, Pacote: t.pkg, Algo: ref.algo,
						Esperado: ref.hash, Obtido: obtido, Config: ref.conf,
					})
				default:
					// CONFERIU. Guardar isto não é simetria decorativa: é o que
					// permite a outros checks SUPRIMIREM um achado com prova.
					// Sem a lista, "tem dono de pacote" viraria licença para
					// calar sobre um arquivo que ninguém verificou.
					f.HashOK = append(f.HashOK, t.caminho)
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	// Ordem estável: sem isso o relatório muda de forma entre execuções
	// idênticas, e a agregação de frota vê diferença onde não há.
	sort.Slice(f.HashDiff, func(i, j int) bool { return f.HashDiff[i].Path < f.HashDiff[j].Path })
	sort.Strings(f.HashOK)
	sort.Strings(semHash)

	if len(semHash) > 0 {
		// "Não pude comparar" nunca pode sair igual a "confere".
		amostra := semHash
		if len(amostra) > 5 {
			amostra = append(amostra[:5:5], "…")
		}
		f.denyPersist("hash", strconv.Itoa(len(semHash))+" arquivo(s) com dono de "+
			"pacote NÃO puderam ser comparados por hash ("+strings.Join(amostra, ", ")+
			"): a base não declara hash para eles ou a leitura falhou")
	}
}

// Timestomp é a divergência entre a data de MODIFICAÇÃO e a de METADADOS.
//
// `touch -r /bin/ls implante` copia a data do vizinho e a evidência temporal
// morre — a ferramenta cita data em dezenas de evidências, e todas ficam
// inúteis. Mas o `touch` mexe no mtime e NÃO consegue mexer no ctime: só o
// kernel escreve ali, e ele o atualiza justamente quando alguém mexe nos
// metadados. A pegada da falsificação é a própria falsificação.
type Timestomp struct {
	Path    string `json:"path"`
	ModUTC  string `json:"mtime_utc"`
	MetaUTC string `json:"ctime_utc"`
	DeltaH  int    `json:"delta_hours"`
}

// coletarTimestomp compara as duas datas nos arquivos SEM dono de pacote.
//
// A restrição é o que torna o sinal utilizável: arquivo de pacote tem mtime
// muito anterior ao ctime por desenho — a data vem do arquivo dentro do pacote,
// construído meses antes, e o ctime é a hora da instalação. Sem esse recorte,
// todo binário do sistema apareceria como falsificado.
//
// O CLUSTER de ctime é o segundo recorte, e ele mata o falso positivo de
// contêiner. Uma imagem de contêiner (ou uma extração em massa: tar -x, rsync,
// restauração de backup) dá o MESMO ctime a dezenas de arquivos de uma vez — o
// instante em que a camada foi montada. Medido num debian:12 limpo: DOZE
// arquivos de config do apt, todos com o mtime do build da base e o ctime
// idêntico da extração, gritando CRITICAL num host saudável.
//
// Timestomping é o oposto: feito arquivo a arquivo, o `touch -r` deixa um ctime
// ISOLADO — a hora em que o atacante tocou aquele arquivo, distinta do bloco. Um
// ctime compartilhado por muitos arquivos NÃO é backdating; é a operação em
// massa. Suprime o bloco, mantém o isolado.
//
// Não é gate por "estou em contêiner" — isso cegaria a detecção do próprio
// timestomp DENTRO de um contêiner (o A4 planta o backdoor num contêiner e tem
// de ser pego). É a DISTRIBUIÇÃO dos ctimes que separa build de backdating.
func coletarTimestomp(f *Facts, e *env.Env) {
	var cand []Timestomp
	for i := range f.Ownership {
		o := &f.Ownership[i]
		if o.Owned {
			continue
		}
		fi, err := e.Lstat(o.Path)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		mt, ct, ok := datasDe(fi)
		if !ok {
			continue
		}
		delta := int(ct.Sub(mt).Hours())
		if delta < minTimestompH {
			continue
		}
		t := Timestomp{
			Path:    o.Path,
			ModUTC:  mt.UTC().Format("2006-01-02T15:04:05Z"),
			MetaUTC: ct.UTC().Format("2006-01-02T15:04:05Z"),
			DeltaH:  delta,
		}
		cand = append(cand, t)
	}
	f.Timestomps = semClustersDeBuild(cand)
}

// semClustersDeBuild remove os candidatos cujo ctime é compartilhado por
// clusterBulk+ arquivos — o bloco de build/extração, não backdating. Puro, para
// ser testável sem tocar em ctime de arquivo de verdade.
func semClustersDeBuild(cand []Timestomp) []Timestomp {
	porCtime := map[string]int{}
	for _, t := range cand {
		porCtime[t.MetaUTC]++
	}
	var out []Timestomp
	for _, t := range cand {
		if porCtime[t.MetaUTC] >= clusterBulk {
			continue
		}
		out = append(out, t)
	}
	return out
}

// minTimestompH é a folga. Instalação, cópia e build produzem diferenças de
// minutos legitimamente; o que interessa é o arquivo que DIZ ser de meses atrás
// e cujos metadados foram tocados agora.
const minTimestompH = 48

// clusterBulk é quantos arquivos com o MESMO ctime já contam como operação em
// massa (build de imagem, tar -x, rsync) em vez de backdating. O A4 planta DOIS
// timestomps (ctime da hora do plant); o falso positivo de contêiner são doze
// (ctime da extração). Quatro separa os dois com folga dos dois lados.
//
// O limite: um atacante que timestompa 4+ arquivos NO MESMO SEGUNDO por script
// seria perdido — mas esse padrão É a forma do bloco, e o preço de não o perder
// é gritar em todo contêiner, que ensina o operador a ignorar o check.
const clusterBulk = 4

type hashRef struct {
	hash string
	algo string
	// conf marca arquivo de CONFIGURAÇÃO. Editar um deles é o trabalho normal
	// do administrador, e a divergência ali não tem o mesmo peso da de um
	// binário — mas continua importando quando o arquivo executa algo.
	conf bool
}

// hashesDpkg lê os .md5sums dos pacotes envolvidos. Formato: "hash  caminho",
// com o caminho SEM barra inicial.
func hashesDpkg(f *Facts, e *env.Env, porPacote map[string][]string) map[string]hashRef {
	out := map[string]hashRef{}
	for pkg, caminhos := range porPacote {
		// LISTA, e não valor único. É a TERCEIRA vez que este defeito aparece
		// nesta base — já corrigido nos dois lados da pergunta de propriedade e
		// deixado aqui.
		//
		// Sob usrmerge, /bin/sh e /usr/bin/sh são o mesmo arquivo e geram as
		// MESMAS chaves. Guardando um caminho só, a segunda inserção
		// sobrescreve a primeira e um dos dois fica sem hash — 274 arquivos num
		// host real, entre eles /bin/sh, /bin/kill e /bin/true, todos saindo
		// como "não pude comparar".
		quer := map[string][]string{} // forma no arquivo -> caminhos perguntados
		cache := map[string]string{}
		for _, c := range caminhos {
			for _, v := range formasResolvidas(e, c, cache) {
				k := strings.TrimPrefix(v, "/")
				quer[k] = append(quer[k], c)
			}
		}
		// O nome do arquivo de hash acompanha o do .list, inclusive o sufixo de
		// arquitetura (`coreutils:amd64.md5sums`).
		b, err := e.ReadFile("/var/lib/dpkg/info/" + pkg + ".md5sums")
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(strings.NewReader(string(b)))
		sc.Buffer(make([]byte, 0, 4096), 64*1024)
		for sc.Scan() {
			h, caminho, ok := strings.Cut(sc.Text(), "  ")
			if !ok {
				continue
			}
			for _, alvo := range quer[caminho] {
				out[alvo] = hashRef{hash: h, algo: "md5"}
			}
		}
		f.scannerFoiAteOFim(sc, "hash", "/var/lib/dpkg/info/"+pkg+".md5sums")
	}
	return out
}

// hashesApk lê a linha Z: que segue cada R:. O valor é `Q1` mais o SHA1 em
// base64 — não é hexadecimal, e comparar sem decodificar daria divergência em
// todo arquivo.
func hashesApk(f *Facts, e *env.Env, porPacote map[string][]string) map[string]hashRef {
	out := map[string]hashRef{}
	// Lista pelo mesmo motivo do backend do dpkg: duas grafias do mesmo arquivo
	// colidem sob usrmerge, e guardar um valor só perde uma delas.
	quer := map[string][]string{}
	cache := map[string]string{}
	for _, caminhos := range porPacote {
		for _, c := range caminhos {
			for _, v := range formasResolvidas(e, c, cache) {
				quer[v] = append(quer[v], c)
			}
		}
	}

	b, err := e.ReadFile("/lib/apk/db/installed")
	if err != nil {
		return out
	}
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	sc.Buffer(make([]byte, 0, 4096), 256*1024)
	dir, ultimo := "", ""
	for sc.Scan() {
		ln := sc.Text()
		if len(ln) < 2 || ln[1] != ':' {
			continue
		}
		switch ln[0] {
		case 'F':
			dir = "/" + ln[2:]
			ultimo = ""
		case 'R':
			ultimo = dir + "/" + ln[2:]
		case 'Z':
			alvos := quer[ultimo]
			if len(alvos) == 0 || !strings.HasPrefix(ln[2:], "Q1") {
				continue
			}
			bruto, err := base64.StdEncoding.DecodeString(ln[4:])
			if err != nil {
				continue
			}
			for _, alvo := range alvos {
				out[alvo] = hashRef{hash: hex.EncodeToString(bruto), algo: "sha1"}
			}
		}
	}
	f.scannerFoiAteOFim(sc, "hash", "/lib/apk/db/installed")
	return out
}

// hashesPacman lê o mtree do pacote, que é gzip. As linhas úteis têm
// `sha256digest=`, e o caminho vem com `./` na frente e com escapes de octal.
func hashesPacman(f *Facts, e *env.Env, porPacote map[string][]string) map[string]hashRef {
	out := map[string]hashRef{}
	for pkg, caminhos := range porPacote {
		// Lista, pelo mesmo motivo dos outros dois backends.
		quer := map[string][]string{}
		cache := map[string]string{}
		for _, c := range caminhos {
			for _, v := range formasResolvidas(e, c, cache) {
				k := strings.TrimPrefix(v, "/")
				quer[k] = append(quer[k], c)
			}
		}
		mtree := "/var/lib/pacman/local/" + pkg + "/mtree"
		b, err := e.ReadFile(mtree)
		if err != nil {
			continue
		}
		// bytes.NewReader e não strings.NewReader(string(b)): a conversão
		// copiaria o arquivo inteiro só para lê-lo, e são centenas deles.
		zr, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(zr)
		sc.Buffer(make([]byte, 0, 4096), 256*1024)
		for sc.Scan() {
			ln := sc.Text()
			if !strings.HasPrefix(ln, "./") {
				continue
			}
			campos := strings.Fields(ln)
			caminho := desescapaMtree(strings.TrimPrefix(campos[0], "./"))
			alvos := quer[caminho]
			if len(alvos) == 0 {
				continue
			}
			for _, c := range campos[1:] {
				if h, ok := strings.CutPrefix(c, "sha256digest="); ok {
					for _, alvo := range alvos {
						out[alvo] = hashRef{hash: h, algo: "sha256"}
					}
					break
				}
			}
		}
		f.scannerFoiAteOFim(sc, "hash", mtree)
		zr.Close()
	}
	return out
}

// desescapaMtree resolve os escapes octais do formato (`\040` para espaço).
// Sem isso, todo caminho com espaço no nome falharia a comparação em silêncio.
func desescapaMtree(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// hashDoArquivo calcula o hash em fluxo: nada é carregado inteiro na memória,
// porque alguns dos candidatos são binários grandes.
func hashDoArquivo(e *env.Env, p, algo string) (string, error) {
	fi, err := e.Lstat(p)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxHashBytes {
		return "", errGrandeDemais
	}
	var h hash.Hash
	switch algo {
	case "md5":
		h = md5.New()
	case "sha1":
		h = sha1.New()
	default:
		h = sha256.New()
	}
	// Em FLUXO: carregar o arquivo inteiro para depois copiá-lo num hash gasta
	// o dobro da memória e do trabalho, e alguns candidatos são binários de
	// centenas de megabytes.
	fh, err := e.Open(p)
	if err != nil {
		return "", err
	}
	defer fh.Close()
	if _, err := io.Copy(h, fh); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

type erroFixo string

func (e erroFixo) Error() string { return string(e) }

const errGrandeDemais = erroFixo("arquivo irregular ou grande demais para hashear")

// datasDe extrai mtime e ctime. O ctime não é exposto pela interface padrão do
// Go — só pela estrutura do sistema, e é justamente ele que o atacante não
// consegue escrever.
func datasDe(fi fs.FileInfo) (time.Time, time.Time, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return time.Time{}, time.Time{}, false
	}
	// A conversão explícita não é cosmética: em 32 bits os campos são int32, e
	// sem ela o binário i686 nem compila. É o mesmo eixo que os cenários 30 e
	// 54 cobrem — servidor legado de 32 bits ainda existe.
	return fi.ModTime(), time.Unix(int64(st.Ctim.Sec), int64(st.Ctim.Nsec)), true
}

// conffilesDpkg lê os hashes de configuração do status do dpkg.
//
// Formato, dentro do bloco de cada pacote:
//
//	Conffiles:
//	 /etc/adduser.conf cc3493ecd2d09837ffdcc3e25fdfff18
//
// A linha começa com espaço, e é isso que a separa dos outros campos.
func conffilesDpkg(f *Facts, e *env.Env, out map[string]hashRef, donos map[string]string) {
	b, err := e.ReadFile("/var/lib/dpkg/status")
	if err != nil {
		return
	}
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	sc.Buffer(make([]byte, 0, 4096), 256*1024)
	dentro := false
	for sc.Scan() {
		ln := sc.Text()
		if !strings.HasPrefix(ln, " ") {
			dentro = ln == "Conffiles:"
			continue
		}
		if !dentro {
			continue
		}
		campos := strings.Fields(ln)
		if len(campos) < 2 {
			continue
		}
		caminho := campos[0]
		if _, interessa := donos[caminho]; !interessa {
			continue
		}
		// Aqui não há colisão: o status lista o caminho exato, e /etc não tem
		// grafia alternativa sob usrmerge.
		// O terceiro campo, quando existe, marca o conffile como obsoleto — o
		// hash continua valendo para comparação.
		out[caminho] = hashRef{hash: campos[1], algo: "md5", conf: true}
	}
	f.scannerFoiAteOFim(sc, "hash", "/var/lib/dpkg/status")
}

// removerDesviados tira da comparação os caminhos que o dpkg desviou.
//
// O arquivo é texto puro, em blocos de três linhas: o caminho original, para
// onde foi movido, e o pacote que pediu o desvio. Depois de um desvio, o hash
// declarado pelo pacote ORIGINAL não descreve mais o que está no caminho — e
// isso é o funcionamento normal, não adulteração.
func removerDesviados(e *env.Env, esperados map[string]hashRef) map[string]bool {
	out := map[string]bool{}
	b, err := e.ReadFile("/var/lib/dpkg/diversions")
	if err != nil {
		return out
	}
	linhas := strings.Split(string(b), "\n")
	for i := 0; i+2 < len(linhas); i += 3 {
		p := strings.TrimSpace(linhas[i])
		if p == "" {
			continue
		}
		delete(esperados, p)
		out[p] = true
	}
	return out
}

// tamanhoDe é o tamanho do arquivo, ou zero quando ilegível. Serve ao orçamento
// de bytes: ordenar do menor para o maior faz caber mais arquivo antes do corte.
func tamanhoDe(e *env.Env, p string) int64 {
	fi, err := e.Lstat(p)
	if err != nil {
		return 0
	}
	return fi.Size()
}

// modulosRelevantes são os módulos CARREGADOS ou configurados para carregar.
//
// É o mesmo recorte que a ferramenta usa em todo lugar: o que está fazendo
// alguma coisa. Um .ko parado na árvore não roda até alguém carregá-lo, e a
// pergunta de propriedade sobre ele continua sendo feita de graça.
//
// Em modo image não há /proc/modules, então sobra o que está configurado — que
// é justamente o que se procura num rootfs desligado.
func modulosRelevantes(f *Facts) map[string]bool {
	nomes := map[string]bool{}
	for _, m := range f.Cross.ModProc {
		nomes[normalizaModulo(m)] = true
	}
	for i := range f.Modules {
		nomes[normalizaModulo(f.Modules[i].Module)] = true
	}
	if len(nomes) == 0 {
		return nil
	}

	out := map[string]bool{}
	for _, p := range f.ModuleFiles {
		base := p
		if i := strings.LastIndex(base, "/"); i >= 0 {
			base = base[i+1:]
		}
		// Tira a extensão e a compressão: `foo.ko`, `foo.ko.xz`, `foo.ko.zst`.
		if i := strings.Index(base, ".ko"); i > 0 {
			base = base[:i]
		}
		if nomes[normalizaModulo(base)] {
			out[p] = true
		}
	}
	return out
}
