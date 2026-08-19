package facts

import (
	"sort"
	"strings"
)

// Dono de arquivo sem conta (runbook §7.9).
//
// O kernel guarda no inode um NÚMERO, não um nome. `/etc/passwd` é só a tabela
// que traduz — e as duas coisas podem discordar. Um arquivo cujo uid não está
// na tabela é um arquivo que pertence a ninguém: `ls -l` mostra o número cru no
// lugar do nome, e é o único aviso que o sistema dá.
//
// Duas formas fazem isso acontecer, e a diferença entre elas é o incidente:
//
//   - a conta foi APAGADA depois de criar os arquivos. Se o atacante criou uma
//     conta, trabalhou, e removeu a conta na faxina, os arquivos ficam — e o
//     uid órfão é o recibo de uma conta que existiu e foi escondida. `userdel`
//     não varre o disco.
//   - os arquivos vieram de OUTRO sistema, com outra tabela: tarball extraído
//     preservando dono, volume de contêiner, árvore de chroot.
//
// Nenhuma das duas é decidível daqui, e por isso este coletor só CONTA. Quem
// separa uma da outra é a forma: quantos arquivos, se são executáveis, e se
// estão numa árvore de sistema.
//
// Medido no host que originou isto: 571 mil arquivos varridos, UM uid órfão —
// o volume de dados de um contêiner de redis bind-montado num projeto, zero
// executáveis. A classe é de ruído baixo, e é isso que a torna útil.

// maxExemplosDono limita os caminhos guardados por dono. Três bastam para o
// operador reconhecer a árvore; o resto ele acha com um `find`, e a linha de
// comando para isso vai no achado.
const maxExemplosDono = 3

// maxDonosDistintos é o teto de identidades distintas acompanhadas. Num host
// normal são poucas unidades; num servidor compartilhado com milhares de contas
// a varredura de /home traria uma por usuário, e guardar todas trocaria um
// achado por consumo de memória. Estourar vira lacuna DECLARADA.
const maxDonosDistintos = 1024

// arvoresDeSistema são os caminhos onde binário ENTREGUE PELA DISTRIBUIÇÃO
// mora. Um dono sem conta aqui dentro pesa mais que o mesmo dono em /home ou
// /tmp, porque estas árvores têm um proprietário esperado — o gerenciador de
// pacotes, rodando como root.
//
// É observação, não veredito: o coletor conta quantos caíram aqui e o check
// decide o que isso significa.
var arvoresDeSistema = []string{
	"/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/etc/", "/opt/", "/boot/",
}

// DonoDeArquivo resume tudo que a varredura viu de UMA identidade numérica.
//
// Guarda o resumo e não a lista: a lista de 400 mil caminhos de um /home seria
// o relatório inteiro, e não acrescenta nada ao que a contagem já diz.
type DonoDeArquivo struct {
	ID int `json:"id"`
	// Grupo separa as duas tabelas: uid vem do passwd, gid vem do group, e uma
	// pode ter nome enquanto a outra não. No host medido, o uid 999 era órfão e
	// o gid 999 se chamava `adm`.
	Grupo bool `json:"group,omitempty"`

	Arquivos    int `json:"files"`
	Executaveis int `json:"exec,omitempty"`
	EmSistema   int `json:"in_system,omitempty"`

	// Exemplos guarda caminhos quaisquer; os dois campos seguintes guardam o
	// primeiro caso de cada forma que decide gravidade. Separados porque o
	// executável e a árvore de sistema são o que o operador precisa ver
	// PRIMEIRO, e num dono com 400 mil arquivos eles não cairiam na amostra.
	Exemplos       []string `json:"examples,omitempty"`
	ExemploExec    string   `json:"example_exec,omitempty"`
	ExemploSistema string   `json:"example_system,omitempty"`
}

// ehArvoreDeSistema responde se o caminho está numa árvore de distribuição.
func ehArvoreDeSistema(p string) bool {
	for _, d := range arvoresDeSistema {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}

// contar soma UM arquivo a este dono.
func (d *DonoDeArquivo) contar(exec, sistema bool, p string) {
	d.Arquivos++
	if exec {
		d.Executaveis++
		if d.ExemploExec == "" {
			d.ExemploExec = p
		}
	}
	if sistema {
		d.EmSistema++
		if d.ExemploSistema == "" {
			d.ExemploSistema = p
		}
	}
	if len(d.Exemplos) < maxExemplosDono {
		d.Exemplos = append(d.Exemplos, p)
	}
}

// somar funde outro resumo do MESMO dono neste.
func (d *DonoDeArquivo) somar(o DonoDeArquivo) {
	d.Arquivos += o.Arquivos
	d.Executaveis += o.Executaveis
	d.EmSistema += o.EmSistema
	if d.ExemploExec == "" {
		d.ExemploExec = o.ExemploExec
	}
	if d.ExemploSistema == "" {
		d.ExemploSistema = o.ExemploSistema
	}
	for _, p := range o.Exemplos {
		if len(d.Exemplos) >= maxExemplosDono {
			break
		}
		d.Exemplos = append(d.Exemplos, p)
	}
}

// resumoDeDonos acumula os donos de UM diretório, antes do merge global.
//
// É slice com busca linear e não mapa, e a razão é a forma do dado: um
// diretório tem um ou dois donos distintos. Hashear 571 mil vezes para acertar
// na primeira posição custaria mais que a varredura.
type resumoDeDonos struct {
	itens []DonoDeArquivo
}

func (r *resumoDeDonos) ver(grupo bool, id int, exec, sistema bool, p string) {
	for i := range r.itens {
		if r.itens[i].ID == id && r.itens[i].Grupo == grupo {
			r.itens[i].contar(exec, sistema, p)
			return
		}
	}
	d := DonoDeArquivo{ID: id, Grupo: grupo}
	d.contar(exec, sistema, p)
	r.itens = append(r.itens, d)
}

// chaveDono identifica um dono nas duas tabelas.
type chaveDono struct {
	grupo bool
	id    int
}

// acumuladorDeDonos junta os resumos por diretório num só, sob o lock que a
// varredura já toma uma vez por diretório.
type acumuladorDeDonos struct {
	m        map[chaveDono]*DonoDeArquivo
	estourou bool
}

func novoAcumuladorDeDonos() *acumuladorDeDonos {
	return &acumuladorDeDonos{m: make(map[chaveDono]*DonoDeArquivo, 16)}
}

func (a *acumuladorDeDonos) juntar(itens []DonoDeArquivo) {
	for _, it := range itens {
		k := chaveDono{it.Grupo, it.ID}
		if d, ok := a.m[k]; ok {
			d.somar(it)
			continue
		}
		if len(a.m) >= maxDonosDistintos {
			a.estourou = true
			continue
		}
		cp := it
		a.m[k] = &cp
	}
}

// consolidarDonos devolve a lista ordenada, para a saída ser estável entre
// execuções — mapa em Go não tem ordem, e um relatório que muda de ordem sem o
// host mudar não serve para comparar duas coletas.
func consolidarDonos(a *acumuladorDeDonos) []DonoDeArquivo {
	if a == nil || len(a.m) == 0 {
		return nil
	}
	out := make([]DonoDeArquivo, 0, len(a.m))
	for _, d := range a.m {
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Grupo != out[j].Grupo {
			return !out[i].Grupo
		}
		return out[i].ID < out[j].ID
	})
	return out
}
