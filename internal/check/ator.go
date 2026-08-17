package check

import (
	"strconv"
	"strings"

	"github.com/lex0c/aletheia/internal/facts"
)

// Ator: quem está por trás de achados que apontam para coisas diferentes.
//
// A correlação agrupa por SUJEITO, e é isso que ela conseguia ver. Contra um
// invasor competente o resultado era este — quatro avisos, quatro sujeitos:
//
//	binário que nenhum pacote reivindica    /usr/local/sbin/systemd-netlinkd
//	conexão para endereço público           pid=17
//	drop-in acrescenta execução             sshd.service
//
// Os três são o MESMO binário: o caminho, o processo dele, e a unit que o
// executa. A ferramenta tinha os três dados para ligar isso e não ligava,
// porque os sujeitos são de tipos diferentes. O operador juntava na cabeça — e
// juntar na cabeça é exatamente o que uma lista de fatos já permitia. O que
// esta ferramenta promete é a história.
//
// A resolução é mecânica e sem julgamento novo:
//
//	pid=N        vira o exe daquele processo
//	unit.service vira o binário que o ExecStart dela chama
//	/caminho     é ele mesmo
//
// # A guarda contra fundir demais
//
// Resolver sozinho fundiria coisas que não são um ator. Metade dos processos de
// um host é /usr/bin/python3, e agrupar por binário jogaria todos num bloco só,
// afirmando parentesco onde há coincidência de interpretador.
//
// Por isso o ator resolvido só é ADOTADO quando algum outro achado já nomeia
// aquele caminho como sujeito próprio. A correlação passa a se formar somente
// em torno de um binário que a ferramenta já acusou por conta própria — nenhuma
// premissa nova, nenhum caminho que ela não tenha olhado. Se o binário é comum
// e ninguém o acusou, nada funde e a saída é a de sempre.
func resolverAtores(r *Report, f *facts.Facts) {
	if f == nil {
		return
	}

	// Os caminhos que algum achado nomeia diretamente. É a única coisa que
	// autoriza a fusão.
	acusados := map[string]bool{}
	for i := range r.Findings {
		if s := r.Findings[i].Subject; strings.HasPrefix(s, "/") && r.Findings[i].Sev != SevInfo {
			acusados[s] = true
		}
	}
	if len(acusados) == 0 {
		return
	}

	for i := range r.Findings {
		fd := &r.Findings[i]
		if fd.Subject == "" || fd.Sev == SevInfo {
			continue
		}
		for _, alvo := range binariosDoSujeito(fd.Subject, f) {
			// Sujeito que já É o caminho não ganha ator: ele seria o próprio, e
			// marcar isso só encheria o JSONL.
			if alvo == fd.Subject || !acusados[alvo] {
				continue
			}
			fd.Ator = alvo
			break
		}
	}
}

// binariosDoSujeito devolve TODOS os binários que podem estar por trás de um
// sujeito, e o chamador fica com o primeiro que algum achado acusa.
//
// Devolver só um estava errado, e o erro era do tipo que passa em contêiner e
// falha em servidor. Uma unit alvo de drop-in tem mais de um executável:
//
//	ExecStart=/usr/sbin/sshd -D                    da unit do pacote
//	ExecStartPre=/usr/local/sbin/systemd-netlinkd  do drop-in do invasor
//
// A primeira versão pegava o primeiro que encontrasse. No contêiner do cenário
// 71 não existe sshd.service de verdade, então o único candidato era o implante
// e o teste passava. Num host onde o sshd está instalado, a unit do pacote vem
// antes, o candidato virava /usr/sbin/sshd — que nenhum achado acusa — e a
// fusão simplesmente não acontecia. Sem erro, sem aviso: o drop-in voltava a
// ser um aviso solto exatamente no ambiente que a ferramenta existe para varrer.
//
// Com a lista, quem decide é a acusação: entre os executáveis de uma unit, o
// que interessa é o que a ferramenta já apontou por outro caminho.
func binariosDoSujeito(subj string, f *facts.Facts) []string {
	switch {
	case strings.HasPrefix(subj, "pid="):
		n, err := strconv.Atoi(strings.TrimPrefix(subj, "pid="))
		if err != nil {
			return nil
		}
		p := f.ProcessByPID(n)
		if p == nil || p.Exe == "" {
			return nil
		}
		// Exe apagado sai do /proc como "/caminho (deleted)", e o sufixo é
		// informação — mas não é um caminho que outro achado nomeie.
		return []string{strings.TrimSuffix(p.Exe, " (deleted)")}

	case ehNomeDeUnit(subj):
		var out []string
		// Os drop-ins primeiro: quando os dois lados estão acusados, o que
		// alguém ACRESCENTOU à unit é o que interessa, não o que já estava lá.
		for _, dropIn := range []bool{true, false} {
			for i := range f.Units {
				u := &f.Units[i]
				if (u.DropInFor == subj) != dropIn {
					continue
				}
				if !dropIn && u.Name != subj {
					continue
				}
				for _, ex := range u.Exec {
					if b := primeiroBinario(ex.Cmd); b != "" {
						out = append(out, b)
					}
				}
			}
		}
		return out
	}
	return nil
}

func ehNomeDeUnit(s string) bool {
	for _, suf := range []string{".service", ".timer", ".socket", ".path", ".mount"} {
		if strings.HasSuffix(s, suf) {
			return true
		}
	}
	return false
}

// primeiroBinario extrai o executável de uma linha de ExecStart.
//
// O systemd aceita prefixos de modificador antes do caminho (`-` ignora falha,
// `@` troca o argv[0], `+` e `!` mexem em privilégio), e eles grudam no
// executável sem espaço. Não tirá-los devolveria "-/usr/bin/foo", que não casa
// com caminho nenhum e desligaria a fusão em silêncio.
func primeiroBinario(cmd string) string {
	campos := strings.Fields(cmd)
	if len(campos) == 0 {
		return ""
	}
	tok := strings.TrimLeft(campos[0], "-@+!:")
	if !strings.HasPrefix(tok, "/") {
		return ""
	}
	return tok
}
