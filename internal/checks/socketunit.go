package checks

import (
	"strings"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/facts"
)

func init() { check.Register(socketDeBackdoor) }

// socketDeBackdoor — runbook §7.2, §14.
//
// A ativação por socket é do systemd, é legítima, e é o esconderijo perfeito: o
// PID 1 escuta a porta, e o processo do invasor SÓ NASCE quando alguém conecta.
//
// Numa varredura, a porta pertence ao systemd e o implante não existe. Nenhum
// check de processo o vê, porque não há processo; o `net.listener_unowned` vê
// uma porta cujo dono é o PID 1, que é o mais legítimo dos donos.
//
// O que resta é o DISCO, e ali a forma é clara: uma unit `.socket` expondo uma
// porta, apontando para um serviço que executa um binário que nenhum pacote
// entregou. É o mesmo cruzamento do §14, feito sobre o que está parado.
//
// Vale igual para `.path`: a unit dispara na alteração de um arquivo, e o
// gatilho é o mesmo tipo de espera.
var socketDeBackdoor = check.Check{
	ID:       "persist.unit_socket_unowned",
	Ref:      "7.2",
	Title:    "unit de ativação expõe gatilho para binário que nenhum pacote entregou",
	Group:    "persist",
	Mode:     check.ModeAuto,
	Sources:  env.SourceLive | env.SourceImage,
	Requires: env.CapFilesystem,
	Wtf:      true,
	FalsePositives: []string{
		"ativação por socket é o desenho recomendado do systemd, e aplicação " +
			"própria instalada à mão a usa legitimamente — inclusive expondo " +
			"porta. O que dá sinal é o binário não vir de pacote, e isso é a " +
			"norma em software da casa",
		"a unit `.path` legítima existe em ferramenta de configuração e de " +
			"deploy, reagindo a arquivo que muda",
	},
	Run: func(self check.Check, f *facts.Facts, e *env.Env) check.Result {
		var r check.Result
		semDono := caminhosSemDono(f)
		if len(semDono) == 0 {
			r.Partial = append(r.Partial, f.PersistDenied["pkg"]...)
			return r
		}

		for i := range f.Units {
			u := &f.Units[i]
			if u.Kind != "socket" && u.Kind != "path" {
				continue
			}
			if !u.Efetiva() {
				continue // sombreada ou mascarada: não ativa
			}
			if len(u.Listen) == 0 && len(u.WatchPaths) == 0 {
				continue
			}
			alvo := servicoPareado(f, u.Name)
			if alvo == nil {
				continue
			}
			exe := primeiroCaminho(execDaUnit(alvo))
			if exe == "" || !semDono[exe] {
				continue
			}

			sev, nota := pesoDoCaminho(exe)
			ev := []string{
				u.Name + " → " + alvo.Name + " → " + exe,
				"o processo do implante SÓ NASCE quando o gatilho dispara: numa " +
					"varredura, quem escuta é o systemd e o binário não está em " +
					"execução",
				"exe=" + exe + " — nenhum pacote reivindica este binário (base: " +
					f.Pkg.Kind + ") · " + nota,
			}
			if len(u.Listen) > 0 {
				ev = append(ev, "escuta em "+strings.Join(u.Listen, ", "))
				for _, l := range u.Listen {
					// Endereço exposto muda o peso: a espera é por alguém DE FORA.
					if strings.HasPrefix(l, "0.0.0.0") || strings.HasPrefix(l, "[::]") ||
						strings.HasPrefix(l, "*:") {
						sev = check.SevCritical
						ev = append(ev, "e o endereço é exposto para fora: a espera é "+
							"por uma conexão de fora do host")
						break
					}
				}
			}
			if len(u.WatchPaths) > 0 {
				ev = append(ev, "dispara na alteração de "+strings.Join(u.WatchPaths, ", "))
			}

			fd := self.F(sev, u.Name, "", ev...)
			fd.Irreversible = true
			fd.NextSteps = []string{
				"sudo cp " + check.Arg(exe) + " \"$IR/\"   # a amostra, antes de qualquer coisa",
				"desabilite o SOCKET antes do serviço: parar só o serviço deixa o " +
					"gatilho armado, e a próxima conexão o traz de volta",
				"a porta não aparece como dele em nenhuma varredura: procure o " +
					"gatilho, não o processo",
			}
			r.Findings = append(r.Findings, fd)
		}
		r.Partial = append(r.Partial, f.PersistDenied["pkg"]...)
		return r
	},
}

// servicoPareado acha o serviço que a unit de ativação dispara. O systemd
// pareia por NOME: `x.socket` ativa `x.service`, e com `Accept=yes` ativa
// `x@.service`, uma instância por conexão.
func servicoPareado(f *facts.Facts, nome string) *facts.Unit {
	base := strings.TrimSuffix(strings.TrimSuffix(nome, ".socket"), ".path")
	for _, cand := range []string{base + ".service", base + "@.service"} {
		for i := range f.Units {
			if f.Units[i].Name == cand {
				return &f.Units[i]
			}
		}
	}
	return nil
}

func execDaUnit(u *facts.Unit) string {
	for _, ex := range u.Exec {
		if strings.EqualFold(ex.Key, "ExecStart") {
			return ex.Cmd
		}
	}
	if len(u.Exec) > 0 {
		return u.Exec[0].Cmd
	}
	return ""
}
