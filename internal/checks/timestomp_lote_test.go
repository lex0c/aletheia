package checks

import (
	"strings"
	"testing"

	"github.com/lex0c/aletheia/internal/check"
	"github.com/lex0c/aletheia/internal/facts"
)

// A EVASÃO MAIS BARATA DO CATÁLOGO, e ela existia por causa do conserto de um
// falso positivo.
//
// O FP era real: numa debian:12 saudável este check gritava doze CRITICAL sobre
// /etc/apt/apt.conf.d/docker-*, porque a camada da imagem carimba o mesmo ctime
// em tudo. A resposta foi descartar o candidato quando quatro ou mais
// compartilhavam o ctime — e o ctime é truncado a SEGUNDOS. Custo do atacante
// para apagar a evidência: `touch -d` em quatro arquivos, um comando.
//
// Agora o lote REBAIXA. O achado continua existindo, com a severidade dizendo o
// que se sabe, e nada some em silêncio.
func TestTimestompEmLoteRebaixaEmVezDeSumir(t *testing.T) {
	// Quatro alvos de persistência com o MESMO ctime: a forma da extração em
	// massa, e também a do atacante que aprendeu a regra.
	var ts []facts.Timestomp
	var trig []facts.Trigger
	for _, p := range []string{"/etc/rc.local", "/etc/a.sh", "/etc/b.sh", "/etc/c.sh"} {
		ts = append(ts, facts.Timestomp{
			Path: p, ModUTC: "2020-01-01T00:00:00Z",
			MetaUTC: "2026-01-01T00:00:00Z", DeltaH: 52000, Cluster: 4,
		})
		trig = append(trig, facts.Trigger{File: p, Kind: "rc", When: "boot", Exec: true})
	}
	f := &facts.Facts{Timestomps: ts, Triggers: trig}

	r := dataFalsificada.Run(dataFalsificada, f, testEnv())
	if len(r.Findings) != 1 {
		t.Fatalf("o lote vira UMA linha de contexto — nem quatro achados (parede), "+
			"nem zero (era assim que quatro `touch -d` no mesmo segundo limpavam o "+
			"rastro). Achados: %d", len(r.Findings))
	}
	fd := r.Findings[0]
	if fd.Sev != check.SevInfo {
		t.Errorf("sev=%v, queria INFO — sem corroboração forte, lote é contexto", fd.Sev)
	}
	ev := strings.Join(fd.Evidence, " ")
	if !strings.Contains(ev, "extração em massa") || !strings.Contains(ev, "4 arquivo") {
		t.Errorf("a linha precisa dizer QUANTOS e POR QUÊ: %s", ev)
	}
}

// E a corroboração forte VENCE o lote: build de imagem não deixa processo
// rodando nem põe bit setuid em arquivo de configuração. Sem esta metade, o
// atacante recuperaria a evasão só acrescentando vizinhos ao cluster.
func TestTimestompComCorroboracaoForteIgnoraOLote(t *testing.T) {
	f := &facts.Facts{
		Timestomps: []facts.Timestomp{{
			Path: "/usr/local/sbin/implante", ModUTC: "2020-01-01T00:00:00Z",
			MetaUTC: "2026-01-01T00:00:00Z", DeltaH: 52000, Cluster: 40,
		}},
		Suid: []facts.SuidFile{{Path: "/usr/local/sbin/implante"}},
	}
	r := dataFalsificada.Run(dataFalsificada, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("SETUID vence o lote: %+v", r.Findings)
	}
}

// Cluster pequeno (o A4 planta dois) não é lote e não rebaixa nada.
func TestTimestompClusterPequenoContinuaCritico(t *testing.T) {
	f := &facts.Facts{
		Timestomps: []facts.Timestomp{{
			Path: "/etc/rc.local", ModUTC: "2020-01-01T00:00:00Z",
			MetaUTC: "2026-01-01T00:00:00Z", DeltaH: 52000, Cluster: 2,
		}},
		Triggers: []facts.Trigger{{File: "/etc/rc.local", Kind: "rc", When: "boot", Exec: true}},
	}
	r := dataFalsificada.Run(dataFalsificada, f, testEnv())
	if len(r.Findings) != 1 || r.Findings[0].Sev != check.SevCritical {
		t.Fatalf("cluster de 2 não é extração em massa: %+v", r.Findings)
	}
}
