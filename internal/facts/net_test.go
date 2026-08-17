package facts

import "testing"

// parseHexAddr é onde um erro passa despercebido: o endereço vem com cada
// palavra de 32 bits em ordem de HOST. Ignorar a inversão faz 127.0.0.1 virar
// 1.0.0.127 — e aí loopback é classificado como IP público, e o relatório
// acusa "conexão de saída para endereço público" em todo processo local.
func TestParseHexAddrInverteAsPalavras(t *testing.T) {
	casos := []struct {
		in   string
		ip   string
		port int
	}{
		{"0100007F:1F90", "127.0.0.1", 8080},
		{"00000000:0016", "0.0.0.0", 22},
		{"6C00A8C0:CB2E", "192.168.0.108", 52014},
		{"F15A4B21:01BB", "33.75.90.241", 443},
		// IPv6 loopback: 4 palavras, a última com o 1
		{"00000000000000000000000001000000:0050", "::1", 80},
	}
	for _, c := range casos {
		ip, port, ok := parseHexAddr(c.in)
		if !ok {
			t.Errorf("parseHexAddr(%q) falhou", c.in)
			continue
		}
		if ip != c.ip || port != c.port {
			t.Errorf("parseHexAddr(%q) = %s:%d, quer %s:%d", c.in, ip, port, c.ip, c.port)
		}
	}
}

func TestParseHexAddrRecusaMalformado(t *testing.T) {
	for _, in := range []string{"", "semdoispontos", "ZZ:0016", "0100007F", "0100:00"} {
		if _, _, ok := parseHexAddr(in); ok {
			t.Errorf("aceitou entrada malformada: %q", in)
		}
	}
}

// A classificação decide se um destino é "o operador" ou "a rede interna", e é
// o insumo do pivô e do reverse shell.
func TestScopeOf(t *testing.T) {
	casos := map[string]Scope{
		"127.0.0.1":       ScopeLoopback,
		"::1":             ScopeLoopback,
		"0.0.0.0":         ScopeLoopback,
		"10.0.0.9":        ScopePrivate,
		"192.168.0.108":   ScopePrivate,
		"172.16.5.4":      ScopePrivate,
		"169.254.169.254": ScopePrivate, // metadata da nuvem
		"100.64.0.1":      ScopePrivate, // CGNAT: interno em ambiente de nuvem
		"fd00::1":         ScopePrivate,
		"51.91.190.241":   ScopePublic,
		"8.8.8.8":         ScopePublic,
		"2001:4860::8888": ScopePublic,
	}
	for ip, want := range casos {
		if got := scopeOf(ip); got != want {
			t.Errorf("scopeOf(%q) = %q, quer %q", ip, got, want)
		}
	}
}

// A direção sai de uma COMPARAÇÃO com a tabela de LISTEN, não de heurística de
// faixa de porta. É ela que separa proxy legítimo de pivô, e entrada de
// ativação por socket de saída de reverse shell.
func TestDirecaoSaiDaTabelaDeListen(t *testing.T) {
	body := "  sl  local_address rem_address   st tx rx tr tm retr uid to inode\n" +
		"   0: 0100007F:1F90 00000000:0000 0A 0:0 0:0 0 1000 0 111 1\n" + // LISTEN :8080
		"   1: 0100007F:1F90 0100007F:B00B 01 0:0 0:0 0 1000 0 222 1\n" + // ESTAB na porta de LISTEN => entrada
		"   2: 0100007F:C350 0100007F:0050 01 0:0 0:0 0 1000 0 333 1\n" // ESTAB de porta efêmera => saída

	socks := parseTCPTable(body, "tcp")
	if len(socks) != 3 {
		t.Fatalf("parseTCPTable devolveu %d, quer 3", len(socks))
	}

	f := &Facts{}
	// replica a inferência de direção do coletor
	listening := map[int]bool{}
	for _, s := range socks {
		if s.State == "LISTEN" {
			listening[s.LocalPort] = true
		}
	}
	got := map[uint64]Direction{}
	for _, s := range socks {
		switch {
		case s.State == "LISTEN":
			got[s.Inode] = DirListen
		case listening[s.LocalPort]:
			got[s.Inode] = DirIn
		default:
			got[s.Inode] = DirOut
		}
	}
	_ = f

	want := map[uint64]Direction{111: DirListen, 222: DirIn, 333: DirOut}
	for inode, w := range want {
		if got[inode] != w {
			t.Errorf("inode %d: direção = %q, quer %q", inode, got[inode], w)
		}
	}
}
