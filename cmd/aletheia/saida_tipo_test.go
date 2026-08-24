package main

import (
	"os"
	"testing"
)

// O destino do --out e do --json é aceito por TIPO, e o tipo do device decide.
//
// O ramo permissivo existe de propósito: /dev/stdout e /dev/console são uso
// automatizado legítimo. Mas ele confiava no os.Stat, que SEGUE symlink — então
// um `dump.json -> /dev/sda` plantado no diretório de incidente chegava
// classificado como "device, pode" e o collect gravava o dump por cima da
// tabela de partição do host investigado, com fsync e close bem-sucedidos,
// .sha256 escrito ao lado e exit 0.
//
// Esta trava mora aqui, e não num teste de ponta a ponta, porque provar o ramo
// com um /dev/sda gravável exigiria root — e trava que só roda como root não
// roda.
func TestTipoDeSaidaRecusaDeviceDeBlocoEAceitaOsLegitimos(t *testing.T) {
	casos := []struct {
		nome   string
		modo   os.FileMode
		recusa bool
		porque string
	}{
		{"device de bloco (/dev/sda)", os.ModeDevice, true,
			"escrever ali destrói o disco do host investigado"},
		{"arquivo comum", 0, true,
			"trocado entre a conferência e a abertura — nunca sobrescrever"},
		{"char device (/dev/mem, /dev/port, /dev/watchdog)", os.ModeDevice | os.ModeCharDevice, true,
			"/dev/mem escreve memória física e /dev/watchdog ARMA no open — a " +
				"premissa de que char device é inofensivo é falsa"},
		{"socket", os.ModeSocket, true, "não é destino de arquivo"},
		{"fifo (pipe nomeado)", os.ModeNamedPipe, false,
			"escrever num pipe não destrói nada, e o O_NONBLOCK já resolve o " +
				"caso sem leitor"},
	}
	for _, c := range casos {
		t.Run(c.nome, func(t *testing.T) {
			got := tipoDeSaidaRecusado(c.modo)
			if c.recusa && got == "" {
				t.Errorf("ACEITOU %s — %s", c.nome, c.porque)
			}
			if !c.recusa && got != "" {
				t.Errorf("recusou %s (%s), e ele é %s", c.nome, got, c.porque)
			}
		})
	}
}
