//go:build !race

package mcp

import "testing"

// pularSobCorrida não faz nada fora do -race: as capturas vivas rodam.
func pularSobCorrida(t *testing.T) { t.Helper() }
