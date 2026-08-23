// A sonda de capability: ela mede o que o KERNEL concede e o que o CÓDIGO
// decide, lado a lado, no mesmo processo.
//
// Existe porque a decisão de env.CapRoot deixou de ser "euid é zero" e passou a
// ser "este processo alcança as superfícies privilegiadas". Aquela é uma
// afirmação sobre o kernel, e afirmação sobre kernel se prova contra kernel —
// não contra a página de manual, e não contra um conjunto de bits injetado em
// teste unitário.
//
// A saída é `chave=valor`, para o script de prova afirmar sobre ela.
package main

import (
	"fmt"
	"os"

	"github.com/lex0c/aletheia/internal/env"
	"github.com/lex0c/aletheia/internal/mcp"
)

func main() {
	eff, lidas := env.CapsEfetivasDoProcesso()
	e := env.Probe(env.Options{Version: "sonda"})
	defer e.Close()
	p := mcp.LerPrivilegio()
	exige, _ := mcp.ExigeConsentimento(p, mcp.ModoLive)

	// A VERDADE DE CAMPO. Tudo o mais nesta saída é o que o código acha; esta
	// linha é o que o kernel faz. Se as duas discordarem, quem está errado é o
	// código.
	_, errShadow := os.ReadFile("/etc/shadow")

	fmt.Printf("uid=%d euid=%d capeff=%016x capslidas=%v caproot=%v consentimento=%v elevado=%v shadow=%v\n",
		os.Getuid(), os.Geteuid(), eff, lidas,
		e.Has(env.CapRoot), exige, p.Elevado, errShadow == nil)
}
