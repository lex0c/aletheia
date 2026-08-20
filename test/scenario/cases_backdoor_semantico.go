//go:build scenarios

package scenario

// Backdoor SEMÂNTICO — a lacuna da peneira léxica (app.code_backdoor).
//
// A peneira de webshell pega ENTRADA DE REQUEST caindo num SINK: crase, eval,
// system, include. É o que os B1–B6 provam. Mas um backdoor não precisa de
// sink: uma credencial mágica ou um header secreto que concede acesso é
// semanticamente maligno e lexicamente INERTE — nenhuma operação perigosa,
// nenhuma entrada de request num sink. O scanner não prova INTENÇÃO, e não tem
// como: distinguir `if ($u=="suporte" && $p=="...")` de uma checagem legítima
// exige o que o código DEVERIA ser (git diff, fonte assinada, revisão), não o
// que ele É.
//
// É LACUNA CONHECIDA, não falha do cenário: reproduzo o backdoor e SEI que a
// peneira cala. Diferente dos negativos dos B1–B6 (limpo.php é código benigno
// corretamente ignorado); aqui o arquivo é um VERDADEIRO POSITIVO que a
// ferramenta perde. Fechar exige proveniência (comparar com a fonte de
// confiança), que o scanner de conteúdo não tem.

func init() {
	Register(Scenario{
		ID:   "B7-backdoor-semantico-sem-sink",
		Desc: "credencial mágica e header secreto concedem acesso: backdoor sem sink, invisível à peneira léxica",
		// alpine (minimal): a peneira lê o CONTEÚDO do arquivo, não precisa de
		// PHP instalado — e o alpine não tem o timestomp de fábrica do debian,
		// que sujaria a afirmação de silêncio sobre estes arquivos.
		Images: minimal,
		Plant: "mkdir -p /var/www/app\n" +
			// Backdoor 1: credencial mágica hardcoded. Sem sink — só comparação
			// de string. É a porta dos fundos clássica de um "login legítimo".
			"printf '<?php\\nfunction autentica($u, $p) {\\n" +
			"  if ($u == \"suporte\" && $p == \"R3cuperar!2024\") return true;\\n" +
			"  return checa_no_banco($u, $p);\\n}\\n' > /var/www/app/auth.php\n" +
			// Backdoor 2: header secreto que eleva privilégio. Entrada de request
			// SIM ($_SERVER), mas num == e numa atribuição — não num sink.
			"printf '<?php\\nif (isset($_SERVER[\"HTTP_X_OPS_TOKEN\"]) && " +
			"$_SERVER[\"HTTP_X_OPS_TOKEN\"] == \"7c9e6679f7425f3d\") {\\n" +
			"  $_SESSION[\"role\"] = \"admin\";\\n}\\n' > /var/www/app/health.php\n",
		KnownGap: "backdoor semântico (credencial mágica / header secreto) não tem sink " +
			"perigoso: a peneira léxica não prova intenção e não o vê. Fechar exige " +
			"proveniência do código (git diff, fonte assinada), que o scanner não tem.",
		// A AFIRMAÇÃO da ausência: a peneira NÃO pode disparar sobre nenhum dos
		// dois arquivos. Se disparar, a lacuna fechou — promova para Expect.
		ForbidFinding: []Expect{
			{ID: "app.code_backdoor", Subject: "/var/www/app/auth.php"},
			{ID: "app.code_backdoor", Subject: "/var/www/app/health.php"},
		},
		// Orçamento de ruído MEDIDO na verificação: 0 avisos, 0 críticos — a
		// peneira leu os dois arquivos (o app.code_backdoor cobre /var/www, ver
		// B1) e calou. O exit é 1 por INCOMPLETE, não por achado: o alpine
		// mínimo não tem systemd/dpkg, então 4 checks declaram cobertura parcial
		// (100/104) — honestidade de "não olhei", sem relação com o backdoor.
		MaxWarn: SemAvisos,
		Exit:    1,
	})
}
