package scenario

// Um servidor de aplicação PHP de verdade, e o que ele faz com esta ferramenta.
//
// O caso veio de uma saída de `ss -tunap` de produção: 524 processos, 1053
// sockets, e a topologia mais banal que existe num servidor web —
//
//	php-fpm  →  192.0.2.5:443    uma API externa (público)
//	php-fpm  →  10.142.0.55:27017   o MongoDB da casa (privado)
//
// 497 dos 524 processos tinham as DUAS pontas abertas ao mesmo tempo. E "saída
// externa e saída interna no mesmo processo" é, letra por letra, a assinatura de
// pivô da §12.2.
//
// Rodado contra aquele retrato, o `net.pivot` produziu 497 avisos. Nenhum deles
// é ataque: é um pool de php-fpm fazendo o trabalho dele. Um relatório com 497
// linhas iguais não é um relatório — é uma parede, e o operador aprende a
// ignorar a saída inteira, junto com o achado que importaria.
//
// Este cenário é a versão executável daquele host, e existe para que o número
// nunca mais volte a crescer com a quantidade de workers.

// poolPHP monta o pool: um "servidor externo", um "banco interno" e N workers
// com uma conexão para cada — a forma exata do host que originou o caso.
//
// Os endereços são apelidos em `lo` dentro de um guest sem placa de rede: o
// 192.0.2.5 é público para quem classifica, e nenhum pacote sai da máquina.
const poolPHP = `
	ip addr add 192.0.2.5/32 dev lo
	ip addr add 10.142.0.55/32 dev lo
	/helper listen 192.0.2.5:443 &
	/helper listen 10.142.0.55:27017 &
	sleep 0.5
	i=0
	while [ $i -lt 30 ]; do
		/helper argv0 "php-fpm: pool www" /helper connect 192.0.2.5:443 10.142.0.55:27017 &
		i=$((i + 1))
	done
	sleep 1.5
`

func init() {
	Register(Scenario{
		ID:   "Q1-pool-php-fpm-nao-vira-parede",
		Desc: "trinta workers de php-fpm com uma conexão externa e uma interna cada: a forma de pivô, multiplicada pelo tamanho do pool",
		Mode: VM,
		// VM e não contêiner porque o que se mede aqui é ESCALA: trinta
		// processos com duas conexões cada, vistos pelo coletor de verdade,
		// através do /proc de verdade.
		Setup: poolPHP,
		Expect: []Expect{
			// O pivô continua sendo dito — o que muda é quantas vezes.
			{ID: "net.pivot", Sev: "WARN"},
			{ID: "net.pivot", Evidence: "192.0.2.5:443"},
			{ID: "net.pivot", Evidence: "10.142.0.55:27017"},
		},
		// O TETO É O CENÁRIO. Trinta workers idênticos não podem virar trinta
		// avisos: o relatório precisa caber na tela e na cabeça de quem lê.
		//
		// O número medido antes desta unidade era 30 — um por worker. Contra o
		// retrato de produção que originou o caso, 497.
		MaxWarn: 2,
		// Exit 2 vem do RIG, não do pool: para os workers conectarem em :443 e
		// em :27017 alguém precisa escutar ali, e quem escuta é o `/helper` —
		// um binário que pacote nenhum reivindica ocupando a porta de um
		// serviço conhecido. É exatamente o que o `net.listener_unowned` existe
		// para dizer, e ele está certo em dizer.
		Exit:           2,
		MustBeComplete: true,
	})
}
