VERSION ?= 0.1.0-dev

# IDENTIDADE DA BUILD, e ela sai do GIT — nunca do relógio de quem compila.
#
# A data é a do COMMIT (%cI, ISO 8601), e não a do build, porque o binário desta
# ferramenta precisa ser RECONSTRUÍVEL: o toolchain é fixado no go.mod para que
# dois builds da mesma tag saiam idênticos, e um timestamp de build daria hashes
# diferentes para o mesmo código — a conferência que o README documenta passaria
# a falhar sempre, e quem baixa perderia a única forma de verificar o release sem
# confiar em quem o assinou.
#
# Fora de um repositório git as duas ficam VAZIAS, e o `version` omite as linhas
# em vez de imprimir "desconhecido": ausência já é a resposta (build local).
COMMIT     ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null)
COMMIT_AT  ?= $(shell TZ=UTC0 git show -s --date=format-local:%Y-%m-%dT%H:%M:%SZ --format=%cd HEAD 2>/dev/null)

LDFLAGS := -s -w -X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) -X main.commitTime=$(COMMIT_AT)
GOFLAGS := -trimpath

# CGO_ENABLED=0 não é otimização: é a propriedade que justificou escolher Go.
# Sem ele o binário linka contra a glibc do host e perde a imunidade a
# LD_PRELOAD e a binário de sistema trojanizado (SPEC 4).
export CGO_ENABLED = 0

.PHONY: all build helper vm-image test race race-unit lint verify clean dist binarios repro scenarios scenarios-container images fixtures vm-kernels vm-ftrace-proof vm-socket-proof matrix vm-matrix arches

all: verify

helper:
	go build $(GOFLAGS) -o dist/helper ./test/helper

build:
	go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o dist/aletheia ./cmd/aletheia

test:
	go test ./...

# race roda o detector de corrida ONDE ELE FALTAVA.
#
# `go test -race ./...` não alcança a suíte de cenários, que exige a tag de
# build — e foi exatamente ali que uma corrida se escondeu: os subtestes usam
# t.Parallel() e um mapa global era montado de forma preguiçosa. Rodar o
# detector só no que já estava coberto dá a sensação de cobertura sem a
# cobertura.
# mutacao mede se a suíte TEM DENTES.
#
# Cobertura diz quais linhas foram executadas; não diz se alguém estava olhando.
# A mutação estraga uma decisão e pergunta se algum teste reclama — e o número
# que sai é a resposta.
#
# Sem --completo roda só os unitários, e MEDE MENOS: metade da verificação desta
# base está nos cenários. A primeira execução deu 70% com unitários e 67% com a
# suíte inteira sobre outra amostra, e achou dois defeitos reais.
mutacao:
	python3 test/mutacao.py --alvo internal/checks --limite 40

# O -race exige cgo, e o CGO_ENABLED=0 do topo vale para o arquivo inteiro:
# sem esta linha o alvo morre em "requires cgo" sem rodar teste nenhum — que é
# o pior jeito de uma verificação falhar, porque parece que ela rodou. A
# concessão vale só AQUI; o binário entregue continua estático pelas outras
# regras, e o `verify` confirma isso.
race: export CGO_ENABLED = 1
race:
	go test -race ./...
	go test -race -tags scenarios -count=1 -timeout 15m ./test/...

# race-unit é a METADE HERMÉTICA do alvo acima, e existe para a CI.
#
# Ela NÃO substitui `make race`: a nota ali em cima diz, com razão, que rodar o
# detector só no que já estava coberto dá sensação de cobertura sem cobertura —
# a corrida que apareceu de verdade estava na suíte de cenários. O que torna
# esta versão honesta é ela ser NOMEADA como parcial e a CI dizer o que ficou
# de fora.
#
# O corte é por DEPENDÊNCIA EXTERNA, não por preferência: a suíte de cenários
# puxa quatro imagens do Docker Hub e tem 22 casos que precisam de qemu. Numa
# CI de pull request isso é um gate que falha por rate limit de terceiro sem
# nada de errado com o código — o mesmo motivo pelo qual ela fica fora do
# caminho de release.
race-unit: export CGO_ENABLED = 1
race-unit:
	go test -race -count=1 ./internal/... ./cmd/...

lint:
	gofmt -l . | tee /dev/stderr | grep -q . && { echo "arquivos não formatados"; exit 1; } || true
	go vet ./...

# verify é o alvo padrão: build estático CONFIRMADO, não presumido.
verify: lint test build
	@echo "--- verificação do binário ---"
	@file dist/aletheia | grep -q "statically linked" \
		|| { echo "FALHA: binário não é estático — algum import puxou cgo"; exit 1; }
	@! ldd dist/aletheia 2>&1 | grep -q "=>" \
		|| { echo "FALHA: binário tem dependência dinâmica"; exit 1; }
	@echo "OK: estático, sem dependência dinâmica"
	@sha256sum dist/aletheia

# dist cross-compila. O eixo que varia é ARQUITETURA, não distro — e o piso de
# RUNTIME é Linux 3.2: é o mínimo do toolchain Go atual (>= 1.24). Alegar 2.6.32
# (RHEL 6) era herança e estava FISICAMENTE errado — o runtime do Go não sustenta
# mais esse kernel desde a 1.24, e o cenário 90-kernel-2.6 já dizia isso. RHEL 6
# ainda pode ser ANALISADO via imagem (`--root`, do lado limpo); o que não roda
# é o binário DENTRO de um 2.6.32. Para isso seria preciso um build separado com
# Go <= 1.23.x — só vale a pena com um usuário real de RHEL 6 na mesa.
# dist DEPENDE de verify: sem isso, um GOOS herdado do ambiente produzia
# executáveis PE chamados aletheia-linux-* com manifesto sha256 de aparência
# autoritativa.
# binarios é SÓ a compilação das três arquiteturas, sem testes.
#
# Existe como alvo próprio porque duas receitas precisam dela e não podem
# divergir: `dist` (o release) e `repro` (a reconstrução de quem confere). Se
# cada uma tivesse sua cópia da linha de build, um flag acrescentado numa e não
# na outra faria a conferência de reprodutibilidade falhar sem nada de errado
# com o código — e uma verificação que falha sozinha é uma que as pessoas
# aprendem a ignorar.
binarios:
	for arch in amd64 arm64 386; do \
		GOOS=linux GOARCH=$$arch go build $(GOFLAGS) -ldflags="$(LDFLAGS)" \
			-o dist/aletheia-linux-$$arch ./cmd/aletheia || exit 1; \
	done

dist: verify binarios
	sha256sum dist/aletheia-linux-*

# repro reconstrói o release SEM rodar a suíte: é a receita de quem BAIXOU o
# binário e quer conferir que ele sai do código publicado.
#
# A propriedade que a sustenta é o toolchain FIXO no go.mod somado ao -trimpath
# e à identidade da build vir do GIT — nunca do relógio de quem compila. Medido:
# três builds seguidos e um a partir de outro diretório dão o mesmo sha256.
#
# VERSION é obrigatória e precisa ser a MESMA da tag: ela entra no binário por
# -ldflags, então `make repro` sem ela produz outro hash e a conferência falha
# por motivo errado.
repro:
	@test -n "$(filter-out 0.1.0-dev,$(VERSION))" || { \
		echo "repro: informe a VERSION da tag, ex.: make repro VERSION=v0.2.0" >&2; \
		exit 1; \
	}
	@$(MAKE) --no-print-directory binarios
	sha256sum dist/aletheia-linux-*

# scenarios roda a CLI de verdade contra /proc de verdade, em distribuições de
# verdade. Fica separado de `test` porque exige docker e leva dezenas de
# segundos — `go test ./...` continua rápido e sem dependência externa.
vm-image: build helper arches
	./test/vm/build.sh amd64
	./test/vm/build.sh 386

# Separado de propósito: exige REDE. Sem ele, os cenários de kernel legado são
# pulados com o motivo dito — nunca passam em silêncio. Não escreve em /boot.
vm-kernels:
	./test/vm/kernels.sh

# vm-modulos compila os módulos de OCULTAÇÃO (socknd hooka tcp4_seq_show; modhide
# some de /proc/modules) contra o linux-lts do Alpine e extrai esse kernel. São o
# que faz os cenários RK-cross-socket-view / RK-cross-module-view / RK-duplo-hide
# medirem cross.socket_view, cross.module_view e kernel.ftrace_hook contra kernel
# REAL — não mais só prova de shell no vm-matrix.
#
# Separado do `scenarios` porque exige DOCKER: sem rodá-lo, o `vm-image` não
# acha os .ko, não escreve o marcador, e os três cenários são PULADOS com o
# motivo. Para medir de verdade: `make vm-modulos && make scenarios`. Nada aqui
# carrega módulo no host — a compilação é em contêiner, o load só dentro do QEMU.
vm-modulos:
	./test/vm/build-modulos.sh

# vm-ftrace-proof prova, bootando um kernel de verdade, que available_filter_functions
# retém um módulo que se escondeu de /proc/modules — a terceira interface do
# check cross.module_view. Compila o módulo num contêiner e o carrega SÓ dentro
# do QEMU descartável; o kernel do host nunca é tocado. Exige docker e qemu.
vm-ftrace-proof:
	./test/vm/ftrace-hidden-module.sh

# vm-socket-proof prova, bootando um kernel de verdade, que uma conexão
# escondida de /proc/net/tcp por um hook em tcp4_seq_show continua visível pelo
# NETLINK_INET_DIAG — e que a aletheia a pega: cross.socket_view CRITICAL. O
# hook é carregado SÓ dentro do QEMU descartável; o kernel do host nunca é
# tocado. Controle negativo incluído: host limpo cala. Exige docker e qemu.
vm-socket-proof:
	./test/vm/socket-hidden-module.sh

# matrix roda a matriz adversarial: monta técnicas de ataque de userspace num
# contêiner descartável e mede quais checks disparam (regressão) e quais passam
# sem sinal (ponto cego). Exige docker. Não toca o kernel do host.
matrix:
	./test/matrix/matrix.sh

# vm-matrix é o tier de KERNEL da matriz: numa VM descartável, hook em
# tcp4_seq_show (cross.socket_view), LKM que se esconde (cross.module_view) e
# binfmt live (kernel.binfmt_interpreter), com baseline limpo como controle
# negativo. Exige docker e qemu. Não toca o kernel do host.
vm-matrix:
	./test/matrix/vm-matrix.sh

# Servidor legado de 32 bits ainda existe. Cross-compilar custa segundos e é a
# única forma de provar que a ferramenta roda lá — tamanho de int e número de
# syscall divergem, e o compilador não pega tudo.
#
# O `go vet ./...` das duas arquiteturas vem ANTES dos binários, e cobre o
# repositório INTEIRO — inclusive os testes e a ferramenta de plantio da matriz.
# Enquanto o alvo construía só ./cmd/aletheia, as duas arquiteturas de ABI mais
# divergente eram as MENOS verificadas: `GOARCH=386 go build ./...` e o
# equivalente em arm64 estavam quebrados sem que nada acusasse, a matriz
# adversarial só podia ser plantada em amd64, e dois testes não compilavam em 32
# bits (Timespec de int32, constante que estoura o int). É justamente onde os
# sys_*.go existem.
arches:
	GOOS=linux GOARCH=386   go vet ./...
	GOOS=linux GOARCH=arm64 go vet ./...
	CGO_ENABLED=0 GOOS=linux GOARCH=386   go build -trimpath -o dist/aletheia-386   ./cmd/aletheia
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o dist/aletheia-arm64 ./cmd/aletheia
	CGO_ENABLED=0 GOOS=linux GOARCH=386   go build -trimpath -o dist/helper-386     ./test/helper

scenarios: build helper arches vm-image
	go test -tags scenarios -v -timeout 10m ./test/...

# scenarios-container é a METADE que cabe numa CI, e ela é NOMEADA como metade.
#
# Não substitui o `scenarios`: o tier de microVM é onde hidepid, sysctl, módulo
# e cgroup são medidos contra kernel de verdade, e nada disso existe em
# contêiner. O que ela remove é a dependência de KVM, que runner de CI não tem —
# sem qemu os cenários de VM se PULAM sozinhos, com o motivo dito, em vez de
# falhar.
#
# Sem o vm-image junto: aquele alvo compila initramfs a partir dos módulos do
# host, e num runner isso falha por um motivo que não é do código.
#
# O anti-apodrecimento da lista de lacunas ambientais sabe desta execução
# parcial (GapAmbiental.SoEmVM): entrada que só se forma em VM não é cobrada
# quando o tier de VM não rodou.
scenarios-container: build helper arches
	go test -tags scenarios -timeout 10m ./test/...

# fixtures constrói os três SERVIDORES DE REFERÊNCIA.
#
# Eles são o material do experimento que mais achou defeito nesta base: três
# máquinas de produção realistas montadas por quem NÃO conhecia a ferramenta —
# web, banco e agente de build —, com o acúmulo que uma máquina de dois anos
# tem. É contra elas que se mede falso positivo, porque nenhuma foi escrita
# olhando para o que os checks procuram.
#
# Separado de `images` porque é caro: o de banco roda initdb, cria 40 mil linhas
# e arquiva WAL de verdade. Sem eles, os cenários correspondentes são PULADOS
# com o comando na mensagem.
fixtures:
	cd test/images/servidores && for h in web db build; do \
		docker build -f Dockerfile.$$h -t servidor-$$h:test . || exit 1; \
	done

# images pré-baixa a matriz, para o primeiro `make scenarios` não medir download.
images:
	for i in debian:12 rockylinux:9 alpine:3.20; do docker pull $$i; done
	docker build -t aletheia-servicos:test test/images/servicos

clean:
	rm -rf dist
