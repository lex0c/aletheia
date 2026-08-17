VERSION ?= 0.1.0-dev
LDFLAGS := -s -w -X main.version=$(VERSION)
GOFLAGS := -trimpath

# CGO_ENABLED=0 não é otimização: é a propriedade que justificou escolher Go.
# Sem ele o binário linka contra a glibc do host e perde a imunidade a
# LD_PRELOAD e a binário de sistema trojanizado (SPEC 4).
export CGO_ENABLED = 0

.PHONY: all build helper vm-image test lint verify clean dist scenarios images vm-kernels arches

all: verify

helper:
	go build $(GOFLAGS) -o dist/helper ./test/helper

build:
	go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o dist/aletheia ./cmd/aletheia

test:
	go test ./...

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

# dist cross-compila. O eixo que varia é ARQUITETURA, não distro — e o piso é
# kernel 2.6.32 (RHEL/CentOS 6+); RHEL 5 fica com o script shell.
# dist DEPENDE de verify: sem isso, um GOOS herdado do ambiente produzia
# executáveis PE chamados aletheia-linux-* com manifesto sha256 de aparência
# autoritativa.
dist: verify
	for arch in amd64 arm64 386; do \
		GOOS=linux GOARCH=$$arch go build $(GOFLAGS) -ldflags="$(LDFLAGS)" \
			-o dist/aletheia-linux-$$arch ./cmd/aletheia || exit 1; \
	done
	sha256sum dist/aletheia-linux-*

# scenarios roda a CLI de verdade contra /proc de verdade, em distribuições de
# verdade. Fica separado de `test` porque exige docker e leva dezenas de
# segundos — `go test ./...` continua rápido e sem dependência externa.
vm-image: build helper
	./test/vm/build.sh

# Separado de propósito: exige REDE. Sem ele, os cenários de kernel legado são
# pulados com o motivo dito — nunca passam em silêncio. Não escreve em /boot.
vm-kernels:
	./test/vm/kernels.sh

# Servidor legado de 32 bits ainda existe. Cross-compilar custa segundos e é a
# única forma de provar que a ferramenta roda lá — tamanho de int e número de
# syscall divergem, e o compilador não pega tudo.
arches:
	CGO_ENABLED=0 GOOS=linux GOARCH=386   go build -trimpath -o dist/aletheia-386   ./cmd/aletheia
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o dist/aletheia-arm64 ./cmd/aletheia
	CGO_ENABLED=0 GOOS=linux GOARCH=386   go build -trimpath -o dist/helper-386     ./test/helper

scenarios: build helper arches vm-image
	go test -tags scenarios -v -timeout 10m ./test/...

# images pré-baixa a matriz, para o primeiro `make scenarios` não medir download.
images:
	for i in debian:12 rockylinux:9 alpine:3.20; do docker pull $$i; done

clean:
	rm -rf dist
