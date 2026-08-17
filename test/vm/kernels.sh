#!/usr/bin/env bash
#
# Baixa kernels ANTIGOS para os cenários de VM legada.
#
# Por que existe: contêiner compartilha o kernel do HOST, então a matriz de
# imagens testa layout de userland e não procfs de época. "A ferramenta roda em
# VM legada?" só tem resposta honesta bootando um kernel legado.
#
# O QUE ELE NÃO FAZ, e é o ponto: não instala nada, não escreve em /boot, não
# encosta no bootloader nem no initramfs do host. Os arquivos vão para
# dist/vm/kernels/ e são passados ao QEMU com -kernel, como qualquer outro
# arquivo. Remover o diretório desfaz tudo.
#
# A origem é o repositório do Alpine, que ainda serve as versões antigas. O apk
# é um tar.gz comum: dá para extrair sem nenhuma ferramenta de pacote.
#
# Exige rede, e por isso é alvo SEPARADO (`make vm-kernels`). Sem ele, os
# cenários de kernel antigo são PULADOS com o motivo dito em voz alta — nunca
# passam silenciosamente.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
out="$(cd "$here/../.." && pwd)/dist/vm/kernels"
mkdir -p "$out"

# nome | ramo do alpine | arquitetura do repo | pacote | sha256 do apk
#
# Os dois extremos que importam, em 64 e em 32 bits:
#   3.18  o mais antigo que ainda boota com este initramfs (2014)
#   4.14  o LTS do Amazon Linux 2 e da era do Ubuntu 18.04 — o "legado" que
#         mais se encontra em produção de verdade
#
# A variante de 32 bits não é redundante: servidor i686 legado tem kernel SEM
# registrador de 64 bits formatando os campos de 64 bits do /proc.
kernels=(
	"3.18|v3.2|x86_64|linux-vanilla-3.18.22-r1.apk|eff7bcc5b08681cee610fccc8df0caa7ea7bff5cbece96abe421c0775486154a"
	"4.14|v3.8|x86_64|linux-vanilla-4.14.167-r0.apk|20ac63df99948259a38cd3caff50279bc4632ca526c6b7640ac8636420bdcbc6"
	"3.18-386|v3.2|x86|linux-vanilla-3.18.22-r1.apk|6a539f5582a1950a5bd4a9bc447a79a6bcfb1bbb98265d2e5025bef10509b746"
	"4.14-386|v3.8|x86|linux-vanilla-4.14.167-r0.apk|53d9e429f6ba037c67668bec928c82b8a3d089717ecc84e83d930f02c7cb2c87"
)

for entry in "${kernels[@]}"; do
	IFS='|' read -r ver branch repoarch pkg sum <<< "$entry"
	dest="$out/vmlinuz-$ver"
	if [[ -f "$dest" ]]; then
		echo "já existe: $dest"
		continue
	fi

	work="$(mktemp -d)"
	trap 'rm -rf "$work"' EXIT
	url="https://dl-cdn.alpinelinux.org/alpine/$branch/main/$repoarch/$pkg"
	echo "baixando kernel $ver…"
	curl -fsSL --max-time 600 -o "$work/k.apk" "$url"

	# O hash é conferido porque este arquivo vira o kernel de um guest. Baixar
	# e executar sem verificar seria a prática que o runbook §16 condena.
	got="$(sha256sum "$work/k.apk" | cut -d' ' -f1)"
	if [[ "$got" != "$sum" ]]; then
		echo "sha256 NÃO confere para $pkg" >&2
		echo "  esperado $sum" >&2
		echo "  obtido   $got" >&2
		exit 1
	fi

	tar xzf "$work/k.apk" -C "$work" 2>/dev/null || true
	src="$(find "$work" -name 'vmlinuz*' -type f | head -1)"
	[[ -n "$src" ]] || { echo "vmlinuz não encontrado em $pkg" >&2; exit 1; }
	install -m 0644 "$src" "$dest"
	rm -rf "$work"
	trap - EXIT
	echo "kernel $ver: $dest"
done
