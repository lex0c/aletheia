#!/usr/bin/env bash
#
# Constrói o initramfs do guest de teste.
#
# Por que initramfs e não imagem de disco: um guest de distro em qcow2 sobe em
# 5–20s, e com dezenas de cenários isso vira minutos por rodada — aí ninguém
# roda. Boot direto de kernel com initramfs sobe em ~1s: sem bootloader, sem
# tabela de partição, sem cloud-init, sem qemu-img.
#
# Por que docker export e não debootstrap: o rootfs do Alpine já está baixado
# como imagem de contêiner. Reaproveitá-lo evita mais uma dependência de
# ferramenta e mais um download.
#
# O guest NÃO tem rede, NÃO monta diretório do host e NÃO tem SSH. O único canal
# é o console serial: o /init roda o scan, escreve o JSONL em /dev/console e
# desliga. O QEMU captura com -serial file:. Hermético e trivial de roteirizar.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
out="$root/dist/vm"
img="${ALETHEIA_VM_IMAGE:-alpine:3.20}"

mkdir -p "$out"

for b in aletheia helper; do
	[[ -x "$root/dist/$b" ]] || { echo "dist/$b não existe — rode 'make build helper'" >&2; exit 3; }
done

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
rootfs="$work/rootfs"
mkdir -p "$rootfs"

# rootfs a partir da imagem de contêiner que já temos
cid="$(docker create "$img" true)"
docker export "$cid" | tar -x -C "$rootfs"
docker rm -f "$cid" >/dev/null

# os binários sob teste, estáticos: rodam no guest sem libc nenhuma
install -m 0755 "$root/dist/aletheia" "$rootfs/aletheia"
install -m 0755 "$root/dist/helper" "$rootfs/helper"

# /init: PID 1 do guest. Monta o mínimo, aplica o cenário, varre, desliga.
cat > "$rootfs/init" <<'INIT'
#!/bin/sh
# PID 1 do guest de teste.
#
# O cenário chega por linha de comando do kernel (aletheia.setup=...), que o
# QEMU passa em -append. É o canal de ENTRADA; o console serial é o de saída.
# Nenhum dos dois compartilha nada com o host.

mount -t proc     proc     /proc  2>/dev/null
mount -t sysfs    sysfs    /sys   2>/dev/null
mount -t devtmpfs devtmpfs /dev   2>/dev/null
mount -t tmpfs    tmpfs    /tmp   2>/dev/null
chmod 1777 /tmp

# hostname próprio, para o relatório não parecer o do host
hostname aletheia-guest 2>/dev/null

# loopback de pé: sem ele os cenários de rede não conseguem nem escutar. É a
# rede DO GUEST — o QEMU roda com -nic none e não existe placa nenhuma, então
# nada aqui alcança o host.
ip link set lo up 2>/dev/null || ifconfig lo up 2>/dev/null

setup=""
for arg in $(cat /proc/cmdline); do
	case "$arg" in
		aletheia.setup=*) setup="${arg#aletheia.setup=}" ;;
		aletheia.args=*)  args="${arg#aletheia.args=}"   ;;
		aletheia.user=*)  asuser="${arg#aletheia.user=}" ;;
	esac
done

# O setup vem em base64 para caber na linha de comando do kernel sem sofrer
# com aspas, espaço e caractere especial.
if [ -n "$setup" ]; then
	echo "$setup" | base64 -d > /tmp/setup.sh
	sh /tmp/setup.sh >/tmp/setup.log 2>&1 || echo "SETUP-FALHOU rc=$?" > /dev/console
fi

# Varrer sem privilégio é um CENÁRIO, não um detalhe: metade dos defeitos da
# primeira revisão só aparecia sem root, e hidepid só esconde de quem NÃO é root.
#
# A saída vai para arquivo e o root a repassa ao console: /dev/console não é
# gravável por usuário comum, e afrouxar essa permissão tornaria o guest menos
# parecido com um host real justamente no cenário que existe para ser realista.
if [ -n "${asuser:-}" ]; then
	su "$asuser" -s /bin/sh -c "/aletheia scan --json /tmp/out.jsonl ${args:-}" 2>/tmp/human.log
else
	/aletheia scan --json /tmp/out.jsonl ${args:-} 2>/tmp/human.log
fi
rc=$?

echo "---ALETHEIA-BEGIN---" > /dev/console
cat /tmp/out.jsonl > /dev/console 2>/dev/null
echo "---ALETHEIA-EXIT=$rc---" > /dev/console

# o relatório humano vai junto: sem ele, a mensagem de falha do teste é inútil
echo "---HUMAN-BEGIN---" > /dev/console
cat /tmp/human.log > /dev/console 2>/dev/null
echo "---HUMAN-END---" > /dev/console

# desligar sem passar por init de distro
poweroff -f 2>/dev/null || echo o > /proc/sysrq-trigger
sleep 5
INIT
chmod 0755 "$rootfs/init"

( cd "$rootfs" && find . -print0 | cpio --null -o --format=newc 2>/dev/null | gzip -1 ) > "$out/initramfs.gz"

echo "initramfs: $out/initramfs.gz ($(du -h "$out/initramfs.gz" | cut -f1))"
