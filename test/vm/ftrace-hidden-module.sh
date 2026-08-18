#!/usr/bin/env bash
#
# PROVA em VM da terceira interface de módulos do check cross.module_view.
#
# A pergunta: um LKM que se esconde com `list_del(&THIS_MODULE->list)` some de
# /proc/modules — mas o kernel ainda o delata em available_filter_functions?
#
# Este script responde bootando um kernel de verdade e carregando um módulo de
# verdade que se esconde, porque a resposta vem do kernel e não de código que se
# possa ler. É o mesmo motivo pelo qual test/vm/build.sh existe.
#
# SEGURANÇA — o host NUNCA carrega o módulo:
#
#   compilar  acontece num contêiner, contra os headers do linux-lts do Alpine.
#             Compilar gera um arquivo; não insere nada em kernel nenhum.
#   carregar  acontece SÓ dentro do QEMU, que boota o kernel do PRÓPRIO Alpine
#             (não o do host). Se o módulo escondido travar algo, morre a VM.
#             -nic none, sem -drive de disco do host, sem 9p: a VM é cega.
#
# Um módulo que se desencadeia da lista não descarrega sem reboot — por isso ele
# jamais toca o kernel do host. NUNCA rode o insmod deste .ko fora da VM, e em
# especial nunca num contêiner: contêiner compartilha o kernel do host.
#
# Exige docker e qemu-system-x86_64. Não escreve em /boot, não usa rede além do
# docker pull. Imprime OK/FALHOU e sai 0/1.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cp "$here/ftrace-hidden-module.c" "$work/evil.c"
cat > "$work/Makefile" <<'MK'
obj-m := evil.o
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
MK

# O guest NÃO precisa de /lib/modules: o tracefs é builtin, o insmod é o do
# busybox e available_filter_functions já lista todas as funções rastreáveis do
# kernel. O chown final devolve os artefatos ao usuário — sem ele, o make roda
# como root no contêiner e o mktemp não seria removível ao sair.
echo "[1/3] compilando o módulo e extraindo o kernel do Alpine (em contêiner)…"
docker run --rm -v "$work":/m -w /m alpine:3.20 sh -c "
	set -e
	apk add --no-cache build-base linux-lts-dev linux-lts >/dev/null 2>&1
	KREL=\$(ls /lib/modules | grep lts | head -1)
	make -C /lib/modules/\$KREL/build M=/m modules >/tmp/mk.log 2>&1 || { cat /tmp/mk.log; exit 1; }
	cp /boot/vmlinuz-lts /m/vmlinuz
	chown -R $(id -u):$(id -g) /m
"

echo "[2/3] montando o initramfs descartável…"
rootfs="$work/rootfs"
mkdir -p "$rootfs"
cid="$(docker create alpine:3.20 true)"; docker export "$cid" | tar -x -C "$rootfs"; docker rm -f "$cid" >/dev/null
cp "$work/evil.ko" "$rootfs/evil.ko"

cat > "$rootfs/init" <<'INIT'
#!/bin/sh
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
mount -t devtmpfs devtmpfs /dev 2>/dev/null
exec > /dev/console 2>&1
mkdir -p /sys/kernel/tracing
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null
T=/sys/kernel/tracing
echo "===BEGIN==="
echo "baseline_enderecos_crus=$(grep -cE '^0x' $T/available_filter_functions)"
insmod /evil.ko esconder=1
echo "proc_modules_tem_evil=$(grep -c '^evil ' /proc/modules)"
echo "ftrace_tem_evil=$(grep -c 'evil_marcador \[evil\]' $T/available_filter_functions)"
grep -oE '\[[a-z0-9_]+\]$' $T/available_filter_functions | tr -d '[]' | sort -u > /tmp/ft
awk '{print $1}' /proc/modules | sort -u > /tmp/pm
echo "so_no_ftrace=$(comm -23 /tmp/ft /tmp/pm | tr '\n' ',')"
echo "===END==="
poweroff -f 2>/dev/null || echo o > /proc/sysrq-trigger
sleep 3
INIT
chmod 0755 "$rootfs/init"
( cd "$rootfs" && find . -print0 | cpio --null -o --format=newc -R 0:0 2>/dev/null | gzip -1 ) > "$work/initramfs.gz"

echo "[3/3] bootando a VM (kernel do Alpine, sem rede, sem disco do host)…"
timeout 180 qemu-system-x86_64 -M q35 -m 1024 -nographic -no-reboot -nic none \
	-kernel "$work/vmlinuz" -initrd "$work/initramfs.gz" \
	-append "console=ttyS0 panic=1 rdinit=/init" -serial "file:$work/saida.txt" 2>/dev/null || true

out="$(sed -n '/===BEGIN===/,/===END===/p' "$work/saida.txt" | tr -d '\r')"
echo "--- medição ---"; echo "$out"
echo "---------------"

get() { echo "$out" | sed -n "s/^$1=//p"; }
falhou=0
[ "$(get baseline_enderecos_crus)" = "0" ] || { echo "FALHOU: baseline tinha endereço cru"; falhou=1; }
[ "$(get proc_modules_tem_evil)" = "0" ] || { echo "FALHOU: evil não se escondeu de /proc/modules"; falhou=1; }
[ "$(get ftrace_tem_evil)" -ge 1 ] 2>/dev/null || { echo "FALHOU: ftrace NÃO reteve o módulo escondido"; falhou=1; }
case "$(get so_no_ftrace)" in
	*evil*) : ;;
	*) echo "FALHOU: a regra do check não isolou 'evil'"; falhou=1 ;;
esac

if [ "$falhou" = 0 ]; then
	echo "OK — evil sumiu de /proc/modules e o ftrace o delatou; a regra isolou 'evil'."
	exit 0
fi
exit 1
