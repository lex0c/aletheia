#!/usr/bin/env bash
#
# Compila os módulos de OCULTAÇÃO para o harness de cenários e extrai o kernel
# contra o qual eles casam.
#
# Por que existe, separado do build.sh: o build.sh monta o initramfs (userland,
# independente de kernel) e, para o cenário de "módulo sem arquivo", ergue um
# `dummy.ko` LEVANTADO dos módulos já compilados do HOST — sem compilar nada. Os
# módulos que ESCONDEM (socknd hooka tcp4_seq_show; modhide se desencadeia de
# /proc/modules) não existem no host: têm de ser COMPILADOS, e compilar um .ko
# exige os headers do kernel-alvo.
#
# O host de desenvolvimento raramente tem headers do próprio kernel, e mesmo
# quando tem, o gcc dele diverge do que compilou o kernel. A saída provada — a
# mesma do test/matrix/vm-matrix.sh — é compilar DENTRO de um Alpine, contra o
# `linux-lts` do próprio Alpine, e BOOTAR esse kernel (não o do host). Assim o
# .ko e o kernel casam por construção, sem depender de nada instalado no host.
#
# Produz, em dist/vm/:
#   kernels/vmlinuz-lts        o kernel Alpine LTS (o cenário o seleciona por Kernel:"lts")
#   modulos-ocultacao/*.ko     socknd (socket), modhide (módulo), pidhide (PID/
#                              thread), bpfhide (prog eBPF) + inet_diag/tcp_diag
#                              (o diag por netlink que o cross.socket_view confronta)
#
# O build.sh, quando vê modulos-ocultacao/ preenchido, os ENFIA no initramfs e
# escreve o marcador que destrava os cenários. Sem rodar isto, os cenários de
# ocultação são PULADOS com o motivo — nunca passam em silêncio.
#
# SEGURANÇA: nada aqui carrega módulo nenhum. A compilação é num contêiner
# descartável; o carregamento só acontece DENTRO do QEMU do teste, com o kernel
# do Alpine — jamais o do host. Exige docker.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
out="$root/dist/vm"
img="${ALETHEIA_VM_LTS_IMAGE:-alpine:3.20}"

command -v docker >/dev/null 2>&1 || { echo "docker ausente — os cenários de ocultação serão PULADOS" >&2; exit 3; }

mkdir -p "$out/kernels" "$out/modulos-ocultacao"

work="$(mktemp -d)"
# O rootfs do Alpine é extraído por usuário comum e ganha donos != root; o rm do
# host pode não conseguir apagá-lo. Cai para um rm dentro de contêiner, como o
# vm-matrix faz.
trap 'rm -rf "$work" 2>/dev/null || docker run --rm -v "$work":/w "$img" rm -rf /w 2>/dev/null || true' EXIT

cp "$here/socket-hidden-module.c" "$work/socknd.c"
cp "$here/ftrace-hidden-module.c" "$work/modhide.c"
cp "$here/pid-hide-module.c" "$work/pidhide.c"
cp "$here/bpf-hide-module.c" "$work/bpfhide.c"
cat > "$work/Makefile" <<'MK'
obj-m := socknd.o modhide.o pidhide.o bpfhide.o
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
MK

echo "[1/2] compilando socknd + modhide + pidhide + bpfhide contra o linux-lts do Alpine…"
docker run --rm -v "$work":/m -w /m "$img" sh -c '
	set -e
	apk add --no-cache build-base linux-lts-dev linux-lts >/dev/null 2>&1
	KREL=$(ls /lib/modules | grep lts | head -1)
	[ -n "$KREL" ] || { echo "linux-lts não trouxe /lib/modules" >&2; exit 1; }
	make -C /lib/modules/$KREL/build M=/m modules >/tmp/mk.log 2>&1 || { cat /tmp/mk.log >&2; exit 1; }
	cp /boot/vmlinuz-lts /m/vmlinuz-lts
	# inet_diag/tcp_diag são MÓDULO no linux-lts (CONFIG_INET_*_DIAG=m): sem eles
	# o dump por netlink não tem handler, o cross.socket_view não confronta nada
	# e o cenário mediria uma lacuna da própria ferramenta, não a ocultação.
	for mod in inet_diag tcp_diag; do
		f=$(find /lib/modules/$KREL -name $mod.ko.gz -o -name $mod.ko | head -1)
		[ -n "$f" ] || { echo "módulo $mod não encontrado no linux-lts" >&2; exit 1; }
		case "$f" in *.gz) gunzip -c "$f" > /m/$mod.ko;; *) cp "$f" /m/$mod.ko;; esac
	done
	chown -R '"$(id -u):$(id -g)"' /m
'

echo "[2/2] publicando kernel e módulos em dist/vm/…"
install -m 0644 "$work/vmlinuz-lts" "$out/kernels/vmlinuz-lts"
for ko in socknd modhide pidhide bpfhide inet_diag tcp_diag; do
	[ -f "$work/$ko.ko" ] || { echo "esperava $ko.ko e ele não saiu da compilação" >&2; exit 1; }
	install -m 0644 "$work/$ko.ko" "$out/modulos-ocultacao/$ko.ko"
done

echo "ok: kernel LTS em $out/kernels/vmlinuz-lts, módulos em $out/modulos-ocultacao/"
echo "    rode 'make vm-image' (ou 'make scenarios') para enfiá-los no initramfs."
