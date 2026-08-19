#!/usr/bin/env bash
#
# Tier de VM da matriz adversarial: técnicas de KERNEL, numa VM descartável.
#
# Consolida os dois proofs que existiam (hook em tcp4_seq_show -> cross.socket_view;
# LKM que se esconde de /proc/modules E /sys/module -> cross.module_view) e
# acrescenta binfmt live -> kernel.binfmt_interpreter, numa tabela só, com
# controle NEGATIVO: o baseline limpo tem de deixar os três CALADOS.
#
# Contêiner NÃO serve para isto: um hook em seq_show num contêiner esconderia
# conexão do HOST inteiro. Aqui tudo acontece dentro do QEMU, que boota o kernel
# do próprio Alpine (não o do host), sem rede e sem disco do host. Os módulos que
# se escondem/hookam morrem com a VM.
#
# Exige docker, qemu-system-x86_64 e o binário estático. Imprime a tabela e sai 0/1.
#
# A fazer (precisa de um carregador de BPF dentro da VM): cgroup-bpf ->
# atribuição por BPF_PROG_QUERY. Declarado, não silenciado.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
alet="$root/dist/aletheia"
[ -x "$alet" ] || { echo "dist/aletheia não existe — rode 'make build'" >&2; exit 3; }

work="$(mktemp -d)"
trap 'rm -rf "$work" 2>/dev/null || docker run --rm -v "$work":/w alpine:3.20 rm -rf /w 2>/dev/null || true' EXIT
cp "$root/test/vm/socket-hidden-module.c" "$work/socknd.c"
cp "$root/test/vm/ftrace-hidden-module.c" "$work/modhide.c"
cat > "$work/Makefile" <<'MK'
obj-m := socknd.o modhide.o
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
MK

echo "[1/3] compilando os dois módulos e extraindo kernel + inet_diag…"
docker run --rm -v "$work":/m -w /m alpine:3.20 sh -c "
	set -e
	apk add --no-cache build-base linux-lts-dev linux-lts >/dev/null 2>&1
	KREL=\$(ls /lib/modules | grep lts | head -1)
	make -C /lib/modules/\$KREL/build M=/m modules >/tmp/mk.log 2>&1 || { cat /tmp/mk.log; exit 1; }
	cp /boot/vmlinuz-lts /m/vmlinuz
	for mod in inet_diag tcp_diag; do
		f=\$(find /lib/modules/\$KREL -name \$mod.ko.gz -o -name \$mod.ko | head -1)
		case \"\$f\" in *.gz) gunzip -c \"\$f\" > /m/\$mod.ko;; *) cp \"\$f\" /m/\$mod.ko;; esac
	done
	chown -R $(id -u):$(id -g) /m
"

echo "[2/3] montando o initramfs (com a aletheia dentro)…"
rootfs="$work/rootfs"; mkdir -p "$rootfs"
cid="$(docker create alpine:3.20 true)"; docker export "$cid" | tar -x -C "$rootfs"; docker rm -f "$cid" >/dev/null
cp "$work"/socknd.ko "$work"/modhide.ko "$work"/inet_diag.ko "$work"/tcp_diag.ko "$rootfs/"
install -m 0755 "$alet" "$rootfs/aletheia"

cat > "$rootfs/init" <<'INIT'
#!/bin/sh
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
mount -t devtmpfs devtmpfs /dev 2>/dev/null
mount -t tmpfs tmpfs /tmp 2>/dev/null
mkdir -p /sys/kernel/tracing; mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null
mount -t binfmt_misc none /proc/sys/fs/binfmt_misc 2>/dev/null
exec > /dev/console 2>&1

insmod /inet_diag.ko 2>/dev/null; insmod /tcp_diag.ko 2>/dev/null

# fired ID,ID,... para o pid/scan atual (achados com subject)
scan() { rm -f /tmp/o.jsonl; /aletheia scan --only kernel --json /tmp/o.jsonl --no-progress >/dev/null 2>&1; }
tem() { grep -c "\"id\":\"$1\"" /tmp/o.jsonl 2>/dev/null; }

echo "===BEGIN==="

# --- BASELINE: host limpo. os três têm de CALAR (controle negativo). ---
scan
echo "base_socket=$(tem cross.socket_view) base_module=$(tem cross.module_view) base_binfmt=$(tem kernel.binfmt_interpreter)"

# --- socket_view: hook em tcp4_seq_show esconde a porta de /proc/net/tcp ---
insmod /socknd.ko esconder=1
scan
echo "socket_fired=$(tem cross.socket_view)"

# --- module_view: LKM some de /proc/modules E /sys/module; ftrace o delata ---
insmod /modhide.ko esconder=2
echo "modhide_procmodules=$(grep -c '^modhide ' /proc/modules)"
scan
echo "module_fired=$(tem cross.module_view)"

# --- binfmt live: registra um interpretador em /tmp (gravável -> CRITICAL) ---
printf '#!/bin/sh\n' > /tmp/.evilbin; chmod +x /tmp/.evilbin
echo ':evilm:E::evx::/tmp/.evilbin:' > /proc/sys/fs/binfmt_misc/register 2>/tmp/reg.err
echo "binfmt_registrado=$(ls /proc/sys/fs/binfmt_misc/ | grep -c evilm) reg_err=$(cat /tmp/reg.err)"
scan
echo "binfmt_fired=$(tem kernel.binfmt_interpreter)"

echo "===END==="
poweroff -f 2>/dev/null || echo o > /proc/sysrq-trigger
sleep 3
INIT
chmod 0755 "$rootfs/init"
( cd "$rootfs" && find . -print0 | cpio --null -o --format=newc -R 0:0 2>/dev/null | gzip -1 ) > "$work/initramfs.gz"

echo "[3/3] bootando a VM (kernel do Alpine, sem rede, sem disco do host)…"
kvm=""; [ -w /dev/kvm ] && kvm="-enable-kvm"
timeout 300 qemu-system-x86_64 $kvm -M q35 -m 1024 -nographic -no-reboot -nic none \
	-kernel "$work/vmlinuz" -initrd "$work/initramfs.gz" \
	-append "console=ttyS0 panic=1 rdinit=/init" -serial "file:$work/saida.txt" 2>/dev/null || true

out="$(sed -n '/===BEGIN===/,/===END===/p' "$work/saida.txt" | tr -d '\r')"
echo "--- medição ---"; echo "$out" | grep -E '^[a-z_]+=' || true
echo "---------------"
get() { echo "$out" | sed -n "s/.*$1=\\([0-9]*\\).*/\\1/p" | head -1; }

falhou=0
printf '%-22s %-28s %-12s\n' "TÉCNICA (kernel)" "CHECK ESPERADO" "RESULTADO"
printf '%-22s %-28s %-12s\n' "----------------" "--------------" "---------"
linha() { # nome, check, baseline_val, fired_val
	local nome="$1" chk="$2" base="$3" fired="$4"
	local res
	if [ "${base:-9}" != "0" ]; then res="BASE-SUJO!"; falhou=1
	elif [ "${fired:-0}" -ge 1 ] 2>/dev/null; then res="PASS"
	else res="REGRESSÃO!"; falhou=1; fi
	printf '%-22s %-28s %-12s\n' "$nome" "$chk" "$res"
}
linha "hook seq_show"   "cross.socket_view"        "$(get base_socket)"  "$(get socket_fired)"
linha "LKM escondido"   "cross.module_view"        "$(get base_module)"  "$(get module_fired)"
linha "binfmt live"     "kernel.binfmt_interpreter" "$(get base_binfmt)" "$(get binfmt_fired)"

echo
[ "$falhou" = 0 ] && { echo "OK — os três dispararam, e o baseline limpo calou."; exit 0; }
echo "FALHOU — veja a medição acima."; exit 1
