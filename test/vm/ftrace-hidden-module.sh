#!/usr/bin/env bash
#
# PROVA em VM de ponta a ponta do check cross.module_view (terceira interface).
#
# Duas perguntas, e a segunda é a que importa para a ferramenta:
#
#   1. Um LKM que se esconde das DUAS interfaces que o crossview clássico
#      compara — some de /proc/modules (list_del) E de /sys/module (kobject_del)
#      — ainda é delatado pelo kernel em available_filter_functions?
#   2. A aletheia, rodando DENTRO desse host, transforma isso num achado?
#
# A (1) é sobre o kernel; a (2) é sobre a ferramenta. Testes unitários cobrem a
# DECISÃO com fixture, mas não provam que o binário real, contra /proc e tracefs
# reais, emite o achado. Só bootando um kernel de verdade e carregando um módulo
# de verdade que se esconde se responde isso — a resposta vem do kernel, não de
# código que se possa ler.
#
# Por isso este script roda a aletheia DUAS vezes: uma com o host limpo, onde o
# check tem de CALAR, e outra com o módulo escondido, onde ele tem de disparar.
# O controle negativo é parte da prova: um check que nunca foi visto calar não
# foi demonstrado.
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
# Exige docker, qemu-system-x86_64 e o binário estático em dist/aletheia. Não
# escreve em /boot, não usa rede além do docker pull. Imprime OK/FALHOU e sai 0/1.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"

# O binário sob teste é o mesmo que se distribui: estático, para rodar no guest
# mínimo sem libc. Se não existe, o script não tem o que provar.
alet="$root/dist/aletheia"
if [ ! -x "$alet" ]; then
	echo "dist/aletheia não existe — rode 'make build'" >&2
	exit 3
fi

work="$(mktemp -d)"
trap 'rm -rf "$work" 2>/dev/null || docker run --rm -v "$work":/w alpine:3.20 rm -rf /w 2>/dev/null || true' EXIT
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

echo "[2/3] montando o initramfs descartável (com a aletheia dentro)…"
rootfs="$work/rootfs"
mkdir -p "$rootfs"
cid="$(docker create alpine:3.20 true)"; docker export "$cid" | tar -x -C "$rootfs"; docker rm -f "$cid" >/dev/null
cp "$work/evil.ko" "$rootfs/evil.ko"
install -m 0755 "$alet" "$rootfs/aletheia"

cat > "$rootfs/init" <<'INIT'
#!/bin/sh
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
mount -t devtmpfs devtmpfs /dev 2>/dev/null
mount -t tmpfs tmpfs /tmp 2>/dev/null
exec > /dev/console 2>&1
mkdir -p /sys/kernel/tracing
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null
T=/sys/kernel/tracing

# achadosCrossModule imprime UMA linha por achado cross.module_view do JSONL, ou
# nada. É grep de string: o binário é a fonte da verdade, não este parser.
dump() { grep -o '"cross.module_view"' "$1" 2>/dev/null | wc -l; }

echo "===BEGIN==="

# --- PARTE 1: o kernel. baseline sem endereço cru, depois esconde. ---
echo "baseline_enderecos_crus=$(grep -cE '^0x' $T/available_filter_functions)"

# --- PARTE 2a: a aletheia no host LIMPO. cross.module_view tem de CALAR. ---
/aletheia scan --json /tmp/limpo.jsonl >/dev/null 2>&1
echo "aletheia_limpo_cross_module=$(dump /tmp/limpo.jsonl)"

# --- esconde o módulo das DUAS interfaces do crossview clássico; o ftrace fica ---
insmod /evil.ko esconder=2
echo "proc_modules_tem_evil=$(grep -c '^evil ' /proc/modules)"
echo "sys_module_tem_evil=$(ls /sys/module/ | grep -c '^evil$')"
echo "ftrace_tem_evil=$(grep -c 'evil_marcador \[evil\]' $T/available_filter_functions)"

# --- PARTE 2b: a aletheia com o módulo ESCONDIDO. tem de disparar. ---
/aletheia scan --json /tmp/oculto.jsonl >/dev/null 2>&1
echo "aletheia_oculto_cross_module=$(dump /tmp/oculto.jsonl)"
# a linha inteira do achado, para conferir que nomeia 'evil' e é CRITICAL
grep '"cross.module_view"' /tmp/oculto.jsonl 2>/dev/null | head -1 > /tmp/linha
echo "aletheia_oculto_nomeia_evil=$(grep -c 'evil' /tmp/linha)"
echo "aletheia_oculto_critical=$(grep -c '"CRITICAL"' /tmp/linha)"

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

get() { echo "$out" | sed -n "s/^$1=//p"; }
falhou=0

# o kernel
[ "$(get baseline_enderecos_crus)" = "0" ]   || { echo "FALHOU: baseline tinha endereço cru"; falhou=1; }
[ "$(get proc_modules_tem_evil)" = "0" ]      || { echo "FALHOU: evil não se escondeu de /proc/modules"; falhou=1; }
[ "$(get sys_module_tem_evil)" = "0" ]        || { echo "FALHOU: evil não se escondeu de /sys/module — a prova forte exige as DUAS"; falhou=1; }
[ "$(get ftrace_tem_evil)" -ge 1 ] 2>/dev/null || { echo "FALHOU: ftrace NÃO reteve o módulo escondido"; falhou=1; }

# a ferramenta — o controle negativo primeiro
[ "$(get aletheia_limpo_cross_module)" = "0" ] || { echo "FALHOU: cross.module_view disparou no host LIMPO (falso positivo)"; falhou=1; }
[ "$(get aletheia_oculto_cross_module)" -ge 1 ] 2>/dev/null || { echo "FALHOU: a aletheia NÃO reportou o módulo escondido"; falhou=1; }
[ "$(get aletheia_oculto_nomeia_evil)" -ge 1 ] 2>/dev/null || { echo "FALHOU: o achado não nomeia 'evil'"; falhou=1; }
[ "$(get aletheia_oculto_critical)" -ge 1 ] 2>/dev/null || { echo "FALHOU: o achado não é CRITICAL"; falhou=1; }

if [ "$falhou" = 0 ]; then
	echo "OK — módulo escondido de /proc/modules E /sys/module; host limpo cala; e"
	echo "     a aletheia o pega pelo ftrace: cross.module_view CRITICAL nomeando 'evil'."
	exit 0
fi
exit 1
