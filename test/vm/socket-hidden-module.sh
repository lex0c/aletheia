#!/usr/bin/env bash
#
# PROVA em VM de ponta a ponta do check cross.socket_view.
#
# Duas perguntas, e a segunda é a que importa para a ferramenta:
#
#   1. Uma conexão escondida de /proc/net/tcp pela técnica clássica — um hook em
#      tcp4_seq_show — continua visível pelo NETLINK_INET_DIAG? (o inet_diag não
#      passa por tcp4_seq_show; percorre a hashtable de sockets por outro
#      caminho de código.)
#   2. A aletheia, rodando DENTRO desse host, transforma isso num achado
#      cross.socket_view CRITICAL?
#
# A (1) é sobre o kernel; a (2) é sobre a ferramenta. Testes unitários cobrem a
# DECISÃO e o parsing com fixture de bytes, mas não provam que o binário real,
# contra /proc e netlink reais, com um hook real no caminho, emite o achado. Só
# bootando um kernel de verdade e escondendo uma conexão de verdade se responde.
#
# Por isso este script roda a aletheia DUAS vezes: uma com o socket VISÍVEL nas
# duas fontes, onde o check tem de CALAR, e outra com o hook ativo, onde ele tem
# de disparar. O controle negativo é parte da prova: um check que nunca foi
# visto calar não foi demonstrado.
#
# SEGURANÇA — o host NUNCA carrega o módulo nem o hook:
#
#   compilar  acontece num contêiner, contra os headers do linux-lts do Alpine.
#             Compilar gera um arquivo; não insere nada em kernel nenhum.
#   carregar  acontece SÓ dentro do QEMU, que boota o kernel do PRÓPRIO Alpine
#             (não o do host). -nic none, sem -drive de disco do host, sem 9p.
#             O hook em tcp4_seq_show morre com a VM.
#
# NUNCA rode o insmod deste .ko fora da VM, e em especial nunca num contêiner:
# contêiner compartilha o kernel do host, e o hook esconderia conexão do host.
#
# INET_DIAG e TCP_DIAG são =m no Alpine: o script extrai os .ko do contêiner e
# os carrega no init, senão o netlink não responderia e a prova não existiria.
#
# Exige docker, qemu-system-x86_64 e o binário estático em dist/aletheia. Não
# escreve em /boot, não usa rede além do docker pull. Imprime OK/FALHOU e sai 0/1.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"

alet="$root/dist/aletheia"
if [ ! -x "$alet" ]; then
	echo "dist/aletheia não existe — rode 'make build'" >&2
	exit 3
fi

work="$(mktemp -d)"
trap 'rm -rf "$work" 2>/dev/null || docker run --rm -v "$work":/w alpine:3.20 rm -rf /w 2>/dev/null || true' EXIT
cp "$here/socket-hidden-module.c" "$work/evil.c"
cat > "$work/Makefile" <<'MK'
obj-m := evil.o
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
MK

echo "[1/3] compilando o módulo, extraindo o kernel e os .ko do inet_diag…"
docker run --rm -v "$work":/m -w /m alpine:3.20 sh -c "
	set -e
	apk add --no-cache build-base linux-lts-dev linux-lts >/dev/null 2>&1
	KREL=\$(ls /lib/modules | grep lts | head -1)
	make -C /lib/modules/\$KREL/build M=/m modules >/tmp/mk.log 2>&1 || { cat /tmp/mk.log; exit 1; }
	cp /boot/vmlinuz-lts /m/vmlinuz
	# INET_DIAG e TCP_DIAG são módulos: sem eles o netlink não responde, e a
	# consulta de socket do cross.socket_view não teria segunda visão.
	for m in inet_diag tcp_diag; do
		f=\$(find /lib/modules/\$KREL -name \$m.ko.gz -o -name \$m.ko | head -1)
		case \"\$f\" in *.gz) gunzip -c \"\$f\" > /m/\$m.ko;; *) cp \"\$f\" /m/\$m.ko;; esac
	done
	chown -R $(id -u):$(id -g) /m
"

echo "[2/3] montando o initramfs descartável (com a aletheia dentro)…"
rootfs="$work/rootfs"
mkdir -p "$rootfs"
cid="$(docker create alpine:3.20 true)"; docker export "$cid" | tar -x -C "$rootfs"; docker rm -f "$cid" >/dev/null
cp "$work/evil.ko" "$rootfs/evil.ko"
cp "$work/inet_diag.ko" "$rootfs/inet_diag.ko"
cp "$work/tcp_diag.ko" "$rootfs/tcp_diag.ko"
install -m 0755 "$alet" "$rootfs/aletheia"

cat > "$rootfs/init" <<'INIT'
#!/bin/sh
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
mount -t devtmpfs devtmpfs /dev 2>/dev/null
mount -t tmpfs tmpfs /tmp 2>/dev/null
mkdir -p /sys/kernel/tracing
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null
exec > /dev/console 2>&1

# conta os achados cross.socket_view do JSONL (linha de ACHADO tem "subject").
viewhits() { grep '"cross.socket_view"' "$1" 2>/dev/null | grep -c '"subject"'; }

echo "===BEGIN==="

# inet_diag/tcp_diag são módulos: sem eles o NETLINK_INET_DIAG não responde.
insmod /inet_diag.ko 2>/dev/null
insmod /tcp_diag.ko 2>/dev/null
echo "inet_diag_carregado=$(grep -c inet_diag /proc/modules)"

# a aletheia concede CapNetlink? sem isso o check só declara lacuna, e o teste
# não teria o que provar. O collect grava as caps do env no dump.
/aletheia collect --out /tmp/env.json >/dev/null 2>&1
# caps é uma LISTA JSON: "caps":["procfs",...,"netlink",...]. E o motivo de
# uma capacidade negada mora em cap_reasons — imprimo-o para diagnóstico.
# o dump é pretty-printed: uma cap por linha, entre "caps": e o primeiro ].
# cap_reasons cita netlink SÓ quando negado (lá tem dois-pontos: "netlink":).
echo "netlink_concedido=$(sed -n '/"caps":/,/]/p' /tmp/env.json | grep -c '"netlink"')"
echo "netlink_negado=$(grep -c '"netlink":' /tmp/env.json)"

# --- PARTE 1: socket VISÍVEL nas duas fontes. o check tem de CALAR. ---
insmod /evil.ko esconder=0
echo "proc_tem_porta_limpo=$(grep -c ':1337 ' /proc/net/tcp)"
/aletheia scan --only kernel --json /tmp/limpo.jsonl >/dev/null 2>&1
echo "aletheia_limpo_socket_view=$(viewhits /tmp/limpo.jsonl)"
rmmod evil

# --- PARTE 2: hook em tcp4_seq_show esconde a porta de /proc/net/tcp. ---
insmod /evil.ko esconder=1
echo "proc_tem_porta_oculto=$(grep -c ':1337 ' /proc/net/tcp)"
/aletheia scan --only kernel --json /tmp/oculto.jsonl >/dev/null 2>&1
echo "aletheia_oculto_socket_view=$(viewhits /tmp/oculto.jsonl)"
grep '"cross.socket_view"' /tmp/oculto.jsonl 2>/dev/null | grep '"subject"' | head -1 > /tmp/linha
# 0x1337 = 4919: o subject é "tcp 127.0.0.1:4919"
echo "aletheia_oculto_nomeia_porta=$(grep -c '4919' /tmp/linha)"
echo "aletheia_oculto_critical=$(grep -c '"CRITICAL"' /tmp/linha)"
# bônus: o hook de ftrace em tcp4_seq_show explica a divergência, e o outro
# check tem de vê-lo — é a NextStep que o cross.socket_view aponta.
echo "aletheia_oculto_ftrace_hook=$(grep '"kernel.ftrace_hook"' /tmp/oculto.jsonl 2>/dev/null | grep -c 'tcp4_seq_show')"
echo "kernel_expoe_hook=$(grep -c 'tcp4_seq_show' /sys/kernel/tracing/enabled_functions 2>/dev/null)"
echo "aletheia_tem_debugfs=$(sed -n '/"caps":/,/]/p' /tmp/env.json | grep -c '"debugfs"')"

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

[ -n "${KEEP_OUT:-}" ] && cp "$work/saida.txt" "$KEEP_OUT" 2>/dev/null || true
out="$(sed -n '/===BEGIN===/,/===END===/p' "$work/saida.txt" | tr -d '\r')"
echo "--- medição ---"; echo "$out" | grep -E '^[a-z_]+=' || true
echo "---------------"

get() { echo "$out" | sed -n "s/^$1=//p"; }
falhou=0

# o mecanismo tem de existir, senão o teste não prova nada — é SKIP, não OK.
if [ "$(get inet_diag_carregado)" = "0" ] || [ "$(get netlink_concedido)" = "0" ]; then
	echo "SKIP: netlink/inet_diag indisponível na VM — o cross.socket_view não teria segunda visão."
	echo "  inet_diag_carregado=$(get inet_diag_carregado) netlink_concedido=$(get netlink_concedido) netlink_negado=$(get netlink_negado)"
	exit 2
fi

# o kernel: a porta aparece limpa e some com o hook.
[ "$(get proc_tem_porta_limpo)" -ge 1 ] 2>/dev/null  || { echo "FALHOU: a porta mágica não apareceu em /proc/net/tcp no baseline"; falhou=1; }
[ "$(get proc_tem_porta_oculto)" = "0" ]             || { echo "FALHOU: o hook NÃO escondeu a porta de /proc/net/tcp"; falhou=1; }

# a ferramenta: o controle negativo primeiro.
[ "$(get aletheia_limpo_socket_view)" = "0" ]        || { echo "FALHOU: cross.socket_view disparou com o socket VISÍVEL (falso positivo)"; falhou=1; }
[ "$(get aletheia_oculto_socket_view)" -ge 1 ] 2>/dev/null || { echo "FALHOU: a aletheia NÃO reportou o socket escondido"; falhou=1; }
[ "$(get aletheia_oculto_nomeia_porta)" -ge 1 ] 2>/dev/null || { echo "FALHOU: o achado não nomeia a porta 4919"; falhou=1; }
[ "$(get aletheia_oculto_critical)" -ge 1 ] 2>/dev/null || { echo "FALHOU: o achado não é CRITICAL"; falhou=1; }

if [ "$falhou" = 0 ]; then
	echo "OK — socket escondido de /proc/net/tcp por hook em tcp4_seq_show; host"
	echo "     limpo cala; e a aletheia o pega pelo netlink: cross.socket_view"
	echo "     CRITICAL nomeando a porta 4919."
	# não é falha se o bônus não vier, mas vale registrar.
	[ "$(get aletheia_oculto_ftrace_hook)" -ge 1 ] 2>/dev/null \
		&& echo "     (bônus: kernel.ftrace_hook também pegou o hook em tcp4_seq_show.)" \
		|| echo "     (nota: kernel.ftrace_hook não reportou tcp4_seq_show nesta run.)"
	exit 0
fi
exit 1
