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
	for mod in inet_diag tcp_diag cls_bpf act_bpf sch_ingress binfmt_misc; do
		f=\$(find /lib/modules/\$KREL -name \$mod.ko.gz -o -name \$mod.ko | head -1)
		[ -n \"\$f\" ] || continue
		case \"\$f\" in *.gz) gunzip -c \"\$f\" > /m/\$mod.ko;; *) cp \"\$f\" /m/\$mod.ko;; esac
	done
	chown -R $(id -u):$(id -g) /m
"

echo "[2/3] montando o initramfs (com a aletheia dentro)…"
rootfs="$work/rootfs"; mkdir -p "$rootfs"
cid="$(docker create alpine:3.20 true)"; docker export "$cid" | tar -x -C "$rootfs"; docker rm -f "$cid" >/dev/null
cp "$work"/*.ko "$rootfs/" # socknd/modhide/inet_diag/tcp_diag + cls_bpf/act_bpf/sch_ingress se existirem
install -m 0755 "$alet" "$rootfs/aletheia"
CGO_ENABLED=0 go build -trimpath -o "$work/plant" "$root/test/matrix/plant"
install -m 0755 "$work/plant" "$rootfs/plant"

cat > "$rootfs/init" <<'INIT'
#!/bin/sh
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
mount -t devtmpfs devtmpfs /dev 2>/dev/null
mount -t tmpfs tmpfs /tmp 2>/dev/null
mkdir -p /sys/kernel/tracing; mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null
# binfmt_misc é MÓDULO no kernel LTS do Alpine (CONFIG_BINFMT_MISC=m): sem o
# insmod o diretório não existe, o mount falha calado e o `register` escreve no
# vazio. A linha da tabela passava mesmo assim, porque o `tem` antigo contava a
# menção de cobertura — dois defeitos que se cancelavam e escondiam que a
# técnica nunca foi reproduzida.
insmod /binfmt_misc.ko 2>/dev/null
mount -t binfmt_misc none /proc/sys/fs/binfmt_misc 2>/dev/null
mkdir -p /sys/fs/cgroup; mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
exec > /dev/console 2>&1

insmod /inet_diag.ko 2>/dev/null; insmod /tcp_diag.ko 2>/dev/null

# fired ID,ID,... para o pid/scan atual (achados com subject)
scan() { rm -f /tmp/o.jsonl; /aletheia scan --only kernel --json /tmp/o.jsonl --no-progress >/dev/null 2>&1; }
# tem conta ACHADO, não menção.
#
# A linha `coverage` do JSONL carrega os `partial` ANINHADOS, cada um com o id
# do check que declarou a lacuna — e `grep -c` conta a LINHA inteira. Contar só
# pelo id fazia todo check que declarasse cobertura parcial ser lido como se
# tivesse disparado, e o controle NEGATIVO desta matriz saía sujo por um check
# que estava se comportando exatamente como deveria: dizendo o que não pôde
# verificar. Achado tem "sev"; entrada de cobertura não.
tem() { grep "\"id\":\"$1\"" /tmp/o.jsonl 2>/dev/null | grep -c "\"sev\"" ; }

echo "===BEGIN==="

# --- BASELINE: host limpo. os três têm de CALAR (controle negativo). ---
scan
echo "base_socket=$(tem cross.socket_view) base_module=$(tem cross.module_view) base_binfmt=$(tem kernel.binfmt_interpreter)"
echo "base_sockmap=$(grep -c 'segurado por um MAPA' /tmp/o.jsonl 2>/dev/null)"

# --- socket_view: hook em tcp4_seq_show esconde a porta de /proc/net/tcp ---
insmod /socknd.ko esconder=1
scan
echo "socket_fired=$(tem cross.socket_view)"

# --- DUPLO HIDE: esconde a porta de /proc/net/tcp E do SOCK_DIAG ao mesmo tempo.
# Ataca a premissa do cross.socket_view: as duas fontes concordam, e a
# comparação não tem divergência para achar. A pergunta é se sobra sinal
# INDEPENDENTE — e sobra: o hook em tcp4_seq_show aparece em enabled_functions e
# o kernel.ftrace_hook o pega. O mecanismo do ataque é visível mesmo quando o
# efeito não é.
rmmod socknd
insmod /socknd.ko esconder=2
scan
echo "duplo_socketview=$(tem cross.socket_view) duplo_ftracehook=$(tem kernel.ftrace_hook)"
rmmod socknd

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

# --- cgroup BPF: programa anexado a um cgroup, atribuído por BPF_PROG_QUERY.
# a prova é a ATRIBUIÇÃO no dump (o programa não é acusado; ele é NOMEADO). ---
/aletheia collect --out /tmp/dc0.json --no-progress >/dev/null 2>&1
echo "cgroup_base=$(grep -c 'cgroup inet_ingress' /tmp/dc0.json 2>/dev/null)"
echo "netns_base=$(grep -c 'network namespace' /tmp/dc0.json 2>/dev/null)"
/plant cgroup-attach >/tmp/cg.out 2>/tmp/cg.err &
sleep 1
echo "cg_err=$(tr -d '\n' </tmp/cg.err)"
/aletheia collect --out /tmp/dc1.json --no-progress >/dev/null 2>&1
echo "cgroup_attributed=$(grep -c 'cgroup inet_ingress' /tmp/dc1.json 2>/dev/null)"

# --- tc/XDP/act_bpf: programa preso a INTERFACE ou a uma AÇÃO, atribuído por
# rtnetlink (RTM_GETLINK / GETTFILTER / GETACTION). mesma prova: NOMEADO no dump.
# marcador = o NOME do filtro/ação (plant_cls/plant_act), porque a mensagem de
# lacuna "ações de tc (act_bpf)..." também contém a string act_bpf. ---
ip link set lo up 2>/dev/null || ifconfig lo up 2>/dev/null || true
insmod /sch_ingress.ko 2>/dev/null; insmod /cls_bpf.ko 2>/dev/null; insmod /act_bpf.ko 2>/dev/null
/aletheia collect --out /tmp/dn0.json --no-progress >/dev/null 2>&1
echo "net_base=$(grep -cE 'xdp em |plant_cls|plant_act' /tmp/dn0.json 2>/dev/null)"

/plant xdp >/tmp/xdp.out 2>/tmp/xdp.err &
sleep 1
echo "xdp_err=$(tr -d '\n' </tmp/xdp.err)"
/aletheia collect --out /tmp/dnx.json --no-progress >/dev/null 2>&1
echo "xdp_attributed=$(grep -c 'xdp em ' /tmp/dnx.json 2>/dev/null)"

/plant tc-filter >/tmp/tc.out 2>/tmp/tc.err &
sleep 1
echo "tc_err=$(tr -d '\n' </tmp/tc.err)"
/aletheia collect --out /tmp/dnt.json --no-progress >/dev/null 2>&1
echo "tc_attributed=$(grep -c 'plant_cls' /tmp/dnt.json 2>/dev/null)"

/plant act-bpf >/tmp/act.out 2>/tmp/act.err &
sleep 1
echo "act_err=$(tr -d '\n' </tmp/act.err)"
/aletheia collect --out /tmp/dna.json --no-progress >/dev/null 2>&1
echo "act_attributed=$(grep -c 'plant_act' /tmp/dna.json 2>/dev/null)"

# --- netns: cls_bpf preso DENTRO de outro netns. A aletheia não o LÊ (rtnetlink
# roda no netns dela), mas tem de DECLARAR a lacuna — silêncio seria pior. ---
/plant netns-legacy >/tmp/nsl.out 2>/tmp/nsl.err &
sleep 1
echo "nsl_err=$(tr -d '\n' </tmp/nsl.err)"
/aletheia collect --out /tmp/dnl.json --no-progress >/dev/null 2>&1
echo "netns_lacuna=$(grep -c 'network namespace' /tmp/dnl.json 2>/dev/null)"

# --- BPFDoor: socket_filter órfão de fd, preso por um socket que o processo
# segura, compartilhando um mapa com ele. Na VM não há confusão de namespace de
# PID (ao contrário do contêiner), então a pergunta é limpa.
#
# MEDIDO: bpf_unowned dispara CRÍTICO — o programa órfão NÃO passa em silêncio,
# não é falso negativo. Mas a evidência diz "o socket segura, e ele pertence a
# algum processo… e NÃO há socket de captura visível: ou o detentor é um socket
# comum, ou está fora do alcance". Ou seja: o FixSocket resolve socket de CAPTURA
# (AF_PACKET), não socket comum com SO_ATTACH_BPF, então o dono NÃO é nomeado —
# embora o processo tenha o socket aberto. É exatamente a lacuna P11/P12:
# correlacionar prog->map->PID (o processo segura o mapa que o programa usa)
# nomearia o detentor. Este cenário é a catraca: se um dia o dono passar a ser
# nomeado, a linha continua PASS (bpf_unowned pode até parar de disparar, e aí
# esta asserção precisa virar "atribuído"); enquanto isso, o gap está reproduzido
# e medido, não afirmado.
/plant bpfdoor >/tmp/bd.out 2>&1 &
sleep 1
BDPROG=$(sed -n 's/.*prog_id=\([0-9]*\).*/\1/p' /tmp/bd.out)
scan
# bpf_unowned para O PROGRAMA que o plant criou, não qualquer um: os outros
# objetos BPF da VM (cgroup, xdp, tc) continuam vivos, e "existe algum
# bpf_unowned" passaria mesmo que o socket_filter específico sumisse.
echo "bpfdoor_prog=$BDPROG bpfdoor_unowned=$(grep "\"id\":\"kernel.bpf_unowned\"" /tmp/o.jsonl 2>/dev/null | grep -c "prog id=$BDPROG")"

# --- SOCKMAP: um sk_skb preso por um SOCKMAP (STREAM_VERDICT), órfão de fd. É o
# tipo "segurado por MAPA": o kernel.bpf_unowned NÃO acusa (seria falso — o
# conteúdo do mapa não foi lido) mas DECLARA a lacuna. Este caminho (FixMapa)
# só tinha teste tautológico de struct; aqui o programa é REAL num kernel real.
# A prova tem dois lados: o inventário VÊ o programa (nome plant_skskb — a ABI
# de bpf(2) casou com o kernel) E a lacuna é DECLARADA (não silêncio).
/plant sockmap >/tmp/skm.out 2>/tmp/skm.err &
sleep 1
SKMPROG=$(sed -n 's/.*prog_id=\([0-9]*\).*/\1/p' /tmp/skm.out)
echo "sockmap_err=$(tr -d '\n' </tmp/skm.err)"
/aletheia collect --out /tmp/dsk.json --no-progress >/dev/null 2>&1
echo "sockmap_visto=$(grep -c 'plant_skskb' /tmp/dsk.json 2>/dev/null)"
scan
echo "sockmap_prog=$SKMPROG sockmap_lacuna=$(grep -c 'segurado por um MAPA' /tmp/o.jsonl 2>/dev/null)"

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
linha "cgroup BPF"      "atribuído (BPF_PROG_QUERY)" "$(get cgroup_base)" "$(get cgroup_attributed)"
linha "XDP em lo"       "atribuído (RTM_GETLINK)"    "$(get net_base)"    "$(get xdp_attributed)"
linha "cls_bpf (tc)"    "atribuído (RTM_GETTFILTER)" "$(get net_base)"    "$(get tc_attributed)"
linha "act_bpf"         "atribuído (RTM_GETACTION)"  "$(get net_base)"    "$(get act_attributed)"
linha "tc em outro netns" "lacuna netns DECLARADA"   "$(get netns_base)"  "$(get netns_lacuna)"
linha "bpfdoor prog $(get bpfdoor_prog)" "kernel.bpf_unowned (órfão)" "0"     "$(get bpfdoor_unowned)"

# O sk_skb-por-sockmap tem dois lados que TÊM de valer juntos: o inventário VÊ o
# programa (plant_skskb — prova de que a ABI de bpf(2) casa com kernel REAL, não
# com struct de teste) E o kernel.bpf_unowned DECLARA a lacuna FixMapa, em vez
# de calar ou acusar em falso. Baseline sem FixMapa é o controle negativo.
skv="$(get sockmap_visto)"; skl="$(get sockmap_lacuna)"; skb="$(get base_sockmap)"
if [ "${skb:-9}" != "0" ]; then skres="BASE-SUJO!"; falhou=1
elif [ "${skv:-0}" -ge 1 ] 2>/dev/null && [ "${skl:-0}" -ge 1 ] 2>/dev/null; then skres="PASS"
else skres="FALHOU"; falhou=1; fi
printf '%-22s %-28s %-12s\n' "sk_skb por sockmap" "FixMapa lacuna DECLARADA" "$skres"

# O duplo-hide tem dois lados: cross.socket_view CALA (as fontes concordam) e o
# kernel.ftrace_hook DISPARA (o hook em tcp4_seq_show é sinal independente).
# Se o cross.socket_view disparar aqui, o hook do SOCK_DIAG não funcionou — e a
# comparação achou a divergência que este cenário existe para eliminar.
dcv="$(get duplo_socketview)"; dfh="$(get duplo_ftracehook)"
if [ "${dcv:-1}" = "0" ] && [ "${dfh:-0}" -ge 1 ] 2>/dev/null; then
	dres="PASS"
else
	dres="FALHOU"; falhou=1
fi
printf '%-22s %-28s %-12s\n' "duplo-hide (proc+diag)" "ftrace_hook (cross cego OK)" "$dres"

echo
[ "$falhou" = 0 ] && { echo "OK — todas as técnicas dispararam, e o baseline limpo calou."; exit 0; }
echo "FALHOU — veja a medição acima."; exit 1
