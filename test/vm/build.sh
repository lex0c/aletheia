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
#
# Uso: build.sh [amd64|386]
#
# A variante de 32 bits existe porque servidor i686 legado é um ambiente
# INTEIRO diferente, não só um binário diferente: kernel de 32 bits, userland de
# 32 bits, e um /proc onde os campos de 64 bits do stat são formatados por um
# kernel que não tem registradores de 64 bits.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
out="$root/dist/vm"
arch="${1:-amd64}"

case "$arch" in
	amd64) img_default="alpine:3.20";      sfx="" ;;
	386)   img_default="i386/alpine:3.20"; sfx="-386" ;;
	*) echo "arquitetura desconhecida: $arch (use amd64 ou 386)" >&2; exit 3 ;;
esac
img="${ALETHEIA_VM_IMAGE:-$img_default}"

mkdir -p "$out"

for b in aletheia helper; do
	[[ -x "$root/dist/$b$sfx" ]] || {
		echo "dist/$b$sfx não existe — rode 'make build helper arches'" >&2; exit 3; }
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
install -m 0755 "$root/dist/aletheia$sfx" "$rootfs/aletheia"
install -m 0755 "$root/dist/helper$sfx"   "$rootfs/helper"

# QUAIS binários entraram, por hash. O initramfs é artefato de build e NÃO é
# reconstruído pelo `make scenarios`: ele fica com o que o último `make vm-image`
# deixou ali. Sem este marcador, o tier de VM roda contra o binário que sobrou —
# e passa, verde, testando outro programa.
#
# Foi medido: um initramfs de horas antes carregava um binário de SchemaVersion
# 6 enquanto a árvore já estava no 9, e a suíte de VM vinha verde a sessão
# inteira sobre código que não existia mais. Suíte que passa testando outra
# coisa é o pior verde possível — é o mesmo defeito que esta ferramenta persegue
# nos hosts alheios, dentro de casa.
#
# O runner compara este arquivo com o hash dos binários da árvore e PULA com o
# motivo quando eles divergem. Pular alto é honesto; passar é que não era.
{
	echo "aletheia $(sha256sum "$root/dist/aletheia$sfx" | cut -d" " -f1)"
	echo "helper $(sha256sum "$root/dist/helper$sfx" | cut -d" " -f1)"
} > "$out/binarios$sfx.txt"

# Um MÓDULO DE KERNEL de verdade para o guest, quando dá.
#
# O cenário de "módulo carregado sem arquivo em disco" não tem como ser montado
# com plantio de arquivo: o fato vem de /proc/modules, que é o kernel falando. É
# preciso carregar um módulo DE VERDADE — e o guest boota o kernel do HOST, então
# um .ko do host serve.
#
# `dummy` é a escolha: driver de rede inerte, presente na configuração de
# praticamente toda distribuição, e que não toca em nada. Nenhum outro módulo é
# aceito como substituto — carregar um módulo qualquer num guest pode travá-lo, e
# um cenário que trava é pior que um cenário que não roda.
#
# Sem ele, NADA falha aqui: o marcador não é escrito e o cenário correspondente é
# PULADO com o motivo dito. Só no amd64, porque o guest 386 boota outro kernel.
rm -f "$out/modulo$sfx.txt"
if [[ "$arch" == "amd64" ]]; then
	rel="$(uname -r)"
	src=""
	for dir in "/lib/modules/$rel/kernel/drivers/net" "/usr/lib/modules/$rel/kernel/drivers/net"; do
		for ext in "" ".zst" ".xz" ".gz"; do
			if [[ -f "$dir/dummy.ko$ext" ]]; then src="$dir/dummy.ko$ext"; break 2; fi
		done
	done
	if [[ -n "$src" ]]; then
		mkdir -p "$rootfs/modulos"
		ko="$rootfs/modulos/dummy.ko"
		case "$src" in
			*.zst) zstd -d -q -o "$ko" "$src" 2>/dev/null || rm -f "$ko" ;;
			*.xz)  xz  -dc "$src" > "$ko" 2>/dev/null || rm -f "$ko" ;;
			*.gz)  gzip -dc "$src" > "$ko" 2>/dev/null || rm -f "$ko" ;;
			*)     cp "$src" "$ko" ;;
		esac
		if [[ -s "$ko" ]]; then
			echo "dummy" > "$out/modulo$sfx.txt"
			echo "módulo para o guest: $src"
		else
			echo "não consegui descomprimir $src — o cenário de módulo será PULADO"
		fi
	else
		echo "sem dummy.ko para o kernel $rel — o cenário de módulo será PULADO"
	fi
fi

# Os módulos de OCULTAÇÃO, quando o `build-modulos.sh` já os compilou.
#
# socknd (hooka tcp4_seq_show) e modhide (some de /proc/modules) provam
# cross.socket_view e cross.module_view contra kernel real — o que contêiner não
# alcança e teste unitário não prova. Diferente do dummy.ko acima, eles são
# COMPILADOS contra o linux-lts do Alpine e SÓ carregam sob o vmlinuz-lts que o
# `build-modulos.sh` extrai junto; o cenário os seleciona com Kernel:"lts".
#
# Aqui só os ENFIAMOS no initramfs — o carregamento é no Setup do cenário, dentro
# do QEMU. O marcador confirma que ESTE initramfs os contém: é a diferença entre
# "compilei uma vez" e "estão na imagem que vou bootar". Sem ele o harness PULA os
# cenários de ocultação com o motivo, em vez de falhar. Só no amd64 — os .ko são
# de 64 bits e o guest 386 boota outro kernel.
rm -f "$out/modulos-ocultacao$sfx.txt"
if [[ "$arch" == "amd64" && -d "$root/dist/vm/modulos-ocultacao" ]]; then
	kos=("$root/dist/vm/modulos-ocultacao"/*.ko)
	if [[ -f "${kos[0]:-}" ]]; then
		mkdir -p "$rootfs/modulos"
		for ko in "${kos[@]}"; do
			install -m 0644 "$ko" "$rootfs/modulos/$(basename "$ko")"
		done
		echo "módulos de ocultação no initramfs: $(basename -a "${kos[@]}" | tr '\n' ' ')"
		basename -a "${kos[@]}" > "$out/modulos-ocultacao$sfx.txt"
	fi
fi

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
	# A SAÍDA do setup vai junto quando ele falha.
	#
	# A primeira versão mandava só "SETUP-FALHOU rc=N" para o console e
	# descartava o log — o que deixa quem escreve cenário sem nada para
	# diagnosticar. Um harness que esconde a causa da falha custa mais tempo
	# que o cenário que ele testa.
	# O status é capturado ANTES de qualquer teste: dentro de `if ! cmd`, o
	# `$?` já é o do `!` e vale sempre zero. E a variável é própria — `rc`
	# guarda o exit do scan mais abaixo, e reaproveitá-la aqui trocaria o
	# veredito do cenário pelo status do setup.
	sh /tmp/setup.sh >/tmp/setup.log 2>&1
	rcsetup=$?
	if [ "$rcsetup" -ne 0 ]; then
		echo "SETUP-FALHOU rc=$rcsetup" > /dev/console
		echo "--- saída do setup ---" > /dev/console
		cat /tmp/setup.log > /dev/console
		echo "--- fim ---" > /dev/console
	fi
fi

# Os argumentos chegam separados por VÍRGULA porque a linha de comando do kernel
# não aceita espaço dentro de um parâmetro. Sem esta tradução eles chegam ao
# aletheia como UM token — `--ioc,/ioc.yaml` vira flag inválida, o binário
# imprime o uso e o cenário falha com "nenhum achado", que é a mensagem mais
# enganosa possível.
if [ -n "${args:-}" ]; then
	args=$(echo "$args" | tr ',' ' ')
fi

# Varrer sem privilégio é um CENÁRIO, não um detalhe: metade dos defeitos da
# primeira revisão só aparecia sem root, e hidepid só esconde de quem NÃO é root.
#
# A saída vai para arquivo e o root a repassa ao console: /dev/console não é
# gravável por usuário comum, e afrouxar essa permissão tornaria o guest menos
# parecido com um host real justamente no cenário que existe para ser realista.
if [ -n "${asuser:-}" ]; then
	# STDOUT e stderr: com `--json ARQUIVO` o relatório humano sai pelo stdout,
	# e capturar só o stderr deixava /tmp/human.log VAZIO em toda execução de
	# VM. O comentário abaixo prometia que o relatório ia junto, e ele nunca
	# foi — nenhuma asserção de saída humana funcionava em modo VM.
	su "$asuser" -s /bin/sh -c "/aletheia scan --json /tmp/out.jsonl ${args:-}" >/tmp/human.log 2>&1
else
	/aletheia scan --json /tmp/out.jsonl ${args:-} >/tmp/human.log 2>&1
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

# `-R 0:0` não é detalhe: o rootfs é extraído por usuário comum, e sem isto o
# guest inteiro nasce com o uid de quem rodou o build — `/etc/passwd` com dono
# 1000, `/bin/sh` com dono 1000. Um guest assim não parece um Linux nenhum, e a
# distorção ficou invisível até um check PERGUNTAR quem é o dono dos arquivos
# que o root executa (§36.4): ele recusou responder, e tinha razão.
( cd "$rootfs" && find . -print0 | cpio --null -o --format=newc -R 0:0 2>/dev/null | gzip -1 ) > "$out/initramfs$sfx.gz"

echo "initramfs ($arch): $out/initramfs$sfx.gz ($(du -h "$out/initramfs$sfx.gz" | cut -f1))"
