#!/usr/bin/env bash
#
# Matriz adversarial: monta técnicas de ataque e mede quais a aletheia PEGA.
#
# Dois eixos, os dois pedidos:
#   REGRESSÃO   cada técnica é o que um check afirma pegar. Se não pegar, é
#               regressão — um refactor quebrou o check em silêncio.
#   PONTO CEGO  técnicas que se quer medir se passam SEM sinal. Cego confirmado
#               (o check já o declara) é esperado; SURPRESA (pegou, ou deixou de
#               pegar algo que devia) é o achado que vale.
#
# Tier de CONTÊINER (este arquivo): técnicas de userspace, onde a aletheia roda
# como root e vê tudo, e nada toca o kernel do HOST. O tier de kernel (hook em
# seq_show, LKM, cgroup BPF) fica nos proofs de VM descartável.
#
# Exige docker e o binário estático. Imprime a tabela e sai 0/1.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"

work="$(mktemp -d)"
trap 'rm -rf "$work" 2>/dev/null || docker run --rm -v "$work":/w alpine:3.20 rm -rf /w 2>/dev/null || true' EXIT

echo "[1/3] compilando aletheia e plant (estáticos)…"
CGO_ENABLED=0 go build -trimpath -o "$work/aletheia" "$root/cmd/aletheia"
CGO_ENABLED=0 go build -trimpath -o "$work/plant" "$root/test/matrix/plant"
cp "$here/runner.sh" "$work/runner.sh"

# tabela: tech -> "MODO check_esperado :: nota"
#   FIRE  = tem de disparar aquele check
#   BLIND = NÃO deve disparar (ponto cego); a nota diz se é declarado
declare -A ESPERA=(
	[rwx-anon]="FIRE proc.maps_rwx_anon :: injeção clássica gravável+executável"
	[rx-anon]="FIRE proc.maps_exec_anon :: injeção W^X (mmap RW -> mprotect RX)"
	[deleted-exec]="FIRE proc.deleted_mapping :: lib apagada de /tmp, ainda executável"
	[rx-anon-rotulada]="BLIND proc.maps_exec_anon :: DECLARADO — rótulo de VMA é spoofável, o check só conta sem rótulo"
	[deleted-data]="BLIND proc.deleted_mapping :: DECLARADO — o check exige segmento executável"
)
TECHS="rwx-anon rx-anon deleted-exec rx-anon-rotulada deleted-data"

echo "[2/3] rodando as técnicas no contêiner…"
docker run --rm -v "$work":/m -w /m alpine:3.20 sh /m/runner.sh $TECHS >"$work/out.txt" 2>/dev/null

echo "[3/3] resultado:"
echo
printf '%-18s %-24s %-14s %s\n' "TÉCNICA" "CHECK ESPERADO" "RESULTADO" "NOTA"
printf '%-18s %-24s %-14s %s\n' "-------" "--------------" "---------" "----"
falhou=0
for tech in rwx-anon rx-anon deleted-exec rx-anon-rotulada deleted-data; do
	spec="${ESPERA[$tech]}"
	modo="$(echo "$spec" | awk '{print $1}')"
	chk="$(echo "$spec" | awk '{print $2}')"
	nota="$(echo "$spec" | sed 's/^[^:]*:: //')"
	fired="$(sed -n "s/^FIRED tech=$tech ids=//p" "$work/out.txt")"
	if echo ",$fired," | grep -q ",$chk,"; then tem=1; else tem=0; fi
	case "$modo" in
	FIRE)
		if [ "$tem" = 1 ]; then res="PASS"; else res="REGRESSÃO!"; falhou=1; fi ;;
	BLIND)
		if [ "$tem" = 1 ]; then res="SURPRESA+"; else res="cego(ok)"; fi ;;
	esac
	printf '%-18s %-24s %-14s %s\n' "$tech" "$chk" "$res" "$nota"
done
echo
echo "(dispararam além do esperado — contexto, não erro:)"
for tech in rwx-anon rx-anon deleted-exec rx-anon-rotulada deleted-data; do
	fired="$(sed -n "s/^FIRED tech=$tech ids=//p" "$work/out.txt")"
	[ -n "$fired" ] && echo "  $tech: $fired"
done

[ "$falhou" = 0 ] && { echo; echo "OK — nenhuma regressão."; exit 0; }
echo; echo "FALHOU — uma técnica que um check afirma pegar passou sem sinal."; exit 1
