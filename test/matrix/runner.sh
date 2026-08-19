#!/bin/sh
# Runner DENTRO do contêiner. Sobe o C2 falso em TEST-NET-3 (nunca roteado,
# tudo local), e por técnica planta o processo, escaneia com a aletheia (root,
# no PID namespace do contêiner) e reporta quais checks dispararam para o pid.
set -u

# TEST-NET-3 num alias de lo: o destino "público" existe LOCALMENTE, sem egress.
ip addr add 203.0.113.5/32 dev lo 2>/dev/null || true
ip link set lo up 2>/dev/null || true
/m/plant listen >/tmp/listen.out 2>&1 &
sleep 1

for tech in "$@"; do
	# comando por técnica: a maioria é `plant <tech>`; jit-inject roda como
	# /usr/bin/node para cair na isenção de JIT do maps_exec_anon.
	case "$tech" in
	jit-inject)
		cp /m/plant /usr/bin/node
		cmd="/usr/bin/node jit-inject" ;;
	*)
		cmd="/m/plant $tech" ;;
	esac
	$cmd >/tmp/p.out 2>/tmp/p.err &
	pj=$!
	sleep 1
	pid=$(sed -n 's/^PLANT pid=\([0-9]*\).*/\1/p' /tmp/p.out 2>/dev/null)
	if [ -z "$pid" ]; then
		echo "FIRED tech=$tech ids=PLANT_FALHOU:$(tr -d '\n' </tmp/p.err)"
		kill "$pj" 2>/dev/null
		continue
	fi
	rm -f /tmp/out.jsonl
	/m/aletheia scan --only proc,net --json /tmp/out.jsonl --no-progress >/dev/null 2>&1
	ids=$(grep "\"subject\":\"pid=$pid\"" /tmp/out.jsonl 2>/dev/null |
		sed -n 's/.*"id":"\([^"]*\)".*/\1/p' | sort -u | tr '\n' ',')
	echo "FIRED tech=$tech ids=$ids"
	kill "$pj" 2>/dev/null
	# o shell forkado da ponte fica órfão; limpa pelo nome
	pkill -x sh 2>/dev/null || true
done
