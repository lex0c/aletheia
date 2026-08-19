#!/bin/sh
# Runner DENTRO do contêiner: por técnica, planta o processo, escaneia com a
# aletheia (root, no PID namespace do contêiner) e reporta quais checks
# dispararam PARA AQUELE pid.
set -u
for tech in "$@"; do
	/m/plant "$tech" >/tmp/p.out 2>/tmp/p.err &
	pj=$!
	sleep 1 # o plant imprime PLANT só depois de montar a técnica
	pid=$(sed -n 's/^PLANT pid=\([0-9]*\).*/\1/p' /tmp/p.out 2>/dev/null)
	if [ -z "$pid" ]; then
		echo "FIRED tech=$tech ids=PLANT_FALHOU:$(tr -d '\n' </tmp/p.err)"
		kill "$pj" 2>/dev/null
		continue
	fi
	rm -f /tmp/out.jsonl
	/m/aletheia scan --only proc --json /tmp/out.jsonl --no-progress >/dev/null 2>&1
	ids=$(grep "\"subject\":\"pid=$pid\"" /tmp/out.jsonl 2>/dev/null |
		sed -n 's/.*"id":"\([^"]*\)".*/\1/p' | sort -u | tr '\n' ',')
	echo "FIRED tech=$tech ids=$ids"
	kill "$pj" 2>/dev/null
done
