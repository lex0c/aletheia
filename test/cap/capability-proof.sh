#!/usr/bin/env bash
# Prova, contra um kernel de verdade, que env.CapRoot mede ALCANCE e não euid.
#
# # Por que este script existe
#
# A concessão de CapRoot era `os.Geteuid() == 0`, e o servidor MCP do mesmo
# binário explicava em prosa que euid NÃO BASTA. Ela passou a ser
#
#     euid == 0  ||  (capability de leitura de arquivo  E  CAP_SYS_PTRACE)
#
# e isso é uma afirmação sobre o KERNEL: que essas capabilities, e não outras,
# são as que abrem as quatro superfícies que CapRoot promete — environ alheio,
# dono de socket, /etc/shadow e /root.
#
# Afirmação sobre kernel se prova contra kernel. O unitário injeta um conjunto
# de bits e mede a decisão; ele não sabe se o conjunto corresponde a algum poder
# real. Aqui o binário recebe capability de ARQUIVO de verdade, roda como uid
# 1000, e a cada caso a sonda TENTA LER /etc/shadow. Essa é a verdade de campo:
# se o código e o kernel discordarem, quem está errado é o código.
#
# O caso decisivo é CAP_SYS_ADMIN sozinha. Ela é a capability mais larga do
# Linux e é fácil tratá-la como "praticamente root" — o código já a tratou. O
# kernel não a consulta na checagem DAC de leitura de arquivo, e este script
# mede isso: com ela e mais nada, /etc/shadow continua ilegível.
#
# Contêiner descartável, sem qemu. O kernel do host nunca é tocado.
set -euo pipefail

raiz="$(cd "$(dirname "$0")/../.." && pwd)"
sonda="$raiz/dist/cap-sonda"
[ -x "$sonda" ] || { echo "construa antes: make cap-sonda"; exit 1; }

roteiro=$(mktemp); trap 'rm -f "$roteiro"' EXIT
cat > "$roteiro" << 'FIM'
set -e
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq libcap2-bin >/dev/null 2>&1
useradd -u 1000 -m analista 2>/dev/null || true
cp /sonda /tmp/sonda && chmod 755 /tmp/sonda
caso() {
  nome=$1; caps=$2
  if [ -n "$caps" ]; then setcap "$caps" /tmp/sonda; else setcap -r /tmp/sonda 2>/dev/null || true; fi
  printf '%s ' "$nome"
  su analista -s /bin/sh -c /tmp/sonda
}
caso semcaps        ""
caso dac            "cap_dac_read_search+ep"
caso ptrace         "cap_sys_ptrace+ep"
caso dac_ptrace     "cap_dac_read_search,cap_sys_ptrace+ep"
caso sysadmin       "cap_sys_admin+ep"
caso sysadmin_ptrace "cap_sys_admin,cap_sys_ptrace+ep"
setcap -r /tmp/sonda 2>/dev/null || true
printf 'root '; /tmp/sonda
FIM

echo "── capabilities contra kernel real (contêiner descartável) ──"
saida=$(docker run --rm \
  --cap-add=SETFCAP --cap-add=DAC_READ_SEARCH --cap-add=SYS_PTRACE --cap-add=SYS_ADMIN \
  -v "$sonda:/sonda:ro" -v "$roteiro:/r.sh:ro" debian:12 sh /r.sh)
echo "$saida" | sed 's/^/  /'
echo

falhas=0
campo() { echo "$saida" | grep "^$1 " | grep -o "$2=[^ ]*" | cut -d= -f2; }
exigir() {
  local caso=$1 campo=$2 quer=$3 porque=$4
  local got; got=$(campo "$caso" "$campo")
  if [ "$got" != "$quer" ]; then
    echo "FALHA  $caso: $campo=$got, esperado $quer"
    echo "       $porque"
    falhas=$((falhas+1))
  fi
}

# 1. O CASO DECISIVO: CAP_SYS_ADMIN não abre a checagem DAC.
exigir sysadmin shadow false \
  "se o kernel deixasse ler, a lista de capabilities de leitura estaria certa em incluí-la"
exigir sysadmin caproot false \
  "conceder CapRoot aqui faria o check RODAR como se tivesse observado, e a ausência que ele reporta viraria evidência"

# 2. A CONJUNÇÃO é necessária: uma sozinha não basta, mesmo abrindo metade.
exigir dac shadow true \
  "CAP_DAC_READ_SEARCH tem de abrir /etc/shadow — sem isso o teste não mede nada"
exigir dac caproot false \
  "meia superfície não é CapRoot: environ e dono de socket continuam invisíveis"
exigir ptrace caproot false \
  "sem capability de leitura, /etc/shadow e /root continuam invisíveis"
exigir sysadmin_ptrace caproot false \
  "SYS_ADMIN nao substitui a capability DAC, nem acompanhada de ptrace"

# 3. E as duas juntas concedem, com a verdade de campo junto.
exigir dac_ptrace caproot true "as quatro superficies estao alcancaveis"
exigir dac_ptrace shadow true  "e o kernel confirma"

# 4. Controle negativo e positivo.
exigir semcaps caproot false "uid comum sem capability nao alcanca nada"
exigir semcaps shadow  false "e o kernel concorda"
exigir semcaps consentimento false "sem privilegio, o servidor sobe sem --allow-root"
exigir root caproot true "euid 0 continua concedendo"

# 5. O portao de consentimento e CONSERVADOR: qualquer capability de observacao
#    exige --allow-root, mesmo quando ela nao concede CapRoot. Sao perguntas
#    diferentes — "isto alcanca as superficies?" e "isto pede consentimento?".
for c in dac ptrace sysadmin dac_ptrace sysadmin_ptrace; do
  exigir "$c" consentimento true \
    "capability de observacao presente: o operador tem de dizer --allow-root"
done

# 6. capget(2) respondeu em todos os casos.
for c in semcaps dac ptrace dac_ptrace sysadmin sysadmin_ptrace root; do
  exigir "$c" capslidas true "capget(2) falhou: o portao cai para fail-closed"
done

if [ "$falhas" -ne 0 ]; then
  echo; echo "$falhas afirmacao(oes) falharam"; exit 1
fi
echo "OK: o alcance medido bate com o alcance decidido, nos sete casos"
