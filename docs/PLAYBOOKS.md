<!-- Extraído do README para não afogar o começo dele: eram 600 das 1450 linhas,
     e quem chega pela primeira vez precisa de instalação e primeiro comando,
     não de quinze fluxos completos. -->

# Quando usar cada comando

> "Cenário" aqui é um FLUXO DE INVESTIGAÇÃO — a situação em que você está e o
> que fazer nela. Não confundir com os cenários de
> [SCENARIOS.md](SCENARIOS.md), que são hosts montados de propósito para provar
> que um check dispara.

A forma mais simples de pensar na CLI é:

```text
preciso de uma visão rápida?             -> wtf
quero uma triagem completa agora?        -> scan
quero entender um processo/arquivo/IP?   -> info
a evidência pode desaparecer?            -> preserve
quero sair rápido do host?               -> collect
quero analisar depois/offline?           -> analyze
suspeito que o host esteja escondendo?   -> scan --root
o comportamento aparece e some?          -> watch
tenho um estado conhecido anterior?       -> baseline
quero saber exatamente quais regras há?  -> checks
não confio no binário que está no host?  -> mídia read-only (Cenário 14)
quero um agente investigando?            -> mcp (Cenários 16-19)
```

Abaixo estão fluxos concretos de investigação.

## Cenário 1: "Entrei no servidor e alguma coisa parece errada"

Você ainda não tem um IOC específico. Quer saber rapidamente se existem sinais
óbvios de comprometimento sem começar examinando centenas de processos à mão.

Comece por:

```sh
sudo ./aletheia wtf
```

Se aparecer algo relevante ou se você quiser uma triagem mais completa:

```sh
sudo ./aletheia scan -v
```

Se quiser guardar a análise:

```sh
mkdir -p /mnt/ir/host-01

sudo ./aletheia scan \
  -v \
  --json /mnt/ir/host-01/scan.jsonl
```

Use este fluxo para perguntas como:

```text
"esse servidor parece comprometido?"
"há persistência estranha?"
"há processo fileless?"
"há reverse shell?"
"há sinais de rootkit ou BPF suspeito?"
```

`wtf` é para orientação rápida. `scan` é o diagnóstico de triagem.

---

## Cenário 2: "Achei um processo suspeito"

Suponha que você encontrou o PID `812`.

Antes de matar o processo:

```sh
sudo ./aletheia info process 812
```

Isso ajuda a responder:

```text
qual é o executável real?
quem é o pai?
quais sockets pertencem a ele?
há namespaces diferentes?
o executável foi apagado?
há mapas de memória suspeitos?
```

Depois rode a triagem completa para buscar contexto ao redor do processo:

```sh
sudo ./aletheia scan -v
```

Se houver evidência volátil, preserve:

```sh
mkdir -p /mnt/ir/case-812

sudo ./aletheia preserve \
  --out /mnt/ir/case-812 \
  --pid 812 \
  --mem
```

Só depois disso considere matar o processo ou remover persistência.

A ordem é importante porque casos como estes podem desaparecer ao encerrar o
PID:

```text
/proc/812/exe -> /tmp/.x (deleted)
memfd:payload
código injetado em mapping anônimo
socket ativo de C2
```

---

## Cenário 3: "O processo está disfarçado de kernel thread"

Você encontra algo como:

```text
[kswapd0]
[kworker/0:1]
[card0-crtc8]
```

mas suspeita que seja userspace.

Primeiro:

```sh
sudo ./aletheia info process <PID>
```

Depois:

```sh
sudo ./aletheia scan --only proc,net,persist -v
```

Aletheia pode correlacionar situações em que:

```text
argv aparenta kernel thread
+
existe /proc/<pid>/exe apontando para ELF userspace
+
há socket outbound
+
há persistência relacionada
```

Se o executável estiver apagado ou for fileless:

```sh
sudo ./aletheia preserve \
  --out /mnt/ir/case \
  --pid <PID> \
  --mem
```

Esse é um caso onde `kill -9` como primeiro comando pode destruir a melhor
evidência disponível.

---

## Cenário 4: "Tenho um IP de C2 ou outro IOC"

Você recebeu um endereço suspeito:

```text
203.0.113.10
```

Para olhar somente esse alvo:

```sh
sudo ./aletheia info ip 203.0.113.10
```

Para correlacioná-lo com toda a triagem, crie:

```yaml
# incident.yml
ips:
  - 203.0.113.10
```

e execute:

```sh
sudo ./aletheia scan \
  --ioc incident.yml \
  -v
```

Uma lista pode combinar vários tipos de indicador:

```yaml
ips:
  - 203.0.113.10

paths:
  - "*/.config/htop/defunct"
  - "/tmp/.x"

strings:
  - "gs-netcat"
  - "GS_ARGS"

hashes:
  - "0123456789abcdef..."
```

Se o host já foi coletado anteriormente:

```sh
./aletheia analyze host.json --ioc incident.yml
```

Isso permite aplicar IOCs que só ficaram conhecidos depois da aquisição.

---

## Cenário 5: "Tenho pouco tempo no host comprometido"

Você quer minimizar permanência e comandos executados no alvo.

Faça somente a aquisição:

```sh
sudo ./aletheia collect \
  --out /mnt/ir/host-01.json
```

Depois copie o dump para uma estação confiável e saia do host.

Na estação de análise:

```sh
./aletheia analyze host-01.json -v
```

Mais tarde, você pode repetir a análise:

```sh
./aletheia analyze host-01.json \
  --ioc incident.yml \
  --since 7d \
  -v
```

Use esse fluxo quando:

```text
o servidor é crítico;
você quer reduzir interferência;
há várias máquinas para coletar;
o analista que fará a investigação não está no host;
novos IOCs podem surgir depois.
```

O dump guarda o que foi observado no momento da coleta, inclusive lacunas de
cobertura.

---

## Cenário 6: "Suspeito que ls, ps ou o próprio kernel estejam escondendo coisas"

Se existe suspeita de rootkit, não fique repetindo comandos dentro do mesmo
ambiente esperando que a próxima consulta seja magicamente mais honesta.

Obtenha um snapshot do disco e monte-o read-only em uma máquina confiável:

```sh
sudo mount -o ro /dev/mapper/snapshot /mnt/suspect
```

Então:

```sh
./aletheia scan \
  --root /mnt/suspect \
  -v
```

Você também pode inspecionar algo específico:

```sh
./aletheia info \
  --root /mnt/suspect \
  file /etc/ld.so.preload
```

Esse fluxo é indicado para procurar:

```text
arquivo escondido no host live
biblioteca adulterada
systemd unit maliciosa
cron persistence
authorized_keys
módulo em disco
alterações de loader
```

Importante: `--root` troca a autoridade usada para observar o **filesystem**.
Ele não recupera processos ou código exclusivamente em RAM.

Se a hipótese for comprometimento real do kernel, combine isso com aquisição de
memória externa ao guest.

---

## Cenário 7: "A conexão ou processo aparece por poucos segundos"

Um `scan` é uma fotografia. Alguns comportamentos são temporários:

```text
beacon a cada 30 segundos
processo que nasce, executa e morre
reverse shell reconectando
worker criado periodicamente por cron
```

Use:

```sh
sudo ./aletheia watch \
  --interval 2s \
  --full 30s \
  --for 15m
```

Se você estiver principalmente interessado em processo e rede:

```sh
sudo ./aletheia watch \
  --only proc,net \
  --interval 1s \
  --full 60s \
  --for 10m
```

O intervalo é um compromisso:

```text
intervalo menor -> maior chance de pegar eventos curtos
intervalo maior -> menos custo de coleta
```

Polling ainda pode perder algo que exista por menos tempo que o intervalo.

Para monitoramento permanente, Aletheia não substitui sensores event-driven
instalados previamente.

---

## Cenário 8: "Quero capturar o tráfego do processo suspeito"

Depois de identificar um peer:

```sh
sudo ./aletheia info process 812
```

preserve uma janela de tráfego:

```sh
sudo ./aletheia preserve \
  --out /mnt/ir/case-812 \
  --pcap \
  --iface eth0 \
  --host 203.0.113.10 \
  --port 443 \
  --proto tcp \
  --duration 120s
```

Se quiser capturar tudo na interface, isso precisa ser explícito:

```sh
sudo ./aletheia preserve \
  --out /mnt/ir/case-812 \
  --pcap \
  --iface eth0 \
  --all \
  --duration 60s
```

Captura sem filtro pode conter credenciais e tráfego de terceiros. Trate o PCAP
como evidência sensível.

---

## Cenário 9: "Há um programa BPF suspeito"

Comece pelo scan focado em kernel:

```sh
sudo ./aletheia scan --only kernel -vv
```

Se um finding apontar um programa BPF específico, preserve o bytecode antes que
ele desapareça:

```sh
sudo ./aletheia preserve \
  --out /mnt/ir/kernel-case \
  --bpf 42
```

Isso é especialmente importante porque um programa BPF pode existir apenas em
memória e desaparecer quando suas referências forem removidas ou quando a
máquina reiniciar.

Um finding BPF forte deve aumentar a suspeita sobre a confiabilidade das demais
visões fornecidas pelo kernel, mas ainda não substitui aquisição externa de
memória.

---

## Cenário 10: "Quero investigar só persistência"

Em vez de executar o conjunto inteiro:

```sh
sudo ./aletheia scan \
  --only persist \
  -vv
```

Isso direciona a triagem para mecanismos como:

```text
cron
systemd
SSH
ld.so.preload
environment preload
modprobe install
file watchers relacionados a persistência
```

Se quiser olhar o filesystem fora da máquina suspeita:

```sh
./aletheia scan \
  --root /mnt/snapshot \
  --only persist \
  -vv
```

O segundo formato é preferível quando você suspeita que a visão live esteja
sendo manipulada.

---

## Cenário 11: "Quero investigar especificamente sinais de kernel compromise"

Comece reunindo as evidências live disponíveis:

```sh
sudo ./aletheia scan \
  --only kernel \
  -vv
```

Procure principalmente por combinações, não apenas por uma linha isolada:

```text
divergência entre /proc/modules e /sys/module
+
taint de módulo sem explicação
+
hook ftrace em função sensível
+
BPF sem owner ou inconsistente entre visões
+
processos ou threads divergindo entre censos
```

Se houver uma inconsistência forte, trate o kernel como suspeito.

A próxima etapa não deve ser simplesmente executar o mesmo scan novamente.
Prefira mudar a fonte de evidência:

```text
1. preservar evidência volátil;
2. snapshot de disco;
3. scan --root em máquina confiável;
4. aquisição de RAM pelo hypervisor, quando possível;
5. análise forense de memória.
```

Aletheia pode levantar e correlacionar sinais de comprometimento de kernel, mas
uma coleta executada dentro do próprio kernel suspeito não consegue certificar
sua integridade.

---

## Cenário 12: "Tenho dezenas ou centenas de servidores para triar"

Para uma primeira passagem rápida por SSH:

```sh
ssh web01 'sudo ./aletheia wtf --oneline'
ssh web02 'sudo ./aletheia wtf --oneline'
ssh web03 'sudo ./aletheia wtf --oneline'
```

O exit code pode ser usado pela automação:

```sh
sudo ./aletheia wtf --oneline
rc=$?

case "$rc" in
  0) echo "sem findings e cobertura completa" ;;
  1) echo "warning ou cobertura incompleta" ;;
  2) echo "critical" ;;
  3) echo "erro da ferramenta" ;;
esac
```

Para hosts que merecem aprofundamento:

```sh
sudo ./aletheia collect --out /mnt/ir/"$(hostname)".json
```

e centralize a análise em uma estação limpa:

```sh
./aletheia analyze web01.json
./aletheia analyze web02.json
```

---

## Cenário 13: "Quero comparar com um estado conhecido anterior"

Crie baseline apenas quando você tem motivos para considerar o estado atual uma
boa referência:

```sh
sudo ./aletheia baseline -o baseline.json
```

Depois:

```sh
sudo ./aletheia scan \
  --baseline baseline.json \
  -v
```

Isso é útil para distinguir:

```text
"essa unit apareceu hoje"
```

de:

```text
"essa unit já existia na referência"
```

Mas baseline não é allowlist de legitimidade.

Se você criar a baseline depois que o invasor já entrou, o comprometimento
também vira "estado conhecido".

Baseline de esquema anterior é **recusada**, não interpretada: se aparecer
`baseline de esquema incompatível: recapture`, recapture em vez de procurar
contorno. Interpretar uma chave com a forma errada casa achado com achado
errado, e o erro cai para o lado de marcar como conhecido o que é novo — que é
o oposto do que a comparação existe para fazer.

---

## Cenário 14: "Preciso rodar no host, mas não confio no que já está lá"

O binário que você executa é a única coisa da investigação que você controla
inteiramente — desde que ele não venha do host suspeito e não possa ser trocado
depois de chegar.

Prepare a mídia na máquina limpa, verificando antes de gravar:

```sh
ARCH=amd64
BASE="https://github.com/lex0c/aletheia/releases/latest/download"

curl -fLO "$BASE/aletheia-linux-$ARCH"
curl -fLO "$BASE/SHA256SUMS"
curl -fLO "$BASE/SHA256SUMS.minisig"

minisign -Vm SHA256SUMS -p aletheia.pub
sha256sum --ignore-missing -c SHA256SUMS

sha256sum "aletheia-linux-$ARCH" | tee /mnt/ir-media/HASH-ANOTADO
cp "aletheia-linux-$ARCH" /mnt/ir-media/aletheia
cp SHA256SUMS SHA256SUMS.minisig aletheia.pub /mnt/ir-media/
```

Idealmente numa mídia com **trava física** de escrita. Onde não houver, um
cartão SD com a trava, um pendrive com chave, ou uma imagem ISO gravada servem —
o que importa é que o host investigado não consiga reescrever o arquivo.

No host:

```sh
sudo mount -o ro,noexec,nosuid /dev/sdX1 /mnt/ir
```

O `noexec` é intencional: **copie** para executar, em vez de executar direto da
mídia. Assim a mídia continua sendo a referência, e o que roda é uma cópia cuja
identidade você confere:

```sh
cp /mnt/ir/aletheia /run/aletheia
chmod +x /run/aletheia
/run/aletheia version
```

O `sha256` impresso tem que ser igual ao `HASH-ANOTADO` da mídia. Se não for,
pare: alguma coisa entre a mídia e a execução alterou o arquivo.

Por que isso vale a pena:

```text
root no userland
        │
   pode reescrever /usr/bin, /tmp, PATH, LD_PRELOAD
        │
   NÃO pode reescrever mídia montada read-only
```

Contra comprometimento de **userland** isso é forte. Contra comprometimento de
**kernel**, não: quem controla o kernel controla a execução de qualquer binário,
inclusive a leitura que confere o hash. Aí a resposta deixa de ser proteger
melhor a ferramenta e passa a ser não confiar no ambiente de execução — bootar
mídia externa, ou analisar o disco de fora (Cenário 6).

E a mídia é evidência também: ela cria arquivos e montagens na timeline do host.
Anote quando foi montada.

---

## Cenário 15: "Quero saber exatamente por que um finding existe"

Liste o catálogo:

```sh
./aletheia checks
```

Depois rode com mais detalhe:

```sh
sudo ./aletheia scan -vv
```

Se quiser reduzir o ruído para um domínio:

```sh
sudo ./aletheia scan --only net -vv
```

ou:

```sh
sudo ./aletheia scan --only kernel -vv
```

O objetivo de `-vv` não é produzir um relatório "mais assustador". É mostrar
evidência e cobertura suficientes para você decidir se o finding é explicável,
falso positivo ou parte de uma correlação maior.

---

## Cenário 16: "Quero investigar com um agente, sobre um dump que já tenho"

O modo mais seguro de usar o MCP: nada é lido do host durante a sessão.

```sh
sudo ./aletheia collect --out /casos/vm-23.json
```

Configure o cliente apontando para o dump:

```json
{ "mcpServers": {
    "vm-23": { "command": "/opt/aletheia",
               "args": ["mcp", "--snapshot", "/casos/vm-23.json"] } } }
```

O agente tem 17 tools e nenhuma delas toca o filesystem. O servidor **re-aplica
a redação no ingresso**, então um dump de origem duvidosa não entrega segredo em
claro por afirmar que já foi redigido.

Peça ao agente que comece por cobertura, não por achados:

```text
session.status   → o alcance desta execução
coverage.get     → o que NÃO foi verificado, e por quê
findings.list    → os achados, com veredito
finding.get      → evidência e falsos positivos de um achado específico
```

Uma resposta com zero achados e `verdict: INCOMPLETE` significa "não consegui
olhar", nunca "host limpo". Se o agente concluir a partir da lista vazia sem
citar a cobertura, a conclusão está errada.

Para comparar dois momentos:

```sh
aletheia mcp --snapshot /casos/antes.json --snapshot /casos/depois.json
```

`snapshot.compare` exige que os dois retratos tenham sido coletados com o mesmo
alcance. Comparar uma coleta completa com uma volátil produziria centenas de
falsos "sumiu".

---

## Cenário 17: "Preciso investigar uma máquina remota, e não há agente instalado"

Não é preciso instalar nada antes do incidente. Copie o binário estático e use o
SSH que já existe:

```sh
scp aletheia ir@10.0.0.7:/opt/aletheia
ssh ir@10.0.0.7 'sudo tee /etc/sudoers.d/ir <<< "ir ALL=(ALL) NOPASSWD: /opt/aletheia"'
```

Configure o cliente com `ssh` como comando:

```json
{ "mcpServers": {
    "alvo": {
      "command": "ssh",
      "args": ["-T", "-i", "/casos/chave", "ir@10.0.0.7",
               "sudo -n /opt/aletheia mcp --live --allow-root"] } } }
```

O `-T` não é opcional. Com pty, o `ssh` ecoa a requisição de volta no stdout e
traduz `\n` em `\r\n`; o cliente lê o próprio pedido como resposta e o framing
não fecha.

O agente precisa tirar o próprio retrato antes de qualquer pergunta:

```text
snapshot.capture {"scope":"complete"}   ~10s, sustenta achado
snapshot.capture {"scope":"volatile"}   ~164ms, NÃO sustenta achado
```

O escopo volátil serve para pegar processo efêmero. Ele devolve zero achados com
o catálogo inteiro declarado não verificado — use quando a pergunta for "o que
está rodando agora", não "este host está comprometido".

Se não houver `sudo` disponível, o servidor sobe mesmo assim:

```sh
ssh -T 10.0.0.7 '/opt/aletheia mcp --live'
```

Ele roda como uid comum e declara em `session.status` as tools que ficaram
indisponíveis. É uma investigação parcial que diz exatamente o que não alcançou.

**Antes de atribuir qualquer coisa ao invasor**, compare horários. A conta, a
regra de `sudoers` e a sessão SSH que você criou para o caso aparecem no retrato,
e os processos da própria cadeia de acesso aparecem com `/proc` ilegível.

Depois da sessão não fica arquivo nem processo no host — apenas o login no
`wtmp`.

---

## Cenário 18: "O agente encontrou um achado e eu preciso do arquivo"

O perfil padrão responde sobre o retrato. Para ler bytes do host, o operador
precisa autorizar explicitamente — e são dois portões separados:

```text
--profile full      o agente escolhe QUE arquivo ler
--allow-secrets     os bytes CRUS podem sair do processo
```

A separação existe para permitir identificar um binário sem autorizar que o
conteúdo dele vá para um modelo remoto:

```sh
# identifica sem entregar conteúdo: file.hash, file.capabilities
ssh -T alvo 'sudo -n /opt/aletheia mcp --live --allow-root --profile full'

# entrega conteúdo: acrescenta file.read, file.xattrs, process.environ
ssh -T alvo 'sudo -n /opt/aletheia mcp --live --allow-root --profile full --allow-secrets'
```

Fluxo típico depois de um achado de persistência:

```text
finding.get         → a evidência e o caminho citado
file.inspect        → procedência do arquivo, no retrato
file.hash           → sha256 para comparar contra IOC ou pacote
file.capabilities   → capability em xattr, que não aparece em find -perm
file.read           → o conteúdo, se o operador autorizou
```

Estas tools **não** respondem sobre o retrato: elas leem o host no instante da
chamada, e o envelope traz `started_at`/`finished_at` em vez de `snapshot_id`.
Não trate o conteúdo como contemporâneo do snapshot.

Dois campos merecem leitura antes de concluir:

```text
path_binding: "exact"     nenhum symlink foi atravessado — o arquivo está no
                          caminho pedido, e isso é garantia estrutural
path_binding: "followed"  você pediu follow_symlinks; link_chain é observação,
                          e o que vale como fato são dev e inode

stable: false             o arquivo mudou durante o hash: o digest é de uma
                          mistura temporal e não vale comparação contra IOC
```

Cada leitura entra na trilha de auditoria com o caminho e a janela. Redirecione
para arquivo se o caso exigir cadeia de custódia da própria investigação:

```sh
... mcp --live --allow-root --profile full --audit-log /casos/vm-23.audit.jsonl
```

---

## Cenário 19: "Quero que o agente investigue, mas não confio no que ele vai concluir"

O servidor é desenhado para que a conclusão seja verificável, não para que seja
confiável por si. Três mecanismos, e vale saber usá-los.

**Cobertura em toda resposta.** Peça a origem do veredito:

```text
observability.verdict            OK exige achado nenhum E cobertura completa
observability.coverage           total, completos, parciais, não verificados
observability.collector_gaps     o que a COLETA não conseguiu ler
observability.kernel_trust_broken  o kernel entregou visões incompatíveis de si
```

Quando `kernel_trust_broken` não está vazio, nenhuma ausência de achado vale
como resposta — os achados continuam valendo.

**Falso positivo declarado.** Todo check automático declara os seus:

```text
checks.catalog   → o catálogo, com §ref do runbook e falsos positivos
finding.get      → os falsos positivos daquele check específico
```

Se o agente afirma um comprometimento sem ter descartado os falsos positivos
declarados, a afirmação é fraca — e a informação para descartá-los estava na
resposta.

**Texto do alvo é evidência, não instrução.** Toda resposta traz:

```json
"trust": { "domain": "host_supplied", "untrusted": true,
           "host_supplied_paths": ["data", "observability"] }
```

O conteúdo listado ali foi escrito por quem controla o host, o que inclui um
possível invasor. Um `.bashrc` plantado pode conter texto endereçado ao modelo.
Se o agente mudar de comportamento depois de ler evidência, isso é o achado —
não o pedido.

Para conferir qualquer conclusão fora do agente, o mesmo dump responde pela CLI:

```sh
aletheia analyze /casos/vm-23.json -vv
aletheia info --from /casos/vm-23.json file /etc/cron.d/telemetry
```

A cobertura que o MCP publica é a mesma que o `analyze` produz para a mesma
seleção. Divergência entre os dois é defeito, e há catraca para isso.
