# Aletheia

Aletheia coleta e correlaciona sinais de comprometimento em processos, memória,
rede, persistência, integridade de arquivos e kernel. O objetivo não é procurar
uma assinatura específica de malware, mas responder três perguntas durante um
incidente:

1. **O que é anormal neste host?**
2. **Quais evidências sustentam essa conclusão?**
3. **O que a ferramenta não conseguiu verificar?**

> **Aletheia é uma ferramenta de triagem, não uma prova de que o host está
> limpo.** Em um sistema cujo kernel já foi comprometido, interfaces como
> `/proc`, `/sys`, tracefs e até syscalls podem fornecer uma visão falsa. Para
> investigações de alta confiança, combine a coleta live com análise de
> filesystem montado externamente e, quando necessário, forense de memória.

---

## Por que o nome Aletheia?

**Alḗtheia** (`ἀλήθεια`) é uma palavra do grego antigo normalmente traduzida
como **verdade**, mas sua formação também carrega a ideia de
**des-ocultamento**: aquilo que deixa de estar escondido.

---

## O que ela procura

Aletheia trabalha com **comportamento, inconsistências e correlação de
evidências**, em vez de depender de uma base de assinaturas.

O catálogo completo — cada check, o que ele acusa, e o cenário que prova que ele
dispara — está em **[docs/SCENARIOS.md](docs/SCENARIOS.md)**, gerado do próprio
registro. Abaixo, alguns exemplos:

| Área | Exemplos |
| --- | --- |
| Processos e memória | execução via `memfd`, executável apagado ainda em execução, processo userspace disfarçado de kernel thread, mapas anônimos RWX, código executável anônimo e **sem rótulo** (a forma que sobra depois de `mmap(RW)`→`mprotect(RX)`), biblioteca apagada do disco e ainda mapeada, namespaces divergentes, `LD_PRELOAD`/`LD_AUDIT` em processos |
| Rede | provável reverse shell pela estrutura de FDs (fd 0/1/2 no mesmo socket) e por **ponte de pipe** (shell lê de um pipe cujo outro lado fala com a rede), processo fazendo conexões públicas e privadas compatíveis com pivot, correlação socket-processo, **socket que o `NETLINK_INET_DIAG` mostra e `/proc/net` não** — as duas visões vêm do mesmo kernel por caminhos de código diferentes |
| Persistência | `/etc/ld.so.preload`, cron suspeito ou excessivamente frequente, units/drop-ins/timers systemd, SSH `authorized_keys`, `modprobe install`, processos observando arquivos de persistência, parâmetro de boot que desliga proteção do kernel (`selinux=0`, `audit=0`, `lockdown=none`, `init=`) confrontado com o que o kernel responde, **interpretador `binfmt_misc`** com dono ou magic suspeito (registro vivo e configuração que volta no boot) |
| Integridade | arquivo de pacote modificado, sinais de timestomp, executável usado por root mas gravável por usuário menos privilegiado, arquivo cujo dono (uid/gid) não existe em `passwd`/`group` |
| Código servido | padrão de backdoor/webshell em PHP, JS e Python: sink de execução sobre entrada de request (`eval($_POST)`, `` `$_GET` ``, `system`, `subprocess shell=True`), com micro-taint de fluxo de duas linhas que respeita escopo de função e allowlist (`switch` de literais, `in_array` de lista fixa), e distinção entre entrada remota e local. Varre os web roots por padrão, a FS montada inteira com `--all-fs`, e `--ignore PATH` exclui uma árvore (a exclusão é declarada) |
| Kernel | divergência entre três visões independentes de módulos (`/proc/modules`, `/sys/module`, ftrace), módulos sem arquivo correspondente, taint inexplicado, hooks ftrace em funções sensíveis, programas BPF sem owner identificado — com o anexo de **tc (filtro e ação), XDP resolvidos por rtnetlink e cgroup por `BPF_PROG_QUERY`** (árvore inteira em BFS, com budget), de modo que só resta sem atribuição o que é segurado por MAPA (struct_ops, sockmap) —, inconsistências na enumeração BPF e cross-views de processos |
| Logs | o CONTEÚDO dos logs como TESTEMUNHA do passado, e não como lista de regex: eventos normalizados de `auth.log`/`secure`, `syslog`/`messages`, `kern.log`, `cron` e **`audit.log` montado por evento** (os registros `SYSCALL`+`EXECVE`+`CWD`+`PATH` do mesmo serial viram UMA execução, com o caminho resolvido). O que só o log tem: o **fingerprint da chave** que abriu a sessão — cruzado com os `authorized_keys` de agora —, o `COMMAND=` do sudo, e a execução que não existe mais no retrato. Cada arquivo declara **até onde do passado foi observado**, e host sem log em texto (journald-only) é ESCOPO, não lacuna |
| IOC | IPs, hashes, paths e strings fornecidos pelo investigador |

Um finding isolado nem sempre significa comprometimento. JITs legítimos,
agentes de observabilidade, ferramentas de administração, automação de sistema e
atualizações de pacotes podem produzir sinais semelhantes. Por isso os checks
registram falsos positivos conhecidos e o relatório mostra a evidência usada na
decisão.

Para ver o catálogo implementado na versão do binário que você está executando:

```sh
aletheia checks
```

---

## Por que um binário estático

Durante um incidente, o próprio userland pode estar adulterado.

Aletheia é compilado com `CGO_ENABLED=0` e não possui dependências Go externas.
A distribuição oficial produz binários estáticos para Linux em `amd64`, `arm64`
e `386`.

Isso reduz a dependência de componentes do host como:

```text
ps
ss
lsof
rpm
dpkg
libc dinâmica
shell scripts auxiliares
```

Sempre que possível, a ferramenta coleta os fatos diretamente de interfaces do
kernel e de arquivos de sistema.

Isso **não torna o binário imune a um kernel comprometido**. Apenas reduz a
quantidade de userland do alvo em que a análise precisa confiar.

### Operação não intrusiva e sem egress

Aletheia é projetado para operar **offline e de forma não intrusiva no host
investigado**: não inicia conexões de rede, consultas DNS, requisições externas,
telemetria ou uploads, e também não executa remediação automática nem modifica
intencionalmente arquivos, processos, serviços, regras de firewall,
configurações, permissões, módulos ou persistências encontradas. A ferramenta
observa o estado local e coleta evidências; arquivos só são criados quando o
operador solicita explicitamente uma saída, como `--out`, `--json`, `baseline`
ou `preserve`. `preserve --pcap` captura passivamente o tráfego já presente na
interface, sem gerar pacotes ou habilitar modo promíscuo. Ainda assim, como
qualquer ferramenta executada em um sistema vivo, sua própria execução pode
deixar efeitos mínimos de observação, como presença temporária em `/proc`,
page cache, eventos de auditoria e, sem privilégios suficientes para
`O_NOATIME`, eventual atualização de `atime`.

---

## Instalação

Prefira baixar e validar o binário em uma máquina limpa e só depois copiá-lo para
o host investigado.

```sh
ARCH=amd64   # amd64 | arm64 | 386

curl -fLO \
  "https://github.com/lex0c/aletheia/releases/latest/download/aletheia-linux-${ARCH}"

curl -fLO \
  "https://github.com/lex0c/aletheia/releases/latest/download/SHA256SUMS"

grep "aletheia-linux-${ARCH}$" SHA256SUMS | sha256sum -c -

chmod +x "aletheia-linux-${ARCH}"
mv "aletheia-linux-${ARCH}" aletheia
```

O `SHA256SUMS` viaja no mesmo release que os binários: ele pega download
corrompido e troca no caminho, **não** release adulterado. Há três âncoras acima
dele, e cada uma responde uma pergunta diferente.

### Assinatura destacada — verifica sem rede

É a que serve durante um incidente. A chave pública está versionada neste
repositório (`aletheia.pub`), você a carrega junto com o binário, e a verificação
não consulta ninguém:

```sh
curl -fLO \
  "https://github.com/lex0c/aletheia/releases/latest/download/SHA256SUMS.minisig"

minisign -Vm SHA256SUMS -p aletheia.pub
sha256sum --ignore-missing -c SHA256SUMS
```

O comentário confiável que o minisign imprime traz a tag e o commit, e vai
assinado junto — não é um campo que se reescreva de fora.

Rede segmentada durante contenção, ambiente isolado e link caído são exatamente
quando a verificação importa e quando as outras duas não funcionam.

### Proveniência — responde de onde veio

```sh
gh attestation verify "aletheia-linux-${ARCH}" --owner lex0c
```

Diz qual repositório, qual commit e qual workflow construíram o arquivo.
Falsificar exige comprometer o GitHub Actions, não só o release. **Exige rede.**

### Reconstruir e conferir — não confia em quem assinou

O toolchain é fixo no `go.mod` e a identidade da build sai do **git**, não do
relógio de quem compila. A mesma tag reconstrói byte a byte:

```sh
git clone --branch v0.2.0 https://github.com/lex0c/aletheia
cd aletheia && make repro
```

Os hashes impressos têm que bater com o `SHA256SUMS` do release. É a única
verificação que não pede confiança em nós — e a razão de `commitTime` vir do
commit e não do build: um timestamp de compilação daria hashes diferentes para o
mesmo código e quebraria a conferência para sempre.

### Identidade do binário no destino

```sh
./aletheia version
```

```text
aletheia 0.2.0
/mnt/ir/aletheia
sha256=9187f0...
commit=918719acf012
commit-em=2026-08-21T12:00:00Z
kernel mínimo (runtime): Linux 3.2
```

Versão, caminho real, SHA-256 do próprio executável e a identidade da build.
Compare com o que você anotou **na máquina limpa**.

> A comparação usa interfaces fornecidas pelo host em execução. Ela pega
> alteração em transporte e armazenamento; **não** estabelece integridade contra
> um kernel comprometido. Ver [Modelo de confiança](#modelo-de-confiança).

Evite baixar ferramentas diretamente no host suspeito quando isso não for
necessário. Cada arquivo criado e cada conexão nova passam a fazer parte da
timeline do incidente.

---

## Começando uma investigação

### 1. Visão rápida

```sh
sudo ./aletheia wtf
```

`wtf` executa uma triagem rápida com orçamento de tempo limitado. Checks que não
couberem no orçamento são reportados como não verificados, em vez de serem
tratados como negativos.

### 2. Scan completo

```sh
sudo ./aletheia scan -v
```

Para salvar saída estruturada:

```sh
sudo ./aletheia scan -v --json scan.jsonl
```

Para restringir a investigação a uma janela:

```sh
sudo ./aletheia scan --since 72h
```

Para investigar somente determinados subsistemas:

```sh
sudo ./aletheia scan --only proc,net,kernel
```

### 3. Preserve antes de destruir evidência

Se um processo suspeito estiver executando um binário apagado, código via
`memfd` ou regiões anônimas relevantes, preservar primeiro costuma ser mais
valioso do que matar primeiro.

```sh
mkdir -p /mnt/ir/case-001

sudo ./aletheia preserve \
  --out /mnt/ir/case-001 \
  --pid 812 \
  --mem
```

Também é possível preservar arquivos, bytecode BPF e tráfego de rede:

```sh
sudo ./aletheia preserve --out /mnt/ir/case-001 --file /path/suspeito
sudo ./aletheia preserve --out /mnt/ir/case-001 --bpf 42

sudo ./aletheia preserve \
  --out /mnt/ir/case-001 \
  --pcap \
  --iface eth0 \
  --host 203.0.113.10 \
  --duration 60s
```

Se a coleta for interrompida (Ctrl-C, ou o `SIGTERM` de um wrapper com timeout),
`preserve` fecha a peça em curso, **escreve o manifesto do que já foi preservado**
e sai com 130. Isso importa porque os hashes da origem — o que prova que a cópia
bate com o alvo — só existem na memória daquele processo: um dump de memória de
vários minutos morto no meio deixaria os arquivos no disco sem cadeia de custódia
nenhuma.

O sinal é notado **dentro** de uma peça, e não só entre elas: o dump de memória
consulta a interrupção a cada região, e a cópia de arquivo a cada fatia. Um
`--file` de gigabytes ou um `/proc/<pid>/exe` num mount de rede travado não
seguram mais o pedido de parada.

Um **segundo** sinal força a saída na hora, e aí o manifesto **não** é escrito —
o que estiver no diretório fica sem hash de origem. É a saída de emergência para
quando a primeira não responde; use-a sabendo o que ela custa.

Aletheia não mata processos, remove persistência ou altera regras de firewall.

---

## Coletar no alvo, analisar do lado limpo

Para reduzir o tempo gasto no host investigado, coleta e análise podem ser
separadas:

```sh
sudo ./aletheia collect --out host.json
```

Depois, em uma máquina de análise:

```sh
./aletheia analyze host.json
```

O mesmo dump pode ser reanalisado com novos IOCs:

```sh
./aletheia analyze host.json --ioc incident.yml
```

Exemplo:

```yaml
ips:
  - 203.0.113.10

hashes:
  - "0123456789abcdef..."

paths:
  - "*/.config/htop/defunct"
  - "*.dat"

strings:
  - "GS_ARGS"
  - "gs-netcat"
```

A análise **não melhora retroativamente a coleta**. Se determinada fonte não
estava acessível quando o dump foi criado, essa lacuna continua existindo na
análise offline.

### O que o `collect` coleta

`collect` captura os fatos estruturados que serão usados posteriormente pelos
checks do `analyze`.

Ele não salva simplesmente a saída de `ps`, `ss`, `lsof` ou outros comandos.
Aletheia coleta diretamente as fontes que conhece e normaliza os resultados em
um snapshot próprio.

Dependendo do kernel, modo de execução, permissões e interfaces disponíveis, o
dump pode conter:

| Área | Exemplos de fatos coletados |
| --- | --- |
| Host | hostname, kernel, arquitetura, distribuição, uptime, relógio e contexto da aquisição |
| Processos | PID, PPID, UID/GID, argv, executável real, estado, relações pai/filho, cgroups, namespaces e FDs |
| Memória de processos | mappings de `/proc/<pid>/maps` e informações necessárias para identificar `memfd`, executável apagado e mappings executáveis/anônimos |
| Ambiente | variáveis relevantes como `LD_PRELOAD`, `LD_AUDIT` e marcadores conhecidos de ferramentas |
| Rede | sockets TCP/UDP, endereços locais/remotos, estados, inode, associação socket-processo e direção inferida |
| Rede (segunda visão) | a mesma tabela de conexões enumerada por `NETLINK_INET_DIAG`, para confronto com `/proc/net` |
| eBPF | programas carregados, seus detentores (descritor, pin, link, tail call) e o ponto de anexação em interface (`XDP` e filtros de `tc`, lidos por rtnetlink) |
| Cron e `at` | crontabs, jobs periódicos, frequência e jobs `at` observáveis |
| systemd | units, drop-ins, timers e comandos configurados para execução |
| SSH | `authorized_keys`, opções de chave e configurações relevantes do `sshd` |
| Loader | `/etc/ld.so.preload`, configuração do dynamic loader e variáveis de preload persistentes |
| modprobe | regras `install`, `alias` e outras configurações relevantes de carregamento de módulos |
| Linha de boot | `/proc/cmdline` (com o que o kernel subiu) e a configuração do bootloader — GRUB, systemd-boot e UKI — (com o que o próximo boot vai aplicar) |
| initramfs | scripts de GERAÇÃO do initramfs (hooks de initramfs-tools, módulos do dracut, hooks do mkinitcpio, drop-ins do kernel-install) e arquivos embutidos por `install_items`/`FILES` — persistência que roda antes do userland |
| Filesystem | paths relevantes, ownership, permissões, timestamps, symlinks e metadata usada pelos checks |
| Pacotes | ownership de arquivos e hashes declarados pelo gerenciador de pacotes quando o formato é suportado |
| Integridade | hashes e metadata dos arquivos selecionados pela coleta para verificação |
| Kernel modules | módulos visíveis em `/proc/modules`, visão de `/sys/module`, arquivos `.ko` relacionados e taints |
| BPF | programas, maps, links, referências e owners que as APIs disponíveis permitem observar |
| ftrace | funções instrumentadas e callbacks visíveis em tracefs/debugfs |
| Kernel security | lockdown, assinatura obrigatória de módulos, Secure Boot, IMA, `modules_disabled`, `kptr_restrict`, `dmesg_restrict`, unprivileged BPF e Yama |
| Logs (estrutura) | inventário de `/var/log`: arquivos, gerações de rotação (contador e `dateext`), tamanhos e registros de login do `wtmp`/`btmp`/`utmp` |
| Logs (conteúdo) | eventos NORMALIZADOS de `auth.log`/`secure`, `syslog`/`messages`, `kern.log`, `cron` e `audit.log` — este montado por EVENTO, juntando os registros `SYSCALL`+`EXECVE`+`CWD`+`PATH` do mesmo serial. Cada arquivo declara o intervalo que foi efetivamente OBSERVADO, quantas linhas o parser entendeu, e o que ficou de fora — sem isso, uma lista vazia de eventos seria indistinguível de host tranquilo, arquivo ilegível e formato desconhecido |
| Cross-view | fatos usados para comparar visões independentes de processos, threads, módulos e BPF |
| Cobertura | quais fontes foram observadas, quais estavam parciais, quais não puderam ser verificadas e por quê |
| Aquisição | instante da coleta, versão/hash da ferramenta, capabilities disponíveis e lacunas encontradas |

O dump é JSON de uma linha, sem indentação: ele é consumido pelo `analyze`, e
formatar custaria uma segunda cópia do documento inteiro na memória do host
suspeito — no exato momento em que a ferramenta prometeu passar pouco tempo e
pouco recurso ali. Do lado limpo, `jq .` ou `python -m json.tool` resolvem a
leitura a olho nu.

O conjunto exato depende do host.

Por exemplo:

```text
tracefs não montado
        ->
ftrace não observável
        ->
lacuna registrada no dump

BPF_GET_NEXT_ID retorna EPERM
        ->
enumeração BPF indisponível
        ->
lacuna registrada no dump

/proc/<pid>/exe inacessível
        ->
facts daquele processo ficam parciais
        ->
analyze não transforma isso em "executável normal"
```

A mesma ausência pode ser lacuna num lugar e escopo em outro, e o coletor
discrimina: tracefs ausente num host bare-metal é lacuna (o kernel tem tracing e
a interface não está montada); dentro de um contêiner não é, porque o runtime
mascara `/sys/kernel` de propósito e o kernel ali é do host — o mesmo raciocínio
que o eBPF e o bootloader já seguiam.

O fluxo é:

```text
               HOST
                |
                v
             collect
                |
                v
        Facts + Coverage
                |
                v
           host.json
                |
          copia para fora
                |
                v
             analyze
                |
                v
      checks + correlation
                |
                v
             findings
```

Isso permite analisar o mesmo retrato várias vezes:

```sh
./aletheia analyze host.json
./aletheia analyze host.json --ioc incident.yml
./aletheia analyze host.json --since 72h
./aletheia analyze host.json --only kernel -vv
```

inclusive com uma versão futura da ferramenta, desde que o formato do dump seja
compatível.

O dump do `collect` **não é uma aquisição forense completa do host**.

Ele não equivale a:

```text
imagem bit-a-bit do disco
+
dump integral da RAM
+
captura contínua de rede
```

A diferença prática é:

```text
collect
  snapshot estruturado dos fatos que Aletheia sabe interpretar

preserve
  cópia explícita de evidência que pode desaparecer
  executável, arquivo, bytecode BPF, memória anônima, PCAP

scan --root
  análise de um filesystem montado externamente

aquisição forense externa
  imagem de disco / memória obtida fora do kernel suspeito
```

Se um processo possui um executável apagado ou código somente em memória,
`collect` registra os fatos observáveis sobre ele, mas para guardar os bytes
antes que desapareçam use `preserve`:

```sh
sudo ./aletheia preserve \
  --out /mnt/ir/case \
  --pid 812 \
  --mem
```

Se a hipótese inclui comprometimento do kernel, um dump produzido dentro do
próprio guest continua limitado pela visão fornecida por esse kernel. Nesse
caso, complemente a investigação com snapshot externo de disco e, quando
necessário, aquisição de memória pela camada de virtualização/hypervisor.

---

## Analisar um filesystem fora do host

Quando existe suspeita de rootkit ou adulteração do userland, prefira montar um
snapshot ou imagem de disco em uma máquina confiável:

```sh
./aletheia scan --root /mnt/rootfs
```

Nesse modo, a leitura do filesystem é feita pelo kernel da estação de análise,
não pelo kernel do host investigado.

### Cobertura da varredura de código

A peneira de webshell (`app.code_backdoor`) varre, por padrão, as árvores onde
código servido mora (`/var/www`, `/srv`, `/data`, `/usr/local/www`, os homes de
`/etc/passwd`, entre outras) — e não o `/` inteiro, porque arrastar `/usr` e as
camadas de contêiner custa caro sem acrescentar sinal.

Três flags ajustam o alcance, e cada uma vale em `scan`, `wtf` e `collect`:

```sh
# a FS montada INTEIRA, a partir de /: acha webshell num docroot fora da lista
# (Alias de Apache, vhost em /home/cliente). Pseudo-FS e montagem de rede são
# pulados e DECLARADOS; contêiner rodando, arquivo > 2 MB e ofuscação seguem fora.
sudo ./aletheia scan --all-fs

# excluir uma árvore grande e irrelevante do custo (repetível). A exclusão é
# DECLARADA no relatório — um backdoor ali dentro não foi procurado.
sudo ./aletheia scan --all-fs --ignore /data/xmls --ignore /var/backups

# mirar direto numa árvore suspeita, sem varrer o resto:
./aletheia scan --root /data/local/www/data/webapp
```

Quando a varredura estoura um teto (árvore gigante) ou você exclui um caminho, o
relatório **declara a lacuna** em vez de dizer "limpo" — a ausência de achado
onde não se olhou é desconhecimento, não resposta.

Há uma exclusão que **não** vira lacuna, e ela precisa estar dita aqui: árvores
de dependência são puladas pelo NOME, em qualquer nível, sem declarar nada.

```text
node_modules  vendor  bower_components  .git  .svn  .cache  .npm
site-packages venv  .venv  __pycache__  .cargo  .rustup  .gradle
.m2  .pnpm-store  .yarn  .mozilla  .terraform
```

Elas existem em quase todo host, e declarar lacuna por elas degradaria a
cobertura de forma permanente — o que gasta o sinal que separa "não achei" de
"não consegui olhar". A medição que fixou a lista: num corpus real elas eram
**53% dos arquivos e 39% dos bytes** que a varredura lia e passava por regex.

O limite fica DECLARADO aqui e no falso-positivo do check: **código escondido
dentro de uma dependência não é procurado**. Para incluí-las numa investigação
específica, aponte `--root` direto na árvore.

Isso é especialmente útil para procurar:

- persistência escondida;
- binários ou bibliotecas adulterados;
- arquivos que não eram visíveis durante a coleta live;
- alterações em units, cron, SSH, loader e configuração do sistema.

O modo `--root` não substitui análise de memória. Um implante exclusivamente em
RAM pode não existir no filesystem.

---

## Monitoramento de curta duração

```sh
sudo ./aletheia watch
```

`watch` repete amostras de processos e sockets e executa scans completos
periodicamente, reportando mudanças ao longo do tempo.

Exemplo:

```sh
sudo ./aletheia watch \
  --interval 2s \
  --full 30s \
  --for 10m
```

O que o amostrador conclui entra no exit code e no `--json` junto com o resto: um
destino que reaparece em intervalo constante é automação, não pessoa, e sai como
aviso — mesmo que a varredura completa nunca veja aquela conexão, porque ela dura
menos que um ciclo. Se o JSONL parar de ser gravado no meio da vigília (disco
cheio, por exemplo), o `watch` diz isso em stderr e não sai 0: um arquivo
truncado com exit 0 seria a ferramenta afirmando completude sobre um registro que
ela sabe estar incompleto.

Esse mecanismo usa polling. Um processo ou conexão que exista por menos tempo
que o intervalo pode escapar.

Se o objetivo é detecção contínua de eventos efêmeros, use uma solução instalada
antes do incidente baseada em audit/eBPF e trate Aletheia como ferramenta de
triagem e investigação.

---

## Inspeção sem veredito

`info` expõe os fatos coletados sem tentar classificá-los como comprometimento:

```sh
./aletheia info process
./aletheia info process 812

./aletheia info net
./aletheia info ip 203.0.113.10
./aletheia info port 443

./aletheia info file /usr/sbin/sshd
./aletheia info git /srv/app
```

Também funciona sobre um dump:

```sh
./aletheia info --from host.json process 812
```

> **Mudança de saída em `info --json`.** As chaves passaram a ser snake_case em
> inglês, como o resto do JSON produzido pela ferramenta: `Rotulo` virou
> `label`, `Valor` virou `value`, `Nota` virou `meaning`, e o mesmo vale para os
> censos de processo, de rede e de git. Até a v1.7.0 elas saíam com o nome do
> campo em Go. O JSONL de `scan`/`analyze` — que é o consumido pela agregação de
> frota — **não** mudou.

Use `info` quando a pergunta for "o que está acontecendo?" e `scan` quando a
pergunta for "quais sinais de comprometimento existem?".

---

## MCP — investigação conduzida por um agente

O subcomando `mcp` expõe a triagem a um agente por Model Context Protocol, sobre
stdio. O agente consulta achados, cobertura, dossiês e drift; e, sob
consentimento explícito, adquire evidência nova do host.

O servidor roda **dentro do host investigado** — não há nuvem, servidor central
nem agente residente. Para uma máquina remota, o canal é o SSH que já existe:

```sh
ssh -T alvo 'sudo -n /opt/aletheia mcp --live --allow-root'
```

A regra que governa o desenho:

> O servidor concede **observação, não execução**. Dado do host é entrada
> adversária. Privilégio é herdado, nunca adquirido. Evidência ausente nunca é
> ausência de evidência.

Não existe tool que execute comando, escreva no host, encerre processo, resolva
nome ou abra conexão. O que a policy não autoriza não aparece em `tools/list`, e
a ausência é declarada em `session.status` com o motivo.

**Lista vazia não é host limpo.** O `outputSchema` de toda tool em forma de
achado exige `verdict` e `coverage`. Uma resposta sem achados vem acompanhada de
`INCOMPLETE` e da lista do que não foi verificado — é a promessa do exit code
traduzida para um canal que não tem exit code.

| Lançamento | Tools | O que acrescenta |
| --- | --- | --- |
| `--snapshot dump.json` | 18 | achados, cobertura, dossiês, drift |
| `--live` | 20 | `snapshot.capture` / `snapshot.release`, `crossview.get` |
| `--root PATH` | 13 | imagem montada: sem `/proc`, sem processo, sem socket |
| `+ --profile full` | 22 | `file.hash`, `file.capabilities` |
| `+ --allow-secrets` | 25 | `file.read`, `file.xattrs`, `process.environ` |

Referência completa — catálogo de tools, contrato de resposta, modelo de
segurança, limites declarados e diagnóstico: **[docs/MCP.md](docs/MCP.md)**.
Fluxos de investigação: [docs/PLAYBOOKS.md](docs/PLAYBOOKS.md), cenários 16–20.

## Comprometimento sem malware

A maior parte do que uma triagem encontra não é um arquivo. É credencial
roubada, ferramenta legítima e uma sequência operacional que não deveria ter
acontecido: entrou, escalou, criou conta, saiu. Não há binário para achar, nem
hash para comparar.

O que sobra é o **rastro do uso** — e ele mora em duas testemunhas que não
falam a mesma língua:

```text
/var/log/wtmp   registro BINÁRIO: quem entrou, de onde, quando, em que tty
/var/log/btmp   quem TENTOU e falhou                      (só root lê)
/run/utmp       quem está logado AGORA
auth.log        TEXTO: o método, o fingerprint da chave, o COMMAND do sudo,
                a conta criada, a execução que não existe mais
```

O comando `activity` junta as duas.

```sh
aletheia activity                                  # últimas 24h
aletheia activity --since 7d --user deploy
aletheia activity --around 2026-08-25T03:15Z --window 30m
aletheia activity --group-by ip
```

```text
2026-08-25
  03:12:41  auth.login.refused   root@185.44.1.7 password       [btmp+log:/var/log/auth.log ⇄pid]
  03:15:55  auth.login.accepted  deploy@185.44.1.7 publickey SHA256:AbCd pts/2  [wtmp+log:/var/log/auth.log ⇄pid]
  03:17:29  privilege.sudo       deploy → /usr/bin/cat /etc/shadow          [log:/var/log/auth.log]
  03:22:10  account.created      backup2                                    [log:/var/log/auth.log]

cobertura
  wtmp   2026-08-11T09:12Z → 2026-08-26T14:31Z · 2000 de 57412 registros (TRUNCADO: …)
  btmp   NÃO EXAMINADO — permission denied
  auth   2026-08-25T00:00Z → 2026-08-26T14:33Z
  pedido --since 7d: auth alcança 1d14h
```

Três decisões carregam o comando:

**A ligação é por identidade, e a ambiguidade se declara.** O `ut_pid` do wtmp
*é* o pid do sshd da sessão, e o envelope do syslog carrega o mesmo número. A
força sai impressa (`⇄pid`). Mas fundir REMOVE um registro da linha do tempo,
então a fusão só acontece no par **mutuamente único**: se dois registros
disputam a mesma linha de log — dois logins do mesmo usuário e origem a 50s um
do outro cabem os dois em ±90s —, a resposta é "ligação plausível, identidade
ambígua", e os dois eventos ficam. Testemunhas que **discordam** — mesmo pid e
mesma origem, contas diferentes — nunca fundem: apagar a contradição a
transformaria em corroboração. E sem o `/etc/localtime` do alvo não há fusão
nenhuma, nem por pid: a igualdade do número não depende do relógio, mas a
garantia de **não-reciclagem** depende.

**A cobertura exige âncora observada.** A leitura de login é da cauda, com teto
de 2000 registros por arquivo: num host que recebe 400 tentativas por hora, o
btmp alcança uma tarde. E o teto não é o único jeito de o passado ficar de
fora — o logrotate roda no wtmp e no btmp. Então a única prova positiva de
alcance é um registro **observado** anterior ao começo da janela: "li o arquivo
inteiro e não há rotacionado ao lado hoje" não prova nada sobre trinta dias
atrás, e arquivo vazio não cobre janela nenhuma (`: > /var/log/wtmp` deixa
exatamente essa forma). Se o **relógio saltou** dentro do que foi lido — o utmp
registra o par `OLD_TIME`/`NEW_TIME`, e `date -s`, NTP e restore de snapshot
produzem isso —, os carimbos dos dois lados vêm de réguas diferentes e nenhum
alcance é afirmado. Sem root o btmp é ilegível, e ali sai `NÃO EXAMINADO` —
nunca "0 recusas".

As gerações rotacionadas (`wtmp.1`, `btmp.1`) **ainda não são lidas** — só a
viva. A cobertura declara quantas ficaram fechadas ao lado; abri-las é o
próximo passo natural do comando.

**Divergência é estreita de propósito.** "O wtmp viu e o auth.log não" tem a
forma da manipulação de log — e tem, idêntica, a forma de várias coisas
rotineiras. As medidas que estreitaram a regra:

```text
recusa             btmp e auth.log não são 1:1 — uma conexão de bot escreve N
                   linhas de log contra um registro de btmp
console            login(1), gdm e lightdm escrevem wtmp e não escrevem
                   "Accepted": o parser só produz login aceito daquele prefixo
ssh não-interativo scp, rsync, git e ansible produzem "Accepted publickey" sem
                   sessão, e portanto sem registro de wtmp
```

Então a acusação vale só para **login aceito**, só na direção **binário →
texto**, e a decisão é por **arquivo**, não pela família: o mesmo arquivo que
cobre o instante precisa não ter lacuna declarada, ter datas confiáveis — o ano
de um syslog tradicional sai do mtime, que um `touch -d` reescreve, e erra em
*meses* — e já ter produzido evento daquele tipo **com a mesma forma de
origem**. Um auth.log que só registra login de rede não diz nada sobre a falta
de um login de console. Falhando qualquer uma: `não confirmado`.

O `wtf` traz um resumo disso em quatro linhas, com janela fixa de 24h. Ele
decide *por onde começar*; o `activity` investiga.

Em host **journald-only** (Debian 12, Fedora, RHEL moderno, Arch) não existe
`auth.log`: a família sai `FORA DE ESCOPO` com a via nomeada (`journalctl`).
Escopo declarado, nunca silêncio.

`activity` **não conclui** — sai 0 sempre, salvo erro de invocação. Quem conclui
é o `scan`, que traz os falsos positivos junto.

## Quando usar cada comando

```text
preciso de uma visão rápida?             -> wtf
quero uma triagem completa agora?        -> scan
quero entender um processo/arquivo/IP?   -> info
o que ACONTECEU aqui recentemente?       -> activity
a evidência pode desaparecer?            -> preserve
quero sair rápido do host?               -> collect
quero analisar depois/offline?           -> analyze
suspeito que o host esteja escondendo?   -> scan --root
o comportamento aparece e some?          -> watch
tenho um estado conhecido anterior?      -> baseline
o que MUDOU desde um retrato que eu tinha? -> drift
quero saber exatamente quais regras há?  -> checks
quero que uma IA investigue o retrato?   -> mcp
```

Catorze fluxos concretos de investigação — do "entrei no servidor e alguma
coisa parece errada" ao "tenho centenas de servidores para triar" — estão em
**[docs/PLAYBOOKS.md](docs/PLAYBOOKS.md)**.

---

## Drift — o que mudou desde um estado conhecido

Os checks são conhecimento: cada um sabe que uma forma é perigosa, e por isso
alcançam o que alguém já viu antes. O `drift` é expectativa, e alcança a mudança
para a qual **não há regra a escrever** — a de uma forma legítima para outra
forma legítima:

```text
ExecStart=/usr/bin/env sleep 30  ->  ExecStart=/usr/bin/env tail -f /dev/null
command="/usr/bin/rsync",restrict ssh-ed25519 AAAA…  ->  ssh-ed25519 AAAA…
```

A segunda é a mais silenciosa das duas: a chave continua a mesma, o fingerprint
não mudou, o arquivo tem uma linha como antes — e uma chave de tarefa única
virou acesso interativo irrestrito. Nenhuma das duas dispara check, em nenhuma
das pontas.

```sh
sudo ./aletheia collect --out ontem.json     # o retrato
sudo ./aletheia drift ontem.json             # o que mudou desde ele
sudo ./aletheia scan --drift ontem.json      # a triagem inteira, com o drift junto
```

O estado anterior é um **dump** do `collect` — não há formato novo, e o dump para
o qual você aponta *é* a pergunta que você está fazendo: contra o de ontem, "o
que mudou desde ontem"; contra o da instalação, "quanto este host se afastou do
que saiu de fábrica".

Três coisas que ele não faz, e cada uma por um motivo:

- **não guarda estado no host.** Uma referência guardada na máquina que ela
  descreve vale o que aquela máquina vale;
- **não compara retratos de alcance diferente.** Um dump com root contra um sem
  root fabricaria "sumiu" para tudo que só root enxerga. A família afetada é
  declarada, e o silêncio dela deixa de valer como resposta;
- **não data a mudança num instante.** Ela é datada por INTERVALO ("entre t0 e
  t1"), porque é só isso que se sabe: a ferramenta não estava presente na hora.

`--drift` e `--baseline` são eixos diferentes. A baseline fala do **achado** ("já
estava na lista?"); o drift fala do **objeto** ("a unit executa outra coisa
agora?"). Um achado que já estava na baseline, sobre uma unit cujo `ExecStart`
mudou ontem, sai marcado — e a severidade **não** sobe por isso: "mudou desde
ontem" tem a forma de um deploy.

---

## Comandos

| Comando | Uso |
| --- | --- |
| `scan` | coleta e executa os checks de triagem |
| `wtf` | triagem rápida com orçamento de tempo |
| `watch` | amostragem temporal de processos, rede e scans periódicos |
| `collect` | coleta fatos sem emitir veredito |
| `analyze` | analisa um dump previamente coletado |
| `info` | inspeciona processos, rede, arquivos, Git, IPs e portas |
| `activity` | reconstrói o que aconteceu: login, sudo, execução e conta, com a cobertura de cada testemunha |
| `preserve` | preserva artefatos voláteis ou arquivos selecionados |
| `baseline` | captura um estado de referência |
| `drift` | compara com um retrato anterior: o que mudou desde ele |
| `mcp` | serve um retrato a um agente de IA por MCP, sobre stdio |
| `checks` | lista checks, requisitos e falsos positivos conhecidos |
| `version` | mostra versão, caminho e hash do binário |

A referência completa de flags está no próprio binário:

```sh
./aletheia --help
./aletheia <comando> --help
```

---

## Cobertura

Aletheia trata cobertura como parte do resultado.

Um check pode estar:

```text
complete
partial
not checked
out of scope
```

Além disso, a própria coleta pode registrar lacunas quando uma fonte necessária
não estava disponível.

Exemplos comuns de LACUNA:

- execução sem privilégios suficientes;
- `/proc` montado com restrições;
- tracefs presente e ilegível, ou **não montado num host bare-metal** — ali o
  kernel tem tracing e a interface que denunciaria um hook por ftrace não está
  no ar, o que é diferente de não haver o que olhar (`mount -t tracefs nodev
  /sys/kernel/tracing` fecha a lacuna);
- base de pacotes existente e ilegível;
- dados que só podem ser observados no host live;
- limites internos atingidos durante uma coleta hostil ou muito grande.

Um resultado sem findings, mas com cobertura incompleta, não é equivalente a um
resultado totalmente observado.

### Lacuna e escopo não são a mesma coisa

O critério que separa os dois:

- se a pergunta **pode** ser feita neste host e não foi, é **lacuna** — ela
  derruba a cobertura e o veredito vira `INCOMPLETE`;
- se a pergunta **não existe** aqui, é **escopo** — ele aparece no rodapé, mas
  sai do denominador e não derruba nada.

Um kernel compilado sem `inet_diag` nunca vai responder ao `sock_diag`, e nenhum
privilégio muda isso. Enquanto essa ausência contava como lacuna, **toda**
varredura naquele host saía `INCOMPLETE` com exit 1 — inclusive a de um host
limpo —, e a mensagem ainda mandava usar `--allow-kernel-autoload`, que ali não
tem o que carregar. Uma lacuna que nunca fecha deixa de ser informação e vira
ruído fixo.

No rodapé de `--coverage` as duas listas saem separadas:

```text
COBERTURA  105/105 completos · 2 fora de escopo
  fora de escopo (o mecanismo não existe neste host; NÃO conta como lacuna)
    cross.socket_view — este kernel não OFERECE a enumeração de socket por netlink
```

O mesmo vale para o modo `image` (não há kernel vivo para consultar) e para
contêiner, onde `/sys/kernel` é mascarado pelo runtime de propósito.

E vale para o LOG, onde a distinção decide o resultado de metade da frota. Um
host que não instala rsyslog — Debian 12, Fedora e derivados — não tem
`/var/log/auth.log`: o journal é binário, e esta versão não o lê. A pergunta não
existe ali, então os checks de autenticação por log saem do denominador e a
cobertura fica intacta. Já um `auth.log` que EXISTE e não abre — ele é 0640
`root:adm` por desenho no Debian — é lacuna: a pergunta cabia e ficou sem
resposta. Os dois produzem a mesma lista vazia de eventos, e só a observabilidade
por fonte os separa.

Este é o primeiro escopo que só os FATOS respondem. Os outros três saem do
ambiente — modo, capability sem mecanismo, comparação ausente — e são decididos
antes de o check rodar; nenhum bit de capability diz que uma distribuição não
instala rsyslog.

---

## Exit codes

| Código | Resultado | Significado |
| ---: | --- | --- |
| `0` | `OK` | nenhum finding e cobertura completa |
| `1` | `WARNING` | existe warning ou a cobertura ficou incompleta |
| `2` | `CRITICAL` | pelo menos um indicador de alta confiança |
| `3` | `ERROR` | erro da ferramenta, argumentos ou ambiente inválido |

Isso permite usar o scanner em automação sem transformar uma falha de coleta em
"host limpo".

---

## Como pensar nos findings

Aletheia não usa uma regra simples de "arquivo estranho = malware".

Os checks tentam combinar sinais que ganham força quando aparecem juntos.

Exemplo conceitual:

```text
processo executando de memfd
        +
executável sem owner de pacote
        +
conexão outbound pública
        +
persistência relacionada
        =
investigação prioritária
```

Outro exemplo:

```text
processo com argv parecido com "[kworker/...]"
        +
/proc/<pid>/exe aponta para executável userspace
        =
userspace disfarçado de kernel thread
```

Para sinais de kernel, a estratégia inclui cross-view:

```text
/proc/modules
      vs
/sys/module
      vs
funções rastreáveis do ftrace
```

A terceira via pega o caso que as duas primeiras não separam: um módulo que se
desencadeia da lista para sumir do `/proc/modules` continua no `/sys/module`, o
que o torna indistinguível de um módulo embutido no kernel. O ftrace desfaz o
empate, porque o registro da função rastreável do módulo sobrevive a essa
ocultação e só é liberado no descarregamento real.

e:

```text
enumeração BPF
      vs
referências e abertura direta por ID
```

Cross-view aumenta o custo de ocultação, mas todas essas fontes ainda pertencem
ao mesmo kernel. Um rootkit suficientemente sofisticado pode falsificá-las de
forma coerente.

---

## Modelo de confiança

### O que Aletheia tenta não confiar

- comandos administrativos instalados no host;
- bibliotecas dinâmicas do userland;
- resolução DNS;
- reputação online durante o scan;
- uma única visão quando outra fonte local pode ser correlacionada.

### O que continua sendo uma autoridade no modo live

O kernel.

Isso é uma limitação fundamental.

Se o atacante tiver execução arbitrária no kernel, ele pode interferir com:

```text
procfs
sysfs
tracefs
BPF
netlink
VFS
syscalls
```

Por isso:

> **`RESULT: OK` significa "nenhum indicador coberto disparou". Não significa
> "este host foi provado íntegro".**

Quando a hipótese inclui comprometimento de kernel, aumente a independência da
evidência:

1. preserve o que for volátil;
2. obtenha snapshot do disco fora do guest;
3. execute `scan --root` em sistema confiável;
4. se necessário, adquira memória pela camada de virtualização/hypervisor;
5. faça análise forense de memória com ferramentas apropriadas.

---

## Baseline

```sh
sudo ./aletheia baseline -o baseline.json
sudo ./aletheia scan --baseline baseline.json
```

Uma baseline não transforma comportamento conhecido em comportamento legítimo.
Quando um finding já existia na baseline, ele continua no relatório e sua
severidade pode ser reduzida.

**Não crie uma baseline de confiança durante um incidente e assuma que o estado
capturado é benigno.** Se o comprometimento já existia, a baseline também o
capturou.

Uma baseline carrega o esquema da CHAVE que a identifica, e uma baseline de
esquema anterior é **recusada** em vez de interpretada — `recapture`. Recusar é
a única saída segura: uma chave lida com a forma errada casa achado com achado
errado, e o erro cai para o lado de marcar como conhecido o que é novo.

O esquema mudou para 2: a chave passou a admitir um discriminador do achado além
de `id|sujeito`. Sem ele, dois achados diferentes do MESMO check sobre o MESMO
sujeito colidiam — `priv.sudo_nopasswd` usa o usuário como sujeito, então uma
regra recém-inserida em `sudoers.d` herdava a presença da antiga e saía sem a
marca ✳NOVO, sob uma linha afirmando que já estava na baseline. Baselines
capturadas antes disso precisam ser recapturadas.

---

## Preservação e impacto no host

Os scanners não fazem remediação automática.

Comandos que recebem explicitamente um caminho de saída podem gravar os
artefatos solicitados, por exemplo:

- `collect --out`;
- `baseline -o`;
- `scan --json`;
- `preserve --out`;
- `mcp --audit-log`.

`mcp` sem `--audit-log` não escreve nada: a trilha de invocações sai no `stderr`,
que o cliente MCP pode capturar, encaminhar ou ignorar. O destino do
`--audit-log` precisa ser um arquivo comum — a saída padrão é o canal do
protocolo, e a ferramenta recusa apontar a trilha para lá.

As leituras de arquivos tentam usar `O_NOATIME` para reduzir alteração da
timeline. Quando o kernel ou as permissões não permitem esse modo, a ferramenta
pode precisar fazer uma leitura normal.

`preserve` é o comando destinado a copiar evidência do alvo. Nada dentro de
`--out` é sobrescrito silenciosamente.

---

## Arquitetura

A implementação separa aquisição de fatos de interpretação:

```text
              +----------------+
              | env / filesystem|
              +--------+-------+
                       |
                       v
                 +-----------+
                 | collectors |
                 +-----+-----+
                       |
                       v
                 +-----------+
                 |   Facts   |
                 +-----+-----+
                       |
            +----------+----------+
            |                     |
            v                     v
       +---------+           +----------+
       | checks  |           |   info   |
       +----+----+           +----------+
            |
            v
     +-------------+
     | correlation |
     | + coverage  |
     +------+------+
            |
            v
        +--------+
        | report |
        +--------+
```

`collect` serializa os fatos e a cobertura observada.

`analyze` reconstrói esse contexto e executa os checks depois, sem fingir que
fontes ausentes durante a aquisição ficaram disponíveis retroativamente.

Essa separação também permite que os checks sejam testados sobre fatos
controlados, enquanto cenários de integração exercitam a CLI contra sistemas
reais.

O servidor MCP entra como **mais um consumidor do mesmo domínio**, e não como um
segundo caminho de investigação:

```text
   CLI (info / scan / analyze / drift) ----+
                                           +--> info · check · drift · facts · dump · env
   tools MCP (internal/mcp) ---------------+
```

Ele não executa `aletheia info …` para parsear a saída, e não tem lógica de
investigação própria: uma pergunta nova nasce em `internal/info` e é servida
pelos dois lados. Do contrário o CLI e o agente passariam a responder coisas
diferentes sobre o mesmo retrato — e a cobertura, que é o rodapé obrigatório dos
dois, viraria duas contabilidades que divergem em silêncio.

### Docs

| | |
| --- | --- |
| **[docs/SCENARIOS.md](docs/SCENARIOS.md)** | o catálogo do que ela detecta: cada check, o que acusa, e o cenário que prova que dispara. Gerado do próprio registro |
| **[docs/PLAYBOOKS.md](docs/PLAYBOOKS.md)** | quando usar cada comando, e quinze fluxos de investigação de ponta a ponta |
| **[docs/RUNBOOK.md](docs/RUNBOOK.md)** | o runbook de resposta a incidente em Linux que originou os checks. É dele que vêm as seções (`§7.2`, `§35`) citadas em cada achado |

---

## Desenvolvimento

O projeto usa apenas a biblioteca padrão do Go.

Build local:

```sh
make build
```

Verificação padrão:

```sh
make verify
```

`verify` executa formatação, `go vet`, testes, build e confirma que o binário
resultante é realmente estático.

Testes adicionais:

```sh
make scenarios
make race
make mutacao
make fuzz
make test-386
make cap-proof
```

- `scenarios` executa a CLI contra ambientes Linux reais/isolados;
- `race` roda o detector de data races, incluindo a suíte de cenários;
- `mutacao` injeta mutações em decisões dos checks para verificar se os testes
  detectam regressões semânticas;
- `fuzz` busca no codec MCP, que é escrito à mão, o que ninguém imaginou — a
  mensagem e o **framing**, onde mora a drenagem que impede a cauda de uma linha
  gigante de virar mensagem nova;
- `test-386` **roda** a suíte em 32 bits, e não só compila: em i386 o `Timespec`
  do syscall é `int32`, e é por ele que passa a comparação de tempo e de tamanho
  de arquivo;
- `cap-proof` prova, com capability de arquivo num contêiner descartável, que
  `env.CapRoot` mede **alcance** e não euid. Cada caso tenta ler `/etc/shadow`:
  é a verdade de campo contra a qual a decisão do código é conferida. O caso
  decisivo é `CAP_SYS_ADMIN` sozinha — a capability mais larga do Linux, que o
  kernel **não** consulta na checagem DAC de leitura de arquivo.

Reconstruir um release (o que quem baixa roda para conferir):

```sh
git checkout v0.2.0 && make repro
```

`repro` compila as três arquiteturas com os mesmos flags do release e imprime os
hashes, **sem** rodar a suíte. A versão embutida sai de `git describe` do commit
conferido — o release compila com o `v` da tag **descascado**, e uma receita que
mandasse digitar `VERSION=v0.2.0` produziria outro binário e hashes que nunca
bateriam. `make repro-confere` é a catraca disso: compila como o release,
reconstrói pela receita publicada e compara os hashes; ela roda no workflow de
release, contra o artefato que está sendo publicado.

`dist` e `repro` compartilham a receita de build (`binarios`) de propósito: duas
cópias divergiriam em silêncio, e a conferência passaria a falhar sem nada de
errado com o código.

### Chave de assinatura do release

O release assina o `SHA256SUMS` com minisign. A chave pública é versionada
(`aletheia.pub`) para que a verificação funcione **offline**; a privada vive só
no segredo `MINISIGN_KEY` do repositório.

Para criar o par (uma vez, numa máquina confiável):

```sh
minisign -G -W -p aletheia.pub -s aletheia.key
```

`-W` gera a chave sem senha, porque quem a protege é o cofre de segredos do
GitHub — um prompt de senha não tem quem responda dentro de um workflow.

```sh
# a pública entra no repositório, versionada e revisável
git add aletheia.pub && git commit -m "chave pública de assinatura do release"

# a privada vira segredo e NÃO fica em disco
gh secret set MINISIGN_KEY < aletheia.key
shred -u aletheia.key   # guarde um backup offline antes
```

Enquanto o segredo não existir, o release **sai assim mesmo** e a nota dele diz,
em voz alta, que não tem assinatura destacada. Publicar em silêncio um release
indistinguível de um assinado seria a mesma mentira por omissão que a ferramenta
existe para não cometer.

Cross-compilação:

```sh
make arches
```

`arches` roda `go vet ./...` em `386` e `arm64` **antes** de construir, e o `./...`
não é detalhe: enquanto o alvo compilava só `./cmd/aletheia`, as duas
arquiteturas de ABI mais divergente eram as menos verificadas — tamanho de `int`,
número de syscall e layout de struct do kernel divergem justamente ali, e é onde
os arquivos `sys_*.go` existem.

Distribuição:

```sh
make dist
```

Gera binários Linux para as arquiteturas suportadas e hashes SHA-256.

---

## Limitações

Aletheia **não**:

- prova que um host está limpo;
- substitui aquisição e análise forense de memória;
- impede um kernel comprometido de mentir para uma coleta live;
- faz EDR contínuo;
- captura todos os processos ou conexões mais curtos que o intervalo de polling;
- decide automaticamente se uma chave SSH, ferramenta administrativa ou agente
  legítimo pertence à organização;
- usa reputação online ou consulta serviços externos durante o scan;
- remove malware ou corrige o sistema;
- deve ser usado como única fonte para encerrar uma investigação de
  comprometimento de kernel.

O objetivo é reduzir rapidamente o espaço de investigação, preservar evidência
importante e tornar explícito onde a observação foi forte, parcial ou impossível.

---

## Licença

MIT.
