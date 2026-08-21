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

Use `info` quando a pergunta for "o que está acontecendo?" e `scan` quando a
pergunta for "quais sinais de comprometimento existem?".

---

## Quando usar cada comando

```text
preciso de uma visão rápida?             -> wtf
quero uma triagem completa agora?        -> scan
quero entender um processo/arquivo/IP?   -> info
a evidência pode desaparecer?            -> preserve
quero sair rápido do host?               -> collect
quero analisar depois/offline?           -> analyze
suspeito que o host esteja escondendo?   -> scan --root
o comportamento aparece e some?          -> watch
tenho um estado conhecido anterior?      -> baseline
quero saber exatamente quais regras há?  -> checks
```

Catorze fluxos concretos de investigação — do "entrei no servidor e alguma
coisa parece errada" ao "tenho centenas de servidores para triar" — estão em
**[docs/PLAYBOOKS.md](docs/PLAYBOOKS.md)**.

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
| `preserve` | preserva artefatos voláteis ou arquivos selecionados |
| `baseline` | captura um estado de referência |
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
- `preserve --out`.

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
```

- `scenarios` executa a CLI contra ambientes Linux reais/isolados;
- `race` roda o detector de data races, incluindo a suíte de cenários;
- `mutacao` injeta mutações em decisões dos checks para verificar se os testes
  detectam regressões semânticas.

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
