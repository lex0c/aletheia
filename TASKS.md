# Aletheia — implementação

Derivado de `SPEC.md` §15. Cada tarefa é uma unidade coerente e verificável.
Marcar `[x]` só quando compila, roda e tem teste onde faz sentido.

---

## Fase 1 — esqueleto  ▸ estabelece o padrão para todo o resto

- [x] **1.1** `go.mod`, layout, `Makefile`, build estático verificado (`file` diz `statically linked`)
- [x] **1.2** `internal/env` — `Cap`, `Source`, `Probe()`, `Path()` (prefixo `--root`), relógio, hash do próprio binário
- [x] **1.3** `internal/check` — `Severity`, `Origin`, `Finding`, `Result`, `Check`, registry com validação no `init`
- [x] **1.4** `internal/facts` — `Host` + `Processes`: a passada única em `/proc`, com as armadilhas de parsing da spec §9
- [x] **1.5** `internal/check/engine` — `Requires`/`Optional` → `NOT_CHECKED`/`Partial`, cobertura com denominador = conjunto selecionado
- [x] **1.6** `internal/report` — default compacto, `-v`, JSONL, rodapé de cobertura, exit code
- [x] **1.7** `cmd/aletheia` — dispatch sem framework; `scan` e `checks`
- [~] **1.8** auto-identificação: `Self` marca a ferramenta e ancestrais no coletor;
        o marcador embutido para varredura de filesystem fica para a fase 4

## Fase 2 — checks de processo  ▸ maior sinal por segundo

- [x] **2.1** `proc.exe_missing` — `/memfd:` e `(deleted)` (§3.16, §3.14)
- [x] **2.2** `proc.kthread_disguise` — cmdline vazio + argv0 `[…]` com exe existente, relendo contra corrida (§3.5)
- [x] **2.3** `proc.suspicious_path` — `/tmp`, `/dev/shm`, `~/.config/<dir>/<bin>`; `~/.local` é XDG legítimo (§8)
- [x] **2.4** `proc.caps_unexpected` — `CapEff` **comparado com o esperado**, não apenas != 0 (§3.7)
- [x] **2.5** `proc.tracer`, `proc.ns_divergent`, `proc.maps_rwx_anon` (§3.7, §3.15, §3.10)
- [x] **2.6** `correlate.revshell` — fd 0,1,2 no mesmo socket **descartando socket activation** (§17)
- [x] **2.7** `wtf` — mesma coleta, renderização e orçamento próprios

## Fase 3 — rede

- [x] **3.1** `facts/net` — `/proc/net/tcp{,6}` + mapeamento inode→pid sob orçamento
- [ ] **3.2** checks §2 — saída para IP público, listener fora de loopback
- [x] **3.3** `net.pivot` — **saída** externa + **saída** interna no mesmo PID (direção é o que separa do proxy)
- [ ] **3.4** `net.systemd_listener_orphan` — listener do PID 1 **sem** `.socket` unit correspondente

## Fase 4 — persistência (§7)  ▸ maior economia de tempo manual

- [ ] **4.1** `facts/systemd` — **baseado em arquivo**: units, timers, `.socket`, `.path`, `*.wants/`, drop-ins
- [ ] **4.2** cron, `at`, anacron — incluindo extração do intervalo `*/N`
- [ ] **4.3** SSH — `authorized_keys`, `sshd_config` efetivo, `AuthorizedKeysCommand`, `.ssh/rc`
- [ ] **4.4** shell startup — lista exata + diff contra `/etc/skel` (contexto, não achado) + `BASH_ENV`
- [ ] **4.5** loader — `ld.so.preload`, `ld.so.conf.d`, `/etc/environment`
- [ ] **4.6** `rc.local`/`init.d`/generators, PAM, udev, MOTD, hooks de pacote
- [ ] **4.7** CA plantada, `/etc/hosts`, resolver, git hooks, `auto_prepend_file`, metadata de nuvem
- [ ] **4.8** supervisores (pm2, supervisord) e containers (`docker diff`, restart policy)

## Fase 5 — IOC e janela  ▸ o que fecha a §23

- [ ] **5.1** `--ioc` — IPs, hashes, paths, strings, chaves, usuários
- [ ] **5.2** `--since` transversal, com a regra de default explícita

## Fase 6 — anti-forense e catálogo

- [ ] **6.1** família `antiforense` — wtmp com salto, log zerado, `HISTFILE` off, `chattr +a`, timestomp
- [ ] **6.2** `aletheia checks` — catálogo com coluna de falso positivo

## Fase 7 — integridade e privilégio

- [ ] **7.1** `§24` — `dpkg -V`/`rpm -Va` com `origin:tool:*` e rebaixamento
- [ ] **7.2** `§25`/`§36` — SUID, capabilities, sudoers, grupos, gravável-executado-por-root

## Fase 8 — kernel (§35)

- [ ] **8.1** taint decodificado (só bit 13 sem DKMS), `/sys/module` × `/proc/modules`, módulo sem arquivo
- [ ] **8.2** ftrace, kprobes
- [ ] **8.3** eBPF nativo via `bpf()` — `PROG_GET_NEXT_ID`, `GET_FD_BY_ID`, `OBJ_GET_INFO_BY_FD`

## Fase 9 — checks manuais parametrizados

- [ ] **9.1** §37 exfiltração, §10.4 nuvem, §34 hardening, §39 gestão — com âncora e instância preenchidos

## Fase 10 — `watch`

- [ ] **10.1** amostragem, diff entre snapshots, delta e periodicidade, casamento com gatilho

## Fase 11 — collect / analyze / fixtures

- [ ] **11.1** `collect` + `analyze` + `schema_version`
- [ ] **11.2** redação na camada de saída (relatório, JSONL, checklist, facts)
- [ ] **11.3** fixtures por distro + suíte rodando contra todas

## Fase 12 — `preserve`

- [ ] **12.1** `cp /proc/<pid>/exe` + `stat` + sha256 do original e da cópia
- [ ] **12.2** dump de memória nativo (`/proc/<pid>/maps` + `/proc/<pid>/mem`), sem ptrace
- [ ] **12.3** `--pcap` — AF_PACKET + `x/net/bpf`, com `PACKET_STATISTICS` reportado
- [ ] **12.4** run log em `$IR/aletheia-runs.jsonl`

## Fase 13 — rotina

- [ ] **13.1** `baseline` / `diff`
- [ ] **13.2** `readiness`

---

## Invariantes — valem para toda tarefa

```
todo check declara FalsePositives            init falha sem isso
todo check declara Requires/Optional/Sources
cobertura tem denominador = conjunto selecionado
nada escreve sem --out
sem rede, sem DNS, sem executar binário do host
tempo em UTC
campo ausente vira "desconhecido", nunca zero
limite de orçamento vira NOT_CHECKED, nunca truncamento silencioso
```

---

## Registro

**Fase 1 concluída** (esqueleto) + **2.1 / 2.2** (primeiros checks).

```
suíte            7 pacotes · 78 testes · `make verify` CONFIRMA o binário estático · `make verify` CONFIRMA o binário estático, não presume
16 arquivos Go   ~3.5k linhas

achado do teste  Path() deixava ".." escapar do --root: filepath.Join("/mnt/ir",
                 "/../../etc/shadow") resolvia para "/etc/shadow" — a ferramenta leria o
                 host do ANALISTA achando que lia a imagem. Corrigido ancorando com
                 Join("/", p) antes de prefixar. Um caminho pode vir de dado do alvo

achado do run    coleta parcial entrava na aritmética de checks, e o exit saiu 0 com 247
                 processos ilegíveis. Virou eixo próprio (CollectorGaps): não mexe na
                 conta de checks, mas impede veredito de OK

validação e2e    dois cenários plantados (exec -a e binário apagado) detectados com as
                 severidades certas. Kernel thread REAL não disparou — não tem exe
```

---

## Correções da revisão de código (1ª rodada)

15 defeitos confirmados. Os cinco piores eram a **própria promessa da ferramenta
invertida** — ela dizia "não achei" onde a resposta honesta era "não olhei".

```
GRUPO A — a mentira central
[x] nenhum check declarava Optional: CapRoot     sem root, 246 de 303 exe ilegíveis e o
                                                 relatório dizia "cobertura 3/3, exit 0".
                                                 Agora: parciais 3, INCOMPLETE, exit 1
[x] Register valida o invariante                 check que lê /proc e não declara CapRoot
                                                 faz o binário NÃO SUBIR
[x] PID descartado em silêncio                   sob hidepid a ferramenta via 4 de 310 e
                                                 dizia OK. Agora vira lacuna declarada
[x] exe ilegível lido como "kthread real"        um exec -a de root passava por thread de
                                                 kernel legítima num scan não-root
[x] --only com grupo inexistente                 "--only proc,net,kernel" alegava 3/3 sem
                                                 net nem kernel existirem. Agora: exit 3
[x] CollectorGaps ausente do JSONL               humano dizia INCOMPLETE, JSONL dizia 3/3

GRUPO B — dano causado pela ferramenta
[x] --json truncava caminho arbitrário           `--json /var/log/auth.log` zerava o log.
                                                 Agora O_EXCL: nunca sobrescreve
[x] NextSteps prometia `aletheia preserve`       subcomando inexistente; o operador seguia
                                                 para matar e destruía a única cópia.
                                                 Agora emite o `cp /proc/N/exe` que funciona
[x] panic saía com status 2 = CRITICAL           defeito da ferramenta virava "host
                                                 comprometido" na automação de frota.
                                                 Agora: recover, o check vira NÃO VERIFICADO

GRUPO C — evasão pelo atacante
[x] injeção de terminal via argv                 implante que põe ESC no próprio argv
                                                 limpava a tela e forjava RESULT: OK.
                                                 O campo de evidência era o veículo
[x] teto de fds cortava 0,1,2                    ReadDir ordena por NOME: fd 2 caía no
                                                 índice 612 de 1500. Agora ordena numérico
[x] --root escapava por symlink                  symlink ABSOLUTO (normal em rootfs real)
                                                 fazia ler o host do analista. Agora os.Root
                                                 (openat2/RESOLVE_BENEATH)
[x] sleep de 20ms serial                         50 processos de usuário sem privilégio →
                                                 1,2s e 50 críticos. Agora: 2ª passada,
                                                 UM sleep, com teto

GRUPO D/E — vazamento e falso positivo fabricado
[x] cmdline com senha ia para o ticket           pacote internal/redact, aplicado antes de
                                                 o dado entrar no achado
[x] processo morto virava CRITICAL               readNUL confundia ENOENT com vazio.
                                                 Agora distingue, e confere starttime
                                                 contra reuso de PID

BÔNUS — o PID 1 era isento de tudo
[x] ancestorsOf marcava toda a cadeia como Self  e a caminhada terminava em 1, então o
                                                 PID 1 nunca era avaliado em host nenhum —
                                                 junto com o sshd ancestral da sessão de IR
```

### A lição que fica

A suíte estava **verde através de tudo isso**, e em dois pontos produzia
confiança falsa:

```
TestCatalogoSatisfazInvariantes   iterava um registry VAZIO — o pacote `check` não pode
                                  importar `checks` (ciclo), então o corpo do laço nunca
                                  executava. Movido para internal/checks, onde o registry
                                  existe, e ganhou guarda contra reintroduzir
rebaixamento de confiança         4 testes o faziam parecer coberto; em produção é código
                                  morto (chaveia IDs não registrados, e nada gera ToolOrigin)
```

Testei o código que escrevi, não os invariantes que a spec declara. Onde é
possível, o invariante virou validação no `Register` — assim ele falha no build,
não numa revisão.

### Pendente desta rodada

```
[ ] rebaixamento de confiança      só sai do papel quando existir um check com origin:tool
                                   (fase 7, dpkg -V) e o de ld.so.preload (fase 4.5)
[ ] readCgroup escolhe a hierarquia errada no v1 — destrói a proveniência que promete
[ ] readMaps divide path por espaço — nome de diretório com espaço derrota MapsOdd
[ ] env.Reason colapsa gap de múltiplas caps para a ordem de declaração
[ ] Makefile: `dist` não depende de `verify` — GOOS=windows produz PE chamado -linux-*
[ ] build agora exige Go >= 1.25 (os.Root). Runtime segue com piso kernel 2.6.32
```

---

## Ambiente de teste (fase 11.3, adiantada)

`make scenarios` — a CLI de verdade, contra `/proc` de verdade, em distribuições
de verdade. Atrás da tag `scenarios` porque exige docker: `go test ./...`
continua rápido e sem dependência externa.

```
test/scenario/    cenários como arquivos Go, um init() cada — mesmo padrão dos checks,
                  sem parser, sem dependência. O script de plantio é literal de crase
test/helper/      binário estático que monta o que shell não monta: argv0 arbitrário
                  (exec -a é builtin do bash) e execução via memfd_create
test/scenario_test.go  runner: docker run, parse do JSONL, asserção
```

**Asserção pelo mesmo contrato que a frota consome.** O runner lê o JSONL —
`id`, `sev`, `subject` e a linha de cobertura. Testar por ele garante que o que
a suíte valida é o que o operador realmente recebe.

**Estado: 14 execuções verdes, 3 puladas com motivo escrito.**

```
[x] 00-limpo                    zero achados em contêiner intocado (debian, alpine)
[x] 01-sem-root                 cobertura DEGRADA e exit != 0 — o invariante central
[x] 02-kthread-real             kthread legítima não dispara: não tem exe
[x] 10-kthread-disguise         argv0 entre colchetes com exe resolvido
[x] 11-exe-apagado              binário removido com o processo vivo → WARN, não CRITICAL
[x] 12-pid1-nao-eh-isento       regressão: PID 1 é avaliado como qualquer outro
[x] 13-memfd-fileless           execução de memória anônima
[x] 20-image-symlink-absoluto   imagem não pode ler o host do analista
[x] 21-image-sem-processo       imagem sem /proc vira NÃO VERIFICADO, não "limpo"
[~] 90-kernel-antigo            exige VM: contêiner compartilha o kernel do host
[x] 30-hidepid-root             VM: com root, hidepid não esconde — o implante é visto
[x] 31-hidepid-sem-root         VM: sem root o implante é INVISÍVEL e a ferramenta DIZ
[~] 92-userland-trojanizado     construir quando a fase 7 (integridade) existir
```

### Dois invariantes que o harness impõe

```
todo check tem cenário    TestTodoCheckTemCenario recusa check que ninguém provou
                          disparar — mesma lógica do FalsePositives obrigatório.
                          Ele JÁ pegou o proc.memfd_exec sem cenário
binário roda em scratch   `file` DIZ que é estático; rodar numa imagem sem libc,
                          sem shell e sem coreutils PROVA. É a propriedade que
                          justificou escolher Go (SPEC 4)
```

### O que a matriz revelou

```
busybox despacha por argv[0]   em Alpine, /bin/sleep É o busybox: renomeá-lo faz ele
                               procurar um applet inexistente e sair. O cenário de
                               disfarce não plantava processo nenhum, e o de exe
                               apagado também não. Só a matriz pega isso — e é por
                               isso que o helper precisa ser alvo próprio e estático
--json - interleava            o JSONL saía misturado ao relatório humano no mesmo
                               stdout, então `scan --json - > out.jsonl` gerava
                               arquivo inválido. Corrigido: com --json -, o humano
                               vai para stderr
```

### O que o contêiner NÃO cobre — e não adianta fingir que cobre

```
kernel diferente     todo contêiner usa o kernel do HOST. centos:6 testa o layout de
                     userland, não o procfs do 2.6.32 — e osrelease reporta o host
hidepid, ptrace_scope, lockdown, cgroup v1 x v2    são do kernel/mount do host
systemd de verdade   a maioria das imagens não roda systemd
eBPF, ftrace, módulos  a fase 8 inteira precisa de VM
```

### Camada VM — `Mode: VM`

Para o que contêiner não alcança. **Não** é libvirt + qcow2 + virt-manager: isso
é a forma certa para VM de desenvolvimento e errada para suíte automatizada —
traz daemon, XML, permissões e estado persistente, e uma qcow2 de distro sobe em
5–20s. Com dezenas de cenários, ninguém roda mais.

```
kernel     /boot/vmlinuz do HOST — cobre mount, sysctl, módulo, cgroup, eBPF.
           NÃO cobre o FORMATO antigo de procfs: isso exige kernel de época
guest      initramfs construído do `docker export alpine` + os dois binários
           estáticos + um /init de ~40 linhas. Sem qcow2, sem qemu-img, sem
           bootloader, sem cloud-init, sem debootstrap
entrada    cenário em base64 na linha de comando do kernel
saída      console serial (`-serial file:`). Sem rede, sem disco compartilhado,
           sem SSH — o texto que diz "não monte nada do host" só fecha se houver
           um canal, e este é ele
boot       ~0,5s. Instalar: apenas `qemu-system-x86` (19,6 MiB de download)
```

O par `30`/`31` é o coração da suíte: **mesmo implante, mesmo instante.** Com
root, `CRITICAL`, exit 2. Sem privilégio sob `hidepid=2`, o implante é
genuinamente invisível — e a asserção é dupla: o achado NÃO aparece **e** o
veredito NÃO pode ser OK. Sai `0/3 · INCOMPLETE · exit 1`.

Antes da correção da revisão, essa segunda execução imprimia `RESULT: OK`,
exit 0, com um implante CRITICAL bem ali. Agora existe teste no ambiente exato
em que o defeito se manifestava.

### Mais um defeito que o ambiente expôs

```
--json /dev/console recusado   o O_EXCL que fecha `--json /var/log/auth.log`
                               bloqueava também device e fifo, que são uso
                               legítimo. A regra passou a ser por TIPO: recusa
                               arquivo REGULAR existente; device/fifo/socket
                               abre sem criar e sem truncar
```

---

## Registro — rede (2.6, 3.1, 3.3)

`facts/net` lê `/proc/net/tcp{,6}` e junta inode→PID pelos fds que o coletor de
processo já tinha lido. Duas coisas custaram o tempo:

```
endianness    o endereço vem em hex com cada palavra de 32 bits em ordem de
              HOST. Ignorar a inversão faz 127.0.0.1 virar 1.0.0.127 — e aí
              loopback é classificado como público, e o relatório acusa "saída
              para endereço público" em todo processo local
direção       o kernel NÃO registra quem iniciou a conexão. É inferida
              comparando a porta local com a tabela de LISTEN. O parser foi
              conferido contra o `ss` do host: IPs, portas, estados e o join
              inode→PID batem
```

**A direção é o produto todo.** Sem ela os dois checks estão errados, e errados
do jeito pior — disparando no que é legítimo:

```
correlate.revshell   fd 0,1,2 no mesmo socket é também a forma EXATA da ativação
                     por socket do systemd (StandardInput=socket) e do inetd.
                     Sem a direção, dispara em sshd.socket
net.pivot            saída externa + saída interna é também a forma de todo
                     proxy reverso. Sem a direção, dispara em todo nginx
```

Por isso os cenários vêm em par: uma forma que precisa disparar e a forma
legítima quase idêntica que não pode. O positivo sozinho não prova que o check
discrimina — prova só que ele dispara.

```
40-revshell                            CRITICAL, exit 2
41-socket-activation-nao-eh-revshell   Forbid revshell — a matriz inteira
42-pivot                               WARN, exit 1
43-proxy-reverso-nao-eh-pivo           Forbid pivot
```

### Endereço público sem rede

Os cenários precisam de peer de escopo público para exercitar a classificação, e
depender de internet num teste é inaceitável. `--network=none` mais
`--cap-add=NET_ADMIN`, e o cenário cria apelidos em `lo`:

```
ip addr add 51.91.190.241/32 dev lo     público para quem classifica
ip addr add 10.0.0.9/32      dev lo     privado para quem classifica
```

Nenhum pacote sai do namespace. O contêiner não tem sequer `eth0`. Isso também
tornou desnecessário levar estes cenários para a VM — o que estava sob teste era
a classificação, não o kernel.

### Limite conhecido, registrado no código

Não há campo de direção em `/proc/net/tcp`, e não há fonte melhor sem conntrack
ou eBPF. A inferência erra em dois casos, ambos caros de provocar:

```
falso NEGATIVO   implante que amarra a porta de origem numa porta também em
                 LISTEN aparece como entrada
falso POSITIVO   serviço que fecha o listener depois do accept: a conexão
                 aceita passa a parecer saída
```

Trocar isso por faixa de porta efêmera seria pior — é chute, e quem escolhe a
porta é o implante.

---

## Registro — caminho, privilégio e memória (2.3, 2.4, 2.5)

Cinco checks novos: `proc.suspicious_path` (§8), `proc.caps_unexpected` (§3.7),
`proc.tracer` (§3.7), `proc.maps_rwx_anon` (§3.10) e `proc.ns_divergent`
(§3.15). Total: 10 checks automáticos, todos com cenário.

### O coletor engolia dois erros em silêncio

`readMaps` e `readNS` retornavam sem registrar nada quando faltava permissão —
a mesma classe de defeito que a revisão pegou em `exe` e `fd`. Um host sem root
produziria mapa de namespace vazio, e o check leria "nenhum namespace
divergente". Agora viram `MapsDenied`/`NSDenied` por processo e lacuna de coleta
declarada.

### Rodar contra host real pegou o que teste sintético não pegaria

Primeira execução, um achado: `fusermount3`, uid 1000, com o conjunto cheio de
capability. Falso positivo — `Uid: 1000 0 0 0`. O uid REAL é 1000, o EFETIVO é
0: é setuid-root, e portanto É root. O coletor só guardava o primeiro campo.

```
antes    p.UID = fs[0]                      todo setuid do sistema virava escalada
depois   p.UID = fs[0]; p.EUID = fs[1]      e o check testa o EFETIVO
```

O segundo veio do mesmo teste: processo em namespace de usuário (Podman
rootless, sandbox de navegador) exibe `CapEff` cheio, e essas capabilities não
valem nada fora do namespace. Descartadas comparando com o namespace do PID 1.

### E depois, com visão de root sobre o host inteiro

`docker run --pid=host --privileged` dá a visão que `sudo` daria. Resultado:
**36 avisos**, todos de `proc.ns_divergent`. A investigação mudou o desenho do
check:

```
25 de udevd      isUnitCgroup usava HasSuffix, e o cgroup de serviço com
                 subgrupo é /system.slice/systemd-udevd.service/udev
 3 de polkit,    systemd cria namespace de REDE e de USUÁRIO por hardening de
   upower,       unit — PrivateNetwork=, PrivateUsers=. A premissa de que só
   accounts      mnt era comum estava errada
 8 do Firefox    sandbox de navegador. É FP declarado, e só aparece em desktop
```

Passou a pular unit por inteiro, não só o namespace de mount. De 36 para 8 —
e os 8 são o FP declarado. Em servidor, zero. O preço é um ponto cego dito em
voz alta: quem comprometeu uma unit não aparece neste check (aparece nos outros).

Os outros quatro checks novos: **zero achado** contra o host real com visão de
root. É o resultado que interessa — ruído treina o operador a ignorar o
relatório inteiro.

### Cenários novos

O helper ganhou `caps`, `trace`, `rwx`, e o harness ganhou `Caps`/`NoNetwork`
no lugar do `NetAdmin`.

```
14-caminho-suspeito             binário de /tmp
15-capability-sem-root          PR_SET_KEEPCAPS através do setuid: as duas
                                capabilities usadas estão no conjunto PADRÃO do
                                Docker, então não precisa de --cap-add
16-ptrace                       filho sob PTRACE_TRACEME (satisfaz ptrace_scope=1)
17-rwx-anonimo                  mmap PROT_EXEC|PROT_WRITE anônimo
18-jit-de-sistema-nao-dispara   negativo: /usr/bin/node com a mesma forma
19-namespace-proprio            unshare -n com cgroup `/`
```

O `15` é o único `MustBeIncomplete` do bloco, e por um motivo que vale registrar:
trocar de uid zera o flag `dumpable`, e a partir daí nem o root do contêiner lê
o `exe` daquele processo sem `CAP_SYS_PTRACE`. A cobertura CAI — e a ferramenta
diz isso em vez de fingir que olhou.

---

## Registro — `wtf` (2.7)

Comando próprio, não `scan --compacto`. Mesma coleta; seleção, orçamento e
renderização separados.

```
seleção        os checks com Wtf:true. O denominador da cobertura é ELE, não o
               catálogo — senão o wtf sairia INCOMPLETE sempre e o exit code
               deixaria de significar alguma coisa
orçamento      teto de 2s, e o relógio começa ANTES da coleta: a coleta é a
               parte cara, e um orçamento que só cobrisse os checks estaria
               medindo a parte errada
prazo estourado  vira NÃO VERIFICADO, nunca "nada encontrado". Um overview que
               fica rápido calando check é pior que um overview lento
tela           crítico ganha 2 linhas de evidência e o passo irreversível;
               aviso ganha uma linha. Corte em 8, com a contagem do que sobrou
```

Contra host real: **57ms** para 10 checks.

### O rodapé é o comando

`wtf` é o que mais corre risco de ser lido como "host limpo". Sem achado, o
texto diz o contrário do que a tela sugere:

```
✓ nenhum indicador decisivo em 10 checks (57ms)
  isto NÃO significa host limpo (runbook §35.8). Para o resto: aletheia scan
```

E o `RESULT` sempre termina com `Isto NÃO é varredura: rode aletheia scan`.

### `--oneline`, para frota

```
CRITICAL   revshell(21) pivot(22) suspicious_path(32)
OK         —
INCOMPLETE —  [cobertura 4/10]
```

Sem hostname: quem varre a frota já sabe em qual host mandou rodar e prefixa a
linha. A **cobertura entra sempre que estiver degradada** — sem ela, um host
onde metade não rodou apareceria na lista igual a um host varrido inteiro, e é
justamente esse que precisa de atenção primeiro.

O `Subject` passa pelo `Safe()` também aqui, e por um motivo que só existe neste
formato: numa varredura por ssh a saída de dezenas de hosts é concatenada, e uma
sequência de escape vinda de argv forjaria a linha dos outros hosts.

### Cenário

O harness ganhou `Cmd`, e `44-wtf-revshell` roda o comando de verdade. O que ele
trava não é a renderização — é o CONTRATO: mesmo JSONL, mesmo exit code. É por
ele que a frota se ordena.

---

## Registro — ambientes legados

Pergunta que motivou: **a CLI funciona em qualquer Linux? versão antiga? VM
legada?** A resposta honesta exigia bootar kernel legado, e não dava para
responder com contêiner: contêiner compartilha o kernel do host.

### Os dois eixos, e por que são separados

```
userland    contêiner resolve. centos:7 e debian:9 na matriz `legado` —
            valor real: base de pacotes RPM, que a matriz principal não tem
kernel      só VM. `make vm-kernels` baixa 3.18 (2014) e 4.14 (o LTS do
            Amazon Linux 2 e da era do Ubuntu 18.04), verifica o sha256 e
            grava em dist/vm/kernels/. NÃO toca em /boot, não instala nada,
            não encosta no bootloader — os arquivos vão para o QEMU com -kernel
arquitetura `make arches` cross-compila 386 e arm64. O cenário 30 roda o
            binário de 32 bits contra /proc real
```

Sem `make vm-kernels`, os cenários 50–53 são **pulados dizendo o comando** —
nunca passam em silêncio.

### Resultado

```
3.18 · 4.14 · 6.12    guest limpo: 10/10 · OK · exit 0
                      com implantes: os MESMOS seis achados, exit 2
386                   mesmos achados que o binário nativo
cgroup v1 puro        1:name=systemd:/legado.service → cgroup=/legado.service
sem /etc/os-release   cabeçalho perde o nome da distro e SEGUE
```

O limite fica documentado no cenário `90-kernel-2.6`: descer a 2.6.32 exigiria
rootfs de época junto, e o próprio runtime do Go não sustenta mais esse kernel.

### Dois defeitos que só o ambiente legado expôs

**1. `proc.ns_divergent` disparava em thread de KERNEL.** `kdevtmpfs` tem mount
namespace próprio por design, em todo kernel. No desktop isso se perdia no meio
dos oito achados de sandbox de navegador; num guest de sete processos ficou
sozinho na tela.

A causa raiz era pior que o sintoma: meu predicado usava `CmdlineEmpty`, que o
coletor só marca em processo que TEM exe — numa thread de kernel de verdade ele
nunca fica true. E a correção expôs que o controle de fluxo dependia de comparar
`ExeErr == "sem permissão"`, uma string em PORTUGUÊS. Traduzir a mensagem
desligaria checks em silêncio, com a suíte inteira verde. Virou campo tipado:

```
ExeMissing   o kernel não associa executável nenhum ao PID: thread de
             kernel, ou zumbi
ExeDenied    existe, e nós é que não pudemos ler
```

**2. O oposto exato do defeito original.** O cenário de guest limpo falhava uma
vez em quatro com `exit 1`. Não era flake do teste — era a ferramenta contando a
verdade de um jeito que a torna inútil:

```
antes    readProcess devolvia (nil, false) para os dois casos, e ambos viravam
         lacuna de cobertura
```

Processo que TERMINOU durante a coleta não é lacuna: ele não existe mais para
ninguém, nem para um humano rodando `ps`. Num servidor ocupado isso acontece em
toda varredura — bastava um processo sair nos 60ms da coleta para o host nunca
mais reportar OK. A ferramenta passaria de mentir para gritar lobo, que é
igualmente inútil.

```
readGone     terminou     → NÃO é lacuna; a contagem fica no JSONL, porque um
                            número alto é rotatividade anormal
readDenied   existe e não → É lacuna. hidepid=1, permissão. É o que a
             pudemos ler    ferramenta existe para não calar
```

Seis rodadas seguidas dos cenários de VM depois da correção: nenhuma falha.

### Uma correção de segurança do próprio harness

O QEMU x86 acrescenta uma placa de rede em modo usuário **por padrão**. O
comentário do harness prometia "sem rede" e o guest saía com acesso à internet
pelo host. Agora roda com `-nic none`. Um cenário de resposta a incidente não
pode dar saída de rede a implante de teste nenhum.

Total: **44 cenários**, 2 pulados com motivo documentado.
