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
- [ ] **2.3** `proc.suspicious_path` — `/tmp`, `/dev/shm`, `~/.config/<dir>/<bin>`; `~/.local` é XDG legítimo (§8)
- [ ] **2.4** `proc.caps_unexpected` — `CapEff` **comparado com o esperado**, não apenas != 0 (§3.7)
- [ ] **2.5** `proc.tracer`, `proc.ns_divergent`, `proc.maps_rwx_anon` (§3.7, §3.15, §3.10)
- [x] **2.6** `correlate.revshell` — fd 0,1,2 no mesmo socket **descartando socket activation** (§17)
- [ ] **2.7** `wtf` — mesma coleta, renderização e orçamento próprios

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
