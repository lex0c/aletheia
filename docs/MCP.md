<!-- Extraído do README, que tinha 470 linhas de MCP no meio de um documento de
     introdução. Referência de protocolo e de operação vive melhor separada. -->

# `aletheia mcp` — servidor MCP

Expõe a triagem do Aletheia a um agente por Model Context Protocol, sobre stdio.
O agente consulta achados, cobertura, dossiês e drift; e, sob consentimento
explícito do operador, adquire evidência nova do host.

**Escopo do documento:** arquitetura, contrato de resposta, catálogo de tools,
modelo de segurança e operação. Para fluxos de investigação, ver
[PLAYBOOKS.md](PLAYBOOKS.md), cenários 16–19.

---

## 1. Arquitetura

O servidor roda **dentro do host investigado** e lê `/proc`, `/sys`, o
filesystem e netlink diretamente. Não há nuvem, servidor central, console nem
agente residente.

```text
ESTAÇÃO DO ANALISTA                    HOST INVESTIGADO

cliente MCP
    │ stdio
    ▼
   ssh ────────────────────────────────►  sshd
                                            │
                                            ▼
                                       aletheia mcp
                                            │
                                    /proc · /sys · FS · netlink
```

Não há intermediário entre o servidor e a evidência: a mesma leitura de `/proc`
que o `scan` faz é a que responde ao agente. Consequências operacionais:

- **Sem pré-provisionamento.** Nada precisa estar instalado antes do incidente;
  basta copiar um binário estático, sem dependência dinâmica.
- **Aquisição sob demanda.** A pergunta do agente vira leitura no momento em que
  é feita, sem depender de uma consulta ter sido definida antes.
- **Sem superfície de rede.** O servidor não abre porta e não aceita conexão; o
  transporte é stdio. Para uma máquina remota, o canal é o SSH que já existe.
- **Sem credencial de plataforma.** Não há token, chave de API ou tenant: o
  alcance é o do processo, e ele é herdado de quem o lançou.
- **A investigação aparece no retrato.** Ver §7.5.

---

## 2. Modos, perfis e superfície

Dois eixos independentes: **de onde o fato vem** (modo) e **quanto se pode
inspecionar** (perfil). Ambos são fixados no lançamento do processo e não variam
por conexão.

| Lançamento | Modo | Tools | Aquisição |
| --- | --- | --- | --- |
| `--snapshot F` (repetível) | snapshot | 17 | nenhuma: serve dumps selados |
| `--live` | live | 19 | `snapshot.capture` do host |
| `--root PATH` | image | 19 | `snapshot.capture` de imagem montada |
| `+ --profile full` | — | 21 | mais leitura direcionada de arquivo |
| `+ --allow-secrets` | — | 24 | mais bytes crus e environ completo |

A tool que não se aplica **não entra em `tools/list`** — superfície ausente não
pode ser induzida por texto plantado no alvo. A ausência é declarada em
`session.status`, no campo `unavailable_tools`, com o motivo.

---

## 3. Ligando num cliente

### 3.1 Local

```json
{ "mcpServers": {
    "aletheia": { "command": "/opt/aletheia",
                  "args": ["mcp", "--snapshot", "/casos/vm-23.json"] } } }
```

Alguns clientes normalizam o ponto do nome da tool para underscore ao autorizar.
No Claude Code a allowlist usa `mcp__aletheia__findings_list`, não
`...findings.list`; o nome no protocolo continua com ponto. Autorizar com a
forma errada falha em silêncio — o modelo enxerga as tools e não consegue
chamá-las.

### 3.2 Remoto, por SSH

```json
{ "mcpServers": {
    "alvo": {
      "command": "ssh",
      "args": ["-T", "-i", "/casos/chave", "ir@10.0.0.7",
               "sudo -n /opt/aletheia mcp --live --allow-root"] } } }
```

**`-T` é obrigatório.** Sem ele o `ssh` aloca um pty, e um pty:

| Efeito | Consequência |
| --- | --- |
| ecoa a entrada no stdout | o cliente lê a própria requisição como resposta |
| traduz `\n` em `\r\n` | o framing do JSON-RPC deixa de fechar |
| mantém o canal aberto | o processo remoto não termina no fim da sessão |

Medido: com `-T`, 118.753 bytes de resposta e nenhum `\r`. Com pty forçado, seis
pares de CRLF, a requisição ecoada no início do stream, e a sessão pendurada.

O banner do `sshd` e o `motd` **não** poluem o stdout: saem por stderr, junto do
diagnóstico e da trilha de auditoria do servidor.

### 3.3 Privilégio na sessão remota

| Invocação | Resultado |
| --- | --- |
| `sudo -n aletheia mcp --live --allow-root`, com NOPASSWD | alcance completo |
| idem, sem NOPASSWD | falha imediata: `sudo: a password is required`, stdout vazio |
| `aletheia mcp --live`, sem sudo | sobe como uid comum, `elevated: false`, e declara as tools indisponíveis |

O terceiro caso é uma investigação sem privilégio que enumera explicitamente o
que não alcançou. Requer entrada em `sudoers` apenas para o binário:

```text
ir ALL=(ALL) NOPASSWD: /opt/aletheia
```

---

## 4. Contrato de resposta

### 4.1 Envelope de retrato

Toda tool que responde sobre um snapshot devolve quatro blocos:

```json
{
  "provenance":    { "snapshot_id": "...", "source": "live|image", "scope": "...", ... },
  "observability": { "verdict": "...", "coverage": { ... }, "collector_gaps": [ ... ] },
  "trust":         { "domain": "host_supplied", "untrusted": true, "host_supplied_paths": [ ... ] },
  "data":          { ... }
}
```

`observability.verdict` e `observability.coverage` são **obrigatórios no
`outputSchema`** de toda tool em forma de achado. Uma resposta com
`data.items: []` vem acompanhada de `verdict: INCOMPLETE` e da lista do que não
foi verificado. É a tradução, para um canal sem exit code, da regra do CLI:
`exit 0` exige achado nenhum **e** cobertura completa.

Campos de procedência relevantes:

| Campo | Significado |
| --- | --- |
| `source` | `live` ou `image` — o que o retrato descreve |
| `scope` | `volatile` ou `complete` — quanto o retrato leu |
| `redaction` | o que o **artefato afirma** sobre si: `applied`, `absent`, `unknown_version`, `waived` |
| `redaction_enforced` | o que **o servidor fez** antes de servir: `enforced` ou `waived` |
| `sidecar` | resultado do `.sha256` ao lado: `matches`, `absent`, `mismatch`, `not_applicable` |
| `authenticated` | sempre `false` — nada no artefato prova origem |

Só `redaction_enforced` vale como garantia. Ver §6.3.

### 4.2 Envelope de leitura

A família `file.*` do perfil completo **não** responde sobre um retrato: um dump
não carrega conteúdo de arquivo. O envelope dela não tem `provenance`:

```json
{
  "read":  { "started_at": "...", "finished_at": "...", "source": "live|image", "note": "..." },
  "trust": { ... },
  "data":  { ... }
}
```

Dois instantes porque a leitura leva tempo: um `file.hash` de centenas de
megabytes descreve o arquivo em algum ponto entre eles, e o campo `stable`
qualifica esse intervalo.

### 4.3 Ambiente de processo

`process.environ` devolve duas representações, e a distinção importa:

| Campo | O que é |
| --- | --- |
| `entries[].raw` | a entrada inteira, **byte a byte** — é a autoridade da resposta |
| `entries` | as entradas **como o kernel as expôs**: ordem original, duplicatas, e entradas sem sinal de igual preservadas. `key` e `value` são projeções de `raw` |
| `env` | projeção em mapa, por conveniência: chave repetida colapsa e a **última vence** |
| `duplicate_keys` | as chaves que aparecem mais de uma vez |

A repetição é observável e os consumidores discordam: medido, o `ld.so` honra a
**última** ocorrência de `LD_PRELOAD`, enquanto o `getenv` da libc devolve a
primeira. Um implante posto na primeira posição some da projeção e aparece em
`entries`.

Bytes que não são UTF-8 válido saem em `base64`, com o encoding declarado por
campo — forçá-los a string trocaria os inválidos por U+FFFD. Isso vale para
`raw` e para `value`: uma **chave** com byte arbitrário é exatamente o que se
planta para não ser lida de volta igual, e por isso `raw` é a autoridade e não
`key`.

### 4.4 Erros

Duas formas distintas, e o cliente as trata de modo diferente:

| Situação | Forma | Exemplo |
| --- | --- | --- |
| erro de protocolo | `error` JSON-RPC | método inexistente, era ambígua, frame acima do teto |
| erro de tool | `result` com `isError: true` | argumento faltando, escopo que não sustenta a pergunta |

A recusa de tool carrega `trust`, porque pode citar texto do alvo — o alvo de um
symlink, por exemplo, é escolhido por quem controla o host.

---

## 5. Catálogo de tools

`perfil` é o mínimo exigido; `fonte` restringe ao tipo de retrato; `escopo`
indica quando a tool exige um retrato `complete`.

| Tool | Modos | Perfil | Fonte | Escopo | Classe de dados |
| --- | --- | --- | --- | --- | --- |
| `session.status` | todos | standard | — | — | host_redacted |
| `snapshot.list` | todos | standard | — | — | host_redacted |
| `snapshot.info` | todos | standard | — | — | host_redacted |
| `snapshot.compare` | todos | standard | — | complete | host_redacted |
| `snapshot.capture` | live, image | standard | — | — | host_redacted |
| `snapshot.release` | live, image | standard | — | — | engine |
| `host.overview` | todos | standard | — | — | host_redacted |
| `checks.catalog` | todos | standard | — | — | engine |
| `findings.list` | todos | standard | — | — | host_redacted |
| `finding.get` | todos | standard | — | — | host_redacted |
| `findings.correlate` | todos | standard | — | — | host_redacted |
| `coverage.get` | todos | standard | — | — | host_redacted |
| `process.census` | todos | standard | live | — | host_redacted |
| `process.get` | todos | standard | live | — | host_redacted |
| `process.tree` | todos | standard | live | — | host_redacted |
| `net.census` | todos | standard | live | — | host_redacted |
| `net.ip` | todos | standard | live | complete | host_redacted |
| `net.port` | todos | standard | live | — | host_redacted |
| `file.inspect` | todos | standard | — | complete | host_redacted |
| `file.hash` | live, image | **full** | — | — | host_redacted |
| `file.capabilities` | live, image | **full** | — | — | host_redacted |
| `file.read` | live, image | **full** | — | — | **host_raw** |
| `file.xattrs` | live, image | **full** | — | — | **host_raw** |
| `process.environ` | todos | **full** | live | — | **host_raw** |

Não existe tool que execute comando, escreva no host, encerre processo, resolva
nome ou abra conexão. Não existe `finding.create`: achado é conclusão do motor,
com falso positivo declarado; o que o modelo produz é hipótese com referência de
evidência.

---

## 6. Modelo de segurança

### 6.1 O registry é a barreira

As `annotations` do protocolo (`readOnlyHint`, `destructiveHint`) são **hints**,
e um cliente pode ignorá-las. A proteção é o registry: o que a policy não
autoriza não é servido, e chamá-lo devolve *method not found* — não *permission
denied*. "Existe e você não pode" convida o modelo a procurar como poder.

### 6.2 Privilégio é herdado, nunca adquirido

O servidor não eleva privilégio. `--allow-root` é consentimento do operador, e o
portão mede **alcance efetivo**, não euid:

```text
euid == 0  ||  (capability de leitura de arquivo  E  CAP_SYS_PTRACE)
```

Um uid comum com `CAP_DAC_READ_SEARCH` lê `/etc/shadow`; euid não descreve isso.
A regra é verificada contra kernel real por `make cap-proof`. Se o privilégio
**não puder ser determinado** — `capget(2)` e `/proc` ambos indisponíveis — o
servidor recusa subir em modo de aquisição: "não sei" não é tratado como "não
tenho".

`--allow-kernel-autoload` fica desligado: consultar `sock_diag` pode fazer o
kernel chamar `modprobe`, e efeito colateral no host não deve nascer de uma
chamada de tool.

### 6.3 Redação: procedência e imposição

Um dump **não é autenticado** — o próprio envelope diz `authenticated: false`.
O carimbo de redação dele é um campo escolhido por quem escreveu o arquivo, e
não serve como barreira.

Em modo snapshot o servidor **re-aplica a redação no ingresso**, qualquer que
seja o carimbo. Sequência de bytes não atravessa: não existe redação semântica
de bytes arbitrários — a redação tokeniza e reconhece a forma de uma atribuição,
e nada disso se aplica a conteúdo possivelmente binário —, então o padrão para
`[]byte` é **descartar**, e um campo que precise dos bytes exatos declara
`redact:"-"` em voz alta. A operação é idempotente, então um artefato honesto atravessa
sem perda; um artefato que minta sai redigido. Custo medido: 53 ms para um dump
de 1,7 MB com 317 processos, uma vez na carga.

```text
redaction            o que o ARTEFATO afirma        (procedência)
redaction_enforced   o que ESTE servidor garantiu   (imposição)
```

`--snapshot --allow-secrets` dispensa a imposição — "sirva o que estiver cru aí
dentro". Não promete recuperar o que já saiu redigido do host.

### 6.4 Texto do alvo é entrada adversária

Nome de tool, descrição, `inputSchema` e `outputSchema` são constantes de
compilação: nenhuma string vinda do host entra neles. Texto do alvo aparece
apenas sob objeto marcado `trust.untrusted: true`, e `host_supplied_paths` lista
conservadoramente onde ele pode estar — incluindo `observability`, porque as
frases de lacuna citam nomes de cgroup, de binfmt e caminhos escolhidos pelo
alvo.

Os bytes não são removidos: a forense precisa deles. O que se garante é posição
e marcação.

### 6.5 Auditoria

Uma linha JSON por invocação, em stderr; `--audit-log FILE` acrescenta um
arquivo. Toda tool que emite dado cru projeta o alvo acessado:

```json
{"seq":1,"at":"...","method":"tools/call",
 "target":"file.read /etc/shadow offset=0 length=4096",
 "status":"ok","duration_ms":3,"result_bytes":4712}
```

A projeção registra identificação — caminho, janela, pid — e nunca conteúdo. Ela
acontece **antes** da execução, para que a tentativa recusada também apareça.

---

## 7. Limites declarados

O servidor declara o que não consegue, em vez de simular a garantia.

### 7.1 Symlink

Com `follow_symlinks: false` (padrão) o caminho é percorrido componente a
componente por descritor, com `O_PATH` e `O_NOFOLLOW`. Nenhum link é atravessado
em posição alguma, e a resposta traz `path_binding: "exact"` — o arquivo aberto
está no caminho pedido, e isso é garantia estrutural.

Com `follow_symlinks: true` a cadeia é resolvida como **observação** e o caminho
resolvido é aberto pelo mesmo percurso. `link_chain` e `resolved_path` descrevem
o que havia um instante antes; `path_binding` diz `"followed"`, e o que vale como
fato são `dev` e `inode`.

Em modo `--root`, um link de alvo absoluto resolve **dentro da imagem**: um
`/tmp/x -> /etc/shadow` plantado ali apontava, no sistema original, para o
`/etc/shadow` daquele sistema. O percurso nunca sai da raiz montada.

Nos dois casos o objeto é identificado com `O_PATH` e só é aberto para leitura
depois de provado regular — **o `open()` de um device node nunca é acionado**.

### 7.2 Cancelamento

`notifications/cancelled` interrompe a emissão da resposta. A coleta em voo
termina e o resultado é descartado: não há `context.Context` no domínio, e os
coletores não são interrompíveis. Enquanto uma captura completa roda, o servidor
não responde outra chamada.

### 7.3 Escopo volátil

`scope=volatile` lê `/proc`, sockets e a base de usuários — cerca de 9× mais
barato. **Não sustenta achado:** o motor recusa rodar check sobre coleta
parcial, e a resposta é zero achados com o catálogo inteiro em `not_checked`.
Um check de unit encontraria zero units e reportaria "nada encontrado" onde o
correto é "não olhei".

`snapshot.compare` exige que **ambos** os retratos sejam `complete`. Comparar
alcances diferentes produziu, num teste, 771 mudanças — 770 delas falsos
"sumiu".

### 7.4 Orçamento de coleta

`--capture-budget` (padrão 10m) é **cooperativo**, e faz duas coisas: recusa
admitir uma captura nova quando o saldo acaba, e limita cada varredura ao menor
entre o saldo restante e o orçamento por captura. Uma captura já admitida pode
ultrapassar o saldo nas etapas não interrompíveis.

Existe porque o teto de retratos vivos limita **memória**: capturar e liberar em
laço nunca esbarra nele e cobra uma varredura por volta. Liberar não devolve
orçamento. `session.status` publica o saldo antes de ele ser atingido, e o campo
`cooperative: true` evita que o limite seja lido como relógio rígido.

### 7.5 A investigação aparece no retrato

Rodando dentro do host, a cadeia de acesso — `sshd`, o shell, o próprio
`aletheia` — vira processo no censo, e a sessão SSH vira conexão cujo dono a
coleta não consegue ler. A conta e a regra de `sudoers` criadas para o caso são
encontradas pela varredura.

Compare horários antes de atribuir: numa validação, a conta de resposta a
incidente aparecia **onze segundos antes** do implante.

Depois da sessão não fica nada em disco nem processo órfão — apenas o login no
`wtmp`.

---

## 8. Referência de flags

| Flag | Efeito |
| --- | --- |
| `--snapshot F` | serve um dump do `collect`. Repetível; fixa tudo que o processo pode abrir |
| `--live` | adquire do host vivo |
| `--root PATH` | adquire de uma imagem montada |
| `--allow-root` | consentimento para observação privilegiada |
| `--profile full` | destrava leitura de arquivo por caminho escolhido pelo modelo |
| `--allow-secrets` | destrava bytes crus saindo do processo; em snapshot, dispensa a redação de ingresso |
| `--capture-budget D` | orçamento cooperativo de coleta (padrão 10m; `0` desliga, com aviso) |
| `--audit-log F` | grava a trilha também em `F` |

Combinações recusadas no parse, com o motivo:

| Combinação | Motivo |
| --- | --- |
| `--snapshot --profile full` | um dump não carrega conteúdo de arquivo |
| `--allow-secrets` sem `--profile full`, em live/image | a classe de dados crus mora atrás do perfil |
| `--capture-budget` negativo | — |

Nenhuma tool aceita caminho de arquivo no perfil padrão: tudo que o processo
pode abrir é fixado no lançamento. `--profile full` é o operador suspendendo
essa regra deliberadamente.

---

## 9. Protocolo

Duas eras, com encoder por era:

| Versão | Handshake | Campos exclusivos |
| --- | --- | --- |
| 2026-07-28 | sem `initialize`; `_meta` em `params` | `resultType`, `ttlMs`, `cacheScope`, `_meta.serverInfo` |
| 2025-11-25 / 2025-06-18 | `initialize` | — |

O servidor nunca adivinha a era: uma resposta na era errada é lida torta pelo
cliente, em silêncio. Sem `initialize` prévio, a requisição precisa trazer os
dois campos obrigatórios em `params._meta`.

| Situação | Código |
| --- | --- |
| sem `protocolVersion` em `params._meta` (ou sem `params`) | `-32602` |
| sem `clientCapabilities` em `params._meta` | `-32602` |
| `protocolVersion` que este binário não suporta | `-32022`, listando as suportadas |
| batch de JSON-RPC | `-32600` |
| tool inexistente | `-32601` (*method not found*, nunca *permission denied*) |

`server/discover` é implementado e nunca exigido; um cliente pode começar em
`tools/call`.

O transporte impõe teto de frame **antes** do `json.Unmarshal`, e **drena até o
próximo `\n`** após um frame acima do teto — sem isso, a cauda de uma linha
gigante seria interpretada como mensagem nova. Ambos os caminhos têm alvo de
fuzzing (`make fuzz`).

`cacheScope` é `private`: a lista revela modo, perfil e fontes da execução, e
nenhum intermediário compartilhado deve guardá-la.

---

## 10. Diagnóstico

| Sintoma | Causa provável |
| --- | --- |
| o modelo vê as tools e não consegue chamá-las | allowlist com ponto em vez de underscore (§3.1) |
| stdout não parseia; resposta começa com a requisição | `ssh` sem `-T` (§3.2) |
| a sessão remota não termina | idem |
| `sudo: a password is required` | falta `NOPASSWD` para o binário (§3.3) |
| `dump de esquema incompatível` | dump de outra versão; recolete ou analise com a versão que coletou |
| `nenhum retrato existe ainda` | modo live/image antes de `snapshot.capture` |
| `esta pergunta exige um retrato COMPLETO` | a tool não se sustenta em `scope=volatile` (§7.3) |
| `o orçamento de coleta desta sessão acabou` | `--capture-budget` esgotado; reinicie com valor maior (§7.4) |

---

## 11. Verificação

```sh
make verify          # formatação, vet, testes, binário estático
make scenarios       # M1–M14: o servidor contra hosts reais em contêiner
make fuzz            # codec e framing
make cap-proof       # a regra de privilégio contra kernel real
make test-386        # a suíte em 32 bits
```

A suíte de cenários inclui a fronteira de injeção sobre argv (M3) e sobre os
quatro canais do perfil completo (M15), a ausência de superfície de execução
(M4), a paridade de cobertura com o `analyze` (M6), a captura ao vivo (M10–M11),
o portão de consentimento (M12), a aquisição de imagem (M13), o perfil completo
(M14) e o alvo mudando durante a leitura (M16).

`make fuzz` cobre três parsers: a mensagem JSON-RPC, o framing do transporte e o
**carregamento do dump** — este último é o mais exposto, porque o artefato não é
autenticado por desenho e a redação de ingresso percorre reflexivamente uma
estrutura que o atacante moldou.

Um dump hostil é limitado por `MaxDump` (512 MiB). Medido, a expansão em memória
depois de parse, redação e índice é de cerca de **1,8×** o tamanho do arquivo —
o teto de leitura vale, portanto, aproximadamente 1 GiB de heap no lado do
analista.
