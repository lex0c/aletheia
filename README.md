# aletheia

Triagem de resposta a incidente em Linux, num binário estático sem dependência
nenhuma.

`alḗtheia` (ἀλήθεια) é grego para *des-ocultamento*, e o nome não é decorativo: a
propriedade central desta ferramenta é distinguir **"nada estava escondido"** de
**"eu não consegui ver"**. Cobertura incompleta não é detalhe de rodapé — ela
chega ao exit code.

```
$ sudo aletheia scan
web-01 · 6.1.0-18-amd64 · Debian 12 · up 34d · load 0.42 (4 cpu)
relógio sincronizado · 2026-08-17T21:03:11Z · modo live · aletheia 0.1.0

⛔ 2   ⚠ 6   ◆ 4 manuais   ·   cobertura 79/81

⛔ /tmp/.x                 3 sinais no mesmo alvo
     · execução fileless: exe aponta para memória anônima (pid=812)     §3.16
     · binário em execução que nenhum pacote reivindica                 §24
     · saída para endereço público a partir de binário sem dono (pid=812) §4.3

AGORA, nesta ordem (runbook §19 — não inverta):
  1. sudo /opt/ir/aletheia preserve --out "$IR" --pid 812   ← irreversível se pulado
  2. isolar na camada de REDE, não no host (runbook §18)
  3. remover persistência ANTES de matar (runbook §19)

RESULT: CRITICAL        2 críticos · 6 avisos · 4 manuais · cobertura 79/81
```

O primeiro passo é o irreversível, e ele vem com o PID preenchido: matar o
processo destrói a única cópia de um binário que nunca esteve em disco.

---

## Baixar

Os binários de cada release são estáticos e cobrem `amd64`, `386` e `arm64`.

```sh
VER=v0.1.0            # ou: use a URL de /releases/latest/download/…
ARCH=amd64            # amd64 | 386 | arm64
BASE="https://github.com/lex0c/aletheia/releases/download/$VER"

curl -fsSLO "$BASE/aletheia-linux-$ARCH"
curl -fsSLO "$BASE/SHA256SUMS"

# CONFIRA ANTES DE EXECUTAR. Baixar e rodar sem verificar é exatamente a
# prática que o runbook §16 condena — e você está prestes a rodar isto como
# root, num host que talvez já esteja comprometido.
sha256sum --ignore-missing -c SHA256SUMS

chmod +x "aletheia-linux-$ARCH"
sudo ./aletheia-linux-$ARCH version
```

Sempre a última versão, sem descobrir a tag:

```sh
curl -fsSL -o aletheia \
  https://github.com/lex0c/aletheia/releases/latest/download/aletheia-linux-amd64
```

Se o `sha256sum` do seu ambiente não tiver `--ignore-missing`:

```sh
grep "aletheia-linux-$ARCH\$" SHA256SUMS | sha256sum -c -
```

**Não existe `curl | sh` aqui, e isso é decisão.** Executar um script vindo da
rede sem olhar é o oposto do que esta ferramenta faz.

### Onde baixar importa

Este binário **vira artefato na sua timeline**: é um ELF estático, fora de
pacote, com `ctime` de agora — e a própria ferramenta vai reportá-lo assim para
quem varrer o host depois.

O certo é baixar numa máquina limpa, conferir o hash **lá**, e só então copiar
para o alvo. Baixar direto no host suspeito acrescenta uma conexão de rede e um
arquivo novo à cena que você está tentando ler.

```sh
# na máquina LIMPA, depois do sha256sum -c da seção acima
BIN=aletheia-linux-amd64

# 1. scp — a rota comum. O destino NÃO é /tmp: ele é gravável por todos, e
#    num host suspeito isso é uma janela para trocarem o binário entre a
#    cópia e a execução
scp "$BIN" ir@web01:~/aletheia
ssh ir@web01 'chmod +x ~/aletheia'

# 2. cat por SSH — quando não há scp nem sftp do outro lado
ssh ir@web01 'cat > ~/aletheia && chmod +x ~/aletheia' < "$BIN"

# 3. disco — quando o host não deve receber conexão NENHUMA, e o mesmo
#    volume vai levar o --out do preserve de volta
cp "$BIN" /mnt/externo/ir/
```

O disco tem uma vantagem que as outras duas rotas não têm: rodando o binário de
lá, nenhum arquivo novo entra no filesystem do alvo — o artefato fica no seu
volume, e não na timeline que você veio ler.

```sh
sudo /mnt/externo/ir/aletheia-linux-amd64 version
```

Em qualquer uma das três, confira o hash **de novo no alvo** e registre caminho
e hash no war log (§39.3). A cópia é mais um lugar onde o arquivo pode mudar, e
conferir só na origem não cobre isso:

```sh
aletheia version     # imprime versão, caminho real e sha256 do próprio binário
```

O hash impresso ali tem que ser o mesmo do `SHA256SUMS`. Se não for, pare.

---

## Uso

```
aletheia <comando> [flags]
```

| comando | o que responde |
| --- | --- |
| `scan` | este host está comprometido? Coleta e analisa (modo normal) |
| `wtf` | overview em ~1s: este host está pegando fogo? |
| `watch` | varre em ciclo e reporta só o que MUDAR — o eixo que um retrato não tem |
| `collect` | só coleta: tira o retrato e sai. Não conclui nada |
| `analyze` | só analisa: roda os checks sobre um retrato, do lado limpo |
| `info` | responde sobre UM alvo — process, ip, port, file — sem concluir nada |
| `preserve` | guarda a evidência antes que ela suma. O **único** que escreve |
| `baseline` | captura o estado atual como referência para comparar depois |
| `checks` | catálogo: id, §ref, modo, grupo, requires, falsos positivos |
| `version` | versão, caminho e sha256 deste binário |

`aletheia --help` traz as flags de cada um, e o texto de ajuda é documentação da
ferramenta — não saída gerada.

### Os primeiros cinco minutos

```sh
export IR=/mnt/externo/ir-web01        # fora do host suspeito, se possível
mkdir -p "$IR"

sudo aletheia wtf                      # está pegando fogo AGORA?
sudo aletheia scan --json "$IR/scan.jsonl" -v

# o relatório imprime o comando de preservação com o PID já preenchido:
sudo aletheia preserve --out "$IR" --pid 812 --mem
```

### A pergunta que vem antes do veredito

```sh
aletheia info process              # censo: quem roda o quê, e contra que TETO
aletheia info process 812          # o dossiê de um processo
aletheia info net                  # censo de rede: o que expõe, e contra que TETO
aletheia info git                  # censo de um repositório: config que executa, histórico reescrito
aletheia info ip 51.91.190.241
aletheia info port 4100
aletheia info file /usr/sbin/nginx
```

Junta o que hoje custa `ps`, `ss`, `lsof`, `stat`, `getcap`, `lsattr` e `dpkg -S`
encadeados, e diz o que cada número **significa**. O censo compara as tarefas de
cada uid com o `RLIMIT_NPROC` dele — é o número que explica `Resource
temporarily unavailable` em `su`, `fork` e `execve` — e dá **nome** à repetição
quando ela tem forma conhecida:

```
CENSO · 904 processos · 4904 tarefas (processos + threads)

  usuário         proc  tarefas    teto
  node             904     4904    4096  ⛔ NO TETO — fork e execve falham com EAGAIN

O QUE NODE ESTÁ RODANDO
  por executável REAL
     400  /usr/bin/dash
     400  /usr/bin/node
  por processo pai
     503  pid=2 (crond)

PADRÃO RECONHECIDO — CRON SOBREPOSTO · 400 cópias
  /bin/sh -c /home/node/check-pm2.sh
  as cópias começaram em intervalos REGULARES de ~1m0s, e nenhuma terminou
```

Não conclui nada: quem conclui é o `scan`, que traz os falsos positivos junto.
Perguntar sobre processo, ip ou porta custa dezenas de milissegundos — não varre
disco. Também responde sobre um retrato: `info --from retrato.json process`.

### Coletar aqui, analisar do lado limpo

Menos tempo no host comprometido, e o retrato vira acervo: os mesmos fatos podem
ser reanalisados semanas depois, com checks mais novos e com a lista de
indicadores que só apareceu no terceiro dia.

```sh
sudo aletheia collect --out retrato.json          # no host, curto
aletheia analyze retrato.json --ioc incidente.yml # na sua máquina, quantas vezes quiser
```

**A análise herda a cobertura da coleta e não pode melhorá-la.** Um retrato
tirado sem root continua sem root quando analisado numa estação com root: o que
ninguém olhou continua não olhado, e o relatório diz isso.

### Os indicadores DESTE incidente

```sh
sudo aletheia scan --ioc incidente.yml --since 72h
```

```yaml
# incidente.yml
ips:     [51.91.190.241]
hashes:  ["9f2c1e4b…"]
paths:   ["*/htop/defunct", "*.dat"]
strings: [GS_ARGS, gs-netcat]
```

Achado por indicador é CRÍTICO — e vale o que a lista valer. `--since` recorta a
janela da investigação: o que tem data e cai fora sai do relatório e é
**contado**; o que não tem data **fica**.

### Imagem montada

Quando o userland do alvo não é confiável, monte o disco e varra de fora — ali o
kernel é o seu, e ocultamento de arquivo por rootkit não acontece (§35.6):

```sh
aletheia scan --root /mnt/imagem
```

---

## Exit codes

```
0  OK          zero achados E cobertura completa
1  WARNING     achado que precisa de olhar humano, OU cobertura incompleta
2  CRITICAL    indicador de alta confiança
3  ERROR       argumento ou ambiente inválido
```

Exit 0 exige as **duas** condições. Uma execução sem root e sem debugfs não sai
zero — seria a ferramenta contradizendo o próprio nome. Vale igual para o
`watch`: uma vigília que passou a noite sem enxergar não termina dizendo que a
noite foi tranquila.

---

## O que ela não faz

```
não mata processo, não apaga arquivo, não altera regra ou serviço
não executa nada do host: o binário do alvo pode ser o implante
não fala com a rede e não resolve DNS: consulta avisa o atacante (§2.1)
não tem base de assinatura de malware, e não deveria ter
só escreve com `preserve`, e apenas dentro de --out
```

**"RESULT: OK" não prova que o host está limpo.** Significa que nenhum indicador
COBERTO disparou. Um rootkit em kernel mente para todos os checks (§35.8) — é
por isso que a cobertura é impressa junto do veredito, sempre.

---

## Compilar

Sem dependência externa: o `go.mod` não tem um único `require`.

```sh
make verify      # lint + testes + build, com o binário CONFIRMADO estático
make dist        # amd64, 386 e arm64 + sha256
make scenarios   # a suíte de cenários (exige docker; alguns exigem qemu)
```

`CGO_ENABLED=0` não é otimização: sem ele o binário linka contra a glibc do host
e perde a imunidade a `LD_PRELOAD` e a binário de sistema trojanizado.

---

## Como isto é testado

```
88 checks       cada um declara os próprios falsos positivos — é invariante de
                registro, não disciplina: sem eles o programa nem inicia
151 cenários    a CLI de verdade, contra /proc de verdade: debian 12 e alpine
                como matriz, centos 7 e debian 9 para userland de época (rpm,
                systemd de outra geração), e microVM com kernel PRÓPRIO — 3.18,
                4.14 e i686 — para o que contêiner nenhum alcança, porque
                contêiner compartilha o kernel de quem o roda
mutação         mutantes plantados à mão em cada unidade nova, para provar que
                os testes têm dentes
```

O contrato dos cenários não é "passou": é **o que a ferramenta precisa dizer**,
incluindo o silêncio. Um check que nunca foi visto CALAR não foi demonstrado.

---

## Documentação

O registro das decisões é o **histórico do git**. Cada commit diz o que mudou,
o que aquilo quebrava antes e por que a correção é essa — inclusive os defeitos
que a suíte achou e os que só apareceram rodando a ferramenta no host de quem a
escreveu.

```sh
git log                       # a história, com o porquê de cada unidade
aletheia checks               # o catálogo: id, §ref, requires, falsos positivos
aletheia <comando> --help     # as flags, que são documentação e não saída gerada
```

O `--help` e o `checks` são a referência de uso: eles vivem no binário, então
não têm como divergir dele.
