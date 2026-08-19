# Matriz adversarial

Monta técnicas de ataque e mede **quais a aletheia pega**. Dois eixos:

- **Regressão** — cada técnica é a forma que um check *afirma* pegar. Se não
  pegar, é regressão: um refactor quebrou o check em silêncio. É a rede que os
  fixtures não dão, porque exercita o binário real contra `/proc` real.
- **Ponto cego** — técnicas que se quer medir se passam **sem sinal**. Cego
  *confirmado* (o check já declara o limite) é esperado; **surpresa** — pegou
  algo que não devia, ou deixou passar algo que devia pegar — é o achado que
  vale, e o que revela o próximo check necessário.

## Dois tiers, por segurança

- **Contêiner** (`matrix.sh`) — técnicas de **userspace**: injeção em memória,
  mapeamento apagado, memfd. A aletheia roda como **root** dentro do contêiner e
  enxerga tudo; nada toca o kernel do HOST. É o que roda por padrão.
- **VM descartável** (`vm-matrix.sh`) — técnicas de **kernel**, numa tabela só,
  com baseline limpo como controle negativo: hook em `tcp4_seq_show`
  (`cross.socket_view`), LKM que se esconde de `/proc/modules` e `/sys/module`
  (`cross.module_view`), registro de `binfmt` live (`kernel.binfmt_interpreter`)
  e programa `cgroup_skb` preso em `/sys/fs/cgroup`, atribuído por
  `BPF_PROG_QUERY`. Contêiner NÃO serve para kernel: ele compartilha o do host,
  e um hook ali esconderia conexão do host inteiro.

  O passo de cgroup BPF é o que pegou o bug real do `cmdProgQuery` (era 20,
  `BPF_TASK_FD_QUERY`; o correto é 16): planta um `cgroup_skb` mínimo, fecha o
  fd do programa para que só o anexo o segure, e exige atribuição. Sem programa
  real anexado, os unit tests da travessia passavam com a query morta.

Nenhum cenário conecta na internet. Os de rede usam TEST-NET-3
(`203.0.113.0/24`), que nunca é roteada. Nada escreve fora de `/tmp` do contêiner.

## Uso

```sh
make matrix          # tier de contêiner (userspace; exige docker)
make vm-matrix       # tier de kernel (exige docker e qemu)
```

Sai 0 se não houver regressão; 1 se uma técnica que um check afirma pegar passou
sem sinal.

## Técnicas (`plant/`)

| técnica            | check esperado         | eixo         |
| ------------------ | ---------------------- | ------------ |
| `rwx-anon`         | `proc.maps_rwx_anon`   | regressão    |
| `rx-anon`          | `proc.maps_exec_anon`  | regressão    |
| `deleted-exec`     | `proc.deleted_mapping` | regressão    |
| `memfd`            | `proc.memfd_exec`      | regressão    |
| `revshell-direct`  | `correlate.revshell`   | regressão    |
| `revshell-bridge`  | `correlate.revshell_bridge` | regressão |
| `rx-anon-rotulada` | `proc.maps_exec_anon`  | regressão¹   |
| `deleted-data`     | (nenhum)               | ponto cego²  |
| `jit-inject`       | `proc.maps_exec_anon`  | regressão³   |
| `revshell-pty`     | (nenhum)               | ponto cego⁴  |

1. era ponto cego: o rótulo de VMA (`PR_SET_VMA_ANON_NAME`) é spoofável, e o
   check só contava região SEM rótulo — bastava nomear a região de injeção
   `[anon:js-executable-memory]`. FECHADO na mesma classe do exe /usr/bin/node:
   o rótulo só é confiado em runtime confiável; num não-JIT, região rotulada
   conta como qualquer injeção.
2. o check exige segmento EXECUTÁVEL; um segmento de dado apagado passa.
3. era ponto cego: `maps_exec_anon` isentava runtime com JIT só pelo nome e
   diretório, e rodar o payload como `/usr/bin/node` caía na isenção. A matriz
   demonstrou o bypass, e a isenção FOI APERTADA — passou a exigir dono de
   pacote. Um `/usr/bin/node` sem dono (payload copiado) já não escapa; um node
   de pacote de verdade continua isento.

4. `correlate.revshell_bridge` só cobre a ponte por PIPE. A ponte por PTY não
   compartilha inode de pipe, e correlacionar `/dev/ptmx` com `/dev/pts/N`
   passivamente é mais difícil; além disso o FP seria severo (SSM, Teleport e
   ssh com PTY têm essa forma). Fica medido e declarado, sem check por ora.

Os cenários de rede usam TEST-NET-3 num alias de `lo` e um C2 falso local
(`plant listen`); precisam de `--cap-add=NET_ADMIN`, que `matrix.sh` já passa.
