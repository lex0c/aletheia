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
- **VM descartável** (`../vm/*-proof.sh`) — técnicas de **kernel**: hook em
  `tcp4_seq_show` (socket_view), LKM que se esconde (module_view), e — a fazer —
  cgroup BPF, binfmt live. Contêiner NÃO serve para kernel: ele compartilha o do
  host, e um hook ali esconderia conexão do host inteiro.

Nenhum cenário conecta na internet. Os de rede usam TEST-NET-3
(`203.0.113.0/24`), que nunca é roteada. Nada escreve fora de `/tmp` do contêiner.

## Uso

```sh
make matrix          # tier de contêiner (exige docker)
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
| `rx-anon-rotulada` | (nenhum)               | ponto cego¹  |
| `deleted-data`     | (nenhum)               | ponto cego²  |
| `jit-inject`       | `proc.maps_exec_anon`  | regressão³   |

1. rótulo de VMA (`PR_SET_VMA_ANON_NAME`) é spoofável, e o check só conta região
   SEM rótulo — o próprio check declara esse limite.
2. o check exige segmento EXECUTÁVEL; um segmento de dado apagado passa.
3. era ponto cego: `maps_exec_anon` isentava runtime com JIT só pelo nome e
   diretório, e rodar o payload como `/usr/bin/node` caía na isenção. A matriz
   demonstrou o bypass, e a isenção FOI APERTADA — passou a exigir dono de
   pacote. Um `/usr/bin/node` sem dono (payload copiado) já não escapa; um node
   de pacote de verdade continua isento.

Os cenários de rede usam TEST-NET-3 num alias de `lo` e um C2 falso local
(`plant listen`); precisam de `--cap-add=NET_ADMIN`, que `matrix.sh` já passa.
