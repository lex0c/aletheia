# Cobertura por ATT&CK

Mapa dos checks contra a matriz Linux do MITRE ATT&CK.

Existe por um motivo específico, e ele não é conformidade: **os cenários desta
suíte codificam o que eu pensei.** Mais cenários provam principalmente que eu
consigo continuar pensando. Uma taxonomia externa encontra buraco sem depender
da minha imaginação — e a lista de lacunas no fim deste arquivo é o produto que
importa aqui, não a lista de coberturas.

Três rótulos, e o do meio é o que mais informa:

- **coberto** — há check que dispara contra a forma canônica da técnica
- **parcial** — uma variante é vista e outras não, e o texto diz qual
- **ausente** — nada olha para aquilo

---

## Persistência (TA0003)

| Técnica | Estado | Checks |
|---|---|---|
| T1543.002 Serviço systemd | coberto | `persist.unit_exec_suspect`, `unit_dropin_exec`, `unit_socket_unowned` |
| T1053.003 Cron | coberto | `persist.cron_suspect`, `cron_frequent` |
| T1053.006 Timer do systemd | coberto | `persist.timer_frequent` |
| T1053.002 At | coberto | `persist.at_job` |
| T1547.006 Módulo de kernel | parcial | `persist.modprobe_install`, `cross.module_view` — a carga por `modules-load.d` é vista pela propriedade do `.ko`, não por check próprio |
| T1546.004 Configuração de shell | coberto | `persist.shell_startup`, `persist.bash_env` |
| T1546.005 Trap | coberto | `persist.shell_startup` — DEBUG, EXIT e ERR; `trap -` restaura o padrão e não é achado |
| T1546.016 Hook de instalador | coberto | `persist.trigger_exec` (apt.conf.d, dnf, yum) |
| T1098.004 Chave SSH autorizada | coberto | `persist.ssh_keys`, `ssh_forced_command`, `sshd_key_source` |
| T1136.001 Conta local criada | coberto | `priv.account_no_shadow` — a conta que não passou pelo `useradd`, mais os três de privilégio |
| T1505.003 Web shell | parcial | `persist.web_prepend` cobre `auto_prepend_file`; arquivo de webshell largado na raiz do site não é procurado |
| T1574.006 Sequestro do ligador dinâmico | coberto | `persist.ld_preload_global`, `ld_so_conf_odd`, `env_preload`, `proc.ld_preload_env` |
| T1037.004 Script de boot (rc) | coberto | `persist.trigger_exec` |
| T1554 Binário do host comprometido | coberto | `integrity.pkg_file_modified` |
| T1205.001 Port knocking | **ausente** | config de `knockd` não é lida |

## Escalada de privilégio (TA0004)

| Técnica | Estado | Checks |
|---|---|---|
| T1548.001 Setuid/Setgid | coberto | `persist.suid_unowned` — inclui capability em xattr, que um `find -perm -4000` não vê |
| T1548.003 Sudo | coberto | `priv.sudo_nopasswd` |
| T1055 Injeção em processo | parcial | `proc.maps_rwx_anon`, `proc.tracer` — vê a forma na memória e o rastreador, não a injeção em si |
| T1068 Exploração | fora de escopo | um retrato não vê exploração; vê o resultado dela |

## Evasão de defesa (TA0005)

| Técnica | Estado | Checks |
|---|---|---|
| T1070.003 Apagar histórico | coberto | `antiforense.shell_history` |
| T1070.006 Timestomp | coberto | `integrity.timestomp` |
| T1070.002 Apagar logs do sistema | coberto | `antiforense.log_rotation_gap`, `antiforense.wtmp_cleared` |
| T1014 Rootkit | parcial | `cross.hidden_pid`, `module_view`, `thread_count`, `kernel.ftrace_hook` — e o limite está declarado: se o kernel mente, as fontes mentem juntas |
| T1036.005 Nome/lugar legítimo | coberto | `proc.kthread_disguise`, `integrity.no_package_owner` |
| T1564.001 Arquivo oculto | coberto | `path.hidden_exec` — só com executável dentro, e só em árvore temporária |
| T1562.001 Desabilitar ferramenta de defesa | parcial | `antiforense.mac_downgraded` — só a CONTRADIÇÃO entre config e runtime do SELinux; AppArmor e "MAC simplesmente inativo" ficam de fora, e o texto abaixo diz por quê |
| T1562.004 Desabilitar firewall | **ausente** | tabela vazia não é notada |
| T1562.012 Desabilitar auditoria do Linux | coberto | `antiforense.audit_disabled` — só o `-e 0` é achado; sem regra nenhuma é o estado da maioria dos hosts |
| T1222.002 Alterar permissão | parcial | `integrity.immutable_flag` cobre o atributo de inode; mudança de modo não é comparada |
| T1027 Ofuscação | parcial | payload que decodifica a si mesmo é reconhecido em config de persistência |
| T1620 Carga refletida | coberto | `proc.memfd_exec`, `proc.maps_rwx_anon` |
| T1553.004 CA instalada | coberto | `persist.ca_planted` |
| T1006 Acesso direto ao volume | **ausente** | leitura crua de dispositivo de bloco |

## Acesso a credencial (TA0006)

| Técnica | Estado | Checks |
|---|---|---|
| T1552.004 Chave privada exposta | coberto | `cred.ssh_private_key` |
| T1556.003 PAM alterado | coberto | `persist.pam_exec` |
| T1110 Força bruta | coberto | `auth.bruteforce_success` — pelo cruzamento entre btmp e wtmp |
| T1552.001 Credencial em arquivo | coberto | `cred.secret_file` — inventário, com a PERMISSÃO como único juízo objetivo |
| T1003.008 Dump de passwd/shadow | fora de escopo | a LEITURA não deixa rastro num retrato |

## Movimento lateral, C2, exfiltração e impacto

| Técnica | Estado | Checks |
|---|---|---|
| T1021.004 SSH | parcial | `cred.known_hosts` dimensiona o alcance; sessão em curso não é atribuída |
| T1071 Protocolo de aplicação | parcial | `net.egress_unowned` — pela ORIGEM, nunca pelo destino |
| T1571 Porta fora do padrão | parcial | `net.listener_unowned` |
| T1090 Proxy / pivô | coberto | `net.pivot` |
| T1219 Ferramenta de acesso remoto | coberto | `tool.artifact`, `tool.binary` |
| T1567 Exfiltração por serviço web | parcial | `tool.artifact` reconhece rclone e afins pelo artefato |
| T1496 Sequestro de recurso | parcial | a forma do minerador é vista por caminho, disfarce e memória; consumo de CPU não é medido |

---

## As lacunas que valem, em ordem

O critério é duplo: **frequência em intrusão real** e **detectabilidade a
partir de um retrato**. Técnica comum que só se vê em fluxo contínuo não entra.

SEIS foram fechadas e saíram desta lista: T1562.012 (auditoria desligada),
T1070.002 (logs apagados), T1552.001 (credencial em arquivo), T1546.005 (trap de
shell), T1564.001 (arquivo oculto) e T1136.001 (conta criada à mão).

Sobrou UMA, e ela é a de pior relação custo/sinal da lista original — o que é o
resultado esperado quando se trabalha uma lista priorizada até o fim:

### 1. T1562.001 (resto) e T1562.004 — AppArmor e firewall

A parte do SELinux foi fechada, e só a CONTRADIÇÃO: config pedindo enforcing com
o kernel em permissivo. O ESTADO — MAC inativo — continua deliberadamente fora,
e a medição diz por quê: um host meu tem **158 perfis de AppArmor com o módulo
desligado**, que é como a distribuição entrega. Acusar estado acusaria todos.

O que sobra, e cada um tem um problema próprio:

```
AppArmor    o equivalente ao setenforce 0 é o perfil em modo COMPLAIN quando
            foi entregue em enforce. Legível em
            /sys/kernel/security/apparmor/profiles, e o falso positivo é o
            desenvolvedor que rodou aa-complain para depurar
firewall    tabela vazia é comum e legítima (grupo de segurança da nuvem faz
            a filtragem), e ler regra nativamente exige netlink de nftables.
            Custo alto, sinal fraco — é a de pior relação da lista
```

---

## O que este mapa NÃO diz

Cobertura de técnica não é cobertura de ADVERSÁRIO. Um invasor que combina
técnicas cobertas de forma que nenhum check correlacione continua passando.

Metade desse limite caiu. O cenário 71 registrava que os três achados dele têm
sujeitos diferentes — um caminho, um pid e um nome de unit — e que ver o mesmo
ator por trás deles era trabalho humano. A resolução de ator
(`internal/check/ator.go`) traduz pid e unit para o binário e o host sai como
uma história só.

A outra metade continua: ela funde o que aponta para o mesmo binário, e o
adversário cujos sujeitos **não** convergem — implante empacotado, persistência
que não cita o binário, execução por interpretador — não tem o que correlacionar.
Ali a resposta é check novo, não correlação melhor.

E há o eixo que nenhuma técnica desta lista captura: **tempo**. O cenário A3 —
ativação adiada, nada rodando no instante da varredura — não é uma técnica
faltante, é uma propriedade do modelo de retrato.
