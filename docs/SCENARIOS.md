# O que a Aletheia detecta

GERADO de `internal/checks` e `test/scenario`. Não edite à mão:
`go test ./test/scenario -run TestDocumentoDeCenarios -update`.

128 checks, 229 cenários.

Um **check** é uma pergunta que a ferramenta faz ao host. Um **cenário** é um
host montado de propósito — em contêiner, imagem ou microVM — que prova a
resposta. Check sem cenário não entra no catálogo: o portão em
`registro_test.go` recusa.

## Checks

### `app` (6)

| check | § | o que acusa | provado por |
|---|---|---|---|
| `app.code_backdoor` | 24 | padrão de backdoor em código servido (PHP/JS/Python) | `B1-webshell-php`, `B2-php-legado-nao-vira-parede`, `B3-eval-aritmetica-sobre-get` +4 |
| `app.web_config_exec` | 7.12 | configuração por diretório muda o que o servidor web executa | `WC1-webshell-no-proprio-htaccess` |
| `manual.code_integrity` *(manual)* | 16 | código versionado em git: a comparação que esta ferramenta não pode fazer | — |
| `persist.web_prepend` | 7.12 | PHP executa arquivo antes de cada requisição | `65-confianca-e-deploy`, `83-comprometimento-de-aplicacao`, `WC1-webshell-no-proprio-htaccess` |
| `tool.artifact` | 5.10 | config de ferramenta conhecida presente em disco | `73-ferramentas-conhecidas`, `73b-scanner-de-rede-em-vm-invadida`, `82-exfiltracao` |
| `tool.binary` | 5.10 | executável de ferramenta conhecida em execução ou agendado | `73-ferramentas-conhecidas`, `73b-scanner-de-rede-em-vm-invadida`, `82-exfiltracao` |

### `cloud` (2)

| check | § | o que acusa | provado por |
|---|---|---|---|
| `manual.cloud_audit` *(manual)* | 10.4 | a evidência que o root do host não apaga está fora da caixa | — |
| `persist.cloud_metadata` *(manual)* | 7.12 | startup-script no metadata da nuvem: fora do alcance desta varredura | — |

### `integrity` (10)

| check | § | o que acusa | provado por |
|---|---|---|---|
| `integrity.defense_drift` | 34 | o estado de um controle de segurança mudou desde o retrato anterior | `DR5-drift-de-defesa-desligada` |
| `integrity.drift_coverage` | 39.3 | o que a comparação com o retrato anterior NÃO alcançou | `DR1-drift-de-persistencia`, `DR2-drift-sem-mudanca-e-silencio` |
| `integrity.immutable_flag` | 21 | arquivo travado por atributo de inode: a remoção falha até ele sair | `C2-implante-imutavel` |
| `integrity.no_package_owner` | 24 | binário em execução ou agendado que nenhum pacote reivindica | `100-azazel-userland`, `101-nss-backdoor`, `18b-nome-de-runtime-sem-pacote-nao-compra-isencao` +16 |
| `integrity.pkg_file_modified` | 24 | arquivo entregue por um pacote não confere com o que o pacote declara | `92-userland-trojanizado` |
| `integrity.pkgdb_tampered` | 24 | a base de pacotes reivindica arquivo onde distribuição nenhuma instala | `A1-implante-empacotado` |
| `integrity.suid_drift` | 7.10 | bit de privilégio mudou desde o retrato anterior | `DR4-drift-das-sete-superficies` |
| `integrity.timestomp` | 9 | data de modificação muito anterior à de metadados: a evidência temporal foi mexida | `A4-data-forjada` |
| `integrity.trust_drift` | 7.11 | em quem este host confia mudou desde o retrato anterior | `DR4-drift-das-sete-superficies`, `DR5-drift-de-defesa-desligada` |
| `path.hidden_exec` | 8 | executável escondido em diretório com ponto, sob árvore temporária | `H2-executavel-escondido` |

### `ioc` (1)

| check | § | o que acusa | provado por |
|---|---|---|---|
| `ioc.match` | 23 | indicador deste incidente encontrado neste host | `P10-tag-de-ebpf-como-indicador`, `R1-indicador-encontrado` |

### `kernel` (16)

| check | § | o que acusa | provado por |
|---|---|---|---|
| `cross.bpf_hidden` | 35 | programa eBPF existe e não aparece na enumeração do kernel | `RK-bpf-hidden` |
| `cross.hidden_pid` | 35 | processo responde direto mas não aparece na listagem de /proc | `RK-hidden-pid`, `RK3-multivetor-cegueira-parcial` |
| `cross.module_view` | 35.3 | módulo aparece numa interface do kernel e não na outra | `NF1-netfilter-backdoor-oculto`, `RK-cross-module-view`, `RK3-multivetor-cegueira-parcial` |
| `cross.socket_view` | 35.5 | socket que o netlink mostra e /proc/net não | `RK-cross-socket-view` |
| `cross.thread_count` | 35 | contagem de threads diverge entre o status e o diretório de tarefas | `RK-thread-count` |
| `kernel.binfmt_interpreter` | 7.12 | o kernel roteia execução para um interpretador registrado | `GB4-binfmt-registro-vivo`, `U3-binfmt-com-interpretador-plantado` |
| `kernel.bpf_inventory` | 35 | o que está instrumentando este kernel por eBPF | `50-kernel-3.18-limpo`, `P1-bpf-sem-dono`, `P2-bpf-com-dono-nao-acusa` +3 |
| `kernel.bpf_unowned` | 35 | programa eBPF carregado no kernel sem nenhum dono visível | `P1-bpf-sem-dono`, `P10-tag-de-ebpf-como-indicador`, `P8-bpfdoor-completo` |
| `kernel.ftrace_hook` | 35.3 | função de enumeração do kernel interceptada: algo está sendo escondido | `G3-hook-de-ftrace-em-vm`, `RK-duplo-hide-ftrace`, `RK-thread-count` +1 |
| `kernel.load_drift` | 34 | o que o kernel carrega ou invoca mudou desde o retrato anterior | `DR5-drift-de-defesa-desligada` |
| `kernel.module_no_file` | 35.3 | módulo carregado sem arquivo em disco que o explique | `Z1-modulo-carregado-sem-arquivo`, `Z2-modulo-sem-assinatura-e-sem-arquivo` |
| `kernel.mount_over_system` | 35 | montagem por cima de diretório de sistema: esconde o que está embaixo | `G4-montagem-que-esconde-em-vm` |
| `kernel.protection_context` | 35.7 | o que este kernel permite a si mesmo: assinatura, lockdown, IMA | `Z1-modulo-carregado-sem-arquivo`, `Z2-modulo-sem-assinatura-e-sem-arquivo`, `Z3-em-container-o-check-se-cala` |
| `kernel.protection_drift` | 34 | o endurecimento do kernel mudou desde o retrato anterior | `DR6-drift-de-endurecimento-do-kernel` |
| `kernel.surface_drift` | 34 | o que o kernel executa mudou desde o retrato anterior | `DR4-drift-das-sete-superficies` |
| `kernel.taint_unexplained` | 35.3 | o kernel registra um módulo que nenhum módulo carregado admite | `P5-taint-sem-modulo-que-admita` |

### `net` (10)

| check | § | o que acusa | provado por |
|---|---|---|---|
| `correlate.revshell` | 17 | reverse shell: fd 0, 1 e 2 no mesmo socket | `40-revshell`, `44-wtf-revshell`, `70-composto-gsocket` |
| `correlate.revshell_bridge` | 17 | reverse shell por ponte: shell lê de um pipe, o outro lado fala com a rede | `R2-revshell-por-ponte` |
| `manual.exfil_volume` *(manual)* | 37.2 | quanto saiu: o host mediu sem querer, em lugares que esta varredura não lê | — |
| `net.backend_exposed` | 15 | serviço usado só pelo proxy local, mas exposto para a rede inteira | `W2-backend-so-do-proxy-mas-aberto` |
| `net.egress_unowned` | 2.1 | conexão para endereço público a partir de binário que nenhum pacote entregou | `71-adversario-competente`, `86-c2-por-origem`, `99-minerador-fala-com-pool` +2 |
| `net.listen_drift` | 7.2 | porta em escuta mudou desde o retrato anterior | `DR4-drift-das-sete-superficies` |
| `net.listener_unowned` | 14 | porta exposta para fora por binário que nenhum pacote entregou | `87-backdoor-de-escuta`, `88-servico-substituido` |
| `net.packet_socket` | 2.6 | quem consegue ler o tráfego deste host | `102-symbiote`, `P8-bpfdoor-completo`, `P9-socket-de-captura-sem-implante` |
| `net.pivot` | 12.2 | pivô: saída externa e saída interna no mesmo processo | `42-pivot`, `Q1-pool-php-fpm-nao-vira-parede` |
| `net.vector_same_user` | 14 | por onde a entrada pode ter acontecido: serviços do mesmo usuário | `W3-vetor-estreitado-pelo-usuario` |

### `persist` (48)

| check | § | o que acusa | provado por |
|---|---|---|---|
| `antiforense.audit_disabled` | 11 | capacidade de registrar execução neste host | `E4-auditoria-desligada`, `E7-auditoria-sem-execve` |
| `antiforense.hidden_text` | 13 | caractere invisível ou sequência de escape: o que se lê não é o que está lá | `TX1-texto-que-engana-quem-le` |
| `antiforense.log_rotation_gap` | 10 | falta uma geração no meio da rotação de log: alguém removeu | `F1-buraco-na-rotacao` |
| `antiforense.shell_history` | 13 | histórico de shell desligado ou desviado: rastro apagado de propósito | `E2-historico-desligado` |
| `antiforense.wtmp_cleared` | 12 | há sessão aberta e nenhum registro de login: o histórico foi zerado | `F2-sessao-sem-registro` |
| `correlate.persistence_redundant` | 7 | o mesmo alvo persistido por vários mecanismos diferentes | `66-cadeia-completa`, `81-minerador-oportunista`, `94-xorddos` +2 |
| `persist.at_job` | 7.4 | job do at agendado: dispara uma vez, no futuro | `62-cron-e-chaves`, `63-cron-e-chaves-em-imagem` |
| `persist.authorized_key_drift` | 7.3 | chave autorizada de SSH mudou desde o retrato anterior | `DR1-drift-de-persistencia` |
| `persist.bash_env` | 7.6 | BASH_ENV definido: executa em shell NÃO interativo | `64-gatilhos-de-execucao` |
| `persist.binfmt_config` | 7.12 | configuração de binfmt que recria um interpretador no boot | `GB1-binfmt-interpretador-sem-dono` |
| `persist.ca_planted` | 7.12 | âncora de confiança instalada fora do pacote de certificados | `65-confianca-e-deploy` |
| `persist.cron_drift` | 7.5 | agendamento mudou desde o retrato anterior | `DR1-drift-de-persistencia` |
| `persist.cron_frequent` | 7.1 | agendamento com intervalo curto: a cadência de um beacon | `62-cron-e-chaves`, `93-kinsing`, `95-outlaw` +2 |
| `persist.cron_suspect` | 7.1 | agendamento executa de lugar suspeito, ou baixa o que executa | `62-cron-e-chaves`, `63-cron-e-chaves-em-imagem`, `81-minerador-oportunista` +3 |
| `persist.env_preload` | 7.8 | LD_PRELOAD definido em arquivo lido a cada sessão | `60-persistencia-ao-vivo` |
| `persist.file_watch` | 7.12 | processo sem dono de pacote vigiando arquivo de persistência | `74-vigia-de-arquivo-que-recria` |
| `persist.host_trust` | 7.12 | confiança host-based: login sem senha por .rhosts/hosts.equiv | `65-confianca-e-deploy` |
| `persist.hosts_override` | 7.12 | /etc/hosts redireciona nome para endereço não local | `65-confianca-e-deploy` |
| `persist.initramfs_hook` | 7.12 | script ou arquivo que entra na geração do initramfs sem dono de pacote | `GB2-initramfs-hook-sem-dono` |
| `persist.interpreter_hook` | 7.8 | variável faz um interpretador carregar código de terceiro | `L1-bash-env-global`, `L2-node-options-em-unit` |
| `persist.kernel_cmdline_weakening` | 35.7 | a linha de boot do kernel desliga uma proteção | `GB3-cmdline-enfraquecido` |
| `persist.kernel_helper` | 7.12 | o kernel invoca um programa que nenhum pacote entregou | `U1-core-pattern-sequestrado`, `U2-modprobe-trocado` |
| `persist.ld_preload_global` | 7.8 | /etc/ld.so.preload existe: biblioteca injetada em todo processo | `100-azazel-userland`, `102-symbiote`, `60-persistencia-ao-vivo` +2 |
| `persist.ld_so_conf_odd` | 7.8 | diretório de busca de bibliotecas fora dos caminhos de sistema | `60-persistencia-ao-vivo` |
| `persist.modprobe_install` | 7.12 | diretiva de modprobe que executa comando em vez de carregar módulo | `97-modulo-no-boot` |
| `persist.nss_module` | 7.8 | módulo NSS carregado em toda resolução de nome que nenhum pacote entregou | `101-nss-backdoor` |
| `persist.pam_exec` | 7.12 | PAM executa programa ou carrega módulo de fora do lugar padrão | `64-gatilhos-de-execucao` |
| `persist.preload_drift` | 7.6 | pré-carga de código mudou desde o retrato anterior | `DR4-drift-das-sete-superficies`, `DR5-drift-de-defesa-desligada` |
| `persist.shell_env` | 7.6 | ENV definido: arquivo lido a cada shell POSIX interativo | `64-gatilhos-de-execucao` |
| `persist.shell_startup` | 7.6 | arquivo de inicialização de shell executa algo suspeito | `64-gatilhos-de-execucao`, `TX1-texto-que-engana-quem-le` |
| `persist.ssh_client_drift` | 7.3 | hook de execução do cliente SSH mudou desde o retrato anterior | `DR5-drift-de-defesa-desligada` |
| `persist.ssh_client_exec` | 7.7 | config do cliente ssh executa comando ao conectar | `SC1-proxycommand-backdoor`, `SC2-proxycommand-legitimo`, `SC3-proxycommand-em-include` |
| `persist.ssh_forced_command` | 7.5 | chave SSH que executa um comando a cada login | `62-cron-e-chaves`, `63-cron-e-chaves-em-imagem` |
| `persist.ssh_keys` *(manual)* | 7.5 | inventário de chaves SSH autorizadas | `62-cron-e-chaves`, `66-cadeia-completa`, `82-exfiltracao` +2 |
| `persist.ssh_server_drift` | 7.3 | configuração do servidor SSH mudou desde o retrato anterior | `DR5-drift-de-defesa-desligada` |
| `persist.sshd_key_source` | 7.5 | sshd busca chave fora do lugar padrão | `62-cron-e-chaves`, `A9-allowlist-do-sshd-em-usr-local` |
| `persist.suid_unowned` | 25 | binário que carrega privilégio e nenhum pacote entregou | `98-retencao-de-root`, `B1-baseline-cala-o-conhecido`, `B2-baseline-de-host-comprometido` +1 |
| `persist.sysv_shm_channel` | 7.12 | memória compartilhada System V: canal aberto ou perfil do Ebury | `SV1-sysv-shm-mundo`, `SV3-ebury-0600-daemon-de-rede` |
| `persist.timer_frequent` | 7.2 | timer com intervalo curto: a forma de um beacon | `60-persistencia-ao-vivo` |
| `persist.trigger_drift` | 7.6 | arquivo que executa em gatilho mudou desde o retrato anterior | `DR5-drift-de-defesa-desligada` |
| `persist.trigger_exec` | 7.7 | gatilho de boot, login ou pacote executa algo suspeito | `64-gatilhos-de-execucao`, `65-confianca-e-deploy`, `83-comprometimento-de-aplicacao` +3 |
| `persist.udev_run` | 7.12 | regra de udev executa programa em evento de dispositivo | `64-gatilhos-de-execucao` |
| `persist.unit_bind_shadow` | 7.2 | unit monta outro arquivo por cima de um caminho de sistema | `A12-bind-troca-o-arquivo-sob-caminho-limpo` |
| `persist.unit_drift` | 7.4 | unit do systemd mudou desde o retrato anterior | `DR1-drift-de-persistencia` |
| `persist.unit_dropin_exec` | 7.2 | drop-in acrescenta execução a uma unit existente | `60-persistencia-ao-vivo`, `61-persistencia-em-imagem`, `71-adversario-competente` +1 |
| `persist.unit_exec_suspect` | 7.2 | unit de systemd executa de lugar suspeito, ou baixa o que executa | `60-persistencia-ao-vivo`, `61-persistencia-em-imagem`, `81-minerador-oportunista` +4 |
| `persist.unit_socket_unowned` | 7.2 | unit de ativação expõe gatilho para binário que nenhum pacote entregou | `A5-ativacao-por-socket`, `J2-dropin-ao-lado-da-unit-de-verdade` |
| `persist.unit_unowned` | 7.2 | serviço de systemd executa um binário de sistema que nenhum pacote entregou | `100-azazel-userland`, `J7-nome-nu-path-padrao`, `US1-nome-nu-atras-de-env` |

### `priv` (19)

| check | § | o que acusa | provado por |
|---|---|---|---|
| `antiforense.mac_downgraded` | 34.9 | SELinux configurado para enforcing e rodando em permissivo | `G1-mac-rebaixado` |
| `auth.bruteforce_success` | 12.5 | origem que falhou muitas vezes conseguiu entrar | `D2-forca-bruta-que-entrou` |
| `auth.login_inventory` | 12 | inventário de entradas registradas no host | `D2-forca-bruta-que-entrou` |
| `cred.known_hosts` | 12.4 | alcance deste host: para onde ele já se conectou | `E3-alcance-do-host` |
| `cred.secret_file` | 12.3 | credencial em arquivo: até onde este host alcança | `E6-credencial-em-arquivo` |
| `cred.ssh_private_key` | 12.3 | chave SSH privada em disco: para onde este host consegue ir | `E1-chave-privada-sem-senha`, `T6-agente-de-build-como-imagem` |
| `manual.audit_query` *(manual)* | 11 | o auditd está ligado: a consulta que amarra o vetor | — |
| `priv.account_drift` | 7.9 | conta ou grupo mudou desde o retrato anterior | `DR4-drift-das-sete-superficies` |
| `priv.account_no_shadow` | 7.9 | conta existe no passwd e não no shadow: não passou pelo useradd | `H1-conta-sem-shadow` |
| `priv.doas_drift` | 7.9 | regra de doas mudou desde o retrato anterior | `DR5-drift-de-defesa-desligada` |
| `priv.doas_nopasswd` | 7.9 | regra de doas que escala sem pedir senha | `84-acesso-por-credencial`, `85-acesso-por-credencial-imagem` |
| `priv.file_owner_no_account` | 7.9 | arquivo pertence a uid/gid que não existe em passwd/group | `J2-dono-sem-conta` |
| `priv.no_password` | 7.9 | conta com campo de senha vazio: entra sem autenticação | `67-privilegio`, `84-acesso-por-credencial`, `85-acesso-por-credencial-imagem` |
| `priv.root_equivalent_group` | 7.9 | grupo que equivale a root tem membro | `67-privilegio` |
| `priv.root_runs_writable` | 36.4 | root executa um arquivo que outra pessoa pode reescrever | `W1-root-executa-o-que-outro-escreve` |
| `priv.service_account_shell` | 7.9 | conta de serviço com shell de login | `67-privilegio` |
| `priv.sudo_drift` | 7.9 | regra de sudo mudou desde o retrato anterior | `DR1-drift-de-persistencia` |
| `priv.sudo_nopasswd` | 7.9 | regra de sudo que escala sem pedir senha | `84-acesso-por-credencial`, `85-acesso-por-credencial-imagem`, `T5-servidor-de-banco-como-imagem` |
| `priv.uid_zero` | 7.9 | conta com uid 0 além do root | `67-privilegio`, `84-acesso-por-credencial`, `85-acesso-por-credencial-imagem` +3 |

### `proc` (16)

| check | § | o que acusa | provado por |
|---|---|---|---|
| `proc.caps_unexpected` | 3.7 | processo não-root com capability que vale por root | `15-capability-sem-root`, `51-kernel-3.18-implante`, `53-cgroup-v1-puro` +1 |
| `proc.container_boundary` | 38.1 | processo cruza a fronteira entre contêiner e host | `M1-processo-de-container-nao-vira-aviso`, `M2-conteudo-de-imagem-executado-fora`, `Z3-em-container-o-check-se-cala` |
| `proc.deleted_mapping` | 3.14 | biblioteca apagada do disco, ainda mapeada e executável | `11-exe-apagado`, `11b-exe-apagado-de-diretorio-gravavel`, `M3-mapeamento-apagado` |
| `proc.env_tool_marker` | 5.10 | variável de ambiente que identifica a família da ferramenta | `70-composto-gsocket` |
| `proc.exe_deleted` | 3.14 | executável apagado do disco, processo ainda rodando | `11-exe-apagado`, `11b-exe-apagado-de-diretorio-gravavel` |
| `proc.kthread_disguise` | 3.5 | processo de userspace disfarçado de thread de kernel | `10-kthread-disguise`, `29-userland-legado-implante`, `30-32-bits` +7 |
| `proc.ld_preload_env` | 7.8 | LD_PRELOAD no ambiente de um processo em execução | `72-ld-preload-por-processo` |
| `proc.maps_exec_anon` | 3.10 | código executável em memória, sem arquivo e sem rótulo | `M1-injecao-rx-anon` |
| `proc.maps_rwx_anon` | 3.10 | região de memória gravável, executável e sem arquivo por trás | `17-rwx-anonimo`, `18b-nome-de-runtime-sem-pacote-nao-compra-isencao`, `51-kernel-3.18-implante` +3 |
| `proc.memfd_exec` | 3.16 | execução fileless: exe aponta para memória anônima | `13-memfd-fileless`, `29-userland-legado-implante`, `30-32-bits` +4 |
| `proc.ns_divergent` | 3.15 | namespace próprio fora de container e fora de unit | `19-namespace-proprio` |
| `proc.program_drift` | 2 | programa passou a rodar sob outra identidade | `DR4-drift-das-sete-superficies` |
| `proc.service_account_pty` | 3.2 | conta de serviço com terminal interativo | `69-pty-de-conta-de-servico` |
| `proc.shell_from_service` | 3.2 | daemon de rede gerou um shell | `68-linhagem`, `83-comprometimento-de-aplicacao` |
| `proc.suspicious_path` | 8 | processo executando de diretório onde nada se instala | `14-caminho-suspeito`, `29-userland-legado-implante`, `31-sem-os-release` +6 |
| `proc.tracer` | 3.7 | processo sob ptrace: alguém controla a memória dele | `16-ptrace`, `51-kernel-3.18-implante`, `52-kernel-4.14-implante` +1 |

## Cenários

`live` roda a CLI dentro do contêiner; `image` exporta o rootfs e varre de
fora com `--root`; `vm` sobe uma microVM com kernel próprio, para o que
contêiner não alcança — hidepid, sysctl, módulo, cgroup, eBPF.

| cenário | modo | o que monta |
|---|---|---|
| `00-limpo` | live | contêiner intocado não pode produzir achado nenhum |
| `01-sem-root` | live | sem root a cobertura DEGRADA e o exit não pode ser 0 |
| `02-kthread-real` | live | thread de kernel legítima não dispara: ela não tem exe |
| `10-kthread-disguise` | live | implante renomeado com exec -a para se passar por thread de kernel |
| `100-azazel-userland` | live | rootkit de userland azazel: ld.so.preload + serviço-backdoor que o systemd ressuscita |
| `101-nss-backdoor` | live | módulo NSS malicioso: código que roda em TODA resolução de nome, sem processo nem porta |
| `102-symbiote` | live | Symbiote: ocultação em DUAS camadas — LD_PRELOAD para processo/arquivo e filtro de pacote para tráfego |
| `11-exe-apagado` | live | binário apagado com o processo ainda rodando |
| `11b-exe-apagado-de-diretorio-gravavel` | live | o mesmo apagamento, mas o binário rodava de /tmp: aí a explicação de rotina acaba |
| `12-pid1-nao-eh-isento` | live | PID 1 é avaliado como qualquer outro processo |
| `13-memfd-fileless` | live | binário executado de memória anônima: nunca esteve em disco |
| `14-caminho-suspeito` | live | binário rodando de /tmp — onde instalação nenhuma põe binário |
| `15-capability-sem-root` | live | processo de usuário comum com capability que vale por root |
| `16-ptrace` | live | processo sob ptrace: outro processo controla a memória dele |
| `17-rwx-anonimo` | live | memória gravável, executável e sem arquivo por trás |
| `18-jit-de-sistema-nao-dispara` | live | runtime com JIT em diretório de sistema é pulado |
| `18b-nome-de-runtime-sem-pacote-nao-compra-isencao` | live | o MESMO nome de runtime, no MESMO diretório de sistema, sem dono de pacote: a isenção não vale |
| `19-namespace-proprio` | live | unshare fora de container e fora de unit: esconderijo sem rootkit |
| `20-image-symlink-absoluto` | image | imagem com symlink absoluto não pode ler o host do analista |
| `21-image-sem-processo` | image | imagem montada não tem processo: os checks de proc viram NÃO VERIFICADO |
| `27-rpm-declara-a-lacuna` | live | base de pacotes do rpm é binária: a ferramenta DIZ que não pôde perguntar |
| `28-userland-legado-limpo` | live | userland de época intocado não pode produzir achado |
| `29-userland-legado-implante` | live | userland de época não muda o que a ferramenta enxerga |
| `30-32-bits` | live | binário de 32 bits enxerga o mesmo: servidor i686 legado ainda existe |
| `30-hidepid-root` | vm | com root, hidepid=2 não esconde nada: o implante é visto |
| `31-hidepid-sem-root` | vm | sem root sob hidepid=2 o implante é INVISÍVEL — e a ferramenta precisa DIZER isso |
| `31-sem-os-release` | live | distribuição anterior ao os-release não pode quebrar o cabeçalho |
| `32-cota-de-cpu` | live | cota de cgroup é lida: o runtime do Go não a enxerga |
| `40-revshell` | live | fd 0, 1 e 2 no mesmo socket, saindo para endereço público |
| `41-socket-activation-nao-eh-revshell` | live | ativação por socket tem a MESMA forma e não pode disparar |
| `42-pivot` | live | mesmo processo com saída externa e saída interna: a VM é caminho |
| `43-proxy-reverso-nao-eh-pivo` | live | proxy reverso fala com os dois lados e NÃO é pivô |
| `44-wtf-revshell` | live | wtf enxerga o que precisa ser enxergado em 1s, e sai com o mesmo código |
| `50-kernel-3.18-limpo` | vm | kernel de 2014, guest limpo: cobertura completa e nenhum achado |
| `51-kernel-3.18-implante` | vm | kernel de 2014 enxerga os mesmos implantes que o kernel atual |
| `52-kernel-4.14-implante` | vm | kernel do Amazon Linux 2 enxerga os mesmos implantes |
| `53-cgroup-v1-puro` | vm | servidor legado sem cgroup v2: a hierarquia nomeada é a que responde |
| `54-i686-limpo` | vm | i686 de verdade — kernel, userland e binário de 32 bits — limpo |
| `55-i686-implante` | vm | i686 enxerga exatamente os mesmos implantes que amd64 |
| `60-persistencia-ao-vivo` | live | as seis formas da §7 plantadas: unit, drop-in, timer, preload, conf e environment |
| `61-persistencia-em-imagem` | image | o mesmo plantio, varrido DE FORA: persistência não precisa de host vivo |
| `62-cron-e-chaves` | live | as duas persistências mais comuns em invasão real: cron e authorized_keys |
| `63-cron-e-chaves-em-imagem` | image | o mesmo plantio varrido DE FORA: agendamento e chave saem do disco |
| `64-gatilhos-de-execucao` | live | shell startup, BASH_ENV, rc.local, PAM e udev: cada um com o SEU evento |
| `65-confianca-e-deploy` | live | CA plantada, /etc/hosts, hook de git e auto_prepend: persistência fora de /etc/systemd |
| `66-cadeia-completa` | live | invasão inteira com peças que parecem legítimas: nome de sistema, caminho de sistema, comando limpo |
| `67-privilegio` | live | uid 0 disfarçado, senha vazia, conta de serviço com shell e grupo que é root |
| `68-linhagem` | live | daemon de rede gerando shell: a cadeia clássica de pós-exploração web |
| `69-pty-de-conta-de-servico` | live | conta de serviço com terminal: alguém entrou com a identidade dela |
| `70-composto-gsocket` | live | a forma que o runbook §5.10 descreve, inteira: caminho, disfarce, canal e marcador |
| `71-adversario-competente` | live | o MESMO objetivo, evitando cada regra: mede o que hoje passa batido |
| `72-ld-preload-por-processo` | live | LD_PRELOAD no ambiente de um processo vivo rebaixa a confiança da execução |
| `73-ferramentas-conhecidas` | live | reconhece a família por config em disco e por nome de executável |
| `73b-scanner-de-rede-em-vm-invadida` | live | o Explorer do runZero rodando numa VM de aplicação: a capacidade não é acesso, é CONHECIMENTO da rede interna |
| `74-vigia-de-arquivo-que-recria` | live | processo sem dono de pacote vigiando /etc/cron.d: é assim que o backdoor removido volta |
| `74b-vigia-fora-de-persistencia-nao-acusa` | live | o contrapeso: o MESMO binário sem dono, vigiando cache em vez de persistência, não pode virar achado |
| `80-servidor-legitimo` | live | servidor de produção real, sem invasor nenhum: mede o custo em atenção |
| `81-minerador-oportunista` | live | criptominerador: o comprometimento mais comum que existe em VM exposta |
| `82-exfiltracao` | live | coleta e envio de dados: staging comprimido e ferramenta de nuvem com config nova |
| `83-comprometimento-de-aplicacao` | live | aplicação web explorada: shell filho do daemon, e a volta plantada onde a app roda |
| `84-acesso-por-credencial` | live | entrada por senha fraca: conta nova com uid 0, sudoers e chave, sem payload nenhum |
| `85-acesso-por-credencial-imagem` | image | o mesmo host do 84 varrido como rootfs desligado: a resposta não pode divergir |
| `86-c2-por-origem` | live | canal de comando e controle reconhecido pela ORIGEM, sem consultar reputação de destino |
| `87-backdoor-de-escuta` | live | porta alta aberta para fora por binário sem dono: o oposto do shell reverso |
| `88-servico-substituido` | live | porta de serviço conhecido ocupada por outro binário: substituição, não aplicação nova |
| `90-kernel-2.6` | live | procfs de kernel 2.6.32 (RHEL 6): campos ausentes em /proc/<pid>/status ⚠ não reproduzível: os cenários 50–52 cobrem 3.18 e 4.14, que é até onde o initramfs de Alpine atual boota |
| `92-userland-trojanizado` | live | binário e biblioteca do sistema SUBSTITUÍDOS no lugar: a forma do Ebury |
| `93-kinsing` | live | Kinsing: minerador em /tmp com carregador, cron que baixa e executa a cada minuto |
| `94-xorddos` | live | XorDDoS: o malware tem forma de BIBLIOTECA e persiste por três caminhos ao mesmo tempo |
| `95-outlaw` | live | Outlaw: botnet de força bruta em SSH, com tudo escondido dentro do home |
| `96-hiddenwasp` | live | HiddenWasp: rootkit de userland por ld.so.preload, com nome que imita biblioteca de sistema |
| `97-modulo-no-boot` | live | módulo de kernel carregado no boot por configuração: a camada mais funda da persistência |
| `98-retencao-de-root` | live | SUID plantado: a volta que não deixa processo, conexão nem agendamento |
| `99-minerador-fala-com-pool` | live | criptominerador em tmpfs, disfarçado de kthread, abrindo a conexão stratum para o pool |
| `A1-implante-empacotado` | live | o invasor REGISTRA o implante no gerenciador de pacotes: derrota a pergunta de propriedade |
| `A10-run-parts-para-diretorio-proprio` | live | run-parts apontando para /etc/cron.backup: a isenção casava por PREFIXO e a coleta por lista fechada |
| `A11-jit-em-usr-local-nao-herda-isencao` | live | binário chamado `node` em /usr/local/bin: a isenção de JIT casava "/usr/" inteiro, e /usr/local está dentro |
| `A12-bind-troca-o-arquivo-sob-caminho-limpo` | live | a unit monta um implante por cima de /usr/bin: o host mostra o binário da distribuição, e a unit executa outro |
| `A12-pacote-malicioso-de-verdade` | live | o invasor CONSTRÓI e INSTALA um .deb real: propriedade, hash e base ficam TODOS válidos ⚠ lacuna conhecida: pacote do invasor instalado corretamente (propriedade/hash/base/caminho válidos) é indistinguível de um legítimo sem verificar origem/assinatura/repositório |
| `A12b-bind-de-endurecimento-nao-vira-achado` | live | o contrapeso: BindReadOnlyPaths entre caminhos de sistema é o uso para o qual a diretiva existe |
| `A2-sem-binario` | live | persistência sem depositar binário: só o que a distribuição já entregou |
| `A3-ativacao-adiada` | live | nada em execução no instante da varredura: a volta está agendada para depois |
| `A4-data-forjada` | live | timestomping: o implante recebe a data de um arquivo vizinho e a janela do incidente some |
| `A5-ativacao-por-socket` | live | backdoor que só existe quando alguém conecta: no retrato, não há processo nem porta suspeita |
| `A6-dentro-de-runtime-com-jit` | live | o implante roda DENTRO de um runtime com JIT: a isenção some com o achado, e precisa aparecer como LACUNA |
| `A8-listener-fechado-inverte-a-direcao` | live | serviço que fecha o listener depois do accept: a inferência de direção invertia, e o §17 acusava uma conexão de ENTRADA |
| `A9-allowlist-do-sshd-em-usr-local` | live | backdoor com nome de integração conhecida em /usr/local/bin: a isenção do AuthorizedKeysCommand era dada de graça |
| `B1-baseline-cala-o-conhecido` | live | servidor legítimo com baseline: o acúmulo de dois anos cala e o implante novo grita |
| `B1-webshell-php` | live | webshell de uma linha em bootstrap.php: crase sobre $_REQUEST vira CRÍTICO; eval puro fica em aviso |
| `B2-baseline-de-host-comprometido` | live | a captura foi feita com o implante JÁ instalado: ele desce de nível e NÃO desaparece |
| `B2-php-legado-nao-vira-parede` | live | cinco formas de PHP legado que pareciam backdoor não podem alarmar — e o webshell ao lado tem de continuar saindo |
| `B3-baseline-declara-a-si-mesma` | live | baseline capturada SEM privilégio: a execução seguinte diz que a referência é incompleta |
| `B3-eval-aritmetica-sobre-get` | live | eval de string concatenando $_GET cru (RCE pós-auth de app legada) continua CRÍTICO mesmo depois de calar os FPs de PHP legado |
| `B4-all-fs-alcanca-fora-dos-roots` | live | --all-fs varre a FS inteira e acha o webshell num docroot que não está na lista de web roots |
| `B5-ignore-exclui-e-declara` | live | --ignore tira uma árvore da varredura (declarado), sem cegar o resto |
| `B6-closure-e-exec-de-biblioteca` | live | closure literal (array_map/array_filter) e exec de biblioteca com script fixo não alarmam — callback nomeado pelo request continua crítico |
| `B7-backdoor-semantico-sem-sink` | live | credencial mágica e header secreto concedem acesso: backdoor sem sink, invisível à peneira léxica ⚠ lacuna conhecida: backdoor semântico (credencial mágica / header secreto) não tem sink perigoso: a peneira léxica não prova intenção e não o vê |
| `C1-capability-em-xattr` | vm | retenção de root por capability em atributo estendido, sem bit de setuid nenhum |
| `C2-implante-imutavel` | vm | implante travado com atributo imutável: a limpeza falha, e falha em silêncio |
| `D2-forca-bruta-que-entrou` | live | a mesma origem que falhou dezenas de vezes conseguiu entrar |
| `DR1-drift-de-persistencia` | live | quatro mudanças legítimas em forma, invisíveis para o catálogo de checks |
| `DR2-drift-sem-mudanca-e-silencio` | live | duas coletas do MESMO contêiner parado: o drift precisa ser VAZIO, senão a feature é ruído |
| `DR3-drift-com-a-ordem-trocada` | live | os dois retratos na ordem errada: a ferramenta precisa RECUSAR, e não responder ao contrário |
| `DR4-drift-das-sete-superficies` | live | sete superfícies mudadas, e a mudança encontrando o achado que fala dela |
| `DR5-drift-de-defesa-desligada` | live | sete controles enfraquecidos entre dois retratos, nenhum suspeito parado |
| `DR6-drift-de-endurecimento-do-kernel` | vm | sysctl de proteção afrouxado entre dois retratos, num kernel de verdade |
| `E1-chave-privada-sem-senha` | live | chave SSH privada sem senha: credencial de movimento lateral largada aberta |
| `E2-historico-desligado` | live | histórico de shell apontado para /dev/null e desligado no rc: rastro apagado de propósito |
| `E3-alcance-do-host` | live | known_hosts: dezenas de evidências mandam procurar na frota, e esta diz em quais máquinas |
| `E4-auditoria-desligada` | live | auditoria instalada e neutralizada com `-e 0`: a trilha some sem o arquivo sumir |
| `E5-sem-auditoria-nao-eh-achado` | live | host sem auditoria não produz achado: é o estado da maioria dos servidores |
| `E6-credencial-em-arquivo` | live | credencial de nuvem e segredo de aplicação: até onde este host alcança |
| `E7-auditoria-sem-execve` | live | auditoria configurada e sem regra de execução: a presença dela faz parecer que há trilha |
| `F1-buraco-na-rotacao` | live | falta uma geração no meio da série de rotação: o logrotate nunca faz isso |
| `F2-sessao-sem-registro` | live | sessão aberta agora e histórico de login vazio: as duas não podem ser verdade juntas |
| `F3-rotacao-do-wtmp-nao-eh-achado` | live | a MESMA forma, produzida pelo logrotate: arquivo vivo vazio com sessão aberta |
| `G1-mac-rebaixado` | vm | config pede enforcing e o kernel reporta permissivo: alguém rodou setenforce 0 |
| `G2-mac-permissivo-declarado` | vm | config PEDE permissivo: é escolha do administrador e não pode virar achado |
| `G3-hook-de-ftrace-em-vm` | vm | hook de enumeração com tracefs montado pelo próprio guest, sem contêiner privilegiado |
| `G4-montagem-que-esconde-em-vm` | vm | bind por cima de /etc num kernel próprio, sem privilégio emprestado de contêiner |
| `GB1-binfmt-interpretador-sem-dono` | live | config de binfmt aponta para um interpretador sem dono: o systemd-binfmt o recria no boot |
| `GB2-initramfs-hook-sem-dono` | live | script de geração do initramfs sem dono de pacote: roda como root ANTES do userland |
| `GB3-cmdline-enfraquecido` | live | GRUB_CMDLINE_LINUX desliga o confinamento: enfraquece a defesa desde o próximo boot |
| `GB4-binfmt-registro-vivo` | vm | interpretador de binfmt REGISTRADO no kernel vivo, apontando para /tmp gravável |
| `H1-conta-sem-shadow` | live | backdoor de uma linha no /etc/passwd: não passou pelo useradd, e o shadow prova |
| `H2-executavel-escondido` | live | binário parado num diretório com ponto sob /var/tmp: nada precisa estar rodando |
| `I1-censo-com-teto-e-padrao` | live | trinta cópias do mesmo comando sob um usuário: o censo conta as tarefas, compara com o teto e NOMEIA a repetição |
| `I1-rc-local-inerte` | live | rc.local com o mesmo payload e SEM bit de execução: inerte hoje, e um chmod o ativa |
| `I2-dossie-de-processo-que-mente` | live | o dossiê de um processo cujo argv se diz thread de kernel: as três identidades lado a lado |
| `I3-censo-de-rede-com-leque` | live | um processo abrindo conexão para dez endereços na MESMA porta: o censo agrupa por executável e NOMEIA o leque |
| `I4-varredura-de-portas-nao-eh-pool` | live | um processo abrindo dezesseis PORTAS do mesmo host: é varredura, e entrava como pool de conexão |
| `I5-repositorio-adulterado` | live | backdoor commitado com --amend, hooks redirecionados e config que executa: o que a revisão de código não vê |
| `J1-fabrica-com-servicos` | live | Debian com sshd, cron e rsyslog instalados e NADA plantado |
| `J2-dono-sem-conta` | live | conta removida na faxina: o binário que ficou em /usr/bin pertence a um uid que não existe |
| `J2-dropin-ao-lado-da-unit-de-verdade` | live | drop-in com implante numa unit que EXISTE, entregue por pacote |
| `J3-cron-de-invasor-entre-os-de-fabrica` | live | entrada de cron do invasor no meio do /etc/crontab de fábrica |
| `J4-transient-vence-etc` | live | unit efêmera em /run/systemd/transient VENCE a de /etc de mesmo nome |
| `J5-dropin-type-wide` | live | service.d/ (type-wide) com ExecStartPre malicioso atinge toda service |
| `J6-execsearchpath-dropin` | live | ExecSearchPath de drop-in resolve o ExecStart nu da base para /tmp |
| `J7-nome-nu-path-padrao` | live | ExecStart de nome nu resolve contra o PATH fixo; binário sem-dono em /usr/sbin vira unit_unowned |
| `J8-dropin-user-por-home` | live | drop-in em ~/.config/systemd/user/*.service.d/ com ExecStartPre malicioso é visto |
| `K1-ativacao-adiada-o-scan-nao-ve` | live | implante que só conecta depois: o retrato não pega, a vigília pega |
| `K1b-o-mesmo-implante-invisivel-ao-scan` | live | o CONTROLE do K1: o mesmo plantio, visto por um retrato |
| `K2-vigilia-em-host-quieto` | live | host limpo vigiado por quatro ciclos não pode inventar mudança |
| `K3-implante-que-vai-e-volta` | live | processo que aparece, sai e reaparece: a forma de algo com gatilho |
| `K4-beacon-periodico-com-gatilho-nomeado` | live | beacon curto e regular: mede o ritmo e diz QUEM dispara |
| `L1-bash-env-global` | live | BASH_ENV em /etc/environment: todo bash não-interativo executa o arquivo |
| `L2-node-options-em-unit` | live | NODE_OPTIONS=--require numa unit: o serviço carrega módulo alheio |
| `L3-python-hook-vs-o-do-pacote` | live | usercustomize.py do invasor ao lado do sitecustomize.py que o dpkg entregou |
| `L4-fabrica-com-python-instalado` | live | python instalado e nenhum hook plantado: estado de fábrica não é ataque |
| `M1-injecao-rx-anon` | live | injeção W^X: no retrato a região é r-xp anônima e NUNCA foi gravável-e-executável |
| `M1-mcp-vazio-nunca-e-limpo` | live | contêiner limpo: a lista de críticos sai vazia e o veredito NÃO diz OK |
| `M1-processo-de-container-nao-vira-aviso` | vm | binário em camada de imagem, com cgroup de contêiner: é o normal |
| `M2-conteudo-de-imagem-executado-fora` | vm | o MESMO binário, com o cgroup do host: alguém rodou fora do contêiner |
| `M2-mcp-o-veredito-acompanha-o-implante` | live | execução fileless plantada: a MESMA consulta que sai vazia no host limpo traz o crítico aqui |
| `M3-mapeamento-apagado` | live | biblioteca mapeada EXECUTÁVEL e apagada: o exe principal fica íntegro, a lib some do disco |
| `M3-mcp-injecao-nao-alcanca-a-superficie` | live | argv[0] endereçado ao modelo: chega inteiro em data, marcado, e não toca a lista de ferramentas |
| `M4-mcp-nao-existe-tool-de-execucao` | live | o registry concede observação, não execução: nenhuma tool escreve, executa ou mata |
| `M5-mcp-recusa-root-sem-consentimento` | live | como root e sem --allow-root: o servidor recusa subir, e diz por quê |
| `M6-mcp-paridade-de-cobertura-com-analyze` | live | a cobertura que o MCP publica é a MESMA que o analyze imprime sobre o mesmo retrato |
| `M7-mcp-responde-sobre-o-retrato` | live | o processo é morto ANTES do servidor subir: o dossiê continua respondendo sobre ele |
| `M8-mcp-lacuna-de-coleta-tambem-e-regiao-declarada` | live | nome hostil num arquivo que não abre: o texto do alvo alcança observability, e o caminho vem declarado |
| `M9-mcp-responde-sobre-o-artefato-e-nao-sobre-a-maquina` | live | retrato de uma imagem montada servido de outra máquina: as respostas são do artefato, e as tools de processo nem existem |
| `N1-alternatives-legitimo` | live | cadeia do update-alternatives apontando para binário COM dono |
| `N2-alternatives-sequestrado` | live | a MESMA cadeia, apontando para lugar sem dono: continua achado |
| `NF1-netfilter-backdoor-oculto` | vm | backdoor de netfilter que se esconde de /proc/modules é pego pelo cross.module_view via a função do hook no ftrace |
| `P1-bpf-sem-dono` | vm | programa eBPF carregado, anexado a um socket e com o descritor fechado: ninguém visível o segura |
| `P10-tag-de-ebpf-como-indicador` | vm | a tag do implante em eBPF, trazida do host anterior, encontra o mesmo programa aqui |
| `P2-bpf-com-dono-nao-acusa` | vm | o MESMO programa, com o descritor mantido aberto: é o que toda ferramenta com libbpf faz |
| `P3-bpf-pin-e-dono-visivel` | vm | programa preso no bpffs e o carregador SAIU: o pin é dono, e persistência declarada não é achado |
| `P4-bpf-perf-event-legado` | vm | anexo legado por perf_event, sem link nenhum: o kernel é quem sabe quem segura |
| `P5-taint-sem-modulo-que-admita` | vm | o kernel registra módulo não assinado e nenhum módulo carregado assume: o que fica depois que o módulo sai |
| `P6-bpf-anexo-por-cgroup` | vm | programa anexado a um cgroup sem link e sem descritor: a população legítima que NÃO pode virar achado |
| `P7-bpf-preso-a-mapa` | vm | programa vivo apenas por estar num prog_array: é o mapa que segura, e é como o cilium encadeia |
| `P8-bpfdoor-completo` | vm | socket AF_PACKET com filtro eBPF e descritor fechado: o implante que não abre porta, e quem o segura nomeado |
| `P9-socket-de-captura-sem-implante` | live | o MESMO socket de captura, sem programa nenhum: é o gerenciador de rede, e não pode virar acusação |
| `Q1-pool-php-fpm-nao-vira-parede` | vm | trinta workers de php-fpm com uma conexão externa e uma interna cada: a forma de pivô, multiplicada pelo tamanho do pool |
| `R1-indicador-encontrado` | live | o indicador do incidente aparece neste host: é a §23 respondida |
| `R2-indicador-ausente` | live | a mesma lista contra um host que não tem nada dela: silêncio, e a conta do que foi procurado |
| `R2-revshell-por-ponte` | live | reverse shell INDIRETO: o shell lê de um pipe, a ponte segura o pipe E o socket de saída |
| `R3-lista-sem-indicador-falha-alto` | live | arquivo de indicadores que não produz indicador nenhum: erro, não varredura limpa |
| `RK-bpf-hidden` | vm | programa eBPF citado pelo fdinfo de um processo e escondido da enumeração da bpf(2) |
| `RK-cross-module-view` | vm | LKM some de /proc/modules e /sys/module, mas o ftrace ainda retém sua função rastreável |
| `RK-cross-socket-view` | vm | conexão escondida de /proc/net/tcp por hook em tcp4_seq_show, visível pelo INET_DIAG |
| `RK-duplo-hide-ftrace` | vm | esconde socket das DUAS fontes: o cross-view cega, mas o hook de ftrace continua delatando o mecanismo |
| `RK-hidden-pid` | vm | processo some da listagem de /proc mas um filho visível o declara como pai e ele responde a stat |
| `RK-thread-count` | vm | contagem de threads do status diverge do diretório task porque uma entrada de TID foi filtrada do readdir |
| `RK1-diamorphine` | live | LKM clássico: esconde módulo de /proc/modules, esconde PID por sinal, dá root por sinal ⚠ não reproduzível: exige o LKM Diamorphine compilado e carregado; ocultação de módulo/PID só é real vinda do kernel, e carregá-la na suíte Go perderia o controle do ambiente |
| `RK2-reptile` | live | LKM por ftrace: esconde arquivo/dir/PID/porta e persiste, com trigger de rede ⚠ não reproduzível: exige o LKM Reptile compilado e carregado num kernel casado; mesma recusa do RK1 |
| `RK3-multivetor-cegueira-parcial` | vm | full-stealth multivetor: cega o cross-view de socket, é pego em módulo/pid/ftrace, e NÃO alega host íntegro |
| `RK3-singularity-full-stealth` | live | rootkit 6.x que falsifica /proc, /proc/net, module list, sysfs, taint, SOCK_DIAG, BPF, ftrace, audit ⚠ não reproduzível: os PADRÕES de evasão já são medidos no RK3-multivetor-cegueira-parcial |
| `RK4-triplecross` | live | rootkit eBPF multipropósito: stealth, injeção, hijack e C2 por vários tipos de programa/anexo ⚠ não reproduzível: exige o TripleCross carregado; o contrato é por-PROGRAMA (atribuído vs bpf_unowned vs FixMapa), não um veredito único |
| `RK5-ebpfkit` | live | rootkit eBPF com anexos e mapas variados para stealth e controle ⚠ não reproduzível: exige o ebpfkit carregado; contrato por-programa como o RK4, com peso no caminho FixMapa (segurado por mapa) |
| `RK6-boopkit` | live | backdoor eBPF: RCE sobre TCP cru com gatilho de rede e ocultação de processo ⚠ não reproduzível: exige o boopkit carregado e o pacote-gatilho disparado; a expectativa é detecção por algum ângulo (bpf_unowned, hidden_pid, socket cru), mas é previsão a confirmar no vm-matr… |
| `S1-janela-recorta-e-declara` | live | dois agendamentos idênticos, um de 2020 e um de agora: a janela fica com o recente e CONTA o que cortou |
| `S2-sem-data-fica` | live | conta com uid 0 não tem mtime que a situe no tempo: a janela mais estreita do mundo não pode escondê-la |
| `S3-ancora-derivado` | live | sem --since, a ferramenta deriva o âncora do achado mais severo e DIZ que derivou |
| `SC1-proxycommand-backdoor` | live | ProxyCommand do ~/.ssh/config aponta para binário em /tmp: roda a cada ssh |
| `SC2-proxycommand-legitimo` | live | o MESMO ProxyCommand, mas `ssh -W` para um bastion: inventariado, não acusado |
| `SC3-proxycommand-em-include` | live | ProxyCommand escondido num arquivo que o ~/.ssh/config inclui fora de ~/.ssh |
| `SV1-sysv-shm-mundo` | live | segmento SysV SHM gravável por qualquer usuário e de root: o canal aberto do Ebury |
| `SV2-sysv-shm-restrito` | live | o MESMO segmento a 0600 (a forma do banco de dados): restrito, não é canal aberto |
| `SV3-ebury-0600-daemon-de-rede` | live | segmento 0600 GRANDE criado por daemon de rede: o Ebury moderno, que a permissão sozinha perde |
| `SV4-interlock-pequeno-nao-dispara` | live | segmento 0600 PEQUENO de daemon de rede (interlock do Postgres): abaixo do piso, não é o Ebury |
| `T1-servidor-web-de-producao` | live | nó de web real, arrumado e recém-reconstruído: nada de crítico, e o ruído tem teto |
| `T2-servidor-de-banco-de-producao` | live | PostgreSQL 16 numa máquina com três migrações de história: o host mais sujo dos três |
| `T3-agente-de-build-de-producao` | live | runner de CI: chave privada, credencial de registro e grupo docker — tudo legítimo, tudo verdadeiro |
| `T4-servidor-web-como-imagem` | image | o nó de web varrido de fora, como rootfs desligado: os mesmos achados de disco, com a cobertura dizendo o que falta |
| `T5-servidor-de-banco-como-imagem` | image | o banco varrido de fora: a regra de sudo continua aparecendo, e os checks de processo viram NÃO VERIFICADO |
| `T6-agente-de-build-como-imagem` | image | o runner de CI varrido de fora: chave privada e credencial de registro continuam visíveis no disco |
| `TX1-texto-que-engana-quem-le` | live | nome com caractere invisivel ao lado do gemeo limpo, e sequencia de escape escondendo o comando dentro do .bashrc |
| `U1-core-pattern-sequestrado` | vm | o kernel pipa o core dump para um programa em /tmp: execução como root sem unit, sem cron e sem processo pai |
| `U2-modprobe-trocado` | vm | o helper que o kernel executa ao carregar módulo aponta para um caminho gravável |
| `U3-binfmt-com-interpretador-plantado` | vm | interpretador registrado por assinatura: executar um arquivo comum passa a executar outro programa |
| `US1-nome-nu-atras-de-env` | live | ExecStart=/usr/bin/env <bin> resolve o binário embrulhado e o check de dono o pega |
| `V1-preserva-exe-apagado` | live | o binário foi apagado do disco e o processo continua vivo: a cópia em /proc é a última que existe |
| `V2-preserva-memfd-e-memoria-anonima` | live | execução fileless e região anônima RWX: as duas coisas que só existem enquanto o processo viver |
| `V3-coleta-parcial-declarada` | live | sem privilégio, metade da coleta falha — e a metade que falhou aparece com o mesmo destaque da que deu certo |
| `W1-root-executa-o-que-outro-escreve` | live | cron de root chama um script cujo dono é outra conta, e outro que qualquer um escreve |
| `W2-backend-so-do-proxy-mas-aberto` | live | serviço que só o loopback usa, escutando na rede inteira: o atacante pula o proxy |
| `W3-vetor-estreitado-pelo-usuario` | live | o suspeito roda como um uid, e só o serviço daquele uid pode ser a porta de entrada |
| `WC1-webshell-no-proprio-htaccess` | live | o webshell inteiro dentro do .htaccess: nenhum .php novo no docroot, e o arquivo de configuração é ao mesmo tempo o que o torna executável e o payload |
| `X1-coleta-aqui-analise-depois` | live | o implante entra no retrato: a coleta acontece no host e a conclusão acontece do lado limpo |
| `X2-a-analise-nao-melhora-a-cobertura` | live | coleta sem privilégio, análise COMO ROOT: o que ninguém olhou continua não olhado |
| `Y1-captura-o-que-foi-pedido` | live | captura de tráfego sem tcpdump: o que casa o filtro entra no arquivo |
| `Y2-o-filtro-exclui-e-diz-que-excluiu` | live | mesmo tráfego, filtro em outra porta: zero gravados, e a diferença entre 'não casou' e 'não houve' fica dita |
| `Z1-modulo-carregado-sem-arquivo` | vm | insmod seguido de rm: o código continua dentro do kernel e não há arquivo em disco que o explique |
| `Z2-modulo-sem-assinatura-e-sem-arquivo` | vm | o kernel marca o módulo como não assinado E não há arquivo: as duas coisas juntas não têm explicação de rotina |
| `Z3-em-container-o-check-se-cala` | live | dentro de contêiner /proc/modules é o do HOST e /lib/modules é o da imagem: a comparação acusaria todo módulo do host |

## Limites declarados (9)

O que a ferramenta NÃO alcança, dito por escrito. Um cenário que declara o
próprio limite vale mais que a ausência dele: a lacuna fica medida em vez de
ser descoberta no incidente.

- **`90-kernel-2.6`** (não reproduzível aqui) — os cenários 50–52 cobrem 3.18 e 4.14, que é até onde o initramfs de Alpine atual boota
- **`A12-pacote-malicioso-de-verdade`** (lacuna conhecida) — pacote do invasor instalado corretamente (propriedade/hash/base/caminho válidos) é indistinguível de um legítimo sem verificar origem/assinatura/repositório
- **`B7-backdoor-semantico-sem-sink`** (lacuna conhecida) — backdoor semântico (credencial mágica / header secreto) não tem sink perigoso: a peneira léxica não prova intenção e não o vê
- **`RK1-diamorphine`** (não reproduzível aqui) — exige o LKM Diamorphine compilado e carregado; ocultação de módulo/PID só é real vinda do kernel, e carregá-la na suíte Go perderia o controle do ambiente
- **`RK2-reptile`** (não reproduzível aqui) — exige o LKM Reptile compilado e carregado num kernel casado; mesma recusa do RK1
- **`RK3-singularity-full-stealth`** (não reproduzível aqui) — os PADRÕES de evasão já são medidos no RK3-multivetor-cegueira-parcial
- **`RK4-triplecross`** (não reproduzível aqui) — exige o TripleCross carregado; o contrato é por-PROGRAMA (atribuído vs bpf_unowned vs FixMapa), não um veredito único
- **`RK5-ebpfkit`** (não reproduzível aqui) — exige o ebpfkit carregado; contrato por-programa como o RK4, com peso no caminho FixMapa (segurado por mapa)
- **`RK6-boopkit`** (não reproduzível aqui) — exige o boopkit carregado e o pacote-gatilho disparado; a expectativa é detecção por algum ângulo (bpf_unowned, hidden_pid, socket cru), mas é previsão a confirmar no vm-matr…
