# Imagem de cenário COM A CONTRAPARTE LEGÍTIMA PRESENTE.
#
# A matriz de contêineres é magra por desenho — rápida, e prova o binário
# estático. O preço apareceu num defeito real: o cenário 71 planta um drop-in em
# `sshd.service` e roda em alpine, que tem ZERO unit systemd. A resolução de
# ator tinha um bug que só aparece quando a unit de verdade existe ao lado do
# drop-in, e o cenário não podia vê-lo — não havia unit de verdade em lugar
# nenhum.
#
#	alpine:3.20      0 units
#	debian:12       28
#	host real      421
#
# Um check validado só onde o legítimo está AUSENTE pode estar passando pelo
# motivo errado: ele acerta porque só há uma resposta possível no cenário, e
# erra no servidor porque lá há centenas. Esta imagem existe para dar a ele as
# centenas.
#
# O `iproute2` não é serviço: é o que os cenários usam para levantar endereço no
# loopback. Sem ele o `ip addr add` falha calado e o cenário de rede mede outra
# coisa — foi o que aconteceu na primeira tentativa.
#
# O que se instala aqui não é decoração: é serviço que um servidor real tem, com
# unit de pacote, binário com dono no dpkg, config em /etc e usuário próprio.
FROM debian:12

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      openssh-server \
      cron \
      rsyslog \
      ca-certificates \
      iproute2 \
 && rm -rf /var/lib/apt/lists/*

# Um crontab de sistema legítimo, do jeito que um servidor tem.
RUN printf '17 * * * * root cd / && run-parts --report /etc/cron.hourly\n' \
      > /etc/cron.d/padrao \
 && chmod 644 /etc/cron.d/padrao

# E uma conta de serviço, com shell de verdade e home próprio: o alvo típico de
# quem entra e quer ficar.
RUN useradd --create-home --shell /bin/bash deploy
