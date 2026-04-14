FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    bash \
    coreutils \
    findutils \
    grep \
    sed \
    procps \
    iproute2 \
    util-linux \
    strace \
    rsync \
    python3 \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash gcs \
  && mkdir -p /run/sshd /opt/ssh-shadow /var/log/ssh-shadow /shadow/base /shadow/sessions /shadow/state /logs/ssh-shadow/sessions \
  && chown -R gcs:gcs /home/gcs /shadow/sessions /logs/ssh-shadow

COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /opt/ssh-shadow/entrypoint.sh
COPY forced-command.sh /opt/ssh-shadow/forced-command.sh
COPY exec-original-command.sh /opt/ssh-shadow/exec-original-command.sh
COPY interactive-shell.sh /opt/ssh-shadow/interactive-shell.sh
COPY trace-agent.sh /opt/ssh-shadow/trace-agent.sh
COPY build-jail.sh /opt/ssh-shadow/build-jail.sh
COPY preauth_logger.py /opt/ssh-shadow/preauth_logger.py
COPY fakebin/ /opt/ssh-shadow/fakebin/

RUN chmod +x /opt/ssh-shadow/*.sh /opt/ssh-shadow/fakebin/*

EXPOSE 2222
ENTRYPOINT ["/opt/ssh-shadow/entrypoint.sh"]
