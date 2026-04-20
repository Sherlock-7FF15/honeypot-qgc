FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    openssh-client \
    bash \
    coreutils \
    findutils \
    grep \
    sed \
    gawk \
    procps \
    iproute2 \
    net-tools \
    lsof \
    util-linux \
    strace \
    sudo \
    rsync \
    wget \
    curl \
    netcat-openbsd \
    iputils-ping \
    dnsutils \
    ftp \
    file \
    binutils \
    which \
    less \
    vim-tiny \
    nano \
    zip \
    unzip \
    xz-utils \
    bzip2 \
    tar \
    gzip \
    perl \
    git \
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
COPY sandbox-run.sh /opt/ssh-shadow/sandbox-run.sh
COPY prepare-rootfs.sh /opt/ssh-shadow/prepare-rootfs.sh
COPY root-session-launch.sh /opt/ssh-shadow/root-session-launch.sh
COPY preauth_logger.py /opt/ssh-shadow/preauth_logger.py
COPY fake-root.bashrc /opt/ssh-shadow/fake-root.bashrc
COPY fakebin/ /opt/ssh-shadow/fakebin/

RUN chmod +x /opt/ssh-shadow/*.sh /opt/ssh-shadow/fakebin/*

EXPOSE 2222
ENTRYPOINT ["/opt/ssh-shadow/entrypoint.sh"]
