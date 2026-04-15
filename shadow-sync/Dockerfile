FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    rsync \
    coreutils \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY sync.sh /opt/shadow-sync/sync.sh
RUN chmod +x /opt/shadow-sync/sync.sh

ENTRYPOINT ["/opt/shadow-sync/sync.sh"]
