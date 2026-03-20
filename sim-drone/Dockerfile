FROM px4io/px4-dev-simulation-focal:latest

ENV DEBIAN_FRONTEND=noninteractive
ENV PX4_AUTOPILOT_DIR=/opt/PX4-Autopilot
ARG PX4_GIT_REF=v1.16.0

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    socat \
  && rm -rf /var/lib/apt/lists/*

RUN git clone --recursive --branch "${PX4_GIT_REF}" https://github.com/PX4/PX4-Autopilot.git "${PX4_AUTOPILOT_DIR}"

WORKDIR ${PX4_AUTOPILOT_DIR}
COPY entrypoint.sh /opt/sim-drone-entrypoint.sh
RUN chmod +x /opt/sim-drone-entrypoint.sh

ENTRYPOINT ["/opt/sim-drone-entrypoint.sh"]
