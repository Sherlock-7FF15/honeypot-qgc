FROM px4io/px4-dev-base-jammy:latest

ENV DEBIAN_FRONTEND=noninteractive
ENV PX4_AUTOPILOT_DIR=/opt/PX4-Autopilot
ARG PX4_GIT_REF=v1.16.0

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    gnupg \
    lsb-release \
    socat \
    software-properties-common \
    sudo \
    wget \
  && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --single-branch --branch "${PX4_GIT_REF}" \
      --recurse-submodules --shallow-submodules \
      https://github.com/PX4/PX4-Autopilot.git "${PX4_AUTOPILOT_DIR}" \
  && bash "${PX4_AUTOPILOT_DIR}/Tools/setup/ubuntu.sh" --no-nuttx \
  && find "${PX4_AUTOPILOT_DIR}" -name .git -type d -prune -exec rm -rf {} + \
  && rm -rf /var/lib/apt/lists/* /root/.cache/pip

WORKDIR ${PX4_AUTOPILOT_DIR}
COPY entrypoint.sh /opt/sim-drone-entrypoint.sh
RUN chmod +x /opt/sim-drone-entrypoint.sh

ENTRYPOINT ["/opt/sim-drone-entrypoint.sh"]
