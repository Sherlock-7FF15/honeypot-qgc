FROM px4io/px4-dev-simulation-jammy:latest

ENV PX4_AUTOPILOT_DIR=/opt/PX4-Autopilot
ARG PX4_GIT_REF=v1.16.0

RUN git clone --depth 1 --single-branch --branch "${PX4_GIT_REF}" \
      --recurse-submodules --shallow-submodules \
      https://github.com/PX4/PX4-Autopilot.git "${PX4_AUTOPILOT_DIR}"

WORKDIR ${PX4_AUTOPILOT_DIR}
COPY entrypoint.sh /opt/sim-drone-entrypoint.sh
RUN chmod +x /opt/sim-drone-entrypoint.sh

ENTRYPOINT ["/opt/sim-drone-entrypoint.sh"]
