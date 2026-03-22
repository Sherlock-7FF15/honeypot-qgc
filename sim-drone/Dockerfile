FROM px4io/px4-dev-simulation-jammy:latest

ENV PX4_AUTOPILOT_DIR=/opt/PX4-Autopilot
ARG PX4_GIT_REF=v1.16.0

RUN wget https://packages.osrfoundation.org/gazebo.gpg -O /usr/share/keyrings/pkgs-osrf-archive-keyring.gpg \
  && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/pkgs-osrf-archive-keyring.gpg] http://packages.osrfoundation.org/gazebo/ubuntu-stable $(lsb_release -cs) main" > /etc/apt/sources.list.d/gazebo-stable.list \
  && apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends gz-harmonic \
  && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --single-branch --branch "${PX4_GIT_REF}" \
      --recurse-submodules --shallow-submodules \
      https://github.com/PX4/PX4-Autopilot.git "${PX4_AUTOPILOT_DIR}" \
  && git -C "${PX4_AUTOPILOT_DIR}/platforms/nuttx/NuttX/nuttx" fetch --tags --depth 1 origin \
  && git -C "${PX4_AUTOPILOT_DIR}/platforms/nuttx/NuttX/apps" fetch --tags --depth 1 origin

WORKDIR ${PX4_AUTOPILOT_DIR}
COPY entrypoint.sh /opt/sim-drone-entrypoint.sh
RUN chmod +x /opt/sim-drone-entrypoint.sh

ENTRYPOINT ["/opt/sim-drone-entrypoint.sh"]
