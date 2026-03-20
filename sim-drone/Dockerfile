FROM px4io/px4-dev-base-jammy:latest

ENV DEBIAN_FRONTEND=noninteractive
ENV PX4_AUTOPILOT_DIR=/opt/PX4-Autopilot
ARG PX4_GIT_REF=v1.16.0

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    gnupg \
    lsb-release \
    socat \
  && rm -rf /var/lib/apt/lists/*

RUN curl https://packages.osrfoundation.org/gazebo.gpg --output /usr/share/keyrings/pkgs-osrf-archive-keyring.gpg \
  && echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/pkgs-osrf-archive-keyring.gpg] https://packages.osrfoundation.org/gazebo/ubuntu-stable $(lsb_release -cs) main" > /etc/apt/sources.list.d/gazebo-stable.list \
  && apt-get update \
  && apt-get install -y --no-install-recommends gz-harmonic \
  && rm -rf /var/lib/apt/lists/*

RUN git clone --recursive --branch "${PX4_GIT_REF}" https://github.com/PX4/PX4-Autopilot.git "${PX4_AUTOPILOT_DIR}"

WORKDIR ${PX4_AUTOPILOT_DIR}
RUN DONT_RUN=1 HEADLESS=1 make px4_sitl gz_x500
COPY entrypoint.sh /opt/sim-drone-entrypoint.sh
RUN chmod +x /opt/sim-drone-entrypoint.sh

ENTRYPOINT ["/opt/sim-drone-entrypoint.sh"]
