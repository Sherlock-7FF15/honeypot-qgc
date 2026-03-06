FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

# ---------- runtime deps ----------
# 包列表保持不变；只增加“允许失败后继续修复”的标准 dpkg/apt 修复链
RUN set -eux; \
    apt-get update; \
    (apt-get install -y --no-install-recommends \
      ca-certificates curl \
      xvfb xauth x11vnc novnc websockify \
      x11-utils \
      libx11-xcb1 libxcb1 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 \
      libxcb-randr0 libxcb-render0 libxcb-render-util0 libxcb-shape0 \
      libxcb-shm0 libxcb-sync1 libxcb-xfixes0 libxcb-xinerama0 \
      libxcb-cursor0 libxkbcommon-x11-0 \
      libxrender1 libxext6 libxi6 libxrandr2 libxfixes3 \
      libsm6 libice6 libglib2.0-0 libdbus-1-3 \
      libopengl0 libgl1-mesa-dri libglx-mesa0 libegl1 libegl-mesa0 \
      libfontconfig1 libfreetype6 fonts-dejavu-core \
      libharfbuzz0b libfribidi0 libusb-1.0-0 libjack-jackd2-0 \
      libspeechd2 \
    ) || true; \
    # 标准修复：把 dpkg 半配置状态修复干净
    dpkg --configure -a || true; \
    apt-get -f install -y || true; \
    dpkg --configure -a; \
    rm -rf /var/lib/apt/lists/*

# ---------- user ----------
RUN useradd -m -s /bin/bash qgc
WORKDIR /home/qgc

# ---------- download AppImage at build time ----------
ARG QGC_APPIMAGE_URL
ARG QGC_APPIMAGE_SHA256=""

RUN test -n "$QGC_APPIMAGE_URL" || (echo "ERROR: QGC_APPIMAGE_URL is required" && exit 1)

RUN set -eux; \
    curl -L --fail -o /home/qgc/QGroundControl.AppImage "$QGC_APPIMAGE_URL"; \
    chmod +x /home/qgc/QGroundControl.AppImage; \
    if [ -n "$QGC_APPIMAGE_SHA256" ]; then \
      echo "$QGC_APPIMAGE_SHA256  /home/qgc/QGroundControl.AppImage" | sha256sum -c - ; \
    fi; \
    /home/qgc/QGroundControl.AppImage --appimage-extract; \
    mkdir -p /opt; \
    rm -rf /opt/qgc; \
    mv squashfs-root /opt/qgc; \
    chown -R qgc:qgc /opt/qgc; \
    rm -f /home/qgc/QGroundControl.AppImage

# ---------- entrypoint ----------
COPY --chown=qgc:qgc entrypoint.sh /home/qgc/entrypoint.sh
RUN chmod +x /home/qgc/entrypoint.sh

USER qgc
ENTRYPOINT ["/home/qgc/entrypoint.sh"]
