ARG BASE_IMAGE=m.daocloud.io/ghcr.io/openclaw/openclaw:latest
FROM ${BASE_IMAGE}

USER root

ARG APT_MIRROR=https://mirrors.aliyun.com/debian
ARG APT_SECURITY_MIRROR=https://mirrors.aliyun.com/debian-security
ARG PYPI_INDEX_URL=https://mirrors.aliyun.com/pypi/simple/

# Pre-bake common dependencies used by skill workflows to avoid per-run installs.
RUN set -eux; \
    if [ -f /etc/apt/sources.list.d/debian.sources ]; then \
      sed -i "s@http://deb.debian.org/debian@${APT_MIRROR}@g" /etc/apt/sources.list.d/debian.sources; \
      sed -i "s@http://security.debian.org/debian-security@${APT_SECURITY_MIRROR}@g" /etc/apt/sources.list.d/debian.sources; \
    fi; \
    if [ -f /etc/apt/sources.list ]; then \
      sed -i "s@http://deb.debian.org/debian@${APT_MIRROR}@g" /etc/apt/sources.list; \
      sed -i "s@http://security.debian.org/debian-security@${APT_SECURITY_MIRROR}@g" /etc/apt/sources.list; \
    fi; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      python3 \
      python-is-python3 \
      python3-pip \
      python3-docx \
      python3-openpyxl \
      python3-defusedxml \
      pandoc \
      libreoffice \
      poppler-utils \
      zip \
      unzip \
      p7zip-full \
      curl \
      git \
      procps; \
    rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir --break-system-packages -i "${PYPI_INDEX_URL}" python-pptx

USER root
