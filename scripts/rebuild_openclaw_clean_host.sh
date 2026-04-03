#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="${IMAGE_NAME:-skillrt-openclaw-clean:latest}"
BASE_CONTAINER_NAME="${BASE_CONTAINER_NAME:-skillrt-openclaw-host}"
DOCKERFILE_PATH="${DOCKERFILE_PATH:-docker/openclaw-clean-base.Dockerfile}"
BASE_IMAGE="${BASE_IMAGE:-m.daocloud.io/ghcr.io/openclaw/openclaw:latest}"
APT_MIRROR="${APT_MIRROR:-https://mirrors.aliyun.com/debian}"
APT_SECURITY_MIRROR="${APT_SECURITY_MIRROR:-https://mirrors.aliyun.com/debian-security}"
PYPI_INDEX_URL="${PYPI_INDEX_URL:-https://mirrors.aliyun.com/pypi/simple/}"

echo "[1/4] Building clean OpenClaw image: ${IMAGE_NAME}"
echo "      base_image=${BASE_IMAGE}"
echo "      apt_mirror=${APT_MIRROR}"
echo "      apt_security_mirror=${APT_SECURITY_MIRROR}"
echo "      pypi_index=${PYPI_INDEX_URL}"
docker build \
  --build-arg BASE_IMAGE="${BASE_IMAGE}" \
  --build-arg APT_MIRROR="${APT_MIRROR}" \
  --build-arg APT_SECURITY_MIRROR="${APT_SECURITY_MIRROR}" \
  --build-arg PYPI_INDEX_URL="${PYPI_INDEX_URL}" \
  -f "${DOCKERFILE_PATH}" \
  -t "${IMAGE_NAME}" .

echo "[2/4] Stopping existing host container (if any): ${BASE_CONTAINER_NAME}"
docker rm -f "${BASE_CONTAINER_NAME}" >/dev/null 2>&1 || true

echo "[3/4] Starting host container from clean image"
docker run -d --restart unless-stopped --name "${BASE_CONTAINER_NAME}" "${IMAGE_NAME}" tail -f /dev/null >/dev/null

echo "[4/4] Done"
docker ps --filter "name=^${BASE_CONTAINER_NAME}$" --format "table {{.Names}}\t{{.Image}}\t{{.Status}}"
