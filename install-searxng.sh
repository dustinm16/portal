#!/usr/bin/env bash
# Install SearXNG (metasearch engine) for use as an Open Relay Portal managed service.
#
# What this does:
#   - installs build/runtime apt dependencies (incl. system uWSGI + python3 plugin)
#   - creates a dedicated unprivileged `searxng` system user
#   - clones SearXNG to /usr/local/searxng/searxng-src and builds a venv at
#     /usr/local/searxng/searx-pyenv
#   - creates /etc/searxng (settings.yml is generated at runtime by the portal
#     service module services/searxng.py)
#
# The service itself (process start/stop/restart/health) is managed by the portal,
# NOT by systemd. This script only lays down the tree.
#
# Idempotent: safe to re-run. Re-running updates the SearXNG checkout.

set -euo pipefail

SEARXNG_USER="searxng"
SEARXNG_HOME="/usr/local/searxng"
SEARXNG_SRC="${SEARXNG_HOME}/searxng-src"
SEARXNG_VENV="${SEARXNG_HOME}/searx-pyenv"
SEARXNG_REPO="https://github.com/searxng/searxng"
SETTINGS_DIR="/etc/searxng"

if [[ $EUID -ne 0 ]]; then
    exec sudo -E "$0" "$@"
fi

log() { printf '\n\033[1;32m==>\033[0m %s\n' "$*"; }

log "Installing apt dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends \
    python3-dev python3-babel python3-venv python-is-python3 \
    uwsgi uwsgi-plugin-python3 \
    git build-essential \
    libxslt1-dev zlib1g-dev libffi-dev libssl-dev

log "Ensuring '${SEARXNG_USER}' system user exists"
if ! id "${SEARXNG_USER}" &>/dev/null; then
    useradd --system --create-home --home-dir "${SEARXNG_HOME}" \
        --shell /usr/sbin/nologin "${SEARXNG_USER}"
else
    echo "user already exists"
fi
install -d -o "${SEARXNG_USER}" -g "${SEARXNG_USER}" "${SEARXNG_HOME}"

log "Cloning / updating SearXNG source at ${SEARXNG_SRC}"
if [[ -d "${SEARXNG_SRC}/.git" ]]; then
    sudo -H -u "${SEARXNG_USER}" git -C "${SEARXNG_SRC}" pull --ff-only
else
    sudo -H -u "${SEARXNG_USER}" git clone "${SEARXNG_REPO}" "${SEARXNG_SRC}"
fi

log "Building Python venv at ${SEARXNG_VENV}"
if [[ ! -x "${SEARXNG_VENV}/bin/python" ]]; then
    sudo -H -u "${SEARXNG_USER}" python3 -m venv "${SEARXNG_VENV}"
fi

log "Installing SearXNG into the venv (this compiles lxml etc, ~2-4 min)"
sudo -H -u "${SEARXNG_USER}" bash -euo pipefail <<EOF
source "${SEARXNG_VENV}/bin/activate"
pip install --upgrade pip setuptools wheel
# Build prerequisites: SearXNG's setup.py imports searx/__init__.py which pulls in
# msgspec at build time, so with --no-build-isolation these must be present first.
pip install --upgrade pyyaml msgspec typing-extensions pybind11
cd "${SEARXNG_SRC}"
pip install --use-pep517 --no-build-isolation -e .
EOF

log "Creating ${SETTINGS_DIR} (settings.yml generated at runtime by the portal)"
install -d -o root -g "${SEARXNG_USER}" -m 0750 "${SETTINGS_DIR}"

log "Recording installed version"
sudo -H -u "${SEARXNG_USER}" git -C "${SEARXNG_SRC}" log -1 --format='%h %ci %s' \
    | tee "${SEARXNG_HOME}/.installed-version"

cat <<EOF

SearXNG source : ${SEARXNG_SRC}
venv           : ${SEARXNG_VENV}
python         : $("${SEARXNG_VENV}/bin/python" --version)
settings dir   : ${SETTINGS_DIR}

Done. Next: the portal 'searxng' managed service generates ${SETTINGS_DIR}/settings.yml
and runs it under uWSGI on 127.0.0.1:8888, proxied at https://portal.dddvm.xyz/search/.

Manual smoke test (standalone, no portal):
  sudo install -o root -g ${SEARXNG_USER} -m 0640 \\
      ${SEARXNG_SRC}/searx/settings.yml ${SETTINGS_DIR}/settings.yml
  sudo -u ${SEARXNG_USER} env SEARXNG_SETTINGS_PATH=${SETTINGS_DIR}/settings.yml \\
      ${SEARXNG_VENV}/bin/python -m searx.webapp
  curl -s http://127.0.0.1:8888/ | grep -i searxng
EOF
