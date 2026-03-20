#!/bin/sh
set -eu

PODMAN_MACHINE_NAME="${PODMAN_MACHINE_NAME:-podman-machine-default}"

run_custom_cmd() {
  custom_cmd=$1
  shift
  exec sh -c 'exec "$@"' sh $custom_cmd "$@"
}

docker_ready() {
  command -v docker >/dev/null 2>&1 &&
    docker compose version >/dev/null 2>&1 &&
    docker info >/dev/null 2>&1
}

docker_compose_v1_ready() {
  command -v docker-compose >/dev/null 2>&1 &&
    command -v docker >/dev/null 2>&1 &&
    docker info >/dev/null 2>&1
}

ensure_podman_ready() {
  if ! command -v podman >/dev/null 2>&1; then
    return 1
  fi

  if podman info >/dev/null 2>&1; then
    return 0
  fi

  if podman machine inspect "$PODMAN_MACHINE_NAME" >/dev/null 2>&1; then
    echo "Starting Podman machine ${PODMAN_MACHINE_NAME}..."
    podman machine start "$PODMAN_MACHINE_NAME" >/dev/null 2>&1 || true
  else
    echo "Starting default Podman machine..."
    podman machine start >/dev/null 2>&1 || true
  fi

  if ! podman info >/dev/null 2>&1; then
    echo "Podman is installed but not ready. Start the Podman machine and try again." >&2
    exit 1
  fi
}

run_compose() {
  if [ -n "${DOCKER_COMPOSE_CMD:-}" ]; then
    run_custom_cmd "$DOCKER_COMPOSE_CMD" "$@"
  fi

  if docker_ready; then
    exec docker compose "$@"
  fi

  if docker_compose_v1_ready; then
    exec docker-compose "$@"
  fi

  if command -v podman >/dev/null 2>&1; then
    ensure_podman_ready
    exec podman compose "$@"
  fi

  echo "A Docker-compatible Compose runtime is required." >&2
  exit 1
}

run_runtime() {
  if [ -n "${CONTAINER_RUNTIME_CMD:-}" ]; then
    run_custom_cmd "$CONTAINER_RUNTIME_CMD" "$@"
  fi

  if docker_ready || docker_compose_v1_ready; then
    exec docker "$@"
  fi

  if command -v podman >/dev/null 2>&1; then
    ensure_podman_ready
    exec podman "$@"
  fi

  echo "A Docker-compatible container runtime is required." >&2
  exit 1
}

subcommand=${1:-}
if [ -z "$subcommand" ]; then
  echo "Usage: $0 <compose|runtime> [args...]" >&2
  exit 1
fi
shift

case "$subcommand" in
  compose)
    run_compose "$@"
    ;;
  runtime)
    run_runtime "$@"
    ;;
  *)
    echo "Unknown subcommand: $subcommand" >&2
    exit 1
    ;;
esac
