#!/bin/sh
set -eu

if [ -n "${DOCKER_COMPOSE_CMD:-}" ]; then
  COMPOSE_CMD="$DOCKER_COMPOSE_CMD"
elif command -v docker >/dev/null 2>&1; then
  COMPOSE_CMD="docker compose"
elif command -v podman >/dev/null 2>&1; then
  COMPOSE_CMD="podman compose"
else
  COMPOSE_CMD=""
fi

if [ -n "${CONTAINER_RUNTIME_CMD:-}" ]; then
  CONTAINER_RUNTIME="$CONTAINER_RUNTIME_CMD"
elif command -v docker >/dev/null 2>&1; then
  CONTAINER_RUNTIME="docker"
elif command -v podman >/dev/null 2>&1; then
  CONTAINER_RUNTIME="podman"
else
  CONTAINER_RUNTIME=""
fi

NEO4J_SERVICE="${NEO4J_SERVICE:-neo4j}"
NEO4J_WAIT_RETRIES="${NEO4J_WAIT_RETRIES:-45}"
NEO4J_WAIT_SECONDS="${NEO4J_WAIT_SECONDS:-2}"

if [ -z "$COMPOSE_CMD" ] || [ -z "$CONTAINER_RUNTIME" ]; then
  echo "A Docker-compatible container runtime is required to start the Neo4j dependency." >&2
  exit 1
fi

echo "Starting ${NEO4J_SERVICE} via Docker Compose..."
$COMPOSE_CMD up -d "$NEO4J_SERVICE"

container_id=$($COMPOSE_CMD ps -q "$NEO4J_SERVICE")
if [ -z "$container_id" ]; then
  echo "Unable to determine Docker container id for ${NEO4J_SERVICE}." >&2
  exit 1
fi

echo "Waiting for ${NEO4J_SERVICE} to become healthy..."
attempt=1
while [ "$attempt" -le "$NEO4J_WAIT_RETRIES" ]; do
  status=$($CONTAINER_RUNTIME inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$container_id" 2>/dev/null || true)
  case "$status" in
    healthy)
      echo "${NEO4J_SERVICE} is healthy."
      exec uv run uvicorn app:app --host 0.0.0.0 --port 8000
      ;;
    exited|dead)
      echo "${NEO4J_SERVICE} stopped unexpectedly while starting." >&2
      $COMPOSE_CMD logs "$NEO4J_SERVICE" >&2 || true
      exit 1
      ;;
  esac
  sleep "$NEO4J_WAIT_SECONDS"
  attempt=$((attempt + 1))
done

echo "Timed out waiting for ${NEO4J_SERVICE} to become healthy." >&2
$COMPOSE_CMD logs "$NEO4J_SERVICE" >&2 || true
exit 1
