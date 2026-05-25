#!/bin/sh
set -eu

NEO4J_SERVICE="${NEO4J_SERVICE:-neo4j}"
NEO4J_WAIT_RETRIES="${NEO4J_WAIT_RETRIES:-45}"
NEO4J_WAIT_SECONDS="${NEO4J_WAIT_SECONDS:-2}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
DEV_CONTAINER_SCRIPT="$SCRIPT_DIR/dev_container.sh"
export CODEGRAPH_ENV_FILE="${CODEGRAPH_ENV_FILE:-$PROJECT_ROOT/.env}"
BACKEND_HOST="${CODEGRAPH_HOST:-127.0.0.1}"

echo "Starting ${NEO4J_SERVICE} via Docker Compose..."
"$DEV_CONTAINER_SCRIPT" compose up -d "$NEO4J_SERVICE"

container_id=$("$DEV_CONTAINER_SCRIPT" compose ps -q "$NEO4J_SERVICE")
if [ -z "$container_id" ]; then
  echo "Unable to determine Docker container id for ${NEO4J_SERVICE}." >&2
  exit 1
fi

echo "Waiting for ${NEO4J_SERVICE} to become healthy..."
attempt=1
while [ "$attempt" -le "$NEO4J_WAIT_RETRIES" ]; do
  status=$(
    "$DEV_CONTAINER_SCRIPT" runtime inspect \
      --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' \
      "$container_id" 2>/dev/null || true
  )
  case "$status" in
    healthy)
      echo "${NEO4J_SERVICE} is healthy."
      exec uv run uvicorn app:app --host "$BACKEND_HOST" --port 8000 --reload
      ;;
    exited|dead)
      echo "${NEO4J_SERVICE} stopped unexpectedly while starting." >&2
      "$DEV_CONTAINER_SCRIPT" compose logs "$NEO4J_SERVICE" >&2 || true
      exit 1
      ;;
  esac
  sleep "$NEO4J_WAIT_SECONDS"
  attempt=$((attempt + 1))
done

echo "Timed out waiting for ${NEO4J_SERVICE} to become healthy." >&2
"$DEV_CONTAINER_SCRIPT" compose logs "$NEO4J_SERVICE" >&2 || true
exit 1
