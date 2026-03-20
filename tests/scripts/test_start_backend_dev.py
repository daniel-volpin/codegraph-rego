import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests._support import PROJECT_ROOT
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "start_backend_dev.sh"
DEV_CONTAINER_SCRIPT_PATH = PROJECT_ROOT / "scripts" / "dev_container.sh"


def _write_executable(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class StartBackendDevScriptTests(unittest.TestCase):
    def test_script_fails_when_neo4j_container_exits_during_startup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            compose_cmd = tmp_path / "compose.sh"
            runtime_cmd = tmp_path / "runtime.sh"

            _write_executable(
                compose_cmd,
                """#!/bin/sh
if [ "$1" = "up" ]; then
  exit 0
fi
if [ "$1" = "ps" ] && [ "$2" = "-q" ]; then
  printf '%s\\n' 'neo4j-container'
  exit 0
fi
if [ "$1" = "logs" ]; then
  printf '%s\\n' 'neo4j failed'
  exit 0
fi
exit 1
""",
            )
            _write_executable(
                runtime_cmd,
                """#!/bin/sh
if [ "$1" = "inspect" ]; then
  printf '%s\\n' 'exited'
  exit 0
fi
exit 1
""",
            )

            result = subprocess.run(
                [SCRIPT_PATH.as_posix()],
                cwd=PROJECT_ROOT,
                env={
                    **os.environ,
                    "DOCKER_COMPOSE_CMD": compose_cmd.as_posix(),
                    "CONTAINER_RUNTIME_CMD": runtime_cmd.as_posix(),
                    "NEO4J_WAIT_RETRIES": "1",
                    "NEO4J_WAIT_SECONDS": "0",
                },
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("stopped unexpectedly", result.stderr)

    def test_script_starts_podman_machine_when_needed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            docker_cmd = tmp_path / "docker"
            podman_cmd = tmp_path / "podman"
            uv_cmd = tmp_path / "uv"
            state_file = tmp_path / "podman-state"

            _write_executable(
                docker_cmd,
                """#!/bin/sh
exit 1
""",
            )
            _write_executable(
                podman_cmd,
                f"""#!/bin/sh
state_file="{state_file.as_posix()}"
state="stopped"
if [ -f "$state_file" ]; then
  state=$(cat "$state_file")
fi
case "$1" in
  info)
    if [ "$state" = "running" ]; then
      exit 0
    fi
    exit 125
    ;;
  machine)
    if [ "$2" = "inspect" ]; then
      exit 0
    fi
    if [ "$2" = "start" ]; then
      printf '%s' 'running' > "$state_file"
      exit 0
    fi
    exit 1
    ;;
  compose)
    if [ "$2" = "up" ]; then
      exit 0
    fi
    if [ "$2" = "ps" ] && [ "$3" = "-q" ]; then
      printf '%s\\n' 'neo4j-container'
      exit 0
    fi
    exit 1
    ;;
  inspect)
    printf '%s\\n' 'healthy'
    exit 0
    ;;
esac
exit 1
""",
            )
            _write_executable(
                uv_cmd,
                """#!/bin/sh
exit 0
""",
            )

            result = subprocess.run(
                [SCRIPT_PATH.as_posix()],
                cwd=PROJECT_ROOT,
                env={
                    **os.environ,
                    "PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}",
                    "NEO4J_WAIT_RETRIES": "1",
                    "NEO4J_WAIT_SECONDS": "0",
                },
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0)
            self.assertIn("Starting Podman machine", result.stdout)

    def test_dev_container_script_falls_back_to_legacy_docker_compose(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            docker_cmd = tmp_path / "docker"
            docker_compose_cmd = tmp_path / "docker-compose"
            output_file = tmp_path / "compose-args.txt"

            _write_executable(
                docker_cmd,
                """#!/bin/sh
if [ "$1" = "compose" ] && [ "$2" = "version" ]; then
  exit 1
fi
if [ "$1" = "info" ]; then
  exit 0
fi
exit 1
""",
            )
            _write_executable(
                docker_compose_cmd,
                f"""#!/bin/sh
printf '%s\\n' "$@" > "{output_file.as_posix()}"
exit 0
""",
            )

            result = subprocess.run(
                [DEV_CONTAINER_SCRIPT_PATH.as_posix(), "compose", "up", "-d", "neo4j"],
                cwd=PROJECT_ROOT,
                env={
                    **os.environ,
                    "PATH": f"{tmp_path}{os.pathsep}{os.environ['PATH']}",
                },
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0)
            self.assertEqual(output_file.read_text(encoding="utf-8"), "up\n-d\nneo4j\n")


if __name__ == "__main__":
    unittest.main()
