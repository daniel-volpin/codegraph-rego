import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "start_backend_dev.sh"


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


if __name__ == "__main__":
    unittest.main()
