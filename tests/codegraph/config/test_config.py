from __future__ import annotations

import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from pydantic import ValidationError


class TestConfigSettings(unittest.TestCase):
    def test_settings_can_be_constructed_without_env_file_for_non_runtime_fields(self) -> None:
        from codegraph.config import Settings

        with patch.dict(os.environ, {}, clear=True):
            settings = Settings(_env_file=None)

        self.assertEqual(settings.index_dir, "index")
        self.assertIsNone(settings.neo4j_pass)

    def test_validate_runtime_settings_requires_neo4j_password(self) -> None:
        from codegraph.config import Settings, validate_runtime_settings

        with patch.dict(os.environ, {}, clear=True):
            settings = Settings(_env_file=None)

            with self.assertRaisesRegex(ValueError, "NEO4J_PASS"):
                validate_runtime_settings(settings)

    def test_validate_runtime_settings_passes_when_password_present(self) -> None:
        from codegraph.config import Settings, validate_runtime_settings

        settings = Settings(_env_file=None, neo4j_pass="secret")

        validated = validate_runtime_settings(settings)
        self.assertIs(validated, settings)

    def test_numeric_constraints_reject_invalid_values(self) -> None:
        from codegraph.config import Settings

        with self.assertRaises(ValidationError):
            Settings(_env_file=None, llm_concurrency=0)

        with self.assertRaises(ValidationError):
            Settings(_env_file=None, llm_max_concurrent_requests=0)

        with self.assertRaises(ValidationError):
            Settings(_env_file=None, llm_max_concurrent_requests=9)

        with self.assertRaises(ValidationError):
            Settings(_env_file=None, llm_max_pending_requests=-1)

        with self.assertRaises(ValidationError):
            Settings(_env_file=None, llm_max_pending_requests=33)

        with self.assertRaises(ValidationError):
            Settings(_env_file=None, llm_queue_timeout_seconds=0)

        with self.assertRaises(ValidationError):
            Settings(_env_file=None, llm_queue_timeout_seconds=120.1)

        with self.assertRaises(ValidationError):
            Settings(_env_file=None, remediation_confidence_threshold_apply=1.5)

        with self.assertRaises(ValidationError):
            Settings(_env_file=None, remediation_confidence_threshold_review=-0.1)

        with self.assertRaises(ValidationError):
            Settings(_env_file=None, java_parser_timeout_seconds=0)

        with self.assertRaises(ValidationError):
            Settings(_env_file=None, java_parser_timeout_seconds=120.1)

        with self.assertRaises(ValidationError):
            Settings(_env_file=None, java_parser_heap_mb=127)

        with self.assertRaises(ValidationError):
            Settings(_env_file=None, java_parser_heap_mb=2049)

        with self.assertRaises(ValidationError):
            Settings(_env_file=None, java_parser_max_concurrent_requests=0)

        with self.assertRaises(ValidationError):
            Settings(_env_file=None, java_parser_max_concurrent_requests=3)

        with self.assertRaises(ValidationError):
            Settings(_env_file=None, java_parser_queue_timeout_seconds=0)

        with self.assertRaises(ValidationError):
            Settings(_env_file=None, java_parser_queue_timeout_seconds=120.1)

        with self.assertRaises(ValidationError):
            Settings(_env_file=None, java_parser_max_source_bytes=(1024 * 1024) - 1)

        with self.assertRaises(ValidationError):
            Settings(_env_file=None, java_parser_max_source_bytes=(4 * 1024 * 1024) + 1)

        with self.assertRaises(ValidationError):
            Settings(_env_file=None, java_parser_max_output_bytes=(1024 * 1024) - 1)

        with self.assertRaises(ValidationError):
            Settings(_env_file=None, java_parser_max_output_bytes=(16 * 1024 * 1024) + 1)

    def test_java_parser_settings_have_canonical_defaults_and_env_aliases(self) -> None:
        from codegraph.config import PROJECT_ROOT, Settings

        settings = Settings(_env_file=None)

        self.assertEqual(settings.java_parser_jar, PROJECT_ROOT / "tools/java-parser/target/codegraph-java-parser.jar")
        self.assertEqual(settings.java_parser_timeout_seconds, 30.0)
        self.assertEqual(settings.java_parser_heap_mb, 384)
        self.assertEqual(settings.java_parser_max_concurrent_requests, 1)
        self.assertEqual(settings.java_parser_queue_timeout_seconds, 5.0)
        self.assertEqual(settings.java_parser_max_source_bytes, 4 * 1024 * 1024)
        self.assertEqual(settings.java_parser_max_output_bytes, 16 * 1024 * 1024)
        self.assertEqual(settings.java_parser_language_level, "25")

        with patch.dict(
            os.environ,
            {
                "JAVA_PARSER_JAR": "/opt/parser.jar",
                "JAVA_PARSER_TIMEOUT_SECONDS": "7",
                "JAVA_PARSER_HEAP_MB": "512",
                "JAVA_PARSER_MAX_CONCURRENT_REQUESTS": "2",
                "JAVA_PARSER_QUEUE_TIMEOUT_SECONDS": "3",
                "JAVA_PARSER_MAX_SOURCE_BYTES": str(2 * 1024 * 1024),
                "JAVA_PARSER_MAX_OUTPUT_BYTES": str(2 * 1024 * 1024),
                "JAVA_PARSER_LANGUAGE_LEVEL": "21",
            },
            clear=True,
        ):
            overridden = Settings(_env_file=None)

        self.assertEqual(overridden.java_parser_jar, Path("/opt/parser.jar"))
        self.assertEqual(overridden.java_parser_timeout_seconds, 7.0)
        self.assertEqual(overridden.java_parser_heap_mb, 512)
        self.assertEqual(overridden.java_parser_max_concurrent_requests, 2)
        self.assertEqual(overridden.java_parser_queue_timeout_seconds, 3.0)
        self.assertEqual(overridden.java_parser_max_source_bytes, 2 * 1024 * 1024)
        self.assertEqual(overridden.java_parser_max_output_bytes, 2 * 1024 * 1024)
        self.assertEqual(overridden.java_parser_language_level, "21")

    def test_get_settings_is_cached_and_clearable(self) -> None:
        from codegraph.config import clear_settings_cache, get_settings

        clear_settings_cache()
        settings_a = get_settings()
        settings_b = get_settings()
        self.assertIs(settings_a, settings_b)

        clear_settings_cache()
        settings_c = get_settings()
        self.assertIsNot(settings_a, settings_c)

    def test_get_settings_only_loads_env_file_when_explicitly_configured(self) -> None:
        from codegraph.config import ENV_FILE_OVERRIDE_VAR, clear_settings_cache, get_settings

        with TemporaryDirectory() as tmp_dir:
            env_file = Path(tmp_dir) / "dev.env"
            env_file.write_text("NEO4J_PASS=from-explicit-env\n", encoding="utf-8")

            with patch.dict(os.environ, {ENV_FILE_OVERRIDE_VAR: ""}, clear=True):
                clear_settings_cache()
                self.assertIsNone(get_settings().neo4j_pass)

            with patch.dict(os.environ, {ENV_FILE_OVERRIDE_VAR: env_file.as_posix()}, clear=True):
                clear_settings_cache()
                self.assertEqual(get_settings().neo4j_pass, "from-explicit-env")

    def test_backend_host_defaults_to_loopback(self) -> None:
        from codegraph.config import Settings

        settings = Settings(_env_file=None)

        self.assertEqual(settings.backend_host, "127.0.0.1")

    def test_backend_host_can_be_overridden_from_env(self) -> None:
        from codegraph.config import Settings

        with patch.dict(os.environ, {"CODEGRAPH_HOST": "0.0.0.0"}, clear=True):
            settings = Settings(_env_file=None)

        self.assertEqual(settings.backend_host, "0.0.0.0")

    def test_backend_host_allows_localhost_override(self) -> None:
        from codegraph.config import Settings

        with patch.dict(os.environ, {"CODEGRAPH_HOST": "localhost"}, clear=True):
            settings = Settings(_env_file=None)

        self.assertEqual(settings.backend_host, "localhost")


if __name__ == "__main__":
    unittest.main()
