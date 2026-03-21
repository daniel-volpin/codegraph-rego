from __future__ import annotations

import unittest
import warnings
import os
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
            Settings(_env_file=None, remediation_confidence_threshold_apply=1.5)

        with self.assertRaises(ValidationError):
            Settings(_env_file=None, remediation_confidence_threshold_review=-0.1)

    def test_get_settings_is_cached_and_clearable(self) -> None:
        from codegraph.config import clear_settings_cache, get_settings

        clear_settings_cache()
        settings_a = get_settings()
        settings_b = get_settings()
        self.assertIs(settings_a, settings_b)

        clear_settings_cache()
        settings_c = get_settings()
        self.assertIsNot(settings_a, settings_c)

    def test_legacy_exports_emit_deprecation_warning(self) -> None:
        import codegraph.config as config

        config.clear_settings_cache()
        config._WARNED_LEGACY_EXPORTS.clear()
        previous = config._WARN_LEGACY_EXPORTS
        config._WARN_LEGACY_EXPORTS = True

        try:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always", DeprecationWarning)
                _ = config.CORS_ALLOWED_ORIGINS
        finally:
            config._WARN_LEGACY_EXPORTS = previous

        self.assertTrue(any(issubclass(w.category, DeprecationWarning) for w in caught))


if __name__ == "__main__":
    unittest.main()
