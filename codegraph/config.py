import os
from functools import lru_cache
from typing import Any

from pydantic_settings import SettingsConfigDict

from codegraph.config_models import (
    PROJECT_ROOT,
    BaseCoreSettings,
    BaseJavaSettings,
    BaseLLMSettings,
)

ENV_FILE_OVERRIDE_VAR = "CODEGRAPH_ENV_FILE"


class Settings(BaseCoreSettings, BaseLLMSettings, BaseJavaSettings):
    model_config = SettingsConfigDict(extra="ignore")


def resolve_explicit_env_file() -> str | None:
    configured = os.environ.get(ENV_FILE_OVERRIDE_VAR)
    if configured == "":
        return None
    if configured:
        return configured
    default_env = PROJECT_ROOT / ".env"
    if default_env.is_file():
        return str(default_env)
    return None


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    env_file = resolve_explicit_env_file()
    if env_file:
        return Settings(_env_file=env_file)
    return Settings()


def clear_settings_cache() -> None:
    get_settings.cache_clear()


def validate_runtime_settings(candidate: Settings | None = None) -> Settings:
    settings_obj = candidate or get_settings()
    missing: list[str] = []
    if not settings_obj.neo4j_pass:
        missing.append("NEO4J_PASS")
    if missing:
        raise ValueError(f"Missing required runtime setting(s): {', '.join(missing)}")
    return settings_obj


class _SettingsProxy:
    def __getattr__(self, name: str) -> Any:
        return getattr(get_settings(), name)


settings = _SettingsProxy()
