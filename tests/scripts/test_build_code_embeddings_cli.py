from __future__ import annotations

import importlib
from types import SimpleNamespace

import pytest


def test_parse_args_uses_canonical_settings_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    module = importlib.import_module("scripts.ingestion.build_code_embeddings")
    settings_obj = SimpleNamespace(
        neo4j_uri="bolt://default:7687",
        neo4j_user="neo4j-default",
        neo4j_pass="default-pass",
        embedding_model_name="default-model",
    )
    monkeypatch.setattr(module.config, "get_settings", lambda: settings_obj)

    args = module.parse_args([])

    assert args.neo4j_uri == "bolt://default:7687"
    assert args.neo4j_user == "neo4j-default"
    assert args.neo4j_pass == "default-pass"
    assert args.model == "default-model"
    assert args.quiet is False
    assert args.rebuild_index is False


def test_main_applies_cli_overrides_to_settings_used_by_builder(monkeypatch: pytest.MonkeyPatch) -> None:
    module = importlib.import_module("scripts.ingestion.build_code_embeddings")
    embedding_module = importlib.import_module("codegraph.embedding.service")
    settings_obj = SimpleNamespace(
        neo4j_uri="bolt://default:7687",
        neo4j_user="neo4j-default",
        neo4j_pass="default-pass",
        embedding_model_name="default-model",
    )
    monkeypatch.setattr(module.config, "get_settings", lambda: settings_obj)

    captured: dict[str, object] = {}

    def fake_build_embeddings(*, progress_callback, rebuild_index):  # noqa: ANN001
        from codegraph.config import settings as canonical_settings

        captured["neo4j_uri"] = canonical_settings.neo4j_uri
        captured["neo4j_user"] = canonical_settings.neo4j_user
        captured["neo4j_pass"] = canonical_settings.neo4j_pass
        captured["embedding_model_name"] = canonical_settings.embedding_model_name
        captured["progress_callback"] = progress_callback
        captured["rebuild_index"] = rebuild_index

    monkeypatch.setattr(embedding_module.EmbeddingService, "build_embeddings", fake_build_embeddings)

    exit_code = module.main(
        [
            "--neo4j-uri",
            "bolt://override:7687",
            "--neo4j-user",
            "override-user",
            "--neo4j-pass",
            "override-pass",
            "--model",
            "override-model",
            "--quiet",
            "--rebuild-index",
        ]
    )

    assert exit_code == 0
    assert captured["neo4j_uri"] == "bolt://override:7687"
    assert captured["neo4j_user"] == "override-user"
    assert captured["neo4j_pass"] == "override-pass"
    assert captured["embedding_model_name"] == "override-model"
    assert captured["progress_callback"] is None
    assert captured["rebuild_index"] is True


def test_help_exits_without_invoking_builder(monkeypatch: pytest.MonkeyPatch) -> None:
    module = importlib.import_module("scripts.ingestion.build_code_embeddings")
    embedding_module = importlib.import_module("codegraph.embedding.service")
    calls: list[bool] = []

    def fake_build_embeddings(*, progress_callback, rebuild_index):  # noqa: ANN001,ARG001
        calls.append(True)

    monkeypatch.setattr(embedding_module.EmbeddingService, "build_embeddings", fake_build_embeddings)

    with pytest.raises(SystemExit) as exc:
        module.main(["--help"])
    assert exc.value.code == 0
    assert calls == []
