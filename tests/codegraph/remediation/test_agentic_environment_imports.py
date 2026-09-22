"""Focused tests for agentic workspace import editing."""

from pathlib import Path

from codegraph.remediation.agentic import IsolatedWorktreeEnvironment


def test_add_import_accepts_full_and_shorthand_forms_idempotently(tmp_path: Path) -> None:
    src = tmp_path / "src" / "demo" / "Example.java"
    src.parent.mkdir(parents=True)
    src.write_text(
        "package demo;\n\npublic class Example {}\n",
        encoding="utf-8",
    )

    with IsolatedWorktreeEnvironment(tmp_path) as env:
        relative_path = "src/demo/Example.java"
        for value in (
            "java.util.List",
            "java.util.List;",
            "import java.util.List;",
        ):
            assert env.add_import(relative_path, value) is True

        updated = env.read_file(relative_path)

    assert updated.count("import java.util.List;") == 1
    assert "\njava.util.List;\n" not in updated
    assert src.read_text(encoding="utf-8") == "package demo;\n\npublic class Example {}\n"


def test_add_import_preserves_static_imports(tmp_path: Path) -> None:
    src = tmp_path / "Example.java"
    src.write_text("class Example {}\n", encoding="utf-8")

    with IsolatedWorktreeEnvironment(tmp_path) as env:
        assert env.add_import("Example.java", "static java.util.Collections.emptyList") is True
        updated = env.read_file("Example.java")

    assert updated.startswith("import static java.util.Collections.emptyList;\n")
