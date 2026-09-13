"""Configuration facts must be parsed faithfully and disagreement surfaced.

Crypto and hash controls in OWASP Benchmark resolve their algorithm from a
properties file, and the in-source defaults are misleading in both directions:
one key defaults to a strong algorithm but is configured weak, another defaults
to a weak one but is configured strong. Reading the declared value is therefore
the only correct resolution, which makes parsing fidelity a correctness concern.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from codegraph.ingestion.config_facts import (
    collect_config_properties,
    discover_property_files,
    parse_properties,
    resolve_properties,
)


def _parse(text: str):
    return {p.key: p.value for p in parse_properties(text, source_file="t.properties")}


class TestPropertiesFormat:
    def test_separators_and_comments(self) -> None:
        parsed = _parse(
            "# comment\n"
            "! also a comment\n"
            "\n"
            "equals=one\n"
            "colon:two\n"
            "spaced three\n"
            "  padded  =  four  \n"
        )
        assert parsed == {"equals": "one", "colon": "two", "spaced": "three", "padded": "four"}

    def test_first_separator_wins(self) -> None:
        """A cipher transformation contains '=' padding in some configs."""
        assert _parse("alg=AES/CBC/PKCS5Padding=x") == {"alg": "AES/CBC/PKCS5Padding=x"}

    def test_line_continuation(self) -> None:
        assert _parse("key=one\\\ntwo") == {"key": "onetwo"}

    def test_escaped_separator_is_not_a_split(self) -> None:
        assert _parse("a\\:b=value") == {"a:b": "value"}

    def test_unicode_escape(self) -> None:
        assert _parse("k=\\u0041ES") == {"k": "AES"}

    def test_value_may_be_empty(self) -> None:
        assert _parse("present=") == {"present": ""}

    def test_line_numbers_are_recorded(self) -> None:
        props = parse_properties("# c\nfirst=1\nsecond=2\n", source_file="t.properties")
        assert [(p.key, p.line) for p in props] == [("first", 2), ("second", 3)]


class TestDiscovery:
    def test_build_output_is_excluded(self, tmp_path: Path) -> None:
        """target/classes mirrors src resources; ingesting both invents conflicts."""
        (tmp_path / "src/main/resources").mkdir(parents=True)
        (tmp_path / "target/classes").mkdir(parents=True)
        (tmp_path / "src/main/resources/app.properties").write_text("hashAlg=MD5\n", encoding="utf-8")
        (tmp_path / "target/classes/app.properties").write_text("hashAlg=MD5\n", encoding="utf-8")

        found = discover_property_files(tmp_path)
        assert [p.name for p in found] == ["app.properties"]
        assert "target" not in found[0].parts

    def test_missing_workspace_is_not_an_error(self, tmp_path: Path) -> None:
        assert discover_property_files(tmp_path / "nope") == []


class TestResolution:
    def test_agreeing_duplicates_are_not_a_conflict(self, tmp_path: Path) -> None:
        (tmp_path / "a").mkdir()
        (tmp_path / "b").mkdir()
        (tmp_path / "a/x.properties").write_text("k=MD5\n", encoding="utf-8")
        (tmp_path / "b/y.properties").write_text("k=MD5\n", encoding="utf-8")

        resolved = resolve_properties(collect_config_properties(tmp_path))
        assert resolved["k"].value == "MD5"
        assert not resolved["k"].is_ambiguous
        assert len(resolved["k"].sources) == 2

    def test_disagreement_is_reported_not_hidden(self, tmp_path: Path) -> None:
        (tmp_path / "dev.properties").write_text("cipher=AES/GCM/NoPadding\n", encoding="utf-8")
        (tmp_path / "prod.properties").write_text("cipher=DES/ECB/PKCS5Padding\n", encoding="utf-8")

        resolved = resolve_properties(collect_config_properties(tmp_path))
        assert resolved["cipher"].is_ambiguous
        assert set(resolved["cipher"].conflicting_values) == {
            "AES/GCM/NoPadding",
            "DES/ECB/PKCS5Padding",
        }

    def test_sources_carry_provenance(self, tmp_path: Path) -> None:
        (tmp_path / "conf").mkdir()
        (tmp_path / "conf/app.properties").write_text("# header\nkey=DES\n", encoding="utf-8")

        resolved = resolve_properties(collect_config_properties(tmp_path))
        source = resolved["key"].sources[0]
        assert source.source_file == "conf/app.properties"
        assert source.line == 2


if __name__ == "__main__":
    pytest.main([__file__])
