import base64
import json
import subprocess
from pathlib import Path

import pytest

from codegraph.config import settings
from codegraph.java.models import ParsedJavaFileDTO

ROOT = Path(__file__).resolve().parents[3]
JAR = settings.java_parser_jar
FIXTURES = ROOT / "tests/fixtures/java_parser"


@pytest.fixture(autouse=True)
def require_prebuilt_parser() -> None:
    if not JAR.is_file():
        pytest.fail(f"JDT parser jar is missing at {JAR}; run `make java-parser-build` before these tests.")


def compile_dependency_jar(tmp_path: Path) -> tuple[Path, Path]:
    build_dir = tmp_path / "java-parser-fixture"
    source_dir = build_dir / "src/com/acme"
    classes = build_dir / "classes"
    jar = build_dir / "fixture-lib.jar"
    source_dir.mkdir(parents=True, exist_ok=True)
    marker = build_dir / "executed.marker"
    escaped_marker = marker.as_posix().replace("\\", "\\\\").replace('"', '\\"')
    source = source_dir / "FixtureLib.java"
    source.write_text(
        f"""
package com.acme;

import java.nio.file.Files;
import java.nio.file.Path;

public class FixtureLib {{
    static {{
        try {{
            Files.writeString(Path.of("{escaped_marker}"), "executed");
        }} catch (Exception ignored) {{
        }}
    }}

    public String ping() {{
        return "pong";
    }}
}}
""",
        encoding="utf-8",
    )
    subprocess.run(["javac", "-d", str(classes), str(source)], check=True, cwd=ROOT)
    subprocess.run(["jar", "--create", "--file", str(jar), "-C", str(classes), "."], check=True, cwd=ROOT)
    assert not marker.exists(), "compiling the fixture should not execute its static initializer"
    return jar, marker


def run_parser(
    source: bytes,
    relative_path: str,
    *,
    resolve_bindings: bool = False,
    classpath=(),
    source_roots=(),
    language_level="25",
):
    request = {
        "schema_version": "codegraph-java-request/v1",
        "relative_path": relative_path,
        "source_base64": base64.b64encode(source).decode("ascii"),
        "language_level": language_level,
        "resolve_bindings": resolve_bindings,
        "classpath": [str(Path(p).resolve()) for p in classpath],
        "source_roots": [str(Path(p).resolve()) for p in source_roots],
    }
    return subprocess.run(
        ["java", "-XX:ActiveProcessorCount=1", "-Xmx768m", "-jar", str(JAR)],
        input=json.dumps(request),
        text=True,
        capture_output=True,
        cwd=ROOT,
        timeout=20,
    )


def parse_java(
    source: bytes,
    relative_path: str,
    *,
    resolve_bindings: bool = False,
    classpath=(),
    source_roots=(),
    language_level="25",
):
    completed = run_parser(
        source,
        relative_path,
        resolve_bindings=resolve_bindings,
        classpath=classpath,
        source_roots=source_roots,
        language_level=language_level,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stderr == ""
    assert len(completed.stdout.encode()) < 16 * 1024 * 1024
    return ParsedJavaFileDTO.model_validate_json(completed.stdout)


def by_name(items, name):
    return [item for item in items if item.name == name]


def test_missing_parameter_types_never_claim_a_synthetic_jvm_descriptor() -> None:
    parsed = parse_java(
        b"class MissingTypes { Missing[] echo(Missing[] x) { return x; } }",
        "MissingTypes.java",
        resolve_bindings=True,
    )
    assert parsed.coverage == "partial"
    echo = next(method for method in parsed.methods if method.name == "echo")
    assert echo.resolved_descriptor is None


def test_jdt_extracts_modern_java_shape_and_exact_utf8_ranges() -> None:
    source = (FIXTURES / "ModernShape.java").read_bytes()
    parsed = parse_java(source, "src/main/java/com/acme/ModernShape.java")

    assert parsed.schema_version == "codegraph-java/v1"
    assert parsed.provenance.backend == "eclipse-jdt"
    assert parsed.provenance.backend_version == "3.47.0"
    assert parsed.relative_path == "src/main/java/com/acme/ModernShape.java"
    assert parsed.source_byte_length == len(source)
    assert parsed.package_name == "com.acme"
    assert parsed.source_sha256 == __import__("hashlib").sha256(source).hexdigest()
    assert any(i.name == "java.util.List" for i in parsed.imports)

    kinds = {(t.kind, t.name) for t in parsed.types}
    assert ("record", "ModernShape") in kinds
    assert ("interface", "Worker") in kinds
    assert ("enum", "Mode") in kinds
    assert ("annotation", "Marker") in kinds
    assert any(t.kind == "local" and t.name == "LocalThing" for t in parsed.types)
    assert any(t.kind == "anonymous" for t in parsed.types)

    record = next(t for t in parsed.types if t.name == "ModernShape")
    assert "field" in record.body_declaration_kinds
    assert "constructor" in record.body_declaration_kinds
    assert "method" in record.body_declaration_kinds
    assert record.declaration_range.start_byte == source.index(b"@Marker")

    names = {m.name: m for m in parsed.methods if m.declaring_type_source_key == record.source_key}
    assert names["ModernShape"].kind == "compact_constructor"
    assert names["run"].syntactic_parameter_types == ("java.util.List<java.lang.String>", "int[]")
    assert names["run"].parameters[0].type.source == "List<String>"
    assert names["run"].parameters[1].type.varargs is True
    assert names["run"].body_range is not None
    assert names["run"].display_signature.endswith("run(java.util.List<java.lang.String>, int[])")

    emoji_start = source.index("\U0001f642".encode())
    text_field = next(f for f in parsed.fields if f.name == "TEXT")
    assert text_field.initializer_range.start_byte < emoji_start < text_field.initializer_range.end_byte


def test_jdt_resolves_modern_records_generics_and_primitive_field_uses_strictly() -> None:
    source = b"package status; public record Probe(String value) { public String normalized() { return value.trim(); } }"
    parsed = parse_java(source, "status/Probe.java", resolve_bindings=True)

    assert parsed.coverage == "complete"
    probe = next(t for t in parsed.types if t.name == "Probe")
    assert "field" in probe.body_declaration_kinds
    assert "constructor" in probe.body_declaration_kinds
    value = next(f for f in parsed.fields if f.name == "value")
    assert value.type.qualified_name == "java.lang.String"
    assert value.resolution_status == "resolved"
    assert value.binding_origin == "source"
    canonical = next(m for m in parsed.methods if m.name == "Probe" and m.kind == "constructor")
    assert canonical.syntactic_parameter_types == ("java.lang.String",)
    assert canonical.parameters[0].name == "value"
    normalized = next(m for m in parsed.methods if m.name == "normalized")
    assert next(use for use in normalized.field_uses if use.name == "value").binding_origin == "source"

    modern = parse_java(
        (FIXTURES / "ModernShape.java").read_bytes(),
        "src/main/java/com/acme/ModernShape.java",
        resolve_bindings=True,
    )
    run = next(m for m in modern.methods if m.name == "run" and m.declaring_type_qualified_name == "com.acme.ModernShape")
    values_type = run.parameters[0].type
    assert values_type.qualified_name == "java.util.List<java.lang.String>"
    assert values_type.type_arguments[0].qualified_name == "java.lang.String"
    assert run.syntactic_parameter_types == ("java.util.List<java.lang.String>", "int[]")
    length_use = next(use for use in run.field_uses if use.name == "length")
    assert length_use.resolution_status == "resolved"
    assert length_use.binding_origin in {"source", "binary"}

    defaulted_source = (
        b"package status; public class Defaulted { void f() {} } "
        b"interface Contract { void bodyless(); default void ok() {} }"
    )
    defaulted = parse_java(defaulted_source, "status/Defaulted.java", resolve_bindings=True)
    default_constructor = next(m for m in defaulted.methods if m.declaring_type_qualified_name == "status.Defaulted" and m.kind == "constructor")
    assert default_constructor.declaration_range.status == "absent"
    bodyless = next(m for m in defaulted.methods if m.name == "bodyless")
    assert bodyless.body_range is None
    assert bodyless.resolution_status == "resolved"


def test_jdt_enforces_language_level_wire_contract() -> None:
    class8 = b"package status; public class Plain { public String ok() { return \"ok\"; } }"
    parsed = parse_java(class8, "status/Plain.java", resolve_bindings=True, language_level="8")
    assert parsed.coverage == "complete"
    assert parsed.provenance.language_level == "8"

    record25 = b"package status; public record Probe(String value) {}"
    assert parse_java(record25, "status/Probe.java", resolve_bindings=True, language_level="25").coverage == "complete"

    record8 = run_parser(record25, "status/Probe.java", resolve_bindings=True, language_level="8")
    assert record8.returncode == 0, record8.stderr
    rejected = ParsedJavaFileDTO.model_validate_json(record8.stdout)
    assert rejected.coverage == "failed"
    assert rejected.types == ()
    assert rejected.fields == ()
    assert rejected.methods == ()

    invalid = run_parser(class8, "status/Plain.java", language_level="26")
    assert invalid.returncode != 0
    assert invalid.stdout == ""
    assert "language_level" in invalid.stderr

    missing_level = {
        "schema_version": "codegraph-java-request/v1",
        "relative_path": "status/Plain.java",
        "source_base64": base64.b64encode(class8).decode("ascii"),
        "resolve_bindings": False,
        "classpath": [],
        "source_roots": [],
    }
    completed = subprocess.run(
        ["java", "-XX:ActiveProcessorCount=1", "-Xmx256m", "-jar", str(JAR)],
        input=json.dumps(missing_level),
        text=True,
        capture_output=True,
        cwd=ROOT,
        timeout=10,
    )
    assert completed.returncode != 0
    assert completed.stdout == ""
    assert "language_level" in completed.stderr


def test_jdt_failed_coverage_returns_valid_dto_without_declarations() -> None:
    malformed = b"package broken; public class Broken { void nope( { int x = ; } }"
    parsed = parse_java(malformed, "broken/Broken.java", language_level="25")
    assert parsed.coverage == "failed"
    assert parsed.diagnostics
    assert parsed.types == ()
    assert parsed.fields == ()
    assert parsed.methods == ()


def test_jdt_classpath_fingerprint_tracks_order_and_content(tmp_path: Path) -> None:
    source = b"package status; public class Plain {}"
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    (first_root / "entry.txt").write_text("one", encoding="utf-8")
    (second_root / "entry.txt").write_text("two", encoding="utf-8")
    first_jar = tmp_path / "first.jar"
    second_jar = tmp_path / "second.jar"
    subprocess.run(["jar", "--create", "--file", str(first_jar), "-C", str(first_root), "."], check=True, cwd=ROOT)
    subprocess.run(["jar", "--create", "--file", str(second_jar), "-C", str(second_root), "."], check=True, cwd=ROOT)

    one_two = parse_java(source, "status/Plain.java", classpath=[first_jar, second_jar])
    two_one = parse_java(source, "status/Plain.java", classpath=[second_jar, first_jar])
    assert one_two.provenance.classpath_fingerprint != two_one.provenance.classpath_fingerprint

    before = one_two.provenance.classpath_fingerprint
    (first_root / "entry.txt").write_text("changed", encoding="utf-8")
    subprocess.run(["jar", "--create", "--file", str(first_jar), "-C", str(first_root), "."], check=True, cwd=ROOT)
    changed = parse_java(source, "status/Plain.java", classpath=[first_jar, second_jar])
    assert changed.provenance.classpath_fingerprint != before


def test_source_root_fingerprint_ignores_non_java_files(tmp_path: Path) -> None:
    source = b"class Plain {}"
    (tmp_path / "Plain.java").write_bytes(source)
    unrelated = tmp_path / "notes.txt"
    unrelated.write_text("first", encoding="utf-8")
    before = parse_java(source, "Plain.java", source_roots=[tmp_path])
    unrelated.write_text("second", encoding="utf-8")
    after = parse_java(source, "Plain.java", source_roots=[tmp_path])
    assert before.provenance.classpath_fingerprint == after.provenance.classpath_fingerprint


def test_jdt_method_descriptors_are_erased_jvm_descriptors() -> None:
    source = (
        b"package status; "
        b"public class G<T extends Number> { "
        b"T echo(T x) { return x; } "
        b"<U> U id(U y) { return y; } "
        b"void arrays(String[] names, int... counts) {} "
        b"}"
    )
    parsed = parse_java(source, "status/G.java", resolve_bindings=True)

    echo = next(m for m in parsed.methods if m.name == "echo")
    method_id = next(m for m in parsed.methods if m.name == "id")
    arrays = next(m for m in parsed.methods if m.name == "arrays")

    assert echo.resolved_descriptor == "(Ljava/lang/Number;)Ljava/lang/Number;"
    assert method_id.resolved_descriptor == "(Ljava/lang/Object;)Ljava/lang/Object;"
    assert arrays.resolved_descriptor == "([Ljava/lang/String;[I)V"
    assert all("null" not in descriptor for descriptor in (echo.resolved_descriptor, method_id.resolved_descriptor, arrays.resolved_descriptor))


def test_jdt_scopes_invocations_and_field_uses_to_actual_method_owner() -> None:
    parsed = parse_java((FIXTURES / "ModernShape.java").read_bytes(), "src/main/java/com/acme/ModernShape.java")
    outer = next(m for m in parsed.methods if m.name == "run")
    local = next(m for m in parsed.methods if m.name == "call" and "LocalThing" in m.display_signature)

    outer_call_names = [i.name for i in outer.invocations]
    local_call_names = [i.name for i in local.invocations]
    assert "println" in outer_call_names
    assert "call" in outer_call_names
    assert "trim" not in outer_call_names
    assert "trim" in local_call_names
    assert any(use.name == "TEXT" for use in local.field_uses)
    assert not any(use.name == "TEXT" for use in outer.field_uses)


def test_jdt_resolves_source_jdk_binary_and_missing_symbols_without_execution(tmp_path: Path) -> None:
    jar, marker = compile_dependency_jar(tmp_path)
    source = (FIXTURES / "BindingProbe.java").read_bytes()
    parsed = parse_java(source, "src/main/java/com/acme/BindingProbe.java", resolve_bindings=True, classpath=[jar])

    assert not marker.exists(), "parsing must not load target classes or run static initializers"
    assert parsed.coverage in {"partial", "complete"}
    assert not any("execut" in d.message.lower() for d in parsed.diagnostics)

    probe = next(t for t in parsed.types if t.name == "BindingProbe")
    assert probe.resolution_status == "resolved"
    assert probe.binding_origin == "source"

    method = next(m for m in parsed.methods if m.name == "probe")
    origins = {inv.name: inv.binding_origin for inv in method.invocations if inv.resolution_status == "resolved"}
    assert origins["of"] == "binary"  # java.util.List.of()
    assert origins["ping"] == "binary"  # controlled dependency JAR
    assert any(inv.name == "absent" and inv.resolution_status == "unresolved" for inv in method.invocations)


def test_jdt_reports_protocol_fatal_errors_on_stderr_only() -> None:
    completed = subprocess.run(
        ["java", "-XX:ActiveProcessorCount=1", "-Xmx256m", "-jar", str(JAR)],
        input="{not-json}",
        text=True,
        capture_output=True,
        cwd=ROOT,
        timeout=10,
    )
    assert completed.returncode != 0
    assert completed.stdout == ""
    assert "protocol" in completed.stderr.lower()
    assert len(completed.stderr.encode()) < 8192


def test_jdt_enforces_input_caps_before_parsing() -> None:
    too_large_source = b"class Huge{}" + b" " * (4 * 1024 * 1024 + 1)
    request = {
        "schema_version": "codegraph-java-request/v1",
        "relative_path": "Huge.java",
        "source_base64": base64.b64encode(too_large_source).decode("ascii"),
        "language_level": "25",
        "resolve_bindings": False,
        "classpath": [],
        "source_roots": [],
    }
    completed = subprocess.run(
        ["java", "-XX:ActiveProcessorCount=1", "-Xmx256m", "-jar", str(JAR)],
        input=json.dumps(request),
        text=True,
        capture_output=True,
        cwd=ROOT,
        timeout=10,
    )
    assert completed.returncode != 0
    assert completed.stdout == ""
    assert "decoded source" in completed.stderr.lower()
