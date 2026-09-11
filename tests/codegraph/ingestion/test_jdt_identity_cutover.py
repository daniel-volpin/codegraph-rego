import pytest

from codegraph.ingestion.service import IngestionError, _revision_id, _workspace_id, extract_entities_from_parsed_files
from codegraph.java.models import (
    ArgumentDTO,
    FieldDeclarationDTO,
    FieldUseDTO,
    InvocationDTO,
    JavaParserProvenanceDTO,
    MethodDeclarationDTO,
    ParameterDTO,
    ParsedJavaFileDTO,
    SourceRangeDTO,
    TypeDeclarationDTO,
    TypeRefDTO,
)


def _range(start: int, end: int, start_line: int = 1, end_line: int = 1) -> SourceRangeDTO:
    return SourceRangeDTO(start_byte=start, end_byte=end, start_line=start_line, end_line=end_line, status="verified")


def _type(name: str, *, descriptor: str | None = None) -> TypeRefDTO:
    return TypeRefDTO(
        source=name,
        qualified_name=name,
        binary_name=name,
        descriptor=descriptor,
        binding_key=descriptor or f"L{name.replace('.', '/')};",
        binding_origin="primitive" if name in {"int", "void"} else "binary",
        resolution_status="resolved",
    )


def _method(
    *,
    source_key: str,
    name: str,
    full_signature: str,
    params: tuple[ParameterDTO, ...],
    binding_key: str,
    descriptor: str,
    calls: tuple[InvocationDTO, ...] = (),
    field_uses: tuple[FieldUseDTO, ...] = (),
) -> MethodDeclarationDTO:
    return MethodDeclarationDTO(
        source_key=source_key,
        declaration_key=f"Demo.java:{source_key}",
        declaring_type_source_key="type:Demo",
        declaring_type_qualified_name="com.acme.Demo",
        kind="method",
        name=name,
        display_signature=full_signature,
        full_signature=full_signature,
        syntactic_parameter_types=tuple(param.type.source or "" for param in params),
        parameters=params,
        return_type=_type("void", descriptor="V"),
        declaration_range=_range(20, 90),
        body_range=_range(40, 89),
        invocations=calls,
        field_uses=field_uses,
        resolution_status="resolved",
        resolved_binding_key=binding_key,
        resolved_descriptor=descriptor,
        binding_origin="source",
    )


def test_extract_entities_uses_source_keys_and_preserves_overloads_arrays_and_bindings() -> None:
    field = FieldDeclarationDTO(
        source_key="field:Demo.logger",
        declaring_type_source_key="type:Demo",
        name="logger",
        type=_type("org.slf4j.Logger"),
        declaration_range=_range(5, 15),
        resolution_status="resolved",
        binding_key="field-binding",
        binding_origin="source",
    )
    callee = _method(
        source_key="method:helper-string",
        name="helper",
        full_signature="com.acme.Demo.helper(java.lang.String)",
        params=(ParameterDTO(name="value", type=_type("java.lang.String")),),
        binding_key="helper-string-binding",
        descriptor="(Ljava/lang/String;)V",
    )
    caller = _method(
        source_key="method:caller-array",
        name="caller",
        full_signature="com.acme.Demo.caller(int[])",
        params=(ParameterDTO(name="values", type=_type("int", descriptor="[I")),),
        binding_key="caller-array-binding",
        descriptor="([I)V",
        calls=(
            InvocationDTO(
                source_key="call:helper",
                kind="method",
                name="helper",
                argument_count=1,
                arguments=(ArgumentDTO(source='"x"', range=_range(55, 58)),),
                invocation_range=_range(48, 59),
                resolution_status="resolved",
                resolved_binding_key="helper-string-binding",
                resolved_descriptor="(Ljava/lang/String;)V",
                binding_origin="source",
            ),
            InvocationDTO(
                source_key="call:external",
                kind="method",
                name="println",
                argument_count=1,
                arguments=(ArgumentDTO(source="values", range=_range(65, 71)),),
                invocation_range=_range(60, 72),
                resolution_status="unresolved",
                unresolved_reason="missing receiver binding",
            ),
        ),
        field_uses=(
            FieldUseDTO(
                name="logger",
                range=_range(42, 48),
                resolution_status="resolved",
                field_binding_key="field-binding",
                declaring_type="com.acme.Demo",
                binding_origin="source",
            ),
        ),
    )
    parsed = ParsedJavaFileDTO(
        provenance=JavaParserProvenanceDTO(
            backend_version="3.47.0",
            adapter_version="0.1.0",
            resolution_enabled=True,
            classpath_fingerprint="sha256:classes",
        ),
        relative_path="src/main/java/com/acme/Demo.java",
        package_name="com.acme",
        source_sha256="e" * 64,
        source_byte_length=120,
        coverage="complete",
        types=(
            TypeDeclarationDTO(
                source_key="type:Demo",
                kind="class",
                name="Demo",
                qualified_name="com.acme.Demo",
                binary_name="com.acme.Demo",
                declaration_range=_range(0, 120),
                resolution_status="resolved",
                binding_key="type-binding",
                binding_origin="source",
            ),
        ),
        fields=(field,),
        methods=(callee, caller),
    )

    extracted = extract_entities_from_parsed_files(
        [parsed],
        workspace_id="workspace-a",
        revision_id="revision-b",
    )

    method_keys = {method.method_key for method in extracted.methods}
    assert "workspace-a@revision-b:src/main/java/com/acme/Demo.java#method:helper-string" in method_keys
    assert "workspace-a@revision-b:src/main/java/com/acme/Demo.java#method:caller-array" in method_keys
    caller_entity = next(method for method in extracted.methods if method.name == "caller")
    assert caller_entity.full_signature == "com.acme.Demo.caller(int[])"
    assert caller_entity.resolved_descriptor == "([I)V"
    assert extracted.calls_relations == (
        (
            "workspace-a@revision-b:src/main/java/com/acme/Demo.java#method:caller-array",
            "workspace-a@revision-b:src/main/java/com/acme/Demo.java#method:helper-string",
            "workspace-a@revision-b:src/main/java/com/acme/Demo.java#call:helper",
        ),
    )
    assert extracted.call_evidence[0]["resolution_status"] == "unresolved"
    assert extracted.method_field_relations == (
        (
            "workspace-a@revision-b:src/main/java/com/acme/Demo.java#method:caller-array",
            "workspace-a@revision-b:src/main/java/com/acme/Demo.java#field:Demo.logger",
        ),
    )


def test_extract_entities_does_not_guess_missing_source_call_targets() -> None:
    caller = _method(
        source_key="method:caller",
        name="caller",
        full_signature="com.acme.Demo.caller()",
        params=(),
        binding_key="caller-binding",
        descriptor="()V",
        calls=(
            InvocationDTO(
                source_key="call:missing-helper",
                kind="method",
                name="helper",
                argument_count=0,
                invocation_range=_range(48, 56),
                resolution_status="resolved",
                resolved_binding_key="missing-helper-binding",
                resolved_descriptor="()V",
                target_method_source_key="method:missing-helper",
                binding_origin="source",
            ),
        ),
    )
    parsed = ParsedJavaFileDTO(
        provenance=JavaParserProvenanceDTO(
            backend_version="3.47.0",
            adapter_version="0.1.0",
            resolution_enabled=True,
            classpath_fingerprint="sha256:classes",
        ),
        relative_path="src/main/java/com/acme/Demo.java",
        package_name="com.acme",
        source_sha256="e" * 64,
        source_byte_length=120,
        coverage="complete",
        types=(
            TypeDeclarationDTO(
                source_key="type:Demo",
                kind="class",
                name="Demo",
                qualified_name="com.acme.Demo",
                binary_name="com.acme.Demo",
                declaration_range=_range(0, 120),
                resolution_status="resolved",
                binding_key="type-binding",
                binding_origin="source",
            ),
        ),
        methods=(caller,),
    )

    extracted = extract_entities_from_parsed_files(
        [parsed],
        workspace_id="workspace-a",
        revision_id="revision-b",
    )

    assert extracted.calls_relations == ()
    assert extracted.call_evidence[0]["call_key"] == (
        "workspace-a@revision-b:src/main/java/com/acme/Demo.java#call:missing-helper"
    )
    assert extracted.call_evidence[0]["resolution_status"] == "resolved"


def test_revision_identity_includes_parser_and_classpath_generation() -> None:
    parsed = ParsedJavaFileDTO(
        provenance=JavaParserProvenanceDTO(
            backend_version="3.47.0",
            adapter_version="0.1.0",
            resolution_enabled=True,
            classpath_fingerprint="sha256:one",
        ),
        relative_path="Demo.java",
        source_sha256="e" * 64,
        source_byte_length=1,
        coverage="complete",
    )

    same_source_new_parser = parsed.model_copy(
        update={"provenance": parsed.provenance.model_copy(update={"adapter_version": "0.1.1"})}
    )
    same_source_new_classpath = parsed.model_copy(
        update={"provenance": parsed.provenance.model_copy(update={"classpath_fingerprint": "sha256:two"})}
    )

    assert _revision_id([parsed]) != _revision_id([same_source_new_parser])
    assert _revision_id([parsed]) != _revision_id([same_source_new_classpath])


def test_workspace_identity_uses_canonical_resolved_root(tmp_path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    alias = root / "." / "nested" / ".."

    assert _workspace_id(root.as_posix()) == _workspace_id(alias.as_posix())


def test_extract_entities_rejects_failed_or_mixed_parser_generations() -> None:
    complete = ParsedJavaFileDTO(
        provenance=JavaParserProvenanceDTO(backend_version="3.47.0", adapter_version="0.1.0"),
        relative_path="Good.java",
        source_sha256="e" * 64,
        source_byte_length=1,
        coverage="complete",
    )
    failed = ParsedJavaFileDTO(
        provenance=complete.provenance,
        relative_path="Bad.java",
        source_sha256="f" * 64,
        source_byte_length=1,
        coverage="failed",
        diagnostics=(
            {
                "severity": "error",
                "phase": "parse",
                "code": "bad",
                "message": "bad",
                "coverage_impact": "file_failed",
            },
        ),
    )
    mixed = complete.model_copy(
        update={"provenance": complete.provenance.model_copy(update={"backend_version": "3.48.0"})}
    )

    with pytest.raises(IngestionError, match="failed parser coverage"):
        extract_entities_from_parsed_files([complete, failed], workspace_id="w", revision_id="r")
    with pytest.raises(IngestionError, match="mixed parser generation"):
        extract_entities_from_parsed_files([complete, mixed], workspace_id="w", revision_id="r")
