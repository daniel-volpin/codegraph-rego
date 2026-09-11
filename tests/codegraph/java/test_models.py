import pytest
from pydantic import ValidationError

from codegraph.java.models import (
    ArgumentDTO,
    FieldDeclarationDTO,
    FieldUseDTO,
    ImportDTO,
    InvocationDTO,
    JavaParserProvenanceDTO,
    MethodDeclarationDTO,
    ParameterDTO,
    ParsedJavaFileDTO,
    SourceRangeDTO,
    TypeDeclarationDTO,
    TypeRefDTO,
)


def verified_range(start: int, end: int, start_line: int = 1, end_line: int = 1) -> SourceRangeDTO:
    return SourceRangeDTO(
        start_byte=start,
        end_byte=end,
        start_line=start_line,
        end_line=end_line,
        start_utf16_offset=0,
        end_utf16_offset=end - start,
        status="verified",
    )


def string_type() -> TypeRefDTO:
    return TypeRefDTO(
        source="java.lang.String",
        qualified_name="java.lang.String",
        binary_name="java.lang.String",
        descriptor="Ljava/lang/String;",
        resolution_status="resolved",
        binding_key="Ljava/lang/String;",
        binding_origin="binary",
    )


def test_parsed_java_file_round_trips_representative_contract_json() -> None:
    source_range = verified_range(0, 240, 1, 10)
    type_decl = TypeDeclarationDTO(
        source_key="file:src/main/java/com/acme/Secure.java#type:com.acme.Secure",
        kind="class",
        name="Secure",
        qualified_name="com.acme.Secure",
        binary_name="com.acme.Secure",
        nesting_path=("com.acme.Secure",),
        body_declaration_kinds=("field", "constructor", "method"),
        modifiers=("public",),
        annotation_names=("Service",),
        superclass=TypeRefDTO(
            source="Base",
            qualified_name=None,
            resolution_status="unresolved",
            unresolved_reason="source-only superclass without binding",
        ),
        interfaces=(TypeRefDTO(source="java.io.Serializable", resolution_status="not_attempted"),),
        declaration_range=source_range,
        resolution_status="resolved",
        binding_key="Lcom/acme/Secure;",
        binding_origin="source",
    )
    field = FieldDeclarationDTO(
        source_key="file:src/main/java/com/acme/Secure.java#field:logger#range:32-70",
        declaring_type_source_key=type_decl.source_key,
        name="logger",
        type=TypeRefDTO(
            source="Logger",
            qualified_name="org.slf4j.Logger",
            resolution_status="resolved",
            binding_key="Lorg/slf4j/Logger;",
            binding_origin="binary",
        ),
        modifiers=("private", "final"),
        annotation_names=("Autowired",),
        declaration_range=verified_range(32, 70, 3, 3),
        initializer_range=verified_range(55, 69, 3, 3),
        has_initializer=True,
        resolution_status="resolved",
        binding_key="logger-binding",
        binding_origin="source",
    )
    chained_call = InvocationDTO(
        source_key="file:src/main/java/com/acme/Secure.java#call:150-190",
        kind="method",
        qualifier_source="builder.secure()",
        name="build",
        argument_count=1,
        arguments=(ArgumentDTO(source="input", range=verified_range(184, 189, 8, 8)),),
        invocation_range=verified_range(150, 190, 8, 8),
        terminal_chain_member=True,
        chain_members=("secure", "build"),
        resolution_status="resolved",
        resolved_owner="com.acme.Builder",
        resolved_name="build",
        resolved_parameter_types=(string_type(),),
        resolved_binding_key="Lcom/acme/Builder;.build(Ljava/lang/String;)Lcom/acme/Product;",
        resolved_descriptor="(Ljava/lang/String;)Lcom/acme/Product;",
        binding_origin="binary",
    )
    constructor_call = InvocationDTO(
        source_key="file:src/main/java/com/acme/Secure.java#new:200-230",
        kind="constructor",
        name="Secure",
        argument_count=1,
        arguments=(ArgumentDTO(source="input", range=verified_range(202, 207, 9, 9)),),
        invocation_range=verified_range(200, 210, 9, 9),
        resolution_status="unresolved",
        unresolved_reason="missing classpath entry",
    )
    method = MethodDeclarationDTO(
        source_key="file:src/main/java/com/acme/Secure.java#method:hash/1/java.lang.String#range:90-220",
        declaration_key="src/main/java/com/acme/Secure.java:90:220",
        declaring_type_source_key=type_decl.source_key,
        declaring_type_qualified_name="com.acme.Secure",
        kind="method",
        name="hash",
        display_signature="com.acme.Secure.hash(java.lang.String)",
        full_signature="com.acme.Secure.hash(java.lang.String)",
        syntactic_parameter_types=("java.lang.String",),
        modifiers=("public",),
        annotation_names=("Override",),
        return_type=string_type(),
        parameters=(ParameterDTO(name="input", type=string_type(), range=verified_range(118, 140, 5, 5)),),
        thrown_types=(TypeRefDTO(source="java.io.IOException", resolution_status="not_attempted"),),
        declaration_range=verified_range(90, 220, 5, 9),
        body_range=verified_range(142, 219, 5, 9),
        invocations=(chained_call, constructor_call),
        field_uses=(
            FieldUseDTO(
                name="logger",
                range=verified_range(145, 151, 7, 7),
                resolution_status="resolved",
                declaring_type="com.acme.Secure",
                field_binding_key="logger-key",
                binding_origin="source",
            ),
        ),
        resolution_status="resolved",
        resolved_binding_key="Lcom/acme/Secure;.hash(Ljava/lang/String;)Ljava/lang/String;",
        resolved_descriptor="(Ljava/lang/String;)Ljava/lang/String;",
        binding_origin="source",
    )
    constructor = MethodDeclarationDTO(
        source_key="file:src/main/java/com/acme/Secure.java#method:<init>/0/#range:72-88",
        declaration_key="src/main/java/com/acme/Secure.java:72:88",
        declaring_type_source_key=type_decl.source_key,
        declaring_type_qualified_name="com.acme.Secure",
        kind="constructor",
        name="Secure",
        display_signature="com.acme.Secure.Secure()",
        full_signature="com.acme.Secure.Secure()",
        syntactic_parameter_types=(),
        declaration_range=verified_range(72, 88, 4, 4),
        resolution_status="not_attempted",
    )
    parsed = ParsedJavaFileDTO(
        provenance=JavaParserProvenanceDTO(
            backend_version="3.47.0",
            adapter_version="0.1.0",
            language_level="21",
            resolution_enabled=True,
            classpath_fingerprint="sha256:abc123",
        ),
        relative_path="src/main/java/com/acme/Secure.java",
        package_name="com.acme",
        imports=(
            ImportDTO(
                name="java.util.List",
                is_static=False,
                on_demand=False,
                range=verified_range(16, 38, 2, 2),
            ),
        ),
        source_sha256="a" * 64,
        source_byte_length=240,
        coverage="complete",
        diagnostics=(),
        types=(type_decl,),
        fields=(field,),
        methods=(method, constructor),
    )

    payload_json = parsed.model_dump_json()
    payload = parsed.model_dump(mode="json")
    reparsed = ParsedJavaFileDTO.model_validate_json(payload_json)

    assert payload["schema_version"] == "codegraph-java/v1"
    assert payload["provenance"]["backend"] == "eclipse-jdt"
    assert payload["package_name"] == "com.acme"
    assert payload["imports"][0]["name"] == "java.util.List"
    assert payload["methods"][0]["syntactic_parameter_types"] == ["java.lang.String"]
    assert payload["methods"][0]["binding_origin"] == "source"
    assert payload["methods"][0]["invocations"][0]["terminal_chain_member"] is True
    assert reparsed == parsed
    assert isinstance(reparsed.methods, tuple)
    assert isinstance(reparsed.methods[0].parameters, tuple)


def test_models_are_frozen_and_reject_extra_fields() -> None:
    range_dto = verified_range(1, 2)

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        SourceRangeDTO(start_byte=1, end_byte=2, start_line=1, end_line=1, status="verified", unexpected=True)

    with pytest.raises(ValidationError, match="frozen"):
        range_dto.start_byte = 3  # type: ignore[misc]


def test_strict_schema_rejects_numeric_strings_and_bool_as_ints() -> None:
    with pytest.raises(ValidationError):
        SourceRangeDTO.model_validate(
            {
                "start_byte": "1",
                "end_byte": 2,
                "start_line": 1,
                "end_line": 1,
                "status": "verified",
            }
        )

    with pytest.raises(ValidationError):
        InvocationDTO(
            source_key="call:bool",
            kind="method",
            name="x",
            argument_count=0,
            invocation_range=verified_range(0, 1),
            terminal_chain_member=1,
            resolution_status="not_attempted",
        )


def test_source_range_requires_consistent_nullable_offsets_and_line_numbers() -> None:
    with pytest.raises(ValidationError, match="verified ranges require byte offsets"):
        SourceRangeDTO(start_line=1, end_line=1, status="verified")

    with pytest.raises(ValidationError, match="end_byte must be greater than or equal to start_byte"):
        SourceRangeDTO(start_byte=10, end_byte=9, start_line=1, end_line=1, status="verified")

    with pytest.raises(ValidationError, match="end_line must be greater than or equal to start_line"):
        SourceRangeDTO(start_byte=0, end_byte=1, start_line=2, end_line=1, status="verified")

    unverified = SourceRangeDTO(status="unverified", reason="backend range omitted")
    assert unverified.start_byte is None
    assert unverified.end_byte is None


def test_resolved_references_require_binding_identity() -> None:
    with pytest.raises(ValidationError, match="resolved types require binding_key or descriptor"):
        TypeRefDTO(
            source="String",
            qualified_name="java.lang.String",
            resolution_status="resolved",
            binding_origin="binary",
        )

    with pytest.raises(ValidationError, match="resolved types require binding_origin"):
        TypeRefDTO(
            source="String",
            qualified_name="java.lang.String",
            resolution_status="resolved",
            binding_key="Ljava/lang/String;",
        )

    with pytest.raises(ValidationError, match="non-resolved types must use unknown binding_origin"):
        TypeRefDTO(source="Missing", resolution_status="unresolved", unresolved_reason="missing", binding_origin="source")

    primitive = TypeRefDTO(
        source="int[]",
        descriptor="[I",
        array_dimensions=1,
        resolution_status="resolved",
        binding_origin="primitive",
    )
    assert primitive.binding_origin == "primitive"

    with pytest.raises(ValidationError, match="resolved invocations require resolved_binding_key or resolved_descriptor"):
        InvocationDTO(
            source_key="call:1",
            kind="method",
            name="trim",
            argument_count=0,
            invocation_range=verified_range(1, 7),
            resolution_status="resolved",
            resolved_owner="java.lang.String",
            resolved_name="trim",
            binding_origin="binary",
        )

    with pytest.raises(ValidationError, match="resolved invocations require binding_origin source or binary"):
        InvocationDTO(
            source_key="call:1",
            kind="method",
            name="trim",
            argument_count=0,
            invocation_range=verified_range(1, 7),
            resolution_status="resolved",
            resolved_binding_key="Ljava/lang/String;.trim()Ljava/lang/String;",
        )

    unresolved = InvocationDTO(
        source_key="call:2",
        kind="method",
        name="trim",
        argument_count=0,
        invocation_range=verified_range(1, 7),
        resolution_status="unresolved",
        unresolved_reason="missing receiver type",
    )
    assert unresolved.resolved_binding_key is None


def test_aggregate_validation_checks_coverage_diagnostics_and_range_bounds() -> None:
    diagnostic = {
        "severity": "warning",
        "phase": "symbol",
        "code": "symbol.unresolved",
        "message": "missing classpath",
        "coverage_impact": "file_partial",
    }
    with pytest.raises(ValidationError, match="complete coverage cannot include coverage-impacting diagnostics"):
        ParsedJavaFileDTO(
            provenance=JavaParserProvenanceDTO(backend_version="3.47.0", adapter_version="0.1.0"),
            relative_path="A.java",
            source_sha256="c" * 64,
            source_byte_length=10,
            coverage="complete",
            diagnostics=(diagnostic,),
        )

    method = MethodDeclarationDTO(
        source_key="method:outside",
        declaration_key="A.java:0:20",
        declaring_type_source_key="type:A",
        kind="method",
        name="outside",
        display_signature="A.outside()",
        full_signature="A.outside()",
        declaration_range=verified_range(0, 20),
        resolution_status="not_attempted",
    )
    with pytest.raises(ValidationError, match="verified range exceeds source_byte_length"):
        ParsedJavaFileDTO(
            provenance=JavaParserProvenanceDTO(backend_version="3.47.0", adapter_version="0.1.0"),
            relative_path="A.java",
            source_sha256="d" * 64,
            source_byte_length=10,
            coverage="complete",
            methods=(method,),
        )


def test_candidate_shape_validation_requires_one_root_wrapper_with_one_direct_member() -> None:
    wrapper = TypeDeclarationDTO(
        source_key="type:Wrapper",
        kind="class",
        name="Wrapper",
        body_declaration_kinds=("method",),
        declaration_range=verified_range(0, 40),
        resolution_status="not_attempted",
    )
    method = MethodDeclarationDTO(
        source_key="method:only",
        declaration_key="Only.java:1:20",
        declaring_type_source_key="type:Wrapper",
        kind="method",
        name="only",
        display_signature="Only.only()",
        full_signature="Only.only()",
        declaration_range=verified_range(0, 20),
        resolution_status="not_attempted",
    )
    parsed = ParsedJavaFileDTO(
        provenance=JavaParserProvenanceDTO(backend_version="3.47.0", adapter_version="0.1.0"),
        relative_path="Only.java",
        source_sha256="b" * 64,
        source_byte_length=40,
        coverage="complete",
        types=(wrapper,),
        methods=(method,),
    )

    assert parsed.require_exactly_one_root_wrapper_method().source_key == "method:only"

    extra_field_wrapper = wrapper.model_copy(update={"body_declaration_kinds": ("field", "method")})
    parsed_with_extra_field = parsed.model_copy(update={"types": (extra_field_wrapper,)})
    with pytest.raises(ValueError, match="expected wrapper direct body to contain exactly one method or constructor"):
        parsed_with_extra_field.require_exactly_one_root_wrapper_method()

    nested_type = TypeDeclarationDTO(
        source_key="type:Nested",
        enclosing_type_source_key="type:Wrapper",
        kind="local",
        name="Nested",
        local_ordinal=0,
        body_declaration_kinds=("method",),
        declaration_range=verified_range(10, 30),
        resolution_status="not_attempted",
    )
    parsed_with_nested_local = parsed.model_copy(update={"types": (wrapper, nested_type)})
    assert parsed_with_nested_local.require_exactly_one_root_wrapper_method().source_key == "method:only"

    extra_root = wrapper.model_copy(update={"source_key": "type:Extra"})
    parsed_with_extra_root = parsed.model_copy(update={"types": (wrapper, extra_root)})
    with pytest.raises(ValueError, match="expected exactly one root wrapper type"):
        parsed_with_extra_root.require_exactly_one_root_wrapper_method()

    parsed_with_extra = parsed.model_copy(update={"methods": (method, method.model_copy(update={"source_key": "method:extra"}))})
    with pytest.raises(ValueError, match="expected exactly one method declaration"):
        parsed_with_extra.require_exactly_one_root_wrapper_method()
