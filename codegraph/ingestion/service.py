import logging
import os
from typing import Callable, Dict, List, Optional, Set, Tuple

import javalang
from javalang.tree import (
    ClassDeclaration,
    InterfaceDeclaration,
    MemberReference,
    MethodInvocation,
)
from neo4j import GraphDatabase

from codegraph.config import settings
from codegraph.db import ensure_constraints
from codegraph.ingestion.models import FieldEntity, MethodEntity


LOGGER = logging.getLogger(__name__)


class IngestionError(RuntimeError):
    """Raised when ingestion cannot complete successfully."""


def _line_from_position(position: Optional[Tuple[int, int]]) -> Optional[int]:
    if not position:
        return None
    if isinstance(position, tuple):
        return position[0]
    return getattr(position, "line", None)


def _infer_block_end_line(lines: List[str], start_line: Optional[int]) -> Optional[int]:
    if not start_line or start_line <= 0 or start_line > len(lines):
        return start_line
    open_braces = 0
    seen_body = False
    for idx in range(start_line - 1, len(lines)):
        line = lines[idx]
        if "{" in line:
            brace_count = line.count("{")
            open_braces += brace_count
            if brace_count:
                seen_body = True
        if "}" in line and seen_body:
            open_braces -= line.count("}")
            if open_braces <= 0:
                return idx + 1
    return start_line


def _infer_statement_end_line(lines: List[str], start_line: Optional[int]) -> Optional[int]:
    if not start_line or start_line <= 0 or start_line > len(lines):
        return start_line
    for idx in range(start_line - 1, len(lines)):
        if ";" in lines[idx]:
            return idx + 1
    return start_line


def link_extends_classes_batch(tx, relations: List[Dict[str, str]]) -> None:
    tx.run(
        """
        UNWIND $relations AS rel
        MATCH (child:Class {fqn: rel.child_fqn})
        MATCH (parent:Class {fqn: rel.parent_fqn})
        MERGE (child)-[:EXTENDS]->(parent)
        """,
        relations=relations,
    )


def link_implements_classes_batch(tx, relations: List[Dict[str, str]]) -> None:
    tx.run(
        """
        UNWIND $relations AS rel
        MATCH (cls:Class {fqn: rel.class_fqn})
        MATCH (iface:Class {fqn: rel.interface_fqn})
        MERGE (cls)-[:IMPLEMENTS]->(iface)
        """,
        relations=relations,
    )


def link_uses_batch(tx, relations: List[Dict[str, str]]) -> None:
    tx.run(
        """
        UNWIND $relations AS rel
        MATCH (m:Method {signature: rel.method_sig})
        MATCH (c:Class {fqn: rel.class_fqn})
        MERGE (m)-[:USES]->(c)
        """,
        relations=relations,
    )


def link_depends_on_batch(tx, relations: List[Dict[str, str]]) -> None:
    tx.run(
        """
        UNWIND $relations AS rel
        MATCH (c1:Class {fqn: rel.class_fqn})
        MATCH (c2:Class {fqn: rel.dep_class_fqn})
        MERGE (c1)-[:DEPENDS_ON]->(c2)
        """,
        relations=relations,
    )


def link_calls_batch(tx, relations: List[Dict[str, str]]) -> None:
    tx.run(
        """
        UNWIND $relations AS rel
        MATCH (caller:Method {signature: rel.caller_sig})
        MATCH (callee:Method {signature: rel.callee_sig})
        MERGE (caller)-[:CALLS]->(callee)
        """,
        relations=relations,
    )


def create_field(tx, field: FieldEntity) -> None:
    tx.run(
        """
        MERGE (cls:Class {fqn: $class_fqn})
        MERGE (f:Field {class_fqn: $class_fqn, name: $name})
        SET f.type = $field_type,
            f.modifiers = $modifiers,
            f.annotations = $annotations,
            f.file_path = $file_path,
            f.start_line = $start_line,
            f.end_line = $end_line
        MERGE (cls)-[:DECLARES_FIELD]->(f)
        """,
        class_fqn=field.class_fqn,
        name=field.name,
        field_type=field.type,
        modifiers=field.modifiers,
        annotations=field.annotations,
        file_path=field.file_path,
        start_line=field.start_line,
        end_line=field.end_line,
    )


def link_method_annotation_batch(tx, relations: List[Dict[str, str]]) -> None:
    tx.run(
        """
        UNWIND $relations AS rel
        MATCH (m:Method {signature: rel.method_sig})
        MERGE (ann:Annotation {name: rel.annotation})
        MERGE (m)-[:ANNOTATED_WITH]->(ann)
        """,
        relations=relations,
    )


def link_method_field_use_batch(tx, relations: List[Dict[str, str]]) -> None:
    tx.run(
        """
        UNWIND $relations AS rel
        MATCH (m:Method {signature: rel.method_sig})
        MATCH (f:Field {class_fqn: rel.class_fqn, name: rel.field_name})
        MERGE (m)-[:USES]->(f)
        """,
        relations=relations,
    )


def create_class_and_method(tx, m: MethodEntity) -> None:
    tx.run(
        """
        MERGE (cls:Class {fqn: $class_fqn})
        MERGE (m:Method {signature: $sig})
        SET m.name = $name,
            m.params = $params,
            m.annotations = $annotations,
            m.return_type = $return_type,
            m.modifiers = $modifiers,
            m.file_path = $file_path,
            m.full_signature = $full_signature,
            m.start_line = $start_line,
            m.end_line = $end_line
        MERGE (cls)-[:DECLARES]->(m)
        """,
        class_fqn=m.class_fqn,
        sig=m.signature,
        full_signature=m.full_signature,
        name=m.name,
        params=m.params,
        annotations=m.annotations,
        return_type=m.return_type,
        modifiers=m.modifiers,
        file_path=m.file_path,
        start_line=m.start_line,
        end_line=m.end_line,
    )


def link_nested_classes_batch(tx, relations: List[Dict[str, str]]) -> None:
    tx.run(
        """
        UNWIND $relations AS rel
        MATCH (child:Class {fqn: rel.child_fqn})
        MATCH (parent:Class {fqn: rel.parent_fqn})
        MERGE (child)-[:NESTED_IN]->(parent)
        """,
        relations=relations,
    )


def walk_class_declarations(
    type_decls,
    package: str,
    file_path: str,
    file_lines: List[str],
    parent_fqn: Optional[str] = None,
):
    methods: List[MethodEntity] = []
    nested_relations: List[Tuple[str, str]] = []
    extends_relations: List[Tuple[str, str]] = []
    implements_relations: List[Tuple[str, str]] = []
    uses_relations: List[Tuple[str, str]] = []
    depends_on_relations: List[Tuple[str, str]] = []
    calls_relations: List[Tuple[str, str]] = []
    field_entities: List[FieldEntity] = []
    method_field_relations: List[Tuple[str, str, str]] = []

    for decl in type_decls:
        if not isinstance(decl, (ClassDeclaration, InterfaceDeclaration)):
            continue
        class_name = getattr(decl, "name", "UnknownClass")
        class_fqn = f"{package}.{class_name}" if not parent_fqn else f"{parent_fqn}${class_name}"
        if parent_fqn:
            nested_relations.append((class_fqn, parent_fqn))

        if getattr(decl, "extends", None):
            ext = getattr(decl, "extends")
            extends_relations.append((class_fqn, f"{package}.{getattr(ext, 'name', str(ext))}"))

        if getattr(decl, "implements", None):
            for impl in getattr(decl, "implements"):
                implements_relations.append((class_fqn, f"{package}.{getattr(impl, 'name', str(impl))}"))

        declared_fields: Dict[str, FieldEntity] = {}
        for field in getattr(decl, "fields", []):
            field_type = getattr(field.type, "name", str(field.type))
            depends_on_relations.append((class_fqn, f"{package}.{field_type}"))
            field_annotations = [getattr(ann, "name", str(ann)) for ann in getattr(field, "annotations", [])]
            field_modifiers = list(getattr(field, "modifiers", []) or [])
            base_line = _line_from_position(getattr(field, "position", None))
            for declarator in getattr(field, "declarators", []):
                field_name = getattr(declarator, "name", None)
                if not field_name:
                    continue
                start_line = _line_from_position(getattr(declarator, "position", None)) or base_line
                end_line = _infer_statement_end_line(file_lines, start_line)
                entity = FieldEntity(
                    class_fqn=class_fqn,
                    name=field_name,
                    type=field_type,
                    modifiers=field_modifiers,
                    annotations=field_annotations,
                    file_path=file_path,
                    start_line=start_line,
                    end_line=end_line,
                )
                field_entities.append(entity)
                declared_fields[field_name] = entity

        for method in getattr(decl, "methods", []):
            param_types = [
                getattr(p.type, "name", str(p.type))
                for p in getattr(method, "parameters", [])
                if getattr(p, "type", None) is not None
            ]
            method_name = getattr(method, "name", "unknown_method")
            method_sig = f"{class_fqn}.{method_name}()"
            full_sig = f"{class_fqn}.{method_name}({','.join(param_types)})"
            params = [
                f"{getattr(p.type, 'name', str(p.type))} {p.name}"
                for p in getattr(method, "parameters", [])
                if getattr(p, "type", None) is not None
            ]
            annotations = [getattr(ann, "name", str(ann)) for ann in getattr(method, "annotations", [])]
            uses_types = [
                f"{package}.{getattr(p.type, 'name', str(p.type))}"
                for p in getattr(method, "parameters", [])
                if hasattr(p.type, "name")
            ]
            method_start_line = _line_from_position(getattr(method, "position", None))
            method_end_line = (
                _infer_block_end_line(file_lines, method_start_line)
                if getattr(method, "body", None)
                else method_start_line
            )
            calls: List[str] = []
            field_usage: Set[str] = set()
            if getattr(method, "body", None):
                for _, node in method:
                    if isinstance(node, MethodInvocation):
                        qualifier = getattr(node, "qualifier", None)
                        member = getattr(node, "member", None)
                        if qualifier:
                            called_fqn = f"{package}.{qualifier}.{member}()"
                        else:
                            called_fqn = f"{class_fqn}.{member}()"
                        calls.append(called_fqn)
                        calls_relations.append((method_sig, called_fqn))
                    if isinstance(node, MemberReference):
                        qualifier = getattr(node, "qualifier", None)
                        member = getattr(node, "member", None)
                        if member in declared_fields and (qualifier is None or qualifier == "this"):
                            field_usage.add(member)

            methods.append(
                MethodEntity(
                    class_fqn=class_fqn,
                    signature=method_sig,
                    full_signature=full_sig,
                    name=method_name,
                    params=params,
                    annotations=annotations,
                    return_type=getattr(getattr(method, "return_type", None), "name", None),
                    modifiers=list(getattr(method, "modifiers", [])),
                    file_path=file_path,
                    calls=calls,
                    uses=uses_types,
                    start_line=method_start_line,
                    end_line=method_end_line,
                )
            )
            for used_type in uses_types:
                uses_relations.append((method_sig, used_type))
            for field_name in field_usage:
                method_field_relations.append((method_sig, class_fqn, field_name))

        for ctor in getattr(decl, "constructors", []):
            ctor_param_types = [
                getattr(p.type, "name", str(p.type))
                for p in getattr(ctor, "parameters", [])
                if getattr(p, "type", None) is not None
            ]
            ctor_sig = f"{class_fqn}.{class_name}()"
            ctor_full_sig = f"{class_fqn}.{class_name}({','.join(ctor_param_types)})"
            params = [
                f"{getattr(p.type, 'name', str(p.type))} {p.name}"
                for p in getattr(ctor, "parameters", [])
                if getattr(p, "type", None) is not None
            ]
            annotations = [getattr(ann, "name", str(ann)) for ann in getattr(ctor, "annotations", [])]
            uses_types = [
                f"{package}.{getattr(p.type, 'name', str(p.type))}"
                for p in getattr(ctor, "parameters", [])
                if hasattr(p.type, "name")
            ]
            ctor_start_line = _line_from_position(getattr(ctor, "position", None))
            ctor_end_line = (
                _infer_block_end_line(file_lines, ctor_start_line) if getattr(ctor, "body", None) else ctor_start_line
            )
            methods.append(
                MethodEntity(
                    class_fqn=class_fqn,
                    signature=ctor_sig,
                    full_signature=ctor_full_sig,
                    name=class_name,
                    params=params,
                    annotations=annotations,
                    return_type=None,
                    modifiers=list(getattr(ctor, "modifiers", [])),
                    file_path=file_path,
                    calls=[],
                    uses=uses_types,
                    start_line=ctor_start_line,
                    end_line=ctor_end_line,
                )
            )
            for used_type in uses_types:
                uses_relations.append((ctor_sig, used_type))

        body_types = [
            node for node in getattr(decl, "body", []) if isinstance(node, (ClassDeclaration, InterfaceDeclaration))
        ]
        (
            inner_methods,
            inner_nested,
            inner_extends,
            inner_implements,
            inner_uses,
            inner_depends,
            inner_calls,
            inner_fields,
            inner_method_fields,
        ) = walk_class_declarations(body_types, package, file_path, file_lines, class_fqn)
        methods += inner_methods
        nested_relations += inner_nested
        extends_relations += inner_extends
        implements_relations += inner_implements
        uses_relations += inner_uses
        depends_on_relations += inner_depends
        calls_relations += inner_calls
        field_entities += inner_fields
        method_field_relations += inner_method_fields

    return (
        methods,
        nested_relations,
        extends_relations,
        implements_relations,
        uses_relations,
        depends_on_relations,
        calls_relations,
        field_entities,
        method_field_relations,
    )


def extract_entities_from_file(file_path: str):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        tree = javalang.parse.parse(content)
    except Exception as exc:
        print(f"[WARN] Could not parse {file_path}: {exc}")
        return [], [], [], [], [], [], [], [], []

    package = getattr(tree, "package", None)
    package_name = package.name if package and hasattr(package, "name") else "unknown"
    return walk_class_declarations(
        getattr(tree, "types", []),
        package_name,
        file_path,
        content.splitlines(),
    )


def extract_entities_from_content(file_path: str, content: str):
    try:
        tree = javalang.parse.parse(content)
    except Exception as exc:
        print(f"[WARN] Could not parse in-memory content for {file_path}: {exc}")
        return [], [], [], [], [], [], [], [], []

    package = getattr(tree, "package", None)
    package_name = package.name if package and hasattr(package, "name") else "unknown"
    return walk_class_declarations(
        getattr(tree, "types", []),
        package_name,
        file_path,
        content.splitlines(),
    )


def collect_code_structure(root_dir: str, progress_callback: Optional[Callable[[str, str, float], None]] = None):
    all_methods: List[MethodEntity] = []
    all_nested: List[Tuple[str, str]] = []
    all_extends: List[Tuple[str, str]] = []
    all_implements: List[Tuple[str, str]] = []
    all_uses: List[Tuple[str, str]] = []
    all_depends: List[Tuple[str, str]] = []
    all_calls: List[Tuple[str, str]] = []
    all_fields: List[FieldEntity] = []
    all_method_field_relations: List[Tuple[str, str, str]] = []
    java_files: List[str] = []

    for root, _, files in os.walk(root_dir):
        for file in files:
            if file.endswith(".java"):
                java_files.append(os.path.join(root, file))

    file_count = len(java_files)
    total_files = file_count or 1
    base_progress = 20.0
    span = 40.0

    for index, file_path in enumerate(java_files, start=1):
        rel_path = os.path.relpath(file_path, root_dir)
        if progress_callback:
            pct = min(base_progress + (span * index / total_files), 60.0)
            progress_callback("parsing", f"Parsing {rel_path}", pct)
        (
            methods,
            nested,
            extends,
            implements,
            uses,
            depends,
            calls,
            fields,
            method_field_uses,
        ) = extract_entities_from_file(file_path)
        all_methods.extend(methods)
        all_nested.extend(nested)
        all_extends.extend(extends)
        all_implements.extend(implements)
        all_uses.extend(uses)
        all_depends.extend(depends)
        all_calls.extend(calls)
        all_fields.extend(fields)
        all_method_field_relations.extend(method_field_uses)

    print(f"📄 Parsed {file_count} Java files.")
    print(f"🔍 Found {len(all_methods)} methods/constructors.")
    print(f"🏗️ Found {len(all_nested)} nested class relations.")
    print(f"🧬 Found {len(all_extends)} extends relations.")
    print(f"🧬 Found {len(all_implements)} implements relations.")
    print(f"🔗 Found {len(all_uses)} uses relations.")
    print(f"🔗 Found {len(all_depends)} depends_on relations.")
    print(f"🔗 Found {len(all_calls)} calls relations.")
    print(f"🌱 Found {len(all_fields)} fields.")
    print(f"📦 Found {len(all_method_field_relations)} method-field uses relations.")
    if progress_callback:
        progress_callback("parsing", f"Parsed {file_count} Java files.", 60.0)
    return (
        all_methods,
        all_nested,
        all_extends,
        all_implements,
        all_uses,
        all_depends,
        all_calls,
        all_fields,
        all_method_field_relations,
    )


def ingest_to_neo4j(
    methods: List[MethodEntity],
    nested_relations: List[tuple],
    extends_relations: List[tuple],
    implements_relations: List[tuple],
    uses_relations: List[tuple],
    depends_on_relations: List[tuple],
    calls_relations: List[tuple],
    field_entities: List[FieldEntity],
    method_field_relations: List[tuple],
    progress_callback: Optional[Callable[[str, str, float], None]] = None,
) -> None:
    def safe_write(session, func, *args):
        try:
            session.execute_write(func, *args)
        except Exception as exc:
            print(f"[WARN] Failed to create relationship: {args} - {exc}")

    def chunked_iterable(iterable, size):
        for i in range(0, len(iterable), size):
            yield iterable[i:i + size]

    driver = GraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_pass))
    with driver.session() as session:
        annotation_count = sum(len(m.annotations) for m in methods)
        unique_method_field_relations = list(dict.fromkeys(method_field_relations))
        
        total_operations = (
            len(methods)
            + len(field_entities)
            + (annotation_count // 5000) + 1
            + (len(nested_relations) // 5000) + 1
            + (len(extends_relations) // 5000) + 1
            + (len(implements_relations) // 5000) + 1
            + (len(uses_relations) // 5000) + 1
            + (len(depends_on_relations) // 5000) + 1
            + (len(calls_relations) // 5000) + 1
            + (len(unique_method_field_relations) // 5000) + 1
        ) or 1
        
        processed = 0

        def notify(label: str, index: int, total: int) -> None:
            nonlocal processed
            processed += 1
            if progress_callback:
                pct = min(60.0 + 20.0 * (processed / total_operations), 80.0)
                progress_callback("ingesting", f"{label} ({index}/{total})", pct)

        if progress_callback:
            progress_callback("ingesting", "Persisting entities to Neo4j…", 60.0)

        print(f"🚀 Ingesting {len(methods)} methods/constructors...")
        for idx, method in enumerate(methods, start=1):
            safe_write(session, create_class_and_method, method)
            notify("Methods", idx, len(methods) or 1)

        print(f"🌱 Ingesting {len(field_entities)} fields...")
        for idx, field in enumerate(field_entities, start=1):
            safe_write(session, create_field, field)
            notify("Fields", idx, len(field_entities) or 1)

        print(f"🏷️ Linking {annotation_count} method annotations...")
        relations_ma = [{"method_sig": m.signature, "annotation": ann} for m in methods for ann in m.annotations]
        for idx, chunk in enumerate(chunked_iterable(relations_ma, 5000), start=1):
            safe_write(session, link_method_annotation_batch, chunk)
            notify("Method annotations chunks", idx, (len(relations_ma) // 5000) + 1)

        print(f"🔗 Ingesting {len(nested_relations)} nested class relations...")
        relations_nested = [{"child_fqn": c, "parent_fqn": p} for c, p in nested_relations]
        for idx, chunk in enumerate(chunked_iterable(relations_nested, 5000), start=1):
            safe_write(session, link_nested_classes_batch, chunk)
            notify("Nested relations chunks", idx, (len(relations_nested) // 5000) + 1)

        print(f"🧬 Ingesting {len(extends_relations)} extends relations...")
        relations_extends = [{"child_fqn": c, "parent_fqn": p} for c, p in extends_relations]
        for idx, chunk in enumerate(chunked_iterable(relations_extends, 5000), start=1):
            safe_write(session, link_extends_classes_batch, chunk)
            notify("Extends relations chunks", idx, (len(relations_extends) // 5000) + 1)

        print(f"🧬 Ingesting {len(implements_relations)} implements relations...")
        relations_impl = [{"class_fqn": c, "interface_fqn": p} for c, p in implements_relations]
        for idx, chunk in enumerate(chunked_iterable(relations_impl, 5000), start=1):
            safe_write(session, link_implements_classes_batch, chunk)
            notify("Implements relations chunks", idx, (len(relations_impl) // 5000) + 1)

        print(f"🔗 Ingesting {len(uses_relations)} uses relations...")
        relations_uses = [{"method_sig": m, "class_fqn": c} for m, c in uses_relations]
        for idx, chunk in enumerate(chunked_iterable(relations_uses, 5000), start=1):
            safe_write(session, link_uses_batch, chunk)
            notify("Uses relations chunks", idx, (len(relations_uses) // 5000) + 1)

        print(f"🔗 Ingesting {len(depends_on_relations)} depends_on relations...")
        relations_deps = [{"class_fqn": c1, "dep_class_fqn": c2} for c1, c2 in depends_on_relations]
        for idx, chunk in enumerate(chunked_iterable(relations_deps, 5000), start=1):
            safe_write(session, link_depends_on_batch, chunk)
            notify("Depends_on relations chunks", idx, (len(relations_deps) // 5000) + 1)

        print(f"🔗 Ingesting {len(calls_relations)} calls relations...")
        relations_calls = [{"caller_sig": c1, "callee_sig": c2} for c1, c2 in calls_relations]
        for idx, chunk in enumerate(chunked_iterable(relations_calls, 5000), start=1):
            safe_write(session, link_calls_batch, chunk)
            notify("Calls relations chunks", idx, (len(relations_calls) // 5000) + 1)

        print(f"📦 Ingesting {len(unique_method_field_relations)} method-field uses relations...")
        relations_mf = [{"method_sig": sig, "class_fqn": cls, "field_name": name} for sig, cls, name in unique_method_field_relations]
        for idx, chunk in enumerate(chunked_iterable(relations_mf, 5000), start=1):
            safe_write(session, link_method_field_use_batch, chunk)
            notify("Method-field uses chunks", idx, (len(relations_mf) // 5000) + 1)

        if progress_callback:
            progress_callback("ingesting", "Neo4j ingestion complete.", 80.0)
    driver.close()


def ingest(
    java_root_dir: str,
    progress_callback: Optional[Callable[[str, str, float], None]] = None,
    sync: bool = False,
) -> None:
    java_root_dir = os.path.abspath(java_root_dir)
    print(f"📦 Parsing Java project at: {java_root_dir}")
    if not os.path.isdir(java_root_dir):
        print(f"[ERROR] JAVA_ROOT_DIR does not exist: {java_root_dir}")
        if progress_callback:
            progress_callback("error", f"JAVA_ROOT_DIR does not exist: {java_root_dir}", 100.0)
        raise IngestionError(f"JAVA_ROOT_DIR does not exist: {java_root_dir}")
    if progress_callback:
        progress_callback("connecting", "Checking Neo4j availability…", 10.0)
    try:
        _driver = GraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_pass))
        with _driver.session() as session:
            session.run("RETURN 1 AS ok").consume()
        _driver.close()
    except Exception as exc:
        print("[ERROR] Could not connect to Neo4j.")
        print(f"        URI   : {settings.neo4j_uri}")
        print(f"        USER  : {settings.neo4j_user}")
        print("        HINTS :")
        print("          - Ensure Neo4j is running and listening on the Bolt port.")
        print("          - If using Docker, map '-p 7687:7687' and use 'bolt://127.0.0.1:7687'.")
        print("          - You can override settings via env vars: NEO4J_URI/USER/PASS.")
        print(f"          - Original error: {exc}")
        if progress_callback:
            progress_callback("error", f"Neo4j connection failed: {exc}", 100.0)
        raise IngestionError(f"Neo4j connection failed: {exc}") from exc

    try:
        ensure_constraints()
    except Exception as exc:
        print(f"[WARN] Could not ensure Neo4j constraints: {exc}")

    if progress_callback:
        progress_callback("parsing", "Scanning Java sources…", 15.0)

    all_data = collect_code_structure(java_root_dir, progress_callback=progress_callback)
    print("✅ Ingesting into Neo4j...")
    ingest_to_neo4j(*all_data, progress_callback=progress_callback)

    if sync:
        print("🔄 Syncing graph: checking for stale files...")
        if progress_callback:
            progress_callback("sync", "Pruning stale files...", 80.0)

        # Collect files seen in this scan
        seen_paths = set()
        # all_data[0] is methods, all_data[7] is fields
        for m in all_data[0]:
            seen_paths.add(m.file_path)
        for f in all_data[7]:
            seen_paths.add(f.file_path)

        stale_count = 0
        try:
            driver = GraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_pass))
            with driver.session() as session:
                # Find all file paths currently in DB
                result = session.run("MATCH (m:Method) RETURN DISTINCT m.file_path as p")
                db_paths = {record["p"] for record in result}
                
                # Also check fields in case there are files with fields but no methods (rare but possible)
                result_fields = session.run("MATCH (f:Field) RETURN DISTINCT f.file_path as p")
                db_paths.update({record["p"] for record in result_fields})

                # Determine which are stale (in DB, not in scan, AND inside the root dir)
                for path in db_paths:
                    if path and path.startswith(java_root_dir) and path not in seen_paths:
                        print(f"🗑️ Pruning stale file: {path}")
                        _purge_file_entities(path)
                        stale_count += 1
            driver.close()
            print(f"🧹 Pruned {stale_count} stale files.")
        except Exception as exc:
            print(f"[WARN] Sync failed: {exc}")

    if progress_callback:
        progress_callback("ingesting", "Ingestion complete.", 90.0 if sync else 80.0)
    print("🎉 Ingestion complete.")


def _purge_file_entities(file_path: str) -> None:
    driver = GraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_pass))
    try:
        with driver.session() as session:
            session.run(
                "MATCH (m:Method {file_path: $path}) DETACH DELETE m",
                path=file_path,
            ).consume()
            session.run(
                "MATCH (f:Field {file_path: $path}) DETACH DELETE f",
                path=file_path,
            ).consume()
    finally:
        driver.close()


def purge_workspace_entities(root_dir: str) -> None:
    """
    Remove all file-backed graph entities under a workspace root.

    This is used by the interactive upload workflow so a new uploaded project
    fully replaces the prior `uploaded_code` workspace in Neo4j without
    resetting unrelated benchmark or staged-evaluation graphs.
    """

    workspace_root = os.path.abspath(root_dir)
    driver = GraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_pass))
    LOGGER.info("Purging graph entities under workspace root %s", workspace_root)
    try:
        with driver.session() as session:
            session.run(
                "MATCH (m:Method) WHERE m.file_path STARTS WITH $prefix DETACH DELETE m",
                prefix=workspace_root,
            ).consume()
            session.run(
                "MATCH (f:Field) WHERE f.file_path STARTS WITH $prefix DETACH DELETE f",
                prefix=workspace_root,
            ).consume()
            session.run(
                "MATCH (a:Annotation) WHERE NOT EXISTS { MATCH (:Method)-[:ANNOTATED_WITH]->(a) } DETACH DELETE a"
            ).consume()
    finally:
        driver.close()


def process_single_file(file_path: str, progress_callback: Optional[Callable[[str, str, float], None]] = None) -> None:
    """Re-ingest a single Java source file without touching the rest of the graph."""

    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Java source file not found: {file_path}")
    if progress_callback:
        progress_callback("parsing", f"Parsing single file: {os.path.basename(file_path)}", 20.0)

    (
        methods,
        nested_relations,
        extends_relations,
        implements_relations,
        uses_relations,
        depends_on_relations,
        calls_relations,
        field_entities,
        method_field_relations,
    ) = extract_entities_from_file(file_path)

    _purge_file_entities(file_path)

    ingest_to_neo4j(
        methods,
        nested_relations,
        extends_relations,
        implements_relations,
        uses_relations,
        depends_on_relations,
        calls_relations,
        field_entities,
        method_field_relations,
        progress_callback=progress_callback,
    )

    if progress_callback:
        progress_callback("ingesting", "Single file ingestion complete", 80.0)


def process_single_file_content(
    file_path: str,
    content: str,
    progress_callback: Optional[Callable[[str, str, float], None]] = None,
) -> None:
    """Re-ingest a single Java source file from in-memory content."""

    if progress_callback:
        progress_callback("parsing", f"Parsing in-memory file: {os.path.basename(file_path)}", 20.0)

    (
        methods,
        nested_relations,
        extends_relations,
        implements_relations,
        uses_relations,
        depends_on_relations,
        calls_relations,
        field_entities,
        method_field_relations,
    ) = extract_entities_from_content(file_path, content)

    _purge_file_entities(file_path)

    ingest_to_neo4j(
        methods,
        nested_relations,
        extends_relations,
        implements_relations,
        uses_relations,
        depends_on_relations,
        calls_relations,
        field_entities,
        method_field_relations,
        progress_callback=progress_callback,
    )

    if progress_callback:
        progress_callback("ingesting", "Single file ingestion complete", 80.0)
