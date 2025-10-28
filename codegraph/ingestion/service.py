import os
import javalang
from javalang.tree import ClassDeclaration, InterfaceDeclaration, MethodInvocation

from neo4j import GraphDatabase
from typing import List, Optional
from codegraph.ingestion.models.method import MethodEntity
from codegraph.config import JAVA_ROOT_DIR as _DEFAULT_JAVA_ROOT_DIR, NEO4J_URI, NEO4J_USER, NEO4J_PASS
from codegraph.db import ensure_constraints


def link_extends_classes(tx, child_fqn: str, parent_fqn: str) -> None:
    tx.run("""
    MATCH (child:Class {fqn: $child_fqn}), (parent:Class {fqn: $parent_fqn})
    MERGE (child)-[:EXTENDS]->(parent)
    """, child_fqn=child_fqn, parent_fqn=parent_fqn)

def link_implements_classes(tx, class_fqn: str, interface_fqn: str) -> None:
    tx.run("""
    MATCH (cls:Class {fqn: $class_fqn}), (iface:Class {fqn: $interface_fqn})
    MERGE (cls)-[:IMPLEMENTS]->(iface)
    """, class_fqn=class_fqn, interface_fqn=interface_fqn)

def link_uses(tx, method_sig: str, class_fqn: str) -> None:
    tx.run("""
    MATCH (m:Method {signature: $method_sig}), (c:Class {fqn: $class_fqn})
    MERGE (m)-[:USES]->(c)
    """, method_sig=method_sig, class_fqn=class_fqn)

def link_depends_on(tx, class_fqn: str, dep_class_fqn: str) -> None:
    tx.run("""
    MATCH (c1:Class {fqn: $class_fqn}), (c2:Class {fqn: $dep_class_fqn})
    MERGE (c1)-[:DEPENDS_ON]->(c2)
    """, class_fqn=class_fqn, dep_class_fqn=dep_class_fqn)

def link_calls(tx, caller_sig: str, callee_sig: str) -> None:
    tx.run("""
    MATCH (caller:Method {signature: $caller_sig}), (callee:Method {signature: $callee_sig})
    MERGE (caller)-[:CALLS]->(callee)
    """, caller_sig=caller_sig, callee_sig=callee_sig)

def create_class_and_method(tx, m: 'MethodEntity') -> None:
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
            m.full_signature = $full_signature
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
        file_path=m.file_path
    )

def link_nested_classes(tx, child_fqn: str, parent_fqn: str) -> None:
    tx.run("""
    MATCH (child:Class {fqn: $child_fqn}), (parent:Class {fqn: $parent_fqn})
    MERGE (child)-[:NESTED_IN]->(parent)
    """, child_fqn=child_fqn, parent_fqn=parent_fqn)


    # moved to models/method.py

def walk_class_declarations(type_decls, package, file_path, parent_fqn=None):
    results = []
    nested_relations = []
    extends_relations = []
    implements_relations = []
    uses_relations = []
    depends_on_relations = []
    calls_relations = []
    class_fqn_map = {}
    for decl in type_decls:
        if isinstance(decl, (ClassDeclaration, InterfaceDeclaration)):
            class_fqn = f"{package}.{getattr(decl, 'name', 'UnknownClass')}" if not parent_fqn else f"{parent_fqn}${getattr(decl, 'name', 'UnknownClass')}"
            class_fqn_map[getattr(decl, 'name', 'UnknownClass')] = class_fqn
            if parent_fqn:
                nested_relations.append((class_fqn, parent_fqn))
            if hasattr(decl, "extends") and getattr(decl, "extends", None):
                ext = getattr(decl, "extends")
                ext_name = getattr(ext, "name", str(ext))
                extends_fqn = f"{package}.{ext_name}"
                extends_relations.append((class_fqn, extends_fqn))
            if hasattr(decl, "implements") and getattr(decl, "implements", None):
                for impl in getattr(decl, "implements"):
                    impl_name = getattr(impl, "name", str(impl))
                    implements_fqn = f"{package}.{impl_name}"
                    implements_relations.append((class_fqn, implements_fqn))
            for field in getattr(decl, "fields", []):
                field_type = getattr(field.type, "name", str(field.type))
                depends_on_relations.append((class_fqn, f"{package}.{field_type}"))
            for method in getattr(decl, "methods", []):
                param_types = [
                    getattr(p.type, "name", str(p.type))
                    for p in getattr(method, "parameters", [])
                    if getattr(p, "type", None) is not None
                ]
                method_sig = f"{class_fqn}.{getattr(method, 'name', 'unknown_method')}()"
                full_sig = f"{class_fqn}.{getattr(method, 'name', 'unknown_method')}({','.join(param_types)})"
                params = [f"{getattr(p.type, 'name', str(p.type))} {p.name}" for p in getattr(method, "parameters", [])]
                annotations = [getattr(ann, 'name', str(ann)) for ann in getattr(method, "annotations", [])]
                uses_types = [f"{package}.{getattr(p.type, 'name', str(p.type))}" for p in getattr(method, "parameters", []) if hasattr(p.type, "name")]
                calls = []
                if getattr(method, "body", None):
                    for path, node in method:
                        if isinstance(node, MethodInvocation):
                            qualifier = getattr(node, "qualifier", None)
                            member = getattr(node, "member", None)
                            if qualifier:
                                called_fqn = f"{package}.{qualifier}.{member}()"
                            else:
                                called_fqn = f"{class_fqn}.{member}()"
                            calls.append(called_fqn)
                            calls_relations.append((method_sig, called_fqn))
                results.append(MethodEntity(
                    class_fqn=class_fqn,
                    signature=method_sig,
                    full_signature=full_sig,
                    name=getattr(method, 'name', 'unknown_method'),
                    params=params,
                    annotations=annotations,
                    return_type=getattr(getattr(method, 'return_type', None), 'name', None),
                    modifiers=list(getattr(method, 'modifiers', [])),
                    file_path=file_path,
                    calls=calls,
                    uses=uses_types
                ))
                for used_type in uses_types:
                    uses_relations.append((method_sig, used_type))
            for ctor in getattr(decl, "constructors", []):
                ctor_param_types = [
                    getattr(p.type, "name", str(p.type))
                    for p in getattr(ctor, "parameters", [])
                    if getattr(p, "type", None) is not None
                ]
                ctor_sig = f"{class_fqn}.{getattr(decl, 'name', 'UnknownClass')}()"
                ctor_full_sig = f"{class_fqn}.{getattr(decl, 'name', 'UnknownClass')}({','.join(ctor_param_types)})"
                params = [f"{getattr(p.type, 'name', str(p.type))} {p.name}" for p in getattr(ctor, "parameters", [])]
                annotations = [getattr(ann, 'name', str(ann)) for ann in getattr(ctor, "annotations", [])]
                uses_types = [f"{package}.{getattr(p.type, 'name', str(p.type))}" for p in getattr(ctor, "parameters", []) if hasattr(p.type, "name")]
                results.append(MethodEntity(
                    class_fqn=class_fqn,
                    signature=ctor_sig,
                    full_signature=ctor_full_sig,
                    name=getattr(decl, 'name', 'UnknownClass'),
                    params=params,
                    annotations=annotations,
                    return_type=None,
                    modifiers=list(getattr(ctor, 'modifiers', [])),
                    file_path=file_path,
                    calls=[],
                    uses=uses_types
                ))
                for used_type in uses_types:
                    uses_relations.append((ctor_sig, used_type))
            body_types = [node for node in getattr(decl, "body", []) if isinstance(node, (ClassDeclaration, InterfaceDeclaration))]
            inner_methods, inner_nested, inner_extends, inner_implements, inner_uses, inner_depends, inner_calls = walk_class_declarations(body_types, package, file_path, class_fqn)
            results += inner_methods
            nested_relations += inner_nested
            extends_relations += inner_extends
            implements_relations += inner_implements
            uses_relations += inner_uses
            depends_on_relations += inner_depends
            calls_relations += inner_calls
    return results, nested_relations, extends_relations, implements_relations, uses_relations, depends_on_relations, calls_relations

def extract_entities_from_file(file_path: str):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        tree = javalang.parse.parse(content)
    except Exception as e:
        print(f"[WARN] Could not parse {file_path}: {e}")
        return [], [], [], [], [], [], []

    package = getattr(tree, "package", None)
    package_name = package.name if package and hasattr(package, "name") else "unknown"
    return walk_class_declarations(getattr(tree, "types", []), package_name, file_path)

def collect_code_structure(root_dir: str):
    """
    Walk the Java source tree and collect all methods, classes, and relationships.
    Returns lists of all entities and relationships found.
    """
    all_methods = []
    all_nested = []
    all_extends = []
    all_implements = []
    all_uses = []
    all_depends = []
    all_calls = []
    file_count = 0
    for root, _, files in os.walk(root_dir):
        for file in files:
            if file.endswith(".java"):
                file_count += 1
                file_path = os.path.join(root, file)
                methods, nested, extends, implements, uses, depends, calls = extract_entities_from_file(file_path)
                all_methods.extend(methods)
                all_nested.extend(nested)
                all_extends.extend(extends)
                all_implements.extend(implements)
                all_uses.extend(uses)
                all_depends.extend(depends)
                all_calls.extend(calls)
    print(f"📄 Parsed {file_count} Java files.")
    print(f"🔍 Found {len(all_methods)} methods/constructors.")
    print(f"🏗️ Found {len(all_nested)} nested class relations.")
    print(f"🧬 Found {len(all_extends)} extends relations.")
    print(f"🧬 Found {len(all_implements)} implements relations.")
    print(f"🔗 Found {len(all_uses)} uses relations.")
    print(f"🔗 Found {len(all_depends)} depends_on relations.")
    print(f"🔗 Found {len(all_calls)} calls relations.")
    return all_methods, all_nested, all_extends, all_implements, all_uses, all_depends, all_calls


def ingest_to_neo4j(
    methods: List[MethodEntity],
    nested_relations: List[tuple],
    extends_relations: List[tuple],
    implements_relations: List[tuple],
    uses_relations: List[tuple],
    depends_on_relations: List[tuple],
    calls_relations: List[tuple]
) -> None:
    # ...existing code from codebase_to_neo4j.py...
    pass

    def safe_write(session, func, *args):
        try:
            session.execute_write(func, *args)
        except Exception as e:
            print(f"[WARN] Failed to create relationship: {args} - {e}")

    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    with driver.session() as session:
        print(f"🚀 Ingesting {len(methods)} methods/constructors...")
        for m in methods:
            safe_write(session, create_class_and_method, m)
        print(f"🔗 Ingesting {len(nested_relations)} nested class relations...")
        for child, parent in nested_relations:
            safe_write(session, link_nested_classes, child, parent)
        print(f"🧬 Ingesting {len(extends_relations)} extends relations...")
        for child, parent in extends_relations:
            safe_write(session, link_extends_classes, child, parent)
        print(f"🧬 Ingesting {len(implements_relations)} implements relations...")
        for child, parent in implements_relations:
            safe_write(session, link_implements_classes, child, parent)
        print(f"🔗 Ingesting {len(uses_relations)} uses relations...")
        for method_sig, class_fqn in uses_relations:
            safe_write(session, link_uses, method_sig, class_fqn)
        print(f"🔗 Ingesting {len(depends_on_relations)} depends_on relations...")
        for class_fqn, dep_class_fqn in depends_on_relations:
            safe_write(session, link_depends_on, class_fqn, dep_class_fqn)
        print(f"🔗 Ingesting {len(calls_relations)} calls relations...")
        for caller_sig, callee_sig in calls_relations:
            safe_write(session, link_calls, caller_sig, callee_sig)
    driver.close()

def ingest(java_root_dir: str) -> None:
    """
    Ingest a Java project into Neo4j.
    Parses the Java project and ingests the extracted code structure into Neo4j.
    """
    print(f"📦 Parsing Java project at: {java_root_dir}")
    try:
        _driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
        with _driver.session() as s:
            s.run("RETURN 1 AS ok").consume()
        _driver.close()
    except Exception as e:
        print("[ERROR] Could not connect to Neo4j.")
        print(f"        URI   : {NEO4J_URI}")
        print(f"        USER  : {NEO4J_USER}")
        print("        HINTS :")
        print("          - Ensure Neo4j is running and listening on the Bolt port.")
        print("          - If using Docker, map '-p 7687:7687' and use 'bolt://127.0.0.1:7687'.")
        print("          - You can override settings via env vars: NEO4J_URI/USER/PASS.")
        print(f"          - Original error: {e}")
        return
    try:
        ensure_constraints()
    except Exception as e:
        print(f"[WARN] Could not ensure Neo4j constraints: {e}")
    if not os.path.isdir(java_root_dir):
        print(f"[ERROR] JAVA_ROOT_DIR does not exist: {java_root_dir}")
        return
    all_data = collect_code_structure(java_root_dir)
    print("✅ Ingesting into Neo4j...")
    ingest_to_neo4j(*all_data)
    print("🎉 Ingestion complete.")

