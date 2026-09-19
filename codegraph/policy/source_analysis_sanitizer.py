from __future__ import annotations


def strip_java_lexical_noise(source: str, *, strip_string_literals: bool = True) -> str:
    """Return ``source`` with lexically-inactive content blanked.

    Two modes are supported via ``strip_string_literals``:

    * ``True`` (default) — comments, char literals, string literals,
      and text-block contents are blanked. Produces the *substring-safe*
      view used by the OPA/Rego rules that perform naive
      ``contains(...)`` matching on ``input.source_code``. A token
      mentioned only inside a comment or quoted string cannot trigger a
      substring rule on this view.
    * ``False`` — only comments are blanked; the contents of string
      literals, char literals, and text blocks are preserved. Produces
      the *active-code* view used by the Python regex pre-analysis
      layer (``codegraph.policy.analysis``), whose patterns are
      structurally anchored and intentionally inspect the contents of
      string-literal arguments (for example, the ``"MD5"`` inside
      ``MessageDigest.getInstance("MD5")``). Preserving literals here
      keeps algorithm-name detection working post-F10.

    In both modes, newline characters are emitted verbatim so that
    line numbers, line counts, and per-line character offsets in the
    returned string match the input exactly — the citation-grounding
    contract for evidence cards.

    The state machine recognises:

    * line comments (``// ... \\n`` or ``... \\r``, JLS §3.4)
    * block comments and javadoc (``/* ... */``, ``/** ... */``)
    * char literals (``'c'`` with ``\\'`` escape)
    * string literals (``"..."`` with ``\\"`` escape)
    * text blocks (``\"\"\" ... \"\"\"`` — Java 13+)

    Design note — F10 unification.
    Before F10, comment and literal stripping was applied *ad hoc*: a
    handful of Python analyzers (notably the INSECURE_RANDOM checks in
    ``codegraph.policy.analysis.crypto``) called ``SourceSanitizer`` to
    strip comments and string literals before pattern matching, while
    the OPA/Rego rules and most other Python rules operated on raw
    source and were therefore vulnerable to lexical-noise false
    positives. F10 unifies this pattern across *every* rule path:
    Rego rules receive the substring-safe view, the Python regex
    layer receives the active-code view, and the LLM/UI receive the
    raw view. This means the contract is the same for all rules; there
    are no longer selective callers of an opt-in sanitizer.

    Known limitations (acceptable for the OWASP Benchmark + JHipster /
    PetClinic real-world corpora):

    * Unicode escapes of the form ``\\uXXXX`` are not pre-processed.
      Java's compiler resolves them before tokenisation, so technically
      a quote written as ``\\u0022`` would still toggle string state
      in real Java. We treat ``\\uXXXX`` as ordinary characters; this
      mismatches the language spec only on adversarially obfuscated
      sources, which are out of scope.
    * Nested block comments are not a Java construct (the compiler
      terminates at the first ``*/``); we match that behaviour.
    """
    src_len = len(source)
    out: list[str] = []
    i = 0

    state = "code"
    escaped = False

    while i < src_len:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < src_len else ""
        nxt2 = source[i + 2] if i + 2 < src_len else ""

        if state == "code":
            if ch == "/" and nxt == "/":
                out.append("  ")
                state = "line_comment"
                i += 2
                continue
            if ch == "/" and nxt == "*":
                out.append("  ")
                state = "block_comment"
                i += 2
                continue
            if ch == '"' and nxt == '"' and nxt2 == '"':
                out.append("   " if strip_string_literals else '"""')
                state = "text_block"
                escaped = False
                i += 3
                continue
            if ch == '"':
                out.append(" " if strip_string_literals else '"')
                state = "string"
                escaped = False
                i += 1
                continue
            if ch == "'":
                out.append(" " if strip_string_literals else "'")
                state = "char"
                escaped = False
                i += 1
                continue
            out.append(ch)
            i += 1
            continue

        if state == "line_comment":
            if ch == "\n" or ch == "\r":
                out.append(ch)
                state = "code"
                i += 1
                continue
            out.append(" ")
            i += 1
            continue

        if state == "block_comment":
            if ch == "*" and nxt == "/":
                out.append("  ")
                state = "code"
                i += 2
                continue
            out.append("\n" if ch == "\n" else " ")
            i += 1
            continue

        if state == "string":
            if escaped:
                out.append(" " if strip_string_literals else ch)
                escaped = False
                i += 1
                continue
            if ch == "\\":
                out.append(" " if strip_string_literals else "\\")
                escaped = True
                i += 1
                continue
            if ch == '"':
                out.append(" " if strip_string_literals else '"')
                state = "code"
                i += 1
                continue
            if ch == "\n" or ch == "\r":
                out.append(ch)
                state = "code"
                i += 1
                continue
            out.append(" " if strip_string_literals else ch)
            i += 1
            continue

        if state == "char":
            if escaped:
                out.append(" " if strip_string_literals else ch)
                escaped = False
                i += 1
                continue
            if ch == "\\":
                out.append(" " if strip_string_literals else "\\")
                escaped = True
                i += 1
                continue
            if ch == "'":
                out.append(" " if strip_string_literals else "'")
                state = "code"
                i += 1
                continue
            if ch == "\n" or ch == "\r":
                out.append(ch)
                state = "code"
                i += 1
                continue
            out.append(" " if strip_string_literals else ch)
            i += 1
            continue

        if ch == "\\" and not escaped:
            out.append(" " if strip_string_literals else "\\")
            escaped = True
            i += 1
            continue
        if escaped:
            if ch == "\n":
                out.append("\n")
            else:
                out.append(" " if strip_string_literals else ch)
            escaped = False
            i += 1
            continue
        if ch == '"' and nxt == '"' and nxt2 == '"':
            out.append("   " if strip_string_literals else '"""')
            state = "code"
            i += 3
            continue
        if ch == "\n":
            out.append("\n")
        else:
            out.append(" " if strip_string_literals else ch)
        i += 1

    return "".join(out)
