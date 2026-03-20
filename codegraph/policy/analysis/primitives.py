from __future__ import annotations

import re


class SourceSanitizer:
    @staticmethod
    def strip_comments(source_code: str, *, strip_string_literals: bool) -> str:
        if not source_code:
            return source_code

        sanitized: list[str] = []
        in_block_comment = False
        in_string = False
        in_char = False
        escaped = False
        quote_char = ""
        index = 0

        while index < len(source_code):
            char = source_code[index]
            nxt = source_code[index + 1] if index + 1 < len(source_code) else ""

            if in_block_comment:
                if char == "*" and nxt == "/":
                    sanitized.extend("  ")
                    in_block_comment = False
                    index += 2
                    continue
                sanitized.append("\n" if char == "\n" else " ")
                index += 1
                continue

            if in_string or in_char:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote_char:
                    if in_string:
                        in_string = False
                    else:
                        in_char = False
                if strip_string_literals:
                    sanitized.append("\n" if char == "\n" else " ")
                else:
                    sanitized.append(char)
                index += 1
                continue

            if char == "/" and nxt == "/":
                sanitized.extend("  ")
                index += 2
                while index < len(source_code) and source_code[index] != "\n":
                    sanitized.append(" ")
                    index += 1
                continue

            if char == "/" and nxt == "*":
                sanitized.extend("  ")
                in_block_comment = True
                index += 2
                continue

            if char == '"':
                in_string = True
                quote_char = '"'
                sanitized.append(" " if strip_string_literals else char)
                index += 1
                continue

            if char == "'":
                in_char = True
                quote_char = "'"
                sanitized.append(" " if strip_string_literals else char)
                index += 1
                continue

            sanitized.append(char)
            index += 1

        return "".join(sanitized)

    @staticmethod
    def strip_comments_and_string_literals(source_code: str) -> str:
        return SourceSanitizer.strip_comments(source_code, strip_string_literals=True)

    @staticmethod
    def strip_comments_and_annotations(source_code: str) -> str:
        without_comments = SourceSanitizer.strip_comments(source_code, strip_string_literals=False)
        return re.sub(r"(?m)^\s*@[A-Za-z_][A-Za-z0-9_$.]*(?:\([^)]*\))?\s*$", "", without_comments)
