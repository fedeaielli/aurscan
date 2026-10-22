"""Static parsing of PKGBUILDs and install scripts with tree-sitter-bash.

The parser never executes package content. It walks the syntax tree iteratively
(no Python recursion), keeps raw source slices, and never expands variables.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from tree_sitter import Language, Node, Parser
from tree_sitter_bash import language as bash_language

from aurscan.models import (
    Command,
    Finding,
    InstallScript,
    ParseResult,
    Pkgbuild,
    Severity,
)
from aurscan.shell import basename, split_words

PKGBUILD_FILENAME = "PKGBUILD"
PARSE_FALLBACK_RULE_ID = "PARSE-001"

_COMMAND_NODES = frozenset({"command", "declaration_command"})
_STRING_NODES = frozenset({"string", "raw_string"})

_ASSIGNMENT_RE = re.compile(
    r"^[ \t]*([A-Za-z_][A-Za-z0-9_]*)\+?=(.*)$",
    re.MULTILINE,
)
_FUNCTION_HEADER_RE = re.compile(
    r"^[ \t]*([A-Za-z_][A-Za-z0-9_]*)[ \t]*\([ \t]*\)[ \t]*\{",
    re.MULTILINE,
)
_ARCH_VARIABLE_RE = re.compile(
    r"^(source|sha256sums|sha512sums|md5sums|b2sums)_([A-Za-z0-9_]+)$"
)


@dataclass
class _Analysis:
    """Intermediate result shared by both parse entry points."""

    variables: dict[str, str | list[str]] = field(default_factory=dict)
    functions: dict[str, list[Command]] = field(default_factory=dict)


def parse_pkgbuild(source: str) -> ParseResult:
    """Parse PKGBUILD ``source`` into a :class:`ParseResult`."""
    analysis, parse_failed = _analyse(source)
    findings: list[Finding] = []
    if parse_failed:
        findings.append(_fallback_finding(PKGBUILD_FILENAME))
    return ParseResult(
        pkgbuild=_build_pkgbuild(analysis, source),
        install_scripts=[],
        parse_failed=parse_failed,
        findings=findings,
    )


def parse_install_script(source: str, filename: str) -> ParseResult:
    """Parse one ``.install`` file into a :class:`ParseResult`."""
    analysis, parse_failed = _analyse(source)
    findings: list[Finding] = []
    if parse_failed:
        findings.append(_fallback_finding(filename))
    script = InstallScript(
        filename=filename,
        functions=analysis.functions,
        raw=source,
    )
    return ParseResult(
        pkgbuild=None,
        install_scripts=[script],
        parse_failed=parse_failed,
        findings=findings,
    )


def _analyse(source: str) -> tuple[_Analysis, bool]:
    """Return the analysis and whether the regex fallback was used."""
    try:
        parser = Parser(Language(bash_language()))
        tree = parser.parse(source.encode("utf-8", errors="replace"))
    except Exception:
        return _fallback_analysis(source), True
    if tree.root_node.has_error:
        return _fallback_analysis(source), True
    return _walk_tree(tree.root_node), False


def _walk_tree(root: Node) -> _Analysis:
    """Traverse ``root`` with an explicit stack and collect assignments/commands."""
    analysis = _Analysis()
    pipe_targets: dict[int, str] = {}
    # (node, enclosing function name, is this a direct child of `program`)
    stack: list[tuple[Node, str | None, bool]] = [(root, None, True)]
    while stack:
        node, function, top_level = stack.pop()
        kind = node.type

        if kind == "pipeline":
            _register_pipe_targets(node, pipe_targets)

        if top_level and kind == "variable_assignment":
            name, value = _variable(node)
            if name:
                analysis.variables[name] = value
        elif top_level and kind == "function_definition":
            name_node = node.child_by_field_name("name")
            if name_node is not None:
                function = _text(name_node)
                analysis.functions.setdefault(function, [])

        if kind in _COMMAND_NODES:
            command = _make_command(node, pipe_targets.get(node.id))
            if command is not None and function is not None:
                analysis.functions.setdefault(function, []).append(command)

        child_top_level = top_level and kind == "program"
        for child in reversed(node.named_children):
            stack.append((child, function, child_top_level))
    return analysis


def _register_pipe_targets(node: Node, targets: dict[int, str]) -> None:
    """Map each command in a pipeline to the next command's basename."""
    commands = [
        command
        for child in node.named_children
        if (command := _effective_command(child)) is not None
    ]
    for current, following in zip(commands, commands[1:], strict=False):
        targets[current.id] = _command_name(following)


def _effective_command(node: Node) -> Node | None:
    """Unwrap redirect wrappers until a command node is found."""
    current = node
    while current.type == "redirected_statement":
        body = current.child_by_field_name("body")
        if body is None:
            return None
        current = body
    return current if current.type in _COMMAND_NODES else None


def _command_name(node: Node) -> str:
    """Return the basename of a command node's name token."""
    name_node = node.child_by_field_name("name")
    if name_node is not None:
        return basename(_text(name_node))
    words = split_words(_text(node))
    return basename(words[0]) if words else ""


def _make_command(node: Node, in_pipe_to: str | None) -> Command | None:
    name = _command_name(node)
    if not name:
        return None
    if node.type == "command":
        args = [_text(child) for child in node.children_by_field_name("argument")]
    else:
        args = [_text(child) for child in node.named_children]
    return Command(
        name=name,
        args=args,
        raw=_command_raw(node),
        in_pipe_to=in_pipe_to,
        line=node.start_point.row + 1,
    )


def _command_raw(node: Node) -> str:
    """Use the redirect wrapper's slice so redirects stay visible to rules."""
    parent = node.parent
    if parent is not None and parent.type == "redirected_statement":
        body = parent.child_by_field_name("body")
        if body is not None and body.id == node.id:
            return _text(parent)
    return _text(node)


def _variable(node: Node) -> tuple[str, str | list[str]]:
    name_node = node.child_by_field_name("name")
    if name_node is None:
        return "", ""
    name = _text(name_node)
    value_node = node.child_by_field_name("value")
    if value_node is None:
        return name, ""
    if value_node.type == "array":
        return name, [_element_text(child) for child in value_node.named_children]
    return name, _strip_quotes(_text(value_node))


def _element_text(node: Node) -> str:
    return _strip_quotes(_text(node))


def _strip_quotes(text: str) -> str:
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    return text


def _text(node: Node) -> str:
    raw = node.text
    if raw is None:
        return ""
    return raw.decode("utf-8", errors="replace")


def _build_pkgbuild(analysis: _Analysis, source: str) -> Pkgbuild:
    variables = analysis.variables
    sources_by_arch, checksums_by_arch = _arch_variables(variables)
    return Pkgbuild(
        pkgname=_as_list(variables.get("pkgname")),
        pkgver=_as_optional_str(variables.get("pkgver")),
        pkgrel=_as_optional_str(variables.get("pkgrel")),
        epoch=_as_optional_str(variables.get("epoch")),
        pkgdesc=_as_optional_str(variables.get("pkgdesc")),
        url=_as_optional_str(variables.get("url")),
        install=_as_optional_str(variables.get("install")),
        arch=_as_list(variables.get("arch")),
        license=_as_list(variables.get("license")),
        depends=_as_list(variables.get("depends")),
        makedepends=_as_list(variables.get("makedepends")),
        checkdepends=_as_list(variables.get("checkdepends")),
        optdepends=_as_list(variables.get("optdepends")),
        provides=_as_list(variables.get("provides")),
        conflicts=_as_list(variables.get("conflicts")),
        replaces=_as_list(variables.get("replaces")),
        source=_as_list(variables.get("source")),
        sha256sums=_as_list(variables.get("sha256sums")),
        sha512sums=_as_list(variables.get("sha512sums")),
        md5sums=_as_list(variables.get("md5sums")),
        b2sums=_as_list(variables.get("b2sums")),
        sources_by_arch=sources_by_arch,
        checksums_by_arch=checksums_by_arch,
        functions=analysis.functions,
        variables=variables,
        raw=source,
    )


def _arch_variables(
    variables: dict[str, str | list[str]],
) -> tuple[dict[str, list[str]], dict[str, dict[str, list[str]]]]:
    """Split ``source_<arch>`` and checksum variables from the flat assignment map."""
    sources: dict[str, list[str]] = {}
    checksums: dict[str, dict[str, list[str]]] = {}
    for name, value in variables.items():
        match = _ARCH_VARIABLE_RE.match(name)
        if match is None:
            continue
        kind, arch = match.groups()
        if kind == "source":
            sources[arch] = _as_list(value)
        else:
            checksums.setdefault(arch, {})[kind] = _as_list(value)
    return sources, checksums


def _as_list(value: str | list[str] | None) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return [item for item in value if item != ""]
    return [value]


def _as_optional_str(value: str | list[str] | None) -> str | None:
    if isinstance(value, list):
        return value[0] if value else None
    return value or None


def _fallback_finding(filename: str) -> Finding:
    return Finding(
        rule_id=PARSE_FALLBACK_RULE_ID,
        severity=Severity.INFO,
        message="tree-sitter could not parse this file; used regex fallback",
        file=filename,
        line=None,
        snippet=None,
        source="static",
    )


def _fallback_analysis(source: str) -> _Analysis:
    """Best-effort extraction used only when tree-sitter reports a syntax error."""
    analysis = _Analysis()
    for match in _ASSIGNMENT_RE.finditer(source):
        name = match.group(1)
        analysis.variables[name] = _fallback_value(match.group(2).strip())
    analysis.functions = _fallback_functions(source)
    return analysis


def _fallback_value(rest: str) -> str | list[str]:
    if rest.startswith("("):
        closing = rest.rfind(")")
        inner = rest[1:closing] if closing != -1 else rest[1:]
        return split_words(inner)
    return _strip_quotes(rest)


def _fallback_functions(source: str) -> dict[str, list[Command]]:
    functions: dict[str, list[Command]] = {}
    for match in _FUNCTION_HEADER_RE.finditer(source):
        body_start = match.end()
        body_end = _matching_brace(source, body_start)
        if body_end is None:
            continue
        body = source[body_start:body_end]
        first_line = source[:body_start].count("\n") + 1
        functions[match.group(1)] = _fallback_commands(body, first_line)
    return functions


def _matching_brace(source: str, start: int) -> int | None:
    depth = 1
    index = start
    while index < len(source):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def _fallback_commands(body: str, first_line: int) -> list[Command]:
    commands: list[Command] = []
    for offset, line in enumerate(body.splitlines()):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        words = split_words(stripped)
        if not words or words[0] in {"{", "}"}:
            continue
        commands.append(
            Command(
                name=basename(words[0]),
                args=words[1:],
                raw=stripped,
                in_pipe_to=None,
                line=first_line + offset,
            )
        )
    return commands
