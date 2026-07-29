"""A deliberately small YAML-subset parser (stdlib only).

The toolkit is dependency-free (it also runs compiled to WebAssembly in the
browser), so PyYAML is not an option. Beats configuration files use a tame
subset of YAML that this module covers:

* indentation-nested mappings, with dotted keys kept literal ("filebeat.inputs")
* block sequences ("- item"), including sequence items that are mappings
* inline flow sequences (["a", "b"]) of scalars
* scalars: quoted/unquoted strings, ints, floats, booleans, null
* full-line comments and blank lines

Not covered (raises ValueError so callers can fall back to a skip note):
anchors/aliases, multi-document streams, block scalars (| and >), flow
mappings ({a: b}), and tabs for indentation.
"""

from __future__ import annotations

from typing import Any, List, Tuple


def parse(text: str) -> Any:
    lines = _lines(text)
    if not lines:
        return {}
    value, pos = _block(lines, 0, lines[0][0])
    if pos != len(lines):
        raise ValueError(f"could not parse line: {lines[pos][1]!r}")
    return value


def _lines(text: str) -> List[Tuple[int, str]]:
    out: List[Tuple[int, str]] = []
    for raw in text.splitlines():
        if "\t" in raw[:len(raw) - len(raw.lstrip())]:
            raise ValueError("tabs used for indentation")
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith(("---", "...")):
            continue
        out.append((len(raw) - len(raw.lstrip(" ")), stripped))
    return out


def _block(lines, pos: int, indent: int):
    """Parse the block starting at `pos`, whose items sit at exactly `indent`."""
    content = lines[pos][1]
    if content == "-" or content.startswith("- "):
        return _sequence(lines, pos, indent)
    return _mapping(lines, pos, indent)


def _mapping(lines, pos: int, indent: int):
    out = {}
    while pos < len(lines):
        ind, content = lines[pos]
        if ind < indent:
            break
        if ind > indent:
            raise ValueError(f"unexpected indent at: {content!r}")
        key, sep, rest = content.partition(":")
        if not sep or content.startswith("-"):
            raise ValueError(f"expected `key:` at: {content!r}")
        key, rest = key.strip(), rest.strip()
        if _is_comment(rest):
            rest = ""
        pos += 1
        if rest:
            out[_scalar(key)] = _value(rest)
        elif pos < len(lines) and lines[pos][0] > indent:
            out[_scalar(key)], pos = _block(lines, pos, lines[pos][0])
        else:
            out[_scalar(key)] = None
    return out, pos


def _sequence(lines, pos: int, indent: int):
    out = []
    while pos < len(lines):
        ind, content = lines[pos]
        if ind != indent or not (content == "-" or content.startswith("- ")):
            break
        rest = content[1:].strip()
        if _is_comment(rest):
            rest = ""
        pos += 1
        if not rest:  # nested block belongs to this item
            if pos < len(lines) and lines[pos][0] > indent:
                item, pos = _block(lines, pos, lines[pos][0])
                out.append(item)
            else:
                out.append(None)
        elif ":" in rest and not rest.startswith(("[", "'", '"')) \
                and _looks_like_key(rest):
            # "- key: value" starts an inline mapping; its siblings are the
            # following lines indented past the dash
            item_indent = indent + (len(content) - len(content[1:].lstrip()) - 1) + 1
            sub = [(item_indent, rest)]
            while pos < len(lines) and lines[pos][0] >= item_indent \
                    and not (lines[pos][0] == indent):
                sub.append(lines[pos])
                pos += 1
            item, consumed = _mapping(sub, 0, item_indent)
            if consumed != len(sub):
                raise ValueError(f"could not parse list item near: {rest!r}")
            out.append(item)
        else:
            out.append(_value(rest))
    return out, pos


def _looks_like_key(rest: str) -> bool:
    head = rest.split(":", 1)[0]
    return bool(head) and " " not in head.strip() and not head.startswith("http")


def _is_comment(s: str) -> bool:
    return s.startswith("#")


def _value(raw: str) -> Any:
    raw = raw.strip()
    if raw.startswith("[") and raw.endswith("]"):
        inner = raw[1:-1].strip()
        if not inner:
            return []
        return [_scalar(part.strip()) for part in _split_flow(inner)]
    return _scalar(raw)


def _split_flow(inner: str) -> List[str]:
    parts, buf, quote = [], "", ""
    for ch in inner:
        if quote:
            buf += ch
            if ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
            buf += ch
        elif ch == ",":
            parts.append(buf)
            buf = ""
        else:
            buf += ch
    if buf.strip():
        parts.append(buf)
    return parts


def _scalar(raw: str) -> Any:
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "'\"":
        return raw[1:-1]
    low = raw.lower()
    if low in ("true", "yes", "on"):
        return True
    if low in ("false", "no", "off"):
        return False
    if low in ("null", "~", ""):
        return None
    try:
        return int(raw)
    except ValueError:
        pass
    try:
        return float(raw)
    except ValueError:
        pass
    # strip a trailing comment on unquoted scalars ("5044  # port")
    if " #" in raw:
        return raw.split(" #", 1)[0].rstrip()
    return raw
