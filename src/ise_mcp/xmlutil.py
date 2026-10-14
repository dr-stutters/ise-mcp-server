"""MnT speaks XML. Parse it safely (defusedxml) into plain dicts the formatting helpers understand."""

from __future__ import annotations

import re
from typing import Any
from xml.etree.ElementTree import Element

from defusedxml import ElementTree

_NS_RE = re.compile(r"^\{[^}]*\}")


def _tag(el: Element) -> str:
    return _NS_RE.sub("", el.tag)


def element_to_dict(el: Element) -> Any:
    """Attributes and child elements become keys; repeated child tags become lists; a leaf element
    becomes its text (or None when empty). Use `as_list` where a tag may appear once or many times."""
    children = list(el)
    # Namespaced attributes (xsi:type and friends) are schema noise, not data.
    attrib = {k: v for k, v in el.attrib.items() if not k.startswith("{")}
    if not children and not attrib:
        text = (el.text or "").strip()
        return text or None
    out: dict[str, Any] = dict(attrib)
    counts: dict[str, int] = {}
    for child in children:
        counts[_tag(child)] = counts.get(_tag(child), 0) + 1
    for child in children:
        key = _tag(child)
        value = element_to_dict(child)
        if key in attrib:
            key = f"{key}_element"
        if counts[_tag(child)] > 1:
            out.setdefault(key, []).append(value)
        else:
            out[key] = value
    text = (el.text or "").strip()
    if text and not children:
        out["value"] = text
    return out


def parse_xml(text: str) -> tuple[str, Any]:
    """(root tag, root as dict). Raises ValueError on malformed or unsafe XML."""
    try:
        root = ElementTree.fromstring(text)
        return _tag(root), element_to_dict(root)
    except Exception as e:  # defusedxml raises its own types for entities/DTDs; RecursionError too
        raise ValueError(f"Could not parse XML: {e}") from e


def as_list(v: Any) -> list[Any]:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def mnt_error_detail(body: Any) -> str | None:
    """Readable message from an MnT `<mnt-rest-result>` error body."""
    if not isinstance(body, str) or "<" not in body:
        return body.strip()[:500] if isinstance(body, str) and body.strip() else None
    try:
        _, data = parse_xml(body)
    except ValueError:
        return body.strip()[:500]
    if isinstance(data, dict):
        parts = [data.get("description"), data.get("internal-error-info")]
        msg = " - ".join(str(p) for p in parts if p)
        return msg[:500] or None
    return None
