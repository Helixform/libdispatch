#!/usr/bin/env -S uv run --quiet
# /// script
# requires-python = ">=3.10"
# ///
"""Convert Stash/Clash-style YAML rule providers into Surge-compatible
``.list`` files.

Sources are read from ``xcodeconfig/`` and written to
``xcodeconfig/generated/``.

Filename convention (used to detect inputs and select the output format)::

    libdispatch.<category>.<behavior>.yaml
        behavior in {domain, classical, ipcidr}

Surge consumer-side syntax::

    domain     ->  DOMAIN-SET, <url>, <policy>
    classical  ->  RULE-SET,   <url>, <policy>
    ipcidr     ->  RULE-SET,   <url>, <policy>, no-resolve

Usage::

    uv run xcodescripts/build-list-rules.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "xcodeconfig"
OUT_DIR = SRC_DIR / "generated"

ITEM_RE = re.compile(r"^\s*-\s+(.+?)\s*$")


def parse_payload(path: Path) -> list[str]:
    r"""Parse a ``payload:`` list of strings using a line-based scanner.

    Recognised forms::

        payload:
          - "value"
          - 'value'
          - bare-value

    PyYAML is intentionally avoided: existing sources contain backslash
    sequences like ``\w`` that are invalid in YAML double-quoted scalars
    but accepted by Stash's lenient parser. A line-based scanner passes
    them through verbatim.
    """
    items: list[str] = []
    saw_header = False
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s == "payload:":
            saw_header = True
            continue
        m = ITEM_RE.match(line)
        if not m:
            continue
        v = m.group(1).strip()
        if v.startswith('"'):
            end = v.find('"', 1)
            if end < 0:
                raise ValueError(
                    f"{path.name}:{lineno} unterminated double-quoted string: {line!r}"
                )
            v = v[1:end]
        elif v.startswith("'"):
            end = v.find("'", 1)
            if end < 0:
                raise ValueError(
                    f"{path.name}:{lineno} unterminated single-quoted string: {line!r}"
                )
            v = v[1:end]
        else:
            v = v.split("#", 1)[0].strip()
        if v:
            items.append(v)
    if not saw_header:
        raise ValueError(f"{path.name}: missing 'payload:' header")
    return items


def to_domain_set(items: list[str]) -> list[str]:
    """Map Stash/Clash subdomain syntax ``+.X`` to Surge DOMAIN-SET ``.X``;
    leave exact matches ``X`` unchanged."""
    return [("." + v[2:]) if v.startswith("+.") else v for v in items]


def to_classical(items: list[str]) -> list[str]:
    """Payload entries are already complete Surge rules; just drop the wrapper."""
    return list(items)


def to_ipcidr(items: list[str]) -> list[str]:
    """Prefix bare CIDRs with ``IP-CIDR`` or ``IP-CIDR6`` based on the
    presence of a colon (IPv6 marker)."""
    return [f"{'IP-CIDR6' if ':' in v else 'IP-CIDR'},{v}" for v in items]


CONVERTERS = {
    "domain":    to_domain_set,
    "classical": to_classical,
    "ipcidr":    to_ipcidr,
}


def behavior_of(name: str) -> str | None:
    """Extract the behavior tag from a filename matching
    ``libdispatch.<category>.<behavior>.yaml``; return None otherwise."""
    parts = name.split(".")
    if len(parts) >= 4 and parts[-1] == "yaml" and parts[-2] in CONVERTERS:
        return parts[-2]
    return None


def main() -> int:
    if not SRC_DIR.is_dir():
        print(f"source directory not found: {SRC_DIR}", file=sys.stderr)
        return 1
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    rows: list[tuple[str, Path, str, int]] = []
    skipped: list[str] = []
    for src in sorted(SRC_DIR.glob("*.yaml")):
        beh = behavior_of(src.name)
        if beh is None:
            skipped.append(src.name)
            continue
        try:
            items = parse_payload(src)
        except ValueError as e:
            print(f"[error] {e}", file=sys.stderr)
            return 2
        lines = CONVERTERS[beh](items)
        dst = OUT_DIR / (src.stem + ".list")
        header = (
            f"# Generated from {src.name} by {Path(__file__).name}\n"
            f"# DO NOT EDIT - modify the .yaml source instead.\n\n"
        )
        dst.write_text(header + "\n".join(lines) + "\n", encoding="utf-8")
        rows.append((src.name, dst.relative_to(PROJECT_ROOT), beh, len(lines)))

    if not rows:
        print(
            f"no rule YAML files matching the naming convention were found in {SRC_DIR}",
            file=sys.stderr,
        )
        return 1

    width = max(len(r[0]) for r in rows)
    print(f"output directory: {OUT_DIR.relative_to(PROJECT_ROOT)}/")
    for src_name, dst_rel, beh, n in rows:
        print(f"  {src_name:<{width}}  ->  {dst_rel}  ({beh}, {n} entries)")
    if skipped:
        print(
            f"\nskipped {len(skipped)} non-rule YAML file(s): {', '.join(skipped)}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
