#!/usr/bin/env -S uv run --quiet
# /// script
# requires-python = ">=3.10"
# ///
"""Convert Stash/Clash-style YAML rule providers into Surge and sing-box
rule-set files.

Sources are read from ``xcodeconfig/`` and written to
``xcodeconfig/generated/``.

Filename convention (used to detect inputs and select the output format)::

    libdispatch.<category>.<behavior>.yaml
        behavior in {domain, classical, ipcidr}

Surge consumer-side syntax::

    domain     ->  DOMAIN-SET, <url>, <policy>
    classical  ->  RULE-SET,   <url>, <policy>
    ipcidr     ->  RULE-SET,   <url>, <policy>, no-resolve

sing-box outputs::

    .json      ->  source rule-set (format version 4)
    .srs       ->  binary rule-set compiled by the sing-box CLI

Usage::

    uv run xcodescripts/build-list-rules.py
    uv run xcodescripts/build-list-rules.py --skip-srs
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "xcodeconfig"
OUT_DIR = SRC_DIR / "generated"
SING_BOX_RULE_SET_VERSION = 4

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


def to_sing_box_domain(items: list[str]) -> list[dict[str, list[str]]]:
    """Preserve Clash domain-provider semantics.

    Bare domains are exact matches, while ``+.X`` matches ``X`` and its
    subdomains. Exact and suffix matchers are separate rules because fields
    inside one sing-box rule are combined with AND.
    """
    exact: list[str] = []
    suffix: list[str] = []
    for item in items:
        if item.startswith("+."):
            suffix.append(item[2:])
        else:
            exact.append(item)

    rules: list[dict[str, list[str]]] = []
    if exact:
        rules.append({"domain": exact})
    if suffix:
        rules.append({"domain_suffix": suffix})
    return rules


CLASSICAL_FIELDS = {
    "DOMAIN": "domain",
    "DOMAIN-SUFFIX": "domain_suffix",
    "DOMAIN-KEYWORD": "domain_keyword",
    "DOMAIN-REGEX": "domain_regex",
    "IP-CIDR": "ip_cidr",
    "IP-CIDR6": "ip_cidr",
    "SRC-IP-CIDR": "source_ip_cidr",
    "PROCESS-NAME": "process_name",
    "PROCESS-PATH": "process_path",
    "PROCESS-PATH-REGEX": "process_path_regex",
}


def url_regex_to_domain_regex(pattern: str) -> str:
    """Convert a host-only HTTP(S) URL regex to a domain regex.

    sing-box route rules do not inspect full URLs, so regexes that reference a
    path cannot be translated without changing their meaning.
    """
    for prefix in (r"^https?:\/\/", r"^https?://"):
        if pattern.startswith(prefix):
            domain_pattern = pattern[len(prefix):]
            if (
                not domain_pattern
                or "/" in domain_pattern
                or r"\/" in domain_pattern
            ):
                break
            return "^" + domain_pattern
    raise ValueError(
        f"URL-REGEX cannot be represented by a sing-box domain rule: {pattern!r}"
    )


def to_sing_box_classical(items: list[str]) -> list[dict[str, list[str]]]:
    """Convert supported classical rules into OR-equivalent headless rules."""
    grouped: dict[str, list[str]] = {}
    for item in items:
        rule_type, separator, value = item.partition(",")
        if not separator or not value.strip():
            raise ValueError(f"invalid classical rule: {item!r}")

        rule_type = rule_type.strip().upper()
        value = value.strip()
        if rule_type in {"IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR"}:
            parts = [part.strip() for part in value.split(",")]
            value = parts[0]
            options = [part.lower() for part in parts[1:] if part]
            unsupported = [option for option in options if option != "no-resolve"]
            if unsupported:
                raise ValueError(
                    f"unsupported option(s) in classical rule {item!r}: "
                    + ", ".join(unsupported)
                )

        if rule_type == "URL-REGEX":
            field = "domain_regex"
            value = url_regex_to_domain_regex(value)
        else:
            field = CLASSICAL_FIELDS.get(rule_type, "")
            if not field:
                raise ValueError(
                    f"classical rule type is not supported by sing-box conversion: "
                    f"{rule_type!r}"
                )
        grouped.setdefault(field, []).append(value)

    return [{field: values} for field, values in grouped.items()]


def to_sing_box_ipcidr(items: list[str]) -> list[dict[str, list[str]]]:
    """Use the same sing-box field for IPv4 and IPv6 prefixes."""
    return [{"ip_cidr": list(items)}] if items else []


SING_BOX_CONVERTERS = {
    "domain": to_sing_box_domain,
    "classical": to_sing_box_classical,
    "ipcidr": to_sing_box_ipcidr,
}


def behavior_of(name: str) -> str | None:
    """Extract the behavior tag from a filename matching
    ``libdispatch.<category>.<behavior>.yaml``; return None otherwise."""
    parts = name.split(".")
    if len(parts) >= 4 and parts[-1] == "yaml" and parts[-2] in CONVERTERS:
        return parts[-2]
    return None


def resolve_sing_box(command: str) -> str:
    resolved = shutil.which(command)
    if resolved:
        return resolved
    candidate = Path(command).expanduser()
    if candidate.is_file():
        return str(candidate.resolve())
    raise ValueError(
        f"sing-box executable not found: {command!r}; install it, pass "
        "--sing-box PATH, or use --skip-srs"
    )


def compile_srs(sing_box: str, source: Path, destination: Path) -> None:
    temporary = destination.with_name(f".{destination.stem}.tmp.srs")
    temporary.unlink(missing_ok=True)
    result = subprocess.run(
        [
            sing_box,
            "--disable-color",
            "rule-set",
            "compile",
            "--output",
            str(temporary),
            str(source),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        temporary.unlink(missing_ok=True)
        detail = result.stderr.strip() or result.stdout.strip() or "unknown error"
        raise RuntimeError(f"failed to compile {source.name}: {detail}")
    temporary.replace(destination)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--sing-box",
        default="sing-box",
        metavar="PATH",
        help="sing-box executable used to compile .srs files (default: %(default)s)",
    )
    parser.add_argument(
        "--skip-srs",
        action="store_true",
        help="generate Surge .list and sing-box .json files without compiling .srs",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not SRC_DIR.is_dir():
        print(f"source directory not found: {SRC_DIR}", file=sys.stderr)
        return 1
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    sing_box: str | None = None
    if not args.skip_srs:
        try:
            sing_box = resolve_sing_box(args.sing_box)
        except ValueError as e:
            print(f"[error] {e}", file=sys.stderr)
            return 1

    rows: list[tuple[str, Path, Path, Path | None, str, int, int]] = []
    skipped: list[str] = []
    for src in sorted(SRC_DIR.glob("*.yaml")):
        beh = behavior_of(src.name)
        if beh is None:
            skipped.append(src.name)
            continue
        try:
            items = parse_payload(src)
            lines = CONVERTERS[beh](items)
            sing_box_rules = SING_BOX_CONVERTERS[beh](items)
        except ValueError as e:
            print(f"[error] {src.name}: {e}", file=sys.stderr)
            return 2
        list_dst = OUT_DIR / (src.stem + ".list")
        header = (
            f"# Generated from {src.name} by {Path(__file__).name}\n"
            f"# DO NOT EDIT - modify the .yaml source instead.\n\n"
        )
        list_dst.write_text(header + "\n".join(lines) + "\n", encoding="utf-8")

        json_dst = OUT_DIR / (src.stem + ".json")
        source_rule_set = {
            "version": SING_BOX_RULE_SET_VERSION,
            "rules": sing_box_rules,
        }
        json_dst.write_text(
            json.dumps(source_rule_set, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

        srs_dst: Path | None = None
        if sing_box:
            srs_dst = OUT_DIR / (src.stem + ".srs")
            try:
                compile_srs(sing_box, json_dst, srs_dst)
            except RuntimeError as e:
                print(f"[error] {e}", file=sys.stderr)
                return 3

        rows.append(
            (
                src.name,
                list_dst.relative_to(PROJECT_ROOT),
                json_dst.relative_to(PROJECT_ROOT),
                srs_dst.relative_to(PROJECT_ROOT) if srs_dst else None,
                beh,
                len(lines),
                len(sing_box_rules),
            )
        )

    if not rows:
        print(
            f"no rule YAML files matching the naming convention were found in {SRC_DIR}",
            file=sys.stderr,
        )
        return 1

    width = max(len(r[0]) for r in rows)
    print(f"output directory: {OUT_DIR.relative_to(PROJECT_ROOT)}/")
    for src_name, list_rel, json_rel, srs_rel, beh, entries, rules in rows:
        print(
            f"  {src_name:<{width}}  ->  {list_rel}, {json_rel}"
            + (f", {srs_rel}" if srs_rel else "")
            + f"  ({beh}, {entries} entries, {rules} sing-box rules)"
        )
    if skipped:
        print(
            f"\nskipped {len(skipped)} non-rule YAML file(s): {', '.join(skipped)}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
