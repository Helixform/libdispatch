#!/usr/bin/env -S uv run --quiet
# /// script
# requires-python = ">=3.10"
# ///
"""Compile unified qrule `.qset` files into Stash/Clash, Surge, sing-box, and
qrule / Boost rule configurations.

Single source of truth::

    xcodeconfig/set/<group>.qset

Generated outputs (all placed uniformly in ``xcodeconfig/generated/``)::

    libdispatch.<group>.yaml   ->  Stash / Clash / Mihomo classical rule-provider
    libdispatch.<group>.list   ->  Surge RULE-SET
    libdispatch.<group>.srs    ->  sing-box compiled binary rule-set (version 4)
    libdispatch.qr             ->  qrule custom ruleset configuration for Boost
    libdispatch.boostrules     ->  Boost portable rules bundle (custom.qr + labelMap + remoteSets)

Usage::

    uv run xcodescripts/build-list-rules.py
    uv run xcodescripts/build-list-rules.py --emit-json
    uv run xcodescripts/build-list-rules.py --skip-srs
"""
from __future__ import annotations

import argparse
import dataclasses
import ipaddress
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SET_DIR = PROJECT_ROOT / "xcodeconfig" / "set"
OUT_DIR = PROJECT_ROOT / "xcodeconfig" / "generated"
SING_BOX_RULE_SET_VERSION = 4
BOOST_RULES_BUNDLE_VERSION = 1
DEFAULT_QSET_BASE_URL = "https://cdn.jsdelivr.net/gh/Helixform/libdispatch@dev/xcodeconfig/set"

# Priority order for `.qset` rule groups in `libdispatch.qr`:
#   1. `ai` is placed as far forward as possible so AI endpoints override Microsoft / Global suffixes.
#   2. `apns` MUST precede `apple` because `apple.qset` (`+.apple.com`, `17.0.0.0/8`, IPv6 `/32`s)
#      subsumes APNs domains and subnets.
#   3. Specific service groups precede broad `global` and `direct` (`+.cn`) fallback sets.
QRULE_HEAD_GROUPS: tuple[str, ...] = (
    "ai",
    "apns",
    "apple",
    "microsoft",
    "streaming",
    "social",
)
QRULE_TAIL_GROUPS: tuple[str, ...] = (
    "global",
    "direct",
)
# `.qset` module labels routed `direct` by default; all other `.qset` labels route via proxy (`group:1`).
QRULE_DIRECT_GROUPS: frozenset[str] = frozenset({"direct", "apple", "microsoft"})

DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9_-]+$")
YAML_PLAIN_SAFE_RE = re.compile(r"^[A-Za-z0-9_,./:+-]+$")
# Matches anchored regexes of the form `^<prefix>[\w.-]+<suffix>$` (with escaped dots)
WILDCARD_REGEX_RE = re.compile(
    r"^\^([a-z0-9_-]*)(?:\[\\w\.-\]\+|\.\*)(\\[.][a-z0-9_\\.-]+)\$$",
    re.IGNORECASE,
)


@dataclasses.dataclass
class MixedSet:
    name: str
    full: list[str] = dataclasses.field(default_factory=list)
    suffix: list[str] = dataclasses.field(default_factory=list)
    sub: list[str] = dataclasses.field(default_factory=list)
    keyword: list[str] = dataclasses.field(default_factory=list)
    regex: list[str] = dataclasses.field(default_factory=list)
    cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = dataclasses.field(default_factory=list)
    ports: list[tuple[int, int]] = dataclasses.field(default_factory=list)
    apps: list[str] = dataclasses.field(default_factory=list)

    def total_entries(self) -> int:
        return (
            len(self.full)
            + len(self.suffix)
            + len(self.sub)
            + len(self.keyword)
            + len(self.regex)
            + len(self.cidrs)
            + len(self.ports)
            + len(self.apps)
        )

    def has_domains(self) -> bool:
        return bool(self.full or self.suffix or self.sub or self.keyword or self.regex)


def normalize_domain(raw: str, ctx: str) -> str:
    s = raw.strip().removesuffix(".")
    if not s:
        raise ValueError(f"{ctx}: empty domain name")
    if not s.isascii():
        raise ValueError(f"{ctx}: non-ASCII domain {raw!r} (use punycode)")
    if len(s) > 253:
        raise ValueError(f"{ctx}: domain {raw!r} exceeds 253 bytes")
    lower = s.lower()
    for label in lower.split("."):
        if not label or not DOMAIN_LABEL_RE.match(label):
            raise ValueError(f"{ctx}: invalid domain label {label!r} in {raw!r}")
    return lower


def parse_port_range(raw: str, ctx: str) -> tuple[int, int]:
    if "-" in raw:
        lo_s, hi_s = raw.split("-", 1)
        lo, hi = int(lo_s), int(hi_s)
    else:
        lo = hi = int(raw)
    if not (0 <= lo <= hi <= 65535):
        raise ValueError(f"{ctx}: invalid port range {raw!r}")
    return lo, hi


def is_ip_token(token: str) -> bool:
    if "/" in token or ":" in token:
        return True
    try:
        ipaddress.IPv4Address(token)
        return True
    except ValueError:
        return False


def parse_qset(path: Path) -> MixedSet:
    group = path.stem
    ms = MixedSet(name=group)

    for lineno, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        ctx = f"{path.name}:{lineno}"
        parts = line.split(None, 1)
        if len(parts) == 2:
            head, rest = parts[0], parts[1].strip()
            if head in {"full", "suffix", "sub"}:
                if any(ch.isspace() for ch in rest):
                    raise ValueError(f"{ctx}: unexpected whitespace in {line!r}")
                d = normalize_domain(rest.removeprefix("+.").removeprefix("."), ctx)
                getattr(ms, head).append(d)
            elif head == "keyword":
                if not rest or not rest.isascii() or any(ch.isspace() for ch in rest):
                    raise ValueError(f"{ctx}: invalid keyword {rest!r}")
                ms.keyword.append(rest.lower())
            elif head == "regex":
                try:
                    re.compile(rest)
                except re.error as exc:
                    raise ValueError(f"{ctx}: invalid regex {rest!r}: {exc}") from exc
                ms.regex.append(rest)
            elif head == "cidr":
                try:
                    ms.cidrs.append(ipaddress.ip_network(rest, strict=False))
                except ValueError as exc:
                    raise ValueError(f"{ctx}: invalid CIDR {rest!r}: {exc}") from exc
            elif head == "port":
                ms.ports.append(parse_port_range(rest, ctx))
            elif head in {"app", "string"}:
                if not rest:
                    raise ValueError(f"{ctx}: empty {head} entry")
                ms.apps.append(rest)
            else:
                raise ValueError(
                    f"{ctx}: unknown entry kind {head!r} "
                    "(expected full, suffix, sub, keyword, regex, cidr, port, app, or string)"
                )
        else:
            tok = parts[0]
            if is_ip_token(tok):
                try:
                    ms.cidrs.append(ipaddress.ip_network(tok, strict=False))
                except ValueError as exc:
                    raise ValueError(f"{ctx}: invalid IP/CIDR {tok!r}: {exc}") from exc
            elif tok.startswith("*."):
                ms.sub.append(normalize_domain(tok[2:], ctx))
            elif tok.startswith("+."):
                ms.suffix.append(normalize_domain(tok[2:], ctx))
            elif tok.startswith("."):
                ms.suffix.append(normalize_domain(tok[1:], ctx))
            else:
                ms.suffix.append(normalize_domain(tok, ctx))

    # Canonicalize & deduplicate preserving deterministic order
    ms.suffix = sorted(set(ms.suffix))
    ms.full = sorted(set(ms.full))
    ms.sub = sorted(set(ms.sub))
    ms.keyword = sorted(set(ms.keyword))
    ms.regex = list(dict.fromkeys(ms.regex))
    v4 = sorted({c for c in ms.cidrs if isinstance(c, ipaddress.IPv4Network)}, key=lambda n: (int(n.network_address), n.prefixlen))
    v6 = sorted({c for c in ms.cidrs if isinstance(c, ipaddress.IPv6Network)}, key=lambda n: (int(n.network_address), n.prefixlen))
    ms.cidrs = [*v4, *v6]
    ms.ports = sorted(set(ms.ports))
    ms.apps = sorted(set(ms.apps))
    return ms


def format_yaml_scalar(value: str) -> str:
    if YAML_PLAIN_SAFE_RE.match(value):
        return value
    escaped = value.replace("'", "''")
    return f"'{escaped}'"


def to_clash_yaml(ms: MixedSet, src_name: str) -> str:
    rules: list[str] = []
    for d in ms.suffix:
        rules.append(f"DOMAIN-SUFFIX,{d}")
    for d in ms.full:
        rules.append(f"DOMAIN,{d}")
    for d in ms.sub:
        escaped = d.replace(".", r"\.")
        rules.append(f"DOMAIN-REGEX,^.+\\.{escaped}$")
    for k in ms.keyword:
        rules.append(f"DOMAIN-KEYWORD,{k}")
    for r in ms.regex:
        rules.append(f"DOMAIN-REGEX,{r}")
    for lo, hi in ms.ports:
        rules.append(f"DST-PORT,{lo}" if lo == hi else f"DST-PORT,{lo}-{hi}")
    for net in ms.cidrs:
        tag = "IP-CIDR6" if net.version == 6 else "IP-CIDR"
        rules.append(f"{tag},{net},no-resolve")
    for app in ms.apps:
        rules.append(f"PROCESS-NAME,{app}")

    lines = [
        f"# Generated from set/{src_name} by {Path(__file__).name}",
        "# DO NOT EDIT - modify xcodeconfig/set/" + src_name + " instead.",
        "",
        "payload:",
    ]
    for r in rules:
        lines.append(f"  - {format_yaml_scalar(r)}")
    lines.append("")
    return "\n".join(lines)


def regex_to_surge_rule(pattern: str) -> str:
    m = WILDCARD_REGEX_RE.match(pattern)
    if m:
        prefix = m.group(1)
        suffix = m.group(2).replace(r"\.", ".")
        return f"DOMAIN-WILDCARD,{prefix}*{suffix}"
    # Fallback to host-anchored URL-REGEX when DOMAIN-WILDCARD cannot express it
    body = pattern.removeprefix("^").removesuffix("$")
    return f"URL-REGEX,^https?://{body}"


def to_surge_list(ms: MixedSet, src_name: str) -> tuple[str, int]:
    rules: list[str] = []
    for d in ms.suffix:
        rules.append(f"DOMAIN-SUFFIX,{d}")
    for d in ms.full:
        rules.append(f"DOMAIN,{d}")
    for d in ms.sub:
        rules.append(f"DOMAIN-WILDCARD,*.{d}")
    for k in ms.keyword:
        rules.append(f"DOMAIN-KEYWORD,{k}")
    for r in ms.regex:
        rules.append(regex_to_surge_rule(r))
    for lo, hi in ms.ports:
        if lo == hi:
            rules.append(f"DEST-PORT,{lo}")
        else:
            rules.append(f"PORT-RANGE,{lo}-{hi}")
    for net in ms.cidrs:
        tag = "IP-CIDR6" if net.version == 6 else "IP-CIDR"
        rules.append(f"{tag},{net},no-resolve")
    for app in ms.apps:
        rules.append(f"PROCESS-NAME,{app}")

    header = (
        f"# Generated from set/{src_name} by {Path(__file__).name}\n"
        f"# DO NOT EDIT - modify xcodeconfig/set/{src_name} instead.\n\n"
    )
    return header + "\n".join(rules) + "\n", len(rules)


def to_sing_box_rules(ms: MixedSet) -> list[dict[str, list[str] | list[int]]]:
    rules: list[dict[str, list[str] | list[int]]] = []

    domain_rule: dict[str, list[str]] = {}
    if ms.full:
        domain_rule["domain"] = list(ms.full)
    if ms.suffix:
        domain_rule["domain_suffix"] = list(ms.suffix)
    if ms.keyword:
        domain_rule["domain_keyword"] = list(ms.keyword)
    escaped_dot = r"\."
    regexes = [f"^.+\\.{d.replace('.', escaped_dot)}$" for d in ms.sub] + list(ms.regex)
    if regexes:
        domain_rule["domain_regex"] = regexes
    if domain_rule:
        rules.append(domain_rule)

    if ms.ports:
        port_rule: dict[str, list[int] | list[str]] = {}
        singles = [lo for lo, hi in ms.ports if lo == hi]
        ranges = [f"{lo}:{hi}" for lo, hi in ms.ports if lo != hi]
        if singles:
            port_rule["port"] = singles
        if ranges:
            port_rule["port_range"] = ranges
        rules.append(port_rule)

    if ms.cidrs:
        rules.append({"ip_cidr": [str(n) for n in ms.cidrs]})

    if ms.apps:
        rules.append({"process_name": list(ms.apps)})

    return rules


def order_qrule_sets(
    parsed_sets: list[tuple[Path, MixedSet]],
) -> list[tuple[Path, MixedSet]]:
    by_name = {ms.name: (src, ms) for src, ms in parsed_sets}
    known = set(QRULE_HEAD_GROUPS) | set(QRULE_TAIL_GROUPS)
    middle = sorted(name for name in by_name if name not in known)

    ordered: list[tuple[Path, MixedSet]] = []
    for name in (*QRULE_HEAD_GROUPS, *middle, *QRULE_TAIL_GROUPS):
        item = by_name.get(name)
        if item is not None:
            ordered.append(item)
    return ordered


def qrule_target_for_group(group: str) -> str:
    return "direct" if group in QRULE_DIRECT_GROUPS else "group:1"


def to_qrule_source(ordered_sets: list[tuple[Path, MixedSet]]) -> str:
    script_name = Path(__file__).name
    groups = [ms for _, ms in ordered_sets]
    group_names = {ms.name for ms in groups}
    name_width = max((len(ms.name) for ms in groups), default=0)

    direct_labels = [ms.name for ms in groups if ms.name in QRULE_DIRECT_GROUPS]
    proxy_labels = [ms.name for ms in groups if ms.name not in QRULE_DIRECT_GROUPS]

    lines: list[str] = [
        f"# Generated from set/*.qset by {script_name}",
        "# DO NOT EDIT - modify xcodeconfig/set/*.qset instead.",
        "#",
        "# Module Routing Policy (Label Map defaults in libdispatch.boostrules):",
        f"#   - Direct: {', '.join(f'@{n}' for n in direct_labels)}",
        f"#   - Proxy:  {', '.join(f'@{n}' for n in proxy_labels)}, @proxy",
        "#   - Priority: @ai is evaluated first; @apns is evaluated before @apple",
        "#     (both domain and CIDR) so Apple's broad +.apple.com / 17.0.0.0/8",
        "#     entries do not swallow APNs push traffic.",
        "#",
        "# GeoIP (Boost Built-in Traffic Splitting):",
        "#   Mainland China GeoIP splitting is a built-in Boost capability enabled",
        "#   by default (`RulesConfig.geoIPEnabled`) and independent of `.qr` files.",
        "#   When enabled, Boost inserts GeoIP `cn` matching immediately before the",
        "#   user-defined fallback (`_ => @proxy`): if no explicit rule matches, it",
        "#   first checks `sets/geoip-cn.qset` (lazily resolving Fake-IP domains on",
        "#   the physical interface) and routes mainland China traffic as `@cn.ip`",
        "#   (`direct` unless remapped); `_ => @proxy` is only used when GeoIP also",
        "#   fails to match. Optional `geoip.cn` and `@cn` keywords remain available",
        "#   for custom routing if explicit GeoIP rule placement is ever needed.",
        "",
        'ruleset "libdispatch" version "1"',
        "",
        "runtime set always-reject : domain",
        "runtime set always-direct : domain",
        "",
        'set local-names : domain = [suffix "local", suffix "lan", suffix "home.arpa", suffix "localhost"]',
        "set private-ptr : domain = [",
        '    suffix "10.in-addr.arpa", suffix "168.192.in-addr.arpa", suffix "254.169.in-addr.arpa",',
        '    suffix "16.172.in-addr.arpa", suffix "17.172.in-addr.arpa", suffix "18.172.in-addr.arpa",',
        '    suffix "19.172.in-addr.arpa", suffix "20.172.in-addr.arpa", suffix "21.172.in-addr.arpa",',
        '    suffix "22.172.in-addr.arpa", suffix "23.172.in-addr.arpa", suffix "24.172.in-addr.arpa",',
        '    suffix "25.172.in-addr.arpa", suffix "26.172.in-addr.arpa", suffix "27.172.in-addr.arpa",',
        '    suffix "28.172.in-addr.arpa", suffix "29.172.in-addr.arpa", suffix "30.172.in-addr.arpa",',
        '    suffix "31.172.in-addr.arpa"',
        "]",
        "set lan : cidr = [",
        "    10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16,",
        "    100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16,",
        "    ::1/128, fc00::/7, fe80::/10",
        "]",
        "",
    ]

    for src, ms in ordered_sets:
        lines.append(f'set {ms.name:<{name_width}} = data "sets/{src.name}"')

    lines.extend(
        [
            "",
            "resolver system     = system",
            'resolver cloudflare = doh "https://1.1.1.1/dns-query" via @proxy',
            "",
            "# 198.19.0.0/16 keeps clear of Boost's tunnel infrastructure range 198.18.0.0/24.",
            "pool fake = fakeip 198.19.0.0/16 ttl=5",
            "",
            "dns {",
            "  table main {",
            '    qname == "use-application-dns.net"               => block nxdomain',
            "    qname in always-reject                           => block nxdomain",
            "    qname in always-direct                           => label @direct, forward system",
            "    qname in local-names or qname in private-ptr     => label @direct, forward system",
            "    qtype == AAAA or qtype == HTTPS or qtype == SVCB => block empty",
            "    qtype == A                                       => fakeip fake",
            "    _                                                => forward cloudflare",
            "  }",
            "}",
            "",
            "route {",
            "  table main {",
            "    domain in always-reject => @reject",
            "    domain in always-direct => @direct",
            "    dns.label exists        => dns.label",
            "    dst.ip in lan           => @direct",
        ]
    )

    app_groups = [ms for ms in groups if ms.apps]
    if app_groups:
        w = max(len(ms.name) for ms in app_groups)
        lines.append("")
        lines.append("    # Applications")
        for ms in app_groups:
            lines.append(f"    app in {ms.name:<{w}} => @{ms.name}")

    domain_groups = [ms for ms in groups if ms.has_domains()]
    if domain_groups:
        w = max(len(ms.name) for ms in domain_groups)
        lines.append("")
        lines.append("    # Domains (AI first; APNs before Apple)")
        for ms in domain_groups:
            lines.append(f"    domain in {ms.name:<{w}} => @{ms.name}")

    port_groups = [ms for ms in groups if ms.ports]
    if port_groups:
        w = max(len(ms.name) for ms in port_groups)
        lines.append("")
        lines.append("    # Destination Ports")
        for ms in port_groups:
            lines.append(f"    dst.port in {ms.name:<{w}} => @{ms.name}")

    cidr_groups = [ms for ms in groups if ms.cidrs]
    if cidr_groups:
        w = max(len(ms.name) for ms in cidr_groups)
        lines.append("")
        lines.append("    # Destination IP CIDRs (APNs before Apple)")
        for ms in cidr_groups:
            lines.append(f"    dst.ip in {ms.name:<{w}} => @{ms.name}")

    lines.extend(
        [
            "",
            "    # Catch-all (Boost's built-in GeoIP splits mainland China traffic before @proxy)",
            "    _ => @proxy",
            "  }",
            "}",
            "",
            "test {",
            '  route "ad.example:443/tcp" with always-reject = ["ad.example"]     => @reject',
            '  route "corp.example:443/tcp" with always-direct = ["corp.example"] => @direct',
            '  route "x.example:443/tcp" with dns.label = @direct                 => @direct',
            '  route "192.168.1.1:443/tcp"                                        => @direct',
        ]
    )

    if "ai" in group_names:
        lines.extend(
            [
                '  route "api.openai.com:443/tcp"                                     => @ai',
                '  route "claude.ai:443/tcp"                                          => @ai',
                '  route "copilot.microsoft.com:443/tcp"                              => @ai',
                '  route "sydney.bing.com:443/tcp"                                    => @ai',
            ]
        )
    if "apns" in group_names:
        lines.extend(
            [
                '  route "1-courier.push.apple.com:5223/tcp"                          => @apns',
                '  route "1.push-apple.com.akadns.net:5223/tcp"                       => @apns',
                '  route "1.courier-push-apple.com.akadns.net:5223/tcp"               => @apns',
                '  route "17.57.144.1:5223/tcp"                                       => @apns',
                '  route "[2403:300:a42::1]:5223/tcp"                                 => @apns',
            ]
        )
    if "apple" in group_names:
        lines.extend(
            [
                '  route "www.apple.com:443/tcp"                                      => @apple',
                '  route "bag-cdn.itunes-apple.com.akadns.net:443/tcp"                => @apple',
                '  route "amp-api-edge-lb.itunes-apple.com.akadns.net:443/tcp"        => @apple',
                '  route "amp-api-search-edge.apps-lb.itunes-apple.com.akadns.net:443/tcp" => @apple',
                '  route "is-ssl.mzstatic.com.itunes-apple.com.akadns.net:443/tcp"    => @apple',
                '  route "entitlements.edge-itunes-apple.com.akadns.net:443/tcp"      => @apple',
                '  route "gs-loc-apple.com.akadns.net:443/tcp"                        => @apple',
                '  route "updates-http.cdn-apple.com.akadns.net:443/tcp"              => @apple',
                '  route "17.253.144.10:443/tcp"                                      => @apple',
            ]
        )
    if "microsoft" in group_names:
        lines.extend(
            [
                '  route "www.microsoft.com:443/tcp"                                  => @microsoft',
                '  route "1.2.3.4:443/tcp" with app = "OneDrive"                      => @microsoft',
            ]
        )
    if "streaming" in group_names:
        lines.extend(
            [
                '  route "www.youtube.com:443/tcp"                                    => @streaming',
                '  route "intl.iqiyi.com:443/tcp"                                     => @streaming',
            ]
        )
    if "social" in group_names:
        lines.extend(
            [
                '  route "web.telegram.org:443/tcp"                                   => @social',
                '  route "91.108.4.1:443/tcp"                                         => @social',
            ]
        )
    if "global" in group_names:
        lines.append('  route "www.google.com:443/tcp"                                     => @global')
    if "direct" in group_names:
        lines.append('  route "www.baidu.com:443/tcp"                                      => @direct')

    label_test_entries = ['"*" => proxied']
    for name in sorted(direct_labels):
        label_test_entries.append(f'"{name}" => direct')
    if "direct" not in direct_labels:
        label_test_entries.append('"direct" => direct')
    label_test_entries.append('"reject" => reject')

    lines.extend(
        [
            '  route "unmatched.example:443/tcp"                                  => @proxy',
            '  route "8.8.8.8:443/tcp"                                            => @proxy',
            "",
            f"  labels {{ {', '.join(label_test_entries)} }}",
            '  dns "api.openai.com A"          => fakeip',
            '  dns "www.baidu.com A"           => fakeip',
            '  dns "api.openai.com AAAA"       => block empty',
            '  dns "api.openai.com HTTPS"      => block empty',
            '  dns "use-application-dns.net A" => block nxdomain',
            '  dns "ad.example A" with always-reject = ["ad.example"] => block nxdomain',
            '  dns "printer.local A" with answer system = [192.168.1.9] => accept system, label @direct',
            '  dns "corp.example A" with always-direct = ["corp.example"], answer system = [10.0.0.5] => accept system, label @direct',
            '  dns "example.com MX" with answer cloudflare = [] => accept cloudflare',
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def to_boost_rules_bundle(
    ordered_sets: list[tuple[Path, MixedSet]],
    qrule_source: str,
    qset_base_url: str,
) -> dict[str, object]:
    base = qset_base_url.rstrip("/")
    label_map: list[dict[str, str]] = [{"prefix": "*", "target": "group:1"}]
    seen_prefixes = {"*"}
    for _, ms in ordered_sets:
        label_map.append({"prefix": ms.name, "target": qrule_target_for_group(ms.name)})
        seen_prefixes.add(ms.name)
    for builtin_prefix, target in (("direct", "direct"), ("proxy", "group:1"), ("reject", "reject")):
        if builtin_prefix not in seen_prefixes:
            label_map.append({"prefix": builtin_prefix, "target": target})
            seen_prefixes.add(builtin_prefix)

    remote_sets = [
        {
            "interval": 24,
            "name": src.name,
            "url": f"{base}/{src.name}",
        }
        for src, _ in sorted(ordered_sets, key=lambda item: item[0].name)
    ]

    return {
        "config": {
            "geoIPEnabled": True,
            "labelMap": label_map,
            "runtimeSets": {},
            "source": "custom",
            "vars": {},
            "version": 1,
        },
        "customSource": qrule_source,
        "kind": "boost-rules",
        "localSets": [],
        "remoteSets": remote_sets,
        "version": BOOST_RULES_BUNDLE_VERSION,
    }


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


def compile_srs(sing_box: str, source_json: Path, destination: Path) -> None:
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
            str(source_json),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        temporary.unlink(missing_ok=True)
        detail = result.stderr.strip() or result.stdout.strip() or "unknown error"
        raise RuntimeError(f"failed to compile {source_json.name}: {detail}")
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
        "--emit-json",
        action="store_true",
        help="also keep intermediate sing-box .json source files in generated/",
    )
    parser.add_argument(
        "--skip-srs",
        action="store_true",
        help="skip compiling sing-box .srs binary files",
    )
    parser.add_argument(
        "--qset-base-url",
        default=DEFAULT_QSET_BASE_URL,
        metavar="URL",
        help="base URL for remote .qset definitions in libdispatch.boostrules (default: %(default)s)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not SET_DIR.is_dir():
        print(f"qset directory not found: {SET_DIR}", file=sys.stderr)
        return 1
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    sing_box: str | None = None
    if not args.skip_srs:
        try:
            sing_box = resolve_sing_box(args.sing_box)
        except ValueError as exc:
            print(f"[error] {exc}", file=sys.stderr)
            return 1

    qset_files = sorted(SET_DIR.glob("*.qset"))
    if not qset_files:
        print(f"no .qset files found in {SET_DIR}", file=sys.stderr)
        return 1

    parsed_sets: list[ tuple[Path, MixedSet] ] = []
    for src in qset_files:
        try:
            ms = parse_qset(src)
        except ValueError as exc:
            print(f"[error] {exc}", file=sys.stderr)
            return 2
        if ms.total_entries() == 0:
            print(f"[error] {src.name}: qset is empty", file=sys.stderr)
            return 2
        parsed_sets.append((src, ms))

    # Clean stale generated files before writing fresh outputs
    expected_files: set[Path] = set()
    rows: list[tuple[str, list[str], int, int]] = []

    with tempfile.TemporaryDirectory(prefix="libdispatch-srs-") as tmp_dir_s:
        tmp_dir = Path(tmp_dir_s)
        for src, ms in parsed_sets:
            stem = f"libdispatch.{ms.name}"
            yaml_dst = OUT_DIR / f"{stem}.yaml"
            list_dst = OUT_DIR / f"{stem}.list"
            json_dst = (OUT_DIR / f"{stem}.json") if args.emit_json else (tmp_dir / f"{stem}.json")
            srs_dst = OUT_DIR / f"{stem}.srs"

            yaml_text = to_clash_yaml(ms, src.name)
            list_text, entry_count = to_surge_list(ms, src.name)
            sb_rules = to_sing_box_rules(ms)
            sb_payload = {
                "version": SING_BOX_RULE_SET_VERSION,
                "rules": sb_rules,
            }

            yaml_dst.write_text(yaml_text, encoding="utf-8")
            list_dst.write_text(list_text, encoding="utf-8")
            json_dst.write_text(
                json.dumps(sb_payload, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )

            emitted = [yaml_dst.name, list_dst.name]
            expected_files.update({yaml_dst, list_dst})
            if args.emit_json:
                emitted.append(json_dst.name)
                expected_files.add(json_dst)

            if sing_box:
                try:
                    compile_srs(sing_box, json_dst, srs_dst)
                except RuntimeError as exc:
                    print(f"[error] {exc}", file=sys.stderr)
                    return 3
                emitted.append(srs_dst.name)
                expected_files.add(srs_dst)

            rows.append((src.name, emitted, entry_count, len(sb_rules)))

    ordered_qrule_sets = order_qrule_sets(parsed_sets)
    qr_dst = OUT_DIR / "libdispatch.qr"
    boostrules_dst = OUT_DIR / "libdispatch.boostrules"
    qr_text = to_qrule_source(ordered_qrule_sets)
    boostrules_payload = to_boost_rules_bundle(
        ordered_qrule_sets,
        qr_text,
        args.qset_base_url,
    )
    qr_dst.write_text(qr_text, encoding="utf-8")
    boostrules_dst.write_text(
        json.dumps(boostrules_payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    expected_files.update({qr_dst, boostrules_dst})

    for existing in OUT_DIR.glob("libdispatch.*"):
        if existing not in expected_files:
            existing.unlink()

    width = max(len(r[0]) for r in rows)
    print(f"source directory: {SET_DIR.relative_to(PROJECT_ROOT)}/")
    print(f"output directory: {OUT_DIR.relative_to(PROJECT_ROOT)}/")
    for src_name, emitted, entries, sb_rule_count in rows:
        print(
            f"  {src_name:<{width}}  ->  {', '.join(emitted)}  "
            f"({entries} entries, {sb_rule_count} sing-box rule group(s))"
        )
    print(
        f"  {'*.qset':<{width}}  ->  {qr_dst.name}, {boostrules_dst.name}  "
        f"({len(ordered_qrule_sets)} qrule sets: "
        f"{' > '.join(ms.name for _, ms in ordered_qrule_sets)})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
