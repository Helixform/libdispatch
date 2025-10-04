#!/usr/bin/env python3
"""Build an inactive sing-box router configuration from the current service.

The base sing-box configuration remains the source of truth for secret-bearing
proxy inbounds and VLESS outbounds.  This script adds the TUN, DNS, policy
groups, and remote libdispatch rule sets needed to replace Surge's routing
role.  It can also import ``server:https://...`` entries from Surge's ``[Host]``
section without checking private domain names or resolver URLs into Git.

The generated file targets sing-box 1.13.x.  It is deliberately not installed
or activated by this script.

Usage::

    python3 xcodescripts/build-sing-box-router-config.py \
        --base /opt/homebrew/etc/sing-box/config.json \
        --surge-profile "$HOME/Library/Application Support/Surge/Profiles/S-mini.conf" \
        --output /opt/homebrew/etc/sing-box/router-candidate.json
"""
from __future__ import annotations

import argparse
import copy
import ipaddress
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, urlsplit


RULE_BASE_URL = (
    "https://raw.githubusercontent.com/Helixform/libdispatch/"
    "dev/xcodeconfig/generated"
)
GEOIP_CN_URL = (
    "https://raw.githubusercontent.com/SagerNet/sing-geoip/"
    "rule-set/geoip-cn.srs"
)

TUN_ADDRESS = ["172.19.0.1/30", "fdfe:dcba:9876::1/126"]
TUN_DNS_ADDRESS = ["172.19.0.2/32", "fdfe:dcba:9876::2/128"]

OUTBOUND_RENAMES = {
    "dmit-vless-out": "🇺🇸 DMIT",
    "seattle-vless-out": "🇺🇸 Seattle",
    "dmit-vless-out-ipv6": "🇺🇸 DMIT v6",
    "seattle-vless-out-ipv6": "🇺🇸 Seattle v6",
    "direct": "DIRECT",
}

NODE_TAGS = [
    "🇺🇸 DMIT",
    "🇺🇸 Seattle",
    "🇺🇸 DMIT v6",
    "🇺🇸 Seattle v6",
]

POLICY_GROUPS = [
    "AI",
    "APN",
    "Apple",
    "Microsoft",
    "IM",
    "Global",
    "InTheWall",
    "Fallback",
]

# Order matches the active Surge profile.  Separate rule sets stay separate so
# their priority remains visible and reviewable in the generated JSON.
RULE_SET_ROUTES = [
    ("ai-domain", "libdispatch.ai.domain.srs", "AI"),
    ("ai-classical", "libdispatch.ai.classical.srs", "AI"),
    ("im-domain", "libdispatch.im.domain.srs", "IM"),
    ("im-ipcidr", "libdispatch.im.ipcidr.srs", "IM"),
    ("im-classical", "libdispatch.im.classical.srs", "IM"),
    ("apple-domain", "libdispatch.apple.domain.srs", "Apple"),
    ("apple-ipcidr", "libdispatch.apple.ipcidr.srs", "Apple"),
    ("apn-domain", "libdispatch.apn.domain.srs", "APN"),
    ("ms-domain", "libdispatch.ms.domain.srs", "Microsoft"),
    ("ms-classical", "libdispatch.ms.classical.srs", "Microsoft"),
    ("media-domain", "libdispatch.media.domain.srs", "Global"),
    ("media-ipcidr", "libdispatch.media.ipcidr.srs", "Global"),
    ("global-domain", "libdispatch.global.domain.srs", "Global"),
    ("direct-domain", "libdispatch.direct.domain.srs", "InTheWall"),
    ("direct-ipcidr", "libdispatch.direct.ipcidr.srs", "InTheWall"),
    ("direct-classical", "libdispatch.direct.classical.srs", "InTheWall"),
]

# Surge's skip-proxy list bypasses its VIF.  The TUN equivalent still passes
# through sing-box but exits DIRECT before any user policy rule is evaluated.
SKIP_PROXY_CIDRS = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "192.88.99.0/24",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "255.255.255.255/32",
    "::/128",
    "::1/128",
    "2001:db8::/32",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
]

SKIP_PROXY_DOMAINS = [
    "localhost",
    "injections.adguard.org",
    "local.adguard.org",
]


class ConfigError(ValueError):
    """Raised when the source configuration cannot be migrated safely."""


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ConfigError(f"cannot read base configuration: {error}") from error
    if not isinstance(value, dict):
        raise ConfigError("base configuration must be a JSON object")
    return value


def parse_surge_section(path: Path, wanted: str) -> list[tuple[str, str]]:
    """Read key/value entries from one Surge section.

    A standard INI parser cannot be used because Surge's ``[Rule]`` section
    intentionally contains lines without an equals sign.
    """
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except OSError as error:
        raise ConfigError(f"cannot read Surge profile: {error}") from error

    section = ""
    result: list[tuple[str, str]] = []
    for line_number, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            continue
        if section != wanted:
            continue
        key, separator, value = line.partition("=")
        if not separator:
            raise ConfigError(
                f"invalid [{wanted}] entry at line {line_number}: missing '='"
            )
        result.append((key.strip(), value.strip()))
    return result


def surge_host_matcher(host: str) -> dict[str, str]:
    """Translate the wildcard forms accepted by Surge's ``[Host]`` section."""
    normalized = host.rstrip(".").lower()
    if not normalized:
        raise ConfigError("empty hostname in Surge [Host] section")
    if "?" in normalized:
        raise ConfigError(f"unsupported '?' wildcard in Surge [Host]: {host!r}")
    if "*" not in normalized:
        return {"domain": normalized}
    if normalized.startswith("*.") and normalized.count("*") == 1:
        return {"domain_regex": r"^.+\." + re.escape(normalized[2:]) + "$"}
    if normalized.startswith("*") and normalized.count("*") == 1:
        return {"domain_regex": r"^.*" + re.escape(normalized[1:]) + "$"}
    raise ConfigError(f"unsupported wildcard in Surge [Host]: {host!r}")


def parse_doh_url(value: str) -> SplitResult:
    prefix = "server:"
    if not value.startswith(prefix):
        raise ConfigError(
            "only server:https://... Surge [Host] mappings can be migrated"
        )
    target = value[len(prefix) :].strip()
    parsed = urlsplit(target)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ConfigError(
            "only server:https://... Surge [Host] mappings can be migrated"
        )
    if parsed.username or parsed.password or parsed.fragment:
        raise ConfigError(
            "userinfo and fragments are not supported in Surge [Host] DoH URLs"
        )
    return parsed


def doh_server(tag: str, parsed: SplitResult, detour: str) -> dict[str, Any]:
    path = parsed.path or "/dns-query"
    if parsed.query:
        path += "?" + parsed.query
    server: dict[str, Any] = {
        "type": "https",
        "tag": tag,
        "server": parsed.hostname,
        "server_port": parsed.port or 443,
        "path": path,
        "tls": {
            "enabled": True,
            "server_name": parsed.hostname,
        },
        # Surge's encrypted-dns-follow-outbound-mode is mirrored by sending
        # DoH through the manually selected main policy.
        "detour": detour,
    }
    return server


def import_host_dns(
    surge_profile: Path | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return DNS servers and DNS rules imported from Surge [Host]."""
    if surge_profile is None:
        return [], []

    servers: list[dict[str, Any]] = []
    dns_rules: list[dict[str, Any]] = []
    for index, (host, value) in enumerate(
        parse_surge_section(surge_profile, "Host"), 1
    ):
        parsed = parse_doh_url(value)
        matcher = surge_host_matcher(host)
        tag = f"surge-host-doh-{index}"
        servers.append(doh_server(tag, parsed, "节点选择"))
        dns_rules.append({**matcher, "action": "route", "server": tag})
    return servers, dns_rules


def rewrite_outbound_reference(value: Any, key: str = "") -> Any:
    """Update references to the five renamed base outbounds."""
    if isinstance(value, dict):
        return {
            item_key: rewrite_outbound_reference(item_value, item_key)
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        if key == "outbounds":
            return [OUTBOUND_RENAMES.get(item, item) for item in value]
        return [rewrite_outbound_reference(item) for item in value]
    if isinstance(value, str) and key in {
        "detour",
        "outbound",
        "default",
        "download_detour",
    }:
        return OUTBOUND_RENAMES.get(value, value)
    return value


def migrate_base_outbounds(config: dict[str, Any]) -> list[dict[str, Any]]:
    outbounds = config.get("outbounds")
    if not isinstance(outbounds, list):
        raise ConfigError("base configuration has no outbound list")

    migrated = rewrite_outbound_reference(copy.deepcopy(outbounds))
    found: set[str] = set()
    for outbound in migrated:
        if not isinstance(outbound, dict) or not isinstance(outbound.get("tag"), str):
            raise ConfigError("every base outbound must have a string tag")
        old_tag = outbound["tag"]
        new_tag = OUTBOUND_RENAMES.get(old_tag, old_tag)
        outbound["tag"] = new_tag
        found.add(new_tag)

    missing = set(OUTBOUND_RENAMES.values()) - found
    if missing:
        raise ConfigError(
            "base configuration is missing required outbounds: "
            + ", ".join(sorted(missing))
        )
    if len(found) != len(migrated):
        raise ConfigError("base outbound tags must be unique")
    return migrated


def selector_outbounds() -> list[dict[str, Any]]:
    selectors: list[dict[str, Any]] = [
        {
            "type": "selector",
            "tag": "节点选择",
            "outbounds": NODE_TAGS,
            "default": NODE_TAGS[0],
        }
    ]
    for tag in POLICY_GROUPS:
        selectors.append(
            {
                "type": "selector",
                "tag": tag,
                "outbounds": ["节点选择", "DIRECT"],
                "default": "节点选择",
            }
        )
    return selectors


def remote_rule_sets() -> list[dict[str, Any]]:
    result = [
        {
            "type": "remote",
            "tag": tag,
            "format": "binary",
            "url": f"{RULE_BASE_URL}/{filename}",
            "download_detour": "节点选择",
            "update_interval": "1d",
        }
        for tag, filename, _ in RULE_SET_ROUTES
    ]
    result.append(
        {
            "type": "remote",
            "tag": "geoip-cn",
            "format": "binary",
            "url": GEOIP_CN_URL,
            "download_detour": "节点选择",
            "update_interval": "1d",
        }
    )
    return result


def dns_config(
    host_servers: list[dict[str, Any]], host_rules: list[dict[str, Any]]
) -> dict[str, Any]:
    cloudflare = urlsplit("https://cloudflare-dns.com/dns-query")
    google = urlsplit("https://dns.google/dns-query")
    servers: list[dict[str, Any]] = [
        doh_server("doh-cloudflare", cloudflare, "节点选择"),
        # sing-box 1.13 has no upstream resolver race/fallback primitive.  Keep
        # Google's resolver defined as an explicit standby for a quick manual
        # switch while Cloudflare is the primary.
        doh_server("doh-google-standby", google, "节点选择"),
        {
            "type": "udp",
            "tag": "dns-tencent-bootstrap",
            "server": "119.29.29.29",
            "server_port": 53,
            "detour": "DIRECT",
        },
        {
            "type": "udp",
            "tag": "dns-alibaba-bootstrap",
            "server": "223.5.5.5",
            "server_port": 53,
            "detour": "DIRECT",
        },
        {
            "type": "dhcp",
            "tag": "dns-upstream-lan",
            "interface": "en0",
        },
        {
            "type": "local",
            "tag": "dns-system-local",
        },
        {
            "type": "fakeip",
            "tag": "dns-fakeip",
            "inet4_range": "198.18.0.0/15",
            "inet6_range": "fc00::/18",
        },
        *host_servers,
    ]

    rules: list[dict[str, Any]] = [
        *host_rules,
        # .local uses mDNS through macOS's resolver.  Only .local is sent to
        # this server, avoiding a recursion through the new system DNS peer.
        {
            "domain_suffix": "local",
            "action": "route",
            "server": "dns-system-local",
        },
        # Surge's exclude-simple-hostnames=true leaves single-label names with
        # the local network.  DHCP discovery avoids hard-coding 10.145.0.1.
        {
            "domain_regex": r"^[^.]+$",
            "action": "route",
            "server": "dns-upstream-lan",
        },
        # Fake-IP is the normal client-facing answer, matching Surge Enhanced
        # Mode.  Other record types continue to the encrypted resolver.
        {
            "query_type": ["A", "AAAA"],
            "action": "route",
            "server": "dns-fakeip",
        },
    ]
    return {
        "servers": servers,
        "rules": rules,
        "final": "doh-cloudflare",
        "cache_capacity": 4096,
    }


def route_config() -> dict[str, Any]:
    rules: list[dict[str, Any]] = [
        # Preserve the existing four Shadowsocks entry points independently of
        # the TUN's Surge-compatible routing rules.
        {"inbound": "ss-in", "action": "route", "outbound": "🇺🇸 DMIT"},
        {
            "inbound": "ss-in-ipv6",
            "action": "route",
            "outbound": "🇺🇸 DMIT v6",
        },
        {
            "inbound": "sea-ss-in",
            "action": "route",
            "outbound": "🇺🇸 Seattle",
        },
        {
            "inbound": "sea-ss-in-ipv6",
            "action": "route",
            "outbound": "🇺🇸 Seattle v6",
        },
        {"inbound": "tun-in", "action": "sniff"},
        # mDNSResponder owns port 53 on macOS.  It forwards system/LAN queries
        # to the peer address below; sing-box hijacks only that synthetic peer.
        # Hard-coded third-party DNS remains ordinary routed traffic, as it is
        # in the current Surge profile without hijack-dns=*.
        {
            "inbound": "tun-in",
            "ip_cidr": TUN_DNS_ADDRESS,
            "port": 53,
            "action": "hijack-dns",
        },
        {"domain": "doh.pub", "action": "route", "outbound": "DIRECT"},
        {
            "domain_suffix": "doh.pub",
            "action": "route",
            "outbound": "DIRECT",
        },
        # These are General/skip-proxy exclusions rather than normal Surge
        # rules, so they take precedence over the imported policy rule sets.
        {
            "inbound": "tun-in",
            "domain": SKIP_PROXY_DOMAINS,
            "action": "route",
            "outbound": "DIRECT",
        },
        {
            "inbound": "tun-in",
            "domain_suffix": "local",
            "action": "route",
            "outbound": "DIRECT",
        },
        {
            "inbound": "tun-in",
            "ip_cidr": SKIP_PROXY_CIDRS,
            "action": "route",
            "outbound": "DIRECT",
        },
    ]

    for tag, _, outbound in RULE_SET_ROUTES:
        rules.append(
            {"rule_set": tag, "action": "route", "outbound": outbound}
        )

    # Do not resolve unmatched domains merely to evaluate GeoIP.  This keeps a
    # DNS transport failure from terminating the connection before Fallback:
    # unmatched domains go to Fallback, literal CN IPs go to InTheWall, and
    # other literal IPs continue to Fallback.
    rules.append(
        {
            "rule_set": "geoip-cn",
            "action": "route",
            "outbound": "InTheWall",
        }
    )
    return {
        "auto_detect_interface": True,
        # Resolver hostnames and any future domain-based proxy endpoints need a
        # non-recursive bootstrap resolver.  This mirrors Surge's use of the
        # traditional DNS list when encrypted DNS is enabled.
        "default_domain_resolver": {
            "server": "dns-alibaba-bootstrap",
            "strategy": "prefer_ipv4",
        },
        "rules": rules,
        "rule_set": remote_rule_sets(),
        "final": "Fallback",
    }


def validate_addresses() -> None:
    for value in TUN_ADDRESS + TUN_DNS_ADDRESS + SKIP_PROXY_CIDRS:
        ipaddress.ip_network(value, strict=False)


def build_config(base: dict[str, Any], surge_profile: Path | None) -> dict[str, Any]:
    validate_addresses()
    config = copy.deepcopy(base)
    config["outbounds"] = migrate_base_outbounds(config) + selector_outbounds()

    inbounds = config.get("inbounds")
    if not isinstance(inbounds, list):
        raise ConfigError("base configuration has no inbound list")
    inbound_tags = {
        inbound.get("tag") for inbound in inbounds if isinstance(inbound, dict)
    }
    required_inbounds = {"ss-in", "ss-in-ipv6", "sea-ss-in", "sea-ss-in-ipv6"}
    missing_inbounds = required_inbounds - inbound_tags
    if missing_inbounds:
        raise ConfigError(
            "base configuration is missing required inbounds: "
            + ", ".join(sorted(missing_inbounds))
        )
    if "tun-in" in inbound_tags:
        raise ConfigError("base configuration already contains a tun-in inbound")
    config["inbounds"] = copy.deepcopy(inbounds) + [
        {
            "type": "tun",
            "tag": "tun-in",
            "address": TUN_ADDRESS,
            "mtu": 1500,
            "auto_route": True,
            "stack": "mixed",
        }
    ]

    host_servers, host_dns_rules = import_host_dns(surge_profile)
    config["dns"] = dns_config(host_servers, host_dns_rules)
    config["route"] = route_config()

    experimental = config.get("experimental")
    if not isinstance(experimental, dict):
        experimental = {}
    else:
        experimental = copy.deepcopy(experimental)
    experimental["cache_file"] = {
        "enabled": True,
        "cache_id": "localmini-router",
        "store_fakeip": True,
    }
    # Selectors are controllable through the Clash API.  Loopback-only binding
    # avoids replacing Surge's externally authenticated controller with an
    # unauthenticated LAN service; use an SSH tunnel for initial operation.
    experimental["clash_api"] = {
        "external_controller": "127.0.0.1:9090",
    }
    config["experimental"] = experimental
    return config


def write_config(config: dict[str, Any], output: str, base_path: Path) -> None:
    payload = json.dumps(config, ensure_ascii=False, indent=2) + "\n"
    if output == "-":
        sys.stdout.write(payload)
        return

    destination = Path(output).expanduser()
    try:
        if destination.resolve() == base_path.resolve():
            raise ConfigError("refusing to overwrite the active base configuration")
        destination.parent.mkdir(parents=True, exist_ok=True)
        file_descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            dir=destination.parent,
        )
        try:
            os.fchmod(file_descriptor, 0o600)
            with os.fdopen(file_descriptor, "w", encoding="utf-8") as file:
                file.write(payload)
            os.replace(temporary_name, destination)
        except BaseException:
            try:
                os.close(file_descriptor)
            except OSError:
                pass
            try:
                os.unlink(temporary_name)
            except OSError:
                pass
            raise
    except OSError as error:
        raise ConfigError(f"cannot write candidate configuration: {error}") from error


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base",
        required=True,
        type=Path,
        help="existing sing-box JSON containing the private proxy definitions",
    )
    parser.add_argument(
        "--surge-profile",
        type=Path,
        help="optional Surge profile used to import [Host] server:DoH entries",
    )
    parser.add_argument(
        "--output",
        default="-",
        help="candidate JSON path, or '-' for stdout (default: %(default)s)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        base = read_json(args.base)
        config = build_config(base, args.surge_profile)
        write_config(config, args.output, args.base)
    except ConfigError as error:
        print(f"[error] {error}", file=sys.stderr)
        return 1

    if args.output != "-":
        print(
            "candidate written with "
            f"{len(config['inbounds'])} inbounds, "
            f"{len(config['outbounds'])} outbounds, "
            f"{len(config['dns']['servers'])} DNS servers, and "
            f"{len(config['route']['rule_set'])} rule sets",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
