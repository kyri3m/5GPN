#!/usr/bin/env python3
"""
Convert a rule-list file into a mihomo proxy-provider + rule config.

This powers the `smart` exit: route each domain to a different egress exit,
DIRECT, or REJECT — using mihomo's native rule-providers (no manual .srs
compilation needed).

Rules file syntax (same as sing-box, fully compatible):
    DOMAIN,api.example.com,us
    DOMAIN-SUFFIX,google.com,us
    DOMAIN-KEYWORD,netflix,jp
    IP-CIDR,1.2.3.0/24,direct
    GEOSITE,telegram,us
    GEOIP,cn,direct
    RULE-SET,https://example.com/list.yaml,us     # remote rule-provider
    RULE-SET,/etc/proxy-gateway/rules/my.list,jp  # local file
    FINAL,direct                                   # default policy

Policy = an exit name, `direct`, `DIRECT`, `block`, `REJECT`, or `reject`.

Usage:  mihomo-router-config.py <rules-file>   (emits mihomo YAML on stdout)
Env: EXITS_DIR, WG_DIR, MIHOMO_STACK, MIHOMO_MTU
"""

import hashlib
import json
import os
import re
import sys
import urllib.request

EXITS_DIR = os.environ.get("EXITS_DIR", "/etc/proxy-gateway/exits")
WG_DIR = os.environ.get("WG_DIR", "/etc/wireguard")
STACK = os.environ.get("MIHOMO_STACK", "gvisor")
try:
    MTU = int(os.environ.get("MIHOMO_MTU", "1400"))
except ValueError:
    MTU = 1400
POLICY_MAP_FILE = os.environ.get("PGW_POLICY_MAP", "/etc/proxy-gateway/policy-map.conf")
DEFAULT_TARGET = os.environ.get("PGW_DEFAULT_TARGET", "direct")
GEOSITE_URL = "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geosite.dat"
GEOIP_URL = "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geoip.dat"
RULE_PROVIDER_INTERVAL = 86400  # 24h cache refresh

DOMAIN_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9_-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9_-]*[A-Za-z0-9])?)+$")


def die(msg):
    sys.stderr.write(msg.rstrip() + "\n")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Policy map
# ---------------------------------------------------------------------------
def load_policy_map():
    m = {}
    try:
        for raw in open(POLICY_MAP_FILE, encoding="utf-8"):
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            m[k.strip()] = v.strip()
    except OSError:
        pass
    return m


# ---------------------------------------------------------------------------
# Outbound proxy providers: load existing exit configs into mihomo
# ---------------------------------------------------------------------------
def wg_to_proxy(name, path):
    """Parse WireGuard .conf into mihomo wireguard proxy block."""
    iface, peer, section = {}, {}, None
    for raw in open(path, encoding="utf-8"):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].lower()
            continue
        if "=" not in line:
            continue
        k, v = (x.strip() for x in line.split("=", 1))
        (iface if section == "interface" else peer)[k.lower()] = v

    host, _, port = peer.get("endpoint", "").rpartition(":")
    proxy = {
        "name": name,
        "type": "wireguard",
        "server": host,
        "port": int(port) if port.isdigit() else 51820,
        "ip": (iface.get("address", "172.19.0.2/32").split(",")[0].strip()),
        "private-key": iface.get("privatekey", ""),
        "public-key": peer.get("publickey", ""),
    }
    if peer.get("presharedkey"):
        proxy["preshared-key"] = peer["presharedkey"]
    if iface.get("mtu", "").isdigit():
        proxy["mtu"] = int(iface["mtu"])
    return proxy


def parse_singbox_exit(exit_path, name):
    """Convert a sing-box exit JSON into a mihomo proxy dict."""
    cfg = json.load(open(exit_path))
    ob = dict(cfg["outbounds"][0])
    ptype = ob.get("type", "direct")
    proxy = {"name": name}
    # mihomo type names differ from sing-box
    if ptype == "shadowsocks":
        proxy["type"] = "ss"
        proxy["server"] = ob["server"]
        proxy["port"] = ob["server_port"]
        proxy["cipher"] = ob["method"]
        proxy["password"] = ob["password"]
    elif ptype == "vmess":
        proxy["type"] = "vmess"
        proxy["server"] = ob["server"]
        proxy["port"] = ob["server_port"]
        proxy["uuid"] = ob["uuid"]
        proxy["alterId"] = ob.get("alter_id", 0)
        proxy["cipher"] = ob.get("security", "auto")
        if "tls" in ob:
            proxy["tls"] = True
            proxy["servername"] = ob["tls"].get("server_name", "")
        if "transport" in ob and ob["transport"].get("type") == "ws":
            proxy["network"] = "ws"
            proxy["ws-opts"] = {"path": ob["transport"].get("path", "/")}
    elif ptype == "trojan":
        proxy["type"] = "trojan"
        proxy["server"] = ob["server"]
        proxy["port"] = ob["server_port"]
        proxy["password"] = ob["password"]
        if "tls" in ob:
            proxy["sni"] = ob["tls"].get("server_name", "")
    elif ptype == "vless":
        proxy["type"] = "vless"
        proxy["server"] = ob["server"]
        proxy["port"] = ob["server_port"]
        proxy["uuid"] = ob["uuid"]
        if "tls" in ob:
            proxy["servername"] = ob["tls"].get("server_name", "")
    elif ptype == "hysteria2":
        proxy["type"] = "hysteria2"
        proxy["server"] = ob["server"]
        proxy["port"] = ob["server_port"]
        proxy["password"] = ob["password"]
        proxy["sni"] = ob.get("tls", {}).get("server_name", "")
    elif ptype == "tuic":
        proxy["type"] = "tuic"
        proxy["server"] = ob["server"]
        proxy["port"] = ob["server_port"]
        proxy["uuid"] = ob["uuid"]
        proxy["password"] = ob.get("password", "")
        proxy["sni"] = ob.get("tls", {}).get("server_name", "")
    elif ptype == "socks":
        proxy["type"] = "socks5"
        proxy["server"] = ob["server"]
        proxy["port"] = ob["server_port"]
        if ob.get("username"):
            proxy["username"] = ob["username"]
        if ob.get("password"):
            proxy["password"] = ob["password"]
    elif ptype == "http":
        proxy["type"] = "http"
        proxy["server"] = ob["server"]
        proxy["port"] = ob["server_port"]
        if ob.get("username"):
            proxy["username"] = ob["username"]
        if ob.get("password"):
            proxy["password"] = ob["password"]
    elif ptype == "wireguard":
        proxy["type"] = "wireguard"
        proxy["ip"] = "172.19.0.2/32"  # default, overridden by actual config
    else:
        die("unsupported sing-box outbound type: %s" % ptype)

    return proxy


def load_exit_proxy(name):
    """Load a sing-box exit or WireGuard exit as a mihomo proxy dict.
    Tries exact match first, then case-insensitive."""
    jp = os.path.join(EXITS_DIR, name + ".json")
    if not os.path.exists(jp):
        # Case-insensitive fallback
        try:
            for f in os.listdir(EXITS_DIR):
                if f.lower() == name.lower() + ".json":
                    jp = os.path.join(EXITS_DIR, f)
                    name = f[:-5]  # Use actual filename as name
                    break
        except OSError:
            pass
    if os.path.exists(jp):
        return parse_singbox_exit(jp, name)
    wg = os.path.join(WG_DIR, "pgw-%s.conf" % name)
    if os.path.exists(wg):
        return wg_to_proxy(name, wg)
    return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    if len(sys.argv) != 2:
        die("usage: mihomo-router-config.py <rules-file>")
    rules_path = sys.argv[1]
    if not os.path.exists(rules_path):
        die("rules file not found: " + rules_path)

    policy_map = load_policy_map()
    proxies = []
    proxy_names = set()
    proxy_groups = {}
    rule_providers = {}
    rules = []

    used_exits = set()  # exits referenced in rules
    used_categories = set()

    def resolve_target(t):
        """Resolve a policy/target to a proxy/group name."""
        t = t.strip()
        low = t.lower()
        if low in ("direct", "direct-out", "dir"):
            return "DIRECT"
        if low in ("block", "reject", "reject-drop"):
            return "REJECT"
        # Check policy map — maps category → exit name
        if t in policy_map:
            target = policy_map[t].strip()
            tlow = target.lower()
            if tlow in ("direct", "direct-out", "dir"):
                return "DIRECT"
            if tlow in ("block", "reject", "reject-drop"):
                return "REJECT"
            used_exits.add(target)
            return target
        # Direct exit name: add to used_exits, return as-is for rules
        used_exits.add(t)
        return t

    # Parse rules
    for ln, raw in enumerate(open(rules_path, encoding="utf-8"), 1):
        line = raw.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue
        parts = [p.strip() for p in line.split(",")]
        typ = parts[0].upper().replace("_", "-")
        if typ == "FINAL":
            target = resolve_target(parts[1] if len(parts) > 1 else DEFAULT_TARGET)
            rules.append("MATCH,%s" % target)
            continue
        if len(parts) < 3:
            die("line %d: '%s' needs <type>,<value>,<policy>" % (ln, line))
        value, target = parts[1], resolve_target(parts[2])

        if typ == "DOMAIN":
            rules.append("DOMAIN,%s,%s" % (value, target))
        elif typ == "DOMAIN-SUFFIX":
            rules.append("DOMAIN-SUFFIX,%s,%s" % (value, target))
        elif typ == "DOMAIN-KEYWORD":
            rules.append("DOMAIN-KEYWORD,%s,%s" % (value, target))
        elif typ in ("IP-CIDR", "IP-CIDR6"):
            rules.append("IP-CIDR,%s,%s" % (value, target))
        elif typ == "GEOSITE":
            rules.append("GEOSITE,%s,%s" % (value, target))
        elif typ == "GEOIP":
            rules.append("GEOIP,%s,%s" % (value, target))
        elif typ in ("RULE-SET", "RULESET", "RULE-PROVIDER"):
            # Register as a rule-provider
            tag = "rs_" + hashlib.md5(value.encode()).hexdigest()[:8]
            if value.startswith("http"):
                rule_providers[tag] = {
                    "type": "http",
                    "url": value,
                    "interval": RULE_PROVIDER_INTERVAL,
                    "behavior": "classical" if value.endswith(".yaml") else "domain",
                }
            else:
                rule_providers[tag] = {
                    "type": "file",
                    "path": value,
                    "behavior": "domain",
                }
            rules.append("RULE-SET,%s,%s" % (tag, target))
        else:
            die("line %d: unsupported rule type '%s'" % (ln, parts[0]))

    # Load exit proxies
    for exit_name in used_exits:
        proxy = load_exit_proxy(exit_name)
        if proxy:
            proxies.append(proxy)
            proxy_names.add(proxy["name"])

    # Build proxy-groups
    # Clean up: remove per-exit proxy_groups (rules reference exits directly)
    # The "proxy" group pools all exits together for traffic routing
    proxy_groups = {"proxy": {"type": "select", "proxies": list(proxy_names) + ["DIRECT"]}}

    # Emit YAML
    lines = []
    lines.append("# Mihomo smart routing config")
    lines.append("# Auto-generated by mihomo-router-config.py")
    lines.append("mode: rule")
    lines.append("log-level: warning")
    lines.append("")
    lines.append("# TUN inbound")
    lines.append("tun:")
    lines.append("  enable: true")
    lines.append("  stack: %s" % STACK)
    lines.append("  device: pgw-smart")
    lines.append("  auto-route: false")
    lines.append("  auto-detect-interface: true")
    lines.append("  mtu: %d" % MTU)
    lines.append("")
    lines.append("# DNS (disable — upstream dnsdist handles resolution)")
    lines.append("dns:")
    lines.append("  enable: false")
    lines.append("")

    # Proxies
    if proxies:
        lines.append("proxies:")
        for p in proxies:
            lines.append("  - name: \"%s\"" % p["name"])
            lines.append("    type: %s" % p.pop("type"))
            for k, v in p.items():
                if k == "name":
                    continue
                if isinstance(v, bool):
                    lines.append("    %s: %s" % (k, "true" if v else "false"))
                elif isinstance(v, (int, float)):
                    lines.append("    %s: %d" % (k, int(v)))
                elif isinstance(v, dict):
                    lines.append("    %s:" % k)
                    for sk, sv in v.items():
                        if isinstance(sv, str):
                            lines.append("      %s: \"%s\"" % (sk, sv))
                        else:
                            lines.append("      %s: %s" % (sk, sv))
                else:
                    lines.append("    %s: \"%s\"" % (k, v))
    else:
        lines.append("proxies: []")
    lines.append("")

    # Proxy groups
    lines.append("proxy-groups:")
    for pg_name, pg_info in proxy_groups.items():
        lines.append("  - name: %s" % pg_name)
        lines.append("    type: %s" % pg_info.get("type", "select"))
        lines.append("    proxies:")
        for e in pg_info.get("proxies", []):
            lines.append("      - \"%s\"" % e)
    lines.append("")

    # Rule-providers
    if rule_providers:
        lines.append("rule-providers:")
        for tag, rp in rule_providers.items():
            lines.append("  %s:" % tag)
            lines.append("    type: %s" % rp["type"])
            if "url" in rp:
                lines.append("    url: \"%s\"" % rp["url"])
                lines.append("    interval: %d" % rp.get("interval", RULE_PROVIDER_INTERVAL))
            if "path" in rp:
                lines.append("    path: \"%s\"" % rp["path"])
            lines.append("    behavior: %s" % rp.get("behavior", "domain"))
        lines.append("")

    # Rules
    lines.append("rules:")
    for rule in rules:
        lines.append("  - %s" % rule)
    lines.append("")

    sys.stdout.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
