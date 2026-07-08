#!/usr/bin/env python3
"""
Convert a rule list into the gateway's smart-routing rules.
Also supports --check-url and --from-url for remote rule-set import.

Usage:
  rules-import.py <rule-list-file>          emit gateway rules on stdout
  rules-import.py --check-url <url>         detect format without full import
  rules-import.py --from-url <url> <cat>    fetch + parse + emit rules
  rules-import.py --extract-domains <url>   extract unique domains (for GFWList)
"""
import os
import re
import ssl
import sys
import hashlib
import urllib.request
import urllib.error

# Matchers we can apply on the gateway (domain/IP/list based).
KEEP = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6",
        "RULE-SET", "GEOIP", "GEOSITE"}
# Client-only matchers — meaningless on a server gateway.
DROP = {"PROCESS-NAME", "SRC-IP", "SRC-PORT", "DEST-PORT", "IN-PORT",
        "MAC-ADDRESS", "DEVICE-NAME", "IP-ASN", "USER-AGENT", "SUBNET",
        "PROTOCOL", "CELLULAR-RADIO", "SSID"}
MODIFIERS = re.compile(r"^(no-resolve|extended-matching|dns-failed|pre-matching"
                       r"|update-interval=.*|interval=.*)$", re.I)

DOMAIN_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9_-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9_-]*[A-Za-z0-9])?)+$")


def csv_split(s):
    """Split on commas, respecting double quotes."""
    out, cur, q = [], "", False
    for ch in s:
        if ch == '"':
            q = not q
        elif ch == "," and not q:
            out.append(cur); cur = ""
        else:
            cur += ch
    out.append(cur)
    return [x.strip() for x in out]


def norm_category(p):
    p = p.strip().strip('"').strip()
    p = re.sub(r"^[^\w一-鿿]+", "", p).strip()
    return p or "Proxy"


_KEEP = {c.strip() for c in re.split(r"[,\s]+", os.environ.get("PGW_KEEP_CATEGORIES", "")) if c.strip()}
_DIRECT = {c.strip().lower() for c in re.split(r"[,\s]+", os.environ.get("PGW_DIRECT_CATEGORIES", "")) if c.strip()}


def category_of(policy):
    cat = norm_category(policy)
    if cat.lower() in _DIRECT:
        return "direct"
    if not _KEEP or cat in _KEEP:
        return cat
    low = cat.lower()
    if low in ("dir", "direct", "china", "lan", "domestic"):
        return "direct"
    if any(x in low for x in ("advert", "hijack", "privacy", "reject", "广告", "malware")):
        return "block"
    return "Proxy"


def split_top_parens(s):
    out, depth, start = [], 0, None
    for i, ch in enumerate(s):
        if ch == "(":
            if depth == 0: start = i + 1
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0 and start is not None:
                out.append(s[start:i]); start = None
    return out


def parse_logical(line):
    i = line.index("(")
    depth, end = 0, None
    for j in range(i, len(line)):
        if line[j] == "(": depth += 1
        elif line[j] == ")":
            depth -= 1
            if depth == 0: end = j; break
    if end is None: return [], None
    group = line[i + 1:end]
    tail = line[end + 1:].lstrip(",")
    policy = csv_split(tail)[0] if tail else None
    return split_top_parens(group), policy


def emit(typ, value, category, sink):
    typ = typ.upper()
    if typ == "IP-CIDR6": typ = "IP-CIDR"
    sink.append("%s,%s,%s" % (typ, value, category_of(category)))


def fetch(url, max_bytes=None):
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": "proxy-gateway/1.0"})
    with urllib.request.urlopen(req, timeout=10, context=ctx) as r:
        if max_bytes:
            return r.read(max_bytes)
        return r.read()


def detect_format(data, url=""):
    """Auto-detect rule format: clash, csv, srs, plain"""
    text = data[:4096].decode("utf-8", "replace") if isinstance(data, bytes) else str(data)[:4096]
    if url.lower().endswith(".srs"):
        return "srs"
    if text.strip().startswith(("payload:", "rules:", "rule-providers:", "{")):
        return "clash"
    first_lines = [l for l in text.splitlines() if l.strip() and not l.strip().startswith(("#", ";", "!", "["))]
    if first_lines and re.search(r'^(DOMAIN|DOMAIN-SUFFIX|IP-CIDR|RULE-SET|GEOSITE|GEOIP),', first_lines[0], re.I):
        return "csv"
    return "plain"


def check_url(url):
    """Quick check: fetch headers + first chunk, detect format, return (ok, info)."""
    try:
        data = fetch(url, max_bytes=8192)
        fmt = detect_format(data, url)
        lines = data.decode("utf-8", "replace").count("\n") + 1
        return True, "%s · ~%d 行" % (fmt, lines)
    except Exception as e:
        return False, str(e)[:200]


def parse_clash_yaml(text):
    """Parse Clash rule-provider style YAML into simple rules."""
    rules = []
    domain_suf, domain_kw, ip_cidr = set(), set(), set()
    in_payload = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "!", ";")):
            continue
        if line.startswith("payload:"):
            in_payload = True; continue
        if not in_payload and re.match(r'^\w[\w-]*:', line):
            in_payload = False; continue
        if not in_payload:
            continue
        line = line.lstrip("- ").strip().strip("'\"")
        if "," in line:
            parts = [p.strip().strip("'\"") for p in line.split(",")]
            t, v = parts[0].upper(), (parts[1] if len(parts) > 1 else "")
            if t in ("DOMAIN", "HOST") and DOMAIN_RE.match(v):
                rules.append("DOMAIN,%s" % v)
            elif t in ("DOMAIN-SUFFIX", "HOST-SUFFIX") and DOMAIN_RE.match(v.lstrip(".")):
                rules.append("DOMAIN-SUFFIX,%s" % v.lstrip("."))
            elif t in ("DOMAIN-KEYWORD", "HOST-KEYWORD") and v:
                rules.append("DOMAIN-KEYWORD,%s" % v)
            elif t in ("IP-CIDR", "IP-CIDR6") and v:
                rules.append("IP-CIDR,%s" % v)
        else:
            v = re.sub(r"^[*+]?\.", "", line).rstrip(".")
            if DOMAIN_RE.match(v):
                rules.append("DOMAIN-SUFFIX,%s" % v)
    return rules


def parse_plain_list(text):
    """Parse one-domain-per-line into DOMAIN-SUFFIX rules."""
    rules = []
    for raw in text.splitlines():
        line = raw.split("#")[0].split(";")[0].strip()
        if not line or line.startswith(("!", "[")):
            continue
        v = re.sub(r"^[*+]?\.", "", line.lstrip("- ").strip().strip("'\"").rstrip("."))
        if DOMAIN_RE.match(v):
            rules.append("DOMAIN-SUFFIX,%s" % v)
    return rules


def extract_domains(url):
    """Fetch URL, parse, extract unique domain suffixes (for GFWList)."""
    data = fetch(url).decode("utf-8", "replace")
    fmt = detect_format(data, url)
    domains = set()
    if fmt == "csv":
        for line in data.splitlines():
            parts = csv_split(line.strip())
            if len(parts) >= 2 and parts[0].upper() in ("DOMAIN", "DOMAIN-SUFFIX"):
                d = parts[1].strip().lstrip(".")
                if DOMAIN_RE.match(d):
                    domains.add(d)
    elif fmt == "clash":
        for rule in parse_clash_yaml(data):
            parts = rule.split(",", 1)
            if len(parts) == 2:
                domains.add(parts[1].strip())
    else:
        for rule in parse_plain_list(data):
            parts = rule.split(",", 1)
            if len(parts) == 2:
                domains.add(parts[1].strip())
    return sorted(domains)


def main():
    if len(sys.argv) < 2:
        sys.stderr.write("usage: rules-import.py <file|--check-url url|--from-url url cat|--extract-domains url>\n")
        sys.exit(1)

    if sys.argv[1] == "--check-url":
        ok, info = check_url(sys.argv[2])
        if ok:
            print(info)
            sys.exit(0)
        else:
            sys.stderr.write(info + "\n")
            sys.exit(1)

    if sys.argv[1] == "--from-url":
        url = sys.argv[2]
        category = sys.argv[3] if len(sys.argv) > 3 else "Proxy"
        data = fetch(url).decode("utf-8", "replace")
        fmt = detect_format(data, url)
        rules = []
        if fmt == "csv":
            rules = [l.strip() for l in data.splitlines()
                     if l.strip() and not l.strip().startswith(("#", ";"))]
        elif fmt == "clash":
            rules = parse_clash_yaml(data)
        else:
            rules = parse_plain_list(data)
        # Add category to each rule if missing
        out = []
        for r in rules:
            if r.count(",") >= 2:
                out.append(r)
            else:
                out.append("%s,%s" % (r, category))
        sys.stdout.write("\n".join(out) + "\n")
        sys.stderr.write("imported=%d format=%s\n" % (len(out), fmt))
        sys.exit(0)

    if sys.argv[1] == "--extract-domains":
        url = sys.argv[2]
        domains = extract_domains(url)
        sys.stdout.write("\n".join(domains) + "\n")
        sys.stderr.write("extracted=%d domains\n" % len(domains))
        sys.exit(0)

    # Default: import from local file
    rules, cats = [], {}
    final = None
    dropped, flattened = 0, 0

    for raw in open(sys.argv[1], encoding="utf-8"):
        line = raw.strip()
        if not line or line.startswith(("#", ";", "[")):
            continue
        typ = line.split(",", 1)[0].strip().upper()

        if typ in ("OR", "AND"):
            members, policy = parse_logical(line)
            if not policy: continue
            took = False
            for m in members:
                p = csv_split(m)
                mt = p[0].upper()
                if mt in KEEP and len(p) >= 2:
                    emit(mt, p[1], policy, rules)
                    cats[category_of(policy)] = True
                    took = True
            flattened += 1 if took else 0
            dropped += 0 if took else 1
            continue

        parts = csv_split(line)
        if typ == "FINAL":
            final = category_of(parts[1]) if len(parts) > 1 else None
            continue
        if typ in DROP:
            dropped += 1; continue
        if typ not in KEEP or len(parts) < 3:
            dropped += 1; continue
        rest = [x for x in parts[2:] if not MODIFIERS.match(x.strip().strip('"'))]
        if not rest:
            dropped += 1; continue
        emit(typ, parts[1], rest[0], rules)
        cats[category_of(rest[0])] = True

    if final:
        rules.append("FINAL,%s" % final)
        cats[final] = True

    sys.stdout.write("\n".join(rules) + "\n")
    sys.stderr.write("converted=%d dropped=%d or_flattened=%d categories=%d\n"
                     % (len(rules), dropped, flattened, len(cats)))
    sys.stderr.write("CATEGORIES=" + "\t".join(sorted(cats)) + "\n")


if __name__ == "__main__":
    main()
