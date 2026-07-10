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
import http.client
import ipaddress
import socket
from urllib.parse import urljoin, urlsplit

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
MAX_DOWNLOAD_BYTES = 20 * 1024 * 1024


def _parse_remote_url(url):
    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise ValueError("invalid URL: %s" % exc) from exc
    if parsed.scheme.lower() != "https":
        raise ValueError("only https:// rule URLs are allowed")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("rule URL must contain a hostname and no credentials")
    return parsed


def resolve_public_url(url):
    """Resolve exactly once; return the same validated addresses used to connect."""
    parsed = _parse_remote_url(url)
    try:
        infos = socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError("cannot resolve rule URL hostname") from exc
    addresses = []
    for item in infos:
        address = item[4][0]
        if not ipaddress.ip_address(address).is_global:
            raise ValueError("private or non-global rule URL address is not allowed")
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise ValueError("rule URL hostname has no addresses")
    return parsed, addresses


def validate_remote_url(url):
    resolve_public_url(url)
    return url


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect to a pre-validated IP while preserving hostname TLS checks."""
    def __init__(self, hostname, address, port, context, timeout):
        super().__init__(hostname, port=port, context=context, timeout=timeout)
        self._address = address
        self._tls_context = context

    def connect(self):
        raw = socket.create_connection((self._address, self.port), self.timeout)
        self.sock = self._tls_context.wrap_socket(raw, server_hostname=self.host)


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
    for _redirect in range(6):
        parsed, addresses = resolve_public_url(url)
        conn = None
        response = None
        last_error = None
        for address in addresses:
            try:
                conn = PinnedHTTPSConnection(parsed.hostname, address, parsed.port or 443, ctx, 10)
                path = parsed.path or "/"
                if parsed.query:
                    path += "?" + parsed.query
                host = parsed.hostname if parsed.port in (None, 443) else "%s:%d" % (parsed.hostname, parsed.port)
                conn.request("GET", path, headers={"Host": host, "User-Agent": "proxy-gateway/1.0"})
                response = conn.getresponse()
                break
            except OSError as exc:
                last_error = exc
                if conn:
                    conn.close()
                conn = None
        if conn is None:
            raise ValueError("cannot connect to validated rule URL address") from last_error
        assert response is not None
        if response.status in (301, 302, 303, 307, 308):
            location = response.getheader("Location")
            conn.close()
            if not location:
                raise ValueError("redirect missing Location header")
            url = urljoin(url, location)
            continue
        if not 200 <= response.status < 300:
            conn.close()
            raise ValueError("rule URL returned HTTP %d" % response.status)
        if max_bytes is not None:
            data = response.read(min(max_bytes, MAX_DOWNLOAD_BYTES))
            conn.close()
            return data
        declared = response.getheader("Content-Length")
        if declared and int(declared) > MAX_DOWNLOAD_BYTES:
            conn.close()
            raise ValueError("rule file exceeds 20 MiB limit")
        data = response.read(MAX_DOWNLOAD_BYTES + 1)
        conn.close()
        if len(data) > MAX_DOWNLOAD_BYTES:
            raise ValueError("rule file exceeds 20 MiB limit")
        return data
    raise ValueError("too many redirects")


def detect_format(data, url=""):
    """Auto-detect supported text formats; reject binary sing-box SRS."""
    text = data[:4096].decode("utf-8", "replace") if isinstance(data, bytes) else str(data)[:4096]
    if url.lower().endswith(".srs"):
        raise ValueError("sing-box .srs binary rules are not supported; use Clash YAML or a text list")
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
    dropped, flattened, and_dropped = 0, 0, 0

    for raw in open(sys.argv[1], encoding="utf-8"):
        line = raw.strip()
        if not line or line.startswith(("#", ";", "[")):
            continue
        typ = line.split(",", 1)[0].strip().upper()

        if typ == "AND":
            # The gateway rule format cannot preserve logical conjunction.
            # Expanding members would silently turn AND into OR and broaden policy.
            and_dropped += 1
            dropped += 1
            continue

        if typ == "OR":
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
    sys.stderr.write("converted=%d dropped=%d or_flattened=%d and_dropped=%d categories=%d\n"
                     % (len(rules), dropped, flattened, and_dropped, len(cats)))
    sys.stderr.write("CATEGORIES=" + "\t".join(sorted(cats)) + "\n")


if __name__ == "__main__":
    main()
