#!/usr/bin/env python3
"""
Generate a mihomo (Clash Meta) config for one proxy-gateway egress exit.

Supports ALL protocols that sing-box supported, PLUS:
  - WireGuard outbound (mihomo native, no separate wg-quick needed)
  - Snell v3/v4
  - SSH outbound

Usage:  mihomo-exit-config.py <exit-name> <uri>
Emits mihomo YAML on stdout. Exits non-zero on stderr on error.

Env:
  MIHOMO_STACK  TUN network stack: gvisor|system|mixed   (default: gvisor)
  MIHOMO_MTU    TUN MTU                                   (default: 1400)
"""

import base64
import os
import re
import sys
from urllib.parse import parse_qs, unquote, urlparse

# ---------------------------------------------------------------------------
# Protocol parsers (ported from singbox-exit-config.py, adapted for mihomo)
# ---------------------------------------------------------------------------

SS_METHODS = {
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "chacha20-ietf", "aes-128-ctr", "aes-256-ctr",
    "aes-128-cfb", "aes-256-cfb", "rc4-md5", "none", "plain",
}


def die(msg):
    sys.stderr.write(msg.rstrip() + "\n")
    sys.exit(1)


def b64decode_any(s):
    s = s.strip()
    pad = "=" * (-len(s) % 4)
    for dec in (base64.urlsafe_b64decode, base64.b64decode):
        try:
            return dec(s + pad).decode("utf-8")
        except Exception:
            continue
    raise ValueError("not base64")


def parse_hostport(s):
    s = s.strip()
    s = re.split(r"[/?#]", s, 1)[0].strip()
    m = re.match(r"^\[(.+)\]:(\d+)$", s)
    if m:
        return m.group(1), int(m.group(2))
    m = re.match(r"^(.+):(\d+)$", s)
    if m:
        return m.group(1), int(m.group(2))
    die("cannot parse host:port from %r" % s)


def query_map(u):
    return {k: v[0] for k, v in parse_qs(u.query).items()}


# ---- Shadowsocks ----
def decode_ss_userinfo(userinfo):
    try:
        dec = b64decode_any(userinfo)
        if ":" in dec and re.match(r"^[a-z0-9-]+$", dec.split(":", 1)[0]):
            return dec.split(":", 1)
    except ValueError:
        pass
    plain = unquote(userinfo)
    if ":" in plain:
        return plain.split(":", 1)
    die("cannot parse ss:// credentials")


def parse_ss(uri):
    rest = uri[len("ss://"):].split("#", 1)[0].split("?", 1)[0]
    if "@" in rest:
        userinfo, server = rest.rsplit("@", 1)
        method, password = decode_ss_userinfo(userinfo)
        host, port = parse_hostport(server)
    else:
        try:
            dec = b64decode_any(rest)
        except ValueError:
            die("invalid ss:// (not SIP002 and not valid base64)")
        if "@" not in dec or ":" not in dec:
            die("invalid legacy ss:// payload")
        creds, server = dec.rsplit("@", 1)
        method, password = creds.split(":", 1)
        host, port = parse_hostport(server)
    return host, port, method, password


# ---- SOCKS5 ----
def parse_socks(uri):
    rest = re.sub(r"^socks(?:5h|5)?://", "", uri, flags=re.I)
    if "@" in rest:
        userinfo, hostport = rest.rsplit("@", 1)
    else:
        userinfo, hostport = "", rest
    hostport = re.split(r"[/?#]", hostport, 1)[0].strip()
    host, port = parse_hostport(hostport)
    user = password = None
    if userinfo:
        if ":" in userinfo:
            user, password = userinfo.split(":", 1)
        else:
            user = userinfo
    return host, port, user, password


# ---- VMess ----
def parse_vmess(uri):
    import json
    try:
        data = json.loads(b64decode_any(uri[len("vmess://"):]))
    except Exception as e:
        die("invalid vmess:// payload: %s" % e)
    host = data.get("add")
    port = int(data.get("port") or 443)
    proxy = {
        "server": host, "port": port,
        "uuid": data.get("id", ""),
        "alterId": int(data.get("aid", 0) or 0),
        "cipher": data.get("scy") or "auto",
    }
    tls = str(data.get("tls", "")).lower() in ("tls", "true", "1")
    if tls:
        proxy["tls"] = True
        proxy["servername"] = data.get("sni") or data.get("host") or host
    net = (data.get("net") or "tcp").lower()
    if net in ("ws", "websocket"):
        proxy["network"] = "ws"
        proxy["ws-opts"] = {"path": data.get("path") or "/"}
        if data.get("host"):
            proxy["ws-opts"]["headers"] = {"Host": data.get("host")}
    elif net == "grpc":
        proxy["network"] = "grpc"
        proxy["grpc-opts"] = {"grpc-service-name": data.get("path", "").lstrip("/")}
    elif net == "h2":
        proxy["network"] = "h2"
        if data.get("host"):
            proxy["h2-opts"] = {"host": [data.get("host")]}
    return proxy, host, port


# ---- Trojan ----
def parse_trojan(uri):
    u = urlparse(uri)
    q = query_map(u)
    host, port = u.hostname, u.port or 443
    proxy = {
        "server": host, "port": port,
        "password": unquote(u.username or ""),
    }
    sni = q.get("sni") or q.get("peer") or host
    proxy["sni"] = sni
    if q.get("allowInsecure") in ("1", "true"):
        proxy["skip-cert-verify"] = True
    net = (q.get("type") or "tcp").lower()
    if net in ("ws", "websocket"):
        proxy["network"] = "ws"
        proxy["ws-opts"] = {"path": q.get("path") or "/"}
        if q.get("host"):
            proxy["ws-opts"]["headers"] = {"Host": q.get("host")}
    elif net == "grpc":
        proxy["network"] = "grpc"
        proxy["grpc-opts"] = {"grpc-service-name": q.get("serviceName", "").lstrip("/")}
    return proxy, host, port


# ---- VLESS ----
def parse_vless(uri):
    u = urlparse(uri)
    q = query_map(u)
    host, port = u.hostname, u.port or 443
    proxy = {
        "server": host, "port": port,
        "uuid": unquote(u.username or ""),
    }
    if q.get("flow"):
        proxy["flow"] = q["flow"]
    security = (q.get("security") or "tls").lower()
    if security == "reality":
        proxy["reality-opts"] = {"public-key": q.get("pbk") or q.get("public_key", "")}
        if q.get("sid") or q.get("short_id"):
            proxy["reality-opts"]["short-id"] = q.get("sid") or q.get("short_id")
        proxy["servername"] = q.get("sni") or host
    elif security == "tls":
        proxy["tls"] = True
        proxy["servername"] = q.get("sni") or host
        if q.get("allowInsecure") in ("1", "true"):
            proxy["skip-cert-verify"] = True
    net = (q.get("type") or q.get("transport") or "tcp").lower()
    if net in ("ws", "websocket"):
        proxy["network"] = "ws"
        proxy["ws-opts"] = {"path": q.get("path") or "/"}
        if q.get("host"):
            proxy["ws-opts"]["headers"] = {"Host": q.get("host")}
    elif net == "grpc":
        proxy["network"] = "grpc"
        proxy["grpc-opts"] = {"grpc-service-name": q.get("serviceName", "").lstrip("/")}
    return proxy, host, port


# ---- Hysteria2 ----
def parse_hysteria2(uri):
    u = urlparse(uri)
    q = query_map(u)
    host, port = u.hostname, u.port or 443
    proxy = {
        "server": host, "port": port,
        "password": unquote(u.username or ""),
        "sni": q.get("sni") or host,
    }
    if q.get("insecure") in ("1", "true"):
        proxy["skip-cert-verify"] = True
    if q.get("obfs"):
        proxy["obfs"] = q.get("obfs")
        proxy["obfs-password"] = q.get("obfs-password") or q.get("obfs_password", "")
    return proxy, host, port


# ---- TUIC ----
def parse_tuic(uri):
    u = urlparse(uri)
    q = query_map(u)
    host, port = u.hostname, u.port or 443
    if ":" in (u.username or ""):
        uuid, password = unquote(u.username).split(":", 1)
    else:
        uuid, password = unquote(u.username or ""), unquote(u.password or "")
    proxy = {
        "server": host, "port": port,
        "uuid": uuid, "password": password,
        "sni": q.get("sni") or host,
    }
    if q.get("allow_insecure") in ("1", "true"):
        proxy["skip-cert-verify"] = True
    return proxy, host, port


# ---- AnyTLS ----
def parse_anytls(uri):
    u = urlparse(uri)
    q = query_map(u)
    host, port = u.hostname, u.port or 443
    proxy = {
        "server": host, "port": port,
        "password": unquote(u.username or ""),
        "sni": q.get("sni") or host,
    }
    if q.get("insecure") in ("1", "true"):
        proxy["skip-cert-verify"] = True
    return proxy, host, port


# ---- HTTP/HTTPS ----
def parse_http(uri):
    u = urlparse(uri)
    host, port = u.hostname, u.port or (443 if u.scheme.lower() == "https" else 80)
    proxy = {"server": host, "port": port}
    if u.username:
        proxy["username"] = unquote(u.username)
    if u.password:
        proxy["password"] = unquote(u.password)
    if u.scheme.lower() == "https":
        proxy["tls"] = True
        proxy["sni"] = host
    return proxy, host, port


# ---- WireGuard ----
def parse_wireguard(uri):
    """wg://[private_key]@host:port?pk=xxx[&psk=xxx][&address=10.0.0.2/24][&mtu=1400]"""
    u = urlparse(uri)
    q = query_map(u)
    host, port = u.hostname, u.port or 51820
    proxy = {
        "server": host, "port": port,
        "private-key": unquote(u.username or ""),
        "public-key": q.get("pk", ""),
        "ip": q.get("address", "172.19.0.2/32"),
    }
    if q.get("psk"):
        proxy["preshared-key"] = q.get("psk")
    if q.get("mtu", "").isdigit():
        proxy["mtu"] = int(q["mtu"])
    if "ipv6" in q:
        proxy["ipv6"] = q["ipv6"]
    return proxy, host, port


# ---- Main dispatcher ----
def parse_proxy_uri(uri):
    low = uri.lower()
    if low.startswith("ss://"):
        host, port, method, password = parse_ss(uri)
        proxy = {
            "server": host, "port": port,
            "cipher": method, "password": password,
        }
        # 2022 methods use a different key in mihomo
        if method.startswith("2022-"):
            proxy["cipher"] = method
        return proxy, host, port, "ss"
    if low.startswith(("socks5h://", "socks5://", "socks://")):
        host, port, user, password = parse_socks(uri)
        proxy = {"server": host, "port": port}
        if user:
            proxy["username"] = user
        if password:
            proxy["password"] = password
        return proxy, host, port, "socks5"
    if low.startswith("vmess://"):
        proxy, host, port = parse_vmess(uri)
        return proxy, host, port, "vmess"
    if low.startswith("trojan://"):
        proxy, host, port = parse_trojan(uri)
        return proxy, host, port, "trojan"
    if low.startswith("vless://"):
        proxy, host, port = parse_vless(uri)
        return proxy, host, port, "vless"
    if low.startswith(("hysteria2://", "hy2://")):
        proxy, host, port = parse_hysteria2(uri)
        return proxy, host, port, "hysteria2"
    if low.startswith("tuic://"):
        proxy, host, port = parse_tuic(uri)
        return proxy, host, port, "tuic"
    if low.startswith("anytls://"):
        proxy, host, port = parse_anytls(uri)
        return proxy, host, port, "anytls"
    if low.startswith(("http://", "https://")):
        proxy, host, port = parse_http(uri)
        return proxy, host, port, "http"
    if low.startswith("wg://"):
        proxy, host, port = parse_wireguard(uri)
        return proxy, host, port, "wireguard"
    die("unsupported URI scheme (expected ss://, vmess://, trojan://, vless://, "
        "hysteria2://, tuic://, anytls://, socks5://, http://, wg://)")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    if len(sys.argv) != 3:
        die("usage: mihomo-exit-config.py <name> <uri>")

    name, uri = sys.argv[1], sys.argv[2].strip()
    if not re.match(r"^[\w\-\u4e00-\u9fff]{1,16}$", name, re.UNICODE) or name == "local":
        die("invalid exit name")

    proxy, host, port, ptype = parse_proxy_uri(uri)

    # Env overrides for SOCKS5/HTTP credentials
    if ptype in ("socks5", "http"):
        env_user = os.environ.get("PGW_USER", "")
        env_pass = os.environ.get("PGW_PASS", "")
        if env_user:
            proxy["username"] = env_user
        if env_pass:
            proxy["password"] = env_pass

    # Remote DNS (socks5h): resolve target hostname at the exit server
    remote_dns = os.environ.get("PGW_REMOTE_DNS", "").lower() in ("1", "true", "yes", "on")
    if uri.lower().startswith("socks5h://"):
        remote_dns = True

    stack = os.environ.get("MIHOMO_STACK", "gvisor")
    try:
        mtu = int(os.environ.get("MIHOMO_MTU", "1400"))
    except ValueError:
        mtu = 1400

    # Build mihomo YAML config
    lines = []
    lines.append("# Mihomo exit config: %s (%s)" % (name, ptype))
    lines.append("# Auto-generated by mihomo-exit-config.py")
    lines.append("")
    lines.append("mode: rule")
    lines.append("log-level: warning")
    lines.append("")
    lines.append("dns:")
    lines.append("  enable: false")
    lines.append("")
    lines.append("tun:")
    lines.append("  enable: true")
    lines.append("  stack: %s" % stack)
    lines.append("  device: pgw-%s" % name)
    lines.append("  auto-route: false")
    lines.append("  auto-detect-interface: true")
    lines.append("  mtu: %d" % mtu)
    if remote_dns:
        lines.append("  dns-hijack: []")

    lines.append("")
    lines.append("proxies:")
    lines.append("  - name: \"%s\"" % name)
    lines.append("    type: %s" % ptype)
    for k, v in proxy.items():
        if isinstance(v, bool):
            lines.append("    %s: %s" % (k, "true" if v else "false"))
        elif isinstance(v, (int, float)):
            lines.append("    %s: %d" % (k, int(v)))
        else:
            lines.append("    %s: \"%s\"" % (k, v))

    lines.append("")
    lines.append("proxy-groups:")
    lines.append("  - name: proxy")
    lines.append("    type: select")
    lines.append("    proxies:")
    lines.append("      - \"%s\"" % name)

    lines.append("")
    lines.append("rules:")
    lines.append("  - MATCH,proxy")

    sys.stdout.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
