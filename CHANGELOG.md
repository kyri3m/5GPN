# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Smart routing with per-domain exit selection (DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, IP-CIDR, GEOSITE, GEOIP, RULE-SET)
- QUIC/HTTP3 transparent proxy (cmd/quic-proxy/, pure Go stdlib, zero external deps)
- China DNS race proxy with UDP/TCP fallback (cmd/china-dns-race-proxy/)
- Telegram Bot management interface (tgbot.py)
- Multi-protocol exit support: WireGuard, SOCKS5, Shadowsocks, VMess, Trojan, VLESS, Hysteria2, TUIC, AnyTLS, HTTP/HTTPS
- Firewall management via Telegram Bot (nftables port allow/deny + port notes)
- GFWList management via Telegram Bot (add/remove extra proxy domains)
- iOS DoT profile generation and QR code
- Low-memory mode (auto-detect ≤1GB RAM)
- Policy-based test suite (28 test scripts)

### Changed
- Project directory structure: migrated from `/opt/proxy-gateway` to configurable `BASE_DIR`
- Path references unified under `BASE_DIR` environment variable
- Systemd units use `${BASE_DIR}` template variables

### Fixed
- GitHub token removed from git remote URL
- Hardcoded `/opt/proxy-gateway` paths replaced with configurable defaults
- Stale repository URLs updated in POST.md

## [0.1.0] - 2026-07-01

### Initial Release
- dnsdist DNS over TLS (DoT) with GFWList/ChinaList domain routing
- sniproxy TCP transparent proxy (HTTP/HTTPS)
- WireGuard exit node support
- Basic install.sh management script
- Multi-distro support (Ubuntu, Debian, CentOS, RHEL, Fedora, AlmaLinux, Rocky Linux)
