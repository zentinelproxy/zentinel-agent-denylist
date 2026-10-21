<p align="center">
  <a href="https://zentinelproxy.io">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-dark.svg">
      <img alt="Zentinel" src="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-light.svg" height="52">
    </picture>
  </a>
</p>

<h3 align="center">Denylist agent</h3>

<p align="center">Blocks requests by client IP or CIDR range, path prefix or User-Agent, on the request headers.</p>

<p align="center">
  <a href="https://github.com/zentinelproxy/zentinel-agent-denylist/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/zentinelproxy/zentinel-agent-denylist/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-9b4d8a?style=flat&amp;labelColor=1f161e">
  <img alt="Rust 1.94.1+" src="https://img.shields.io/badge/rust-1.94.1%2B-f68d31?style=flat&amp;labelColor=1f161e&amp;logo=rust&amp;logoColor=white">
  <img alt="Agent protocol v2" src="https://img.shields.io/badge/agent%20protocol-v2-f68d31?style=flat&amp;labelColor=1f161e">
</p>

<p align="center">
  <a href="https://registry.zentinelproxy.io/denylist/">Registry</a> &middot;
  <a href="https://docs.zentinelproxy.io">Docs</a> &middot;
  <a href="https://github.com/zentinelproxy">All repositories</a>
</p>

A small, static denylist for operators who need to shut out known-bad clients,
paths or tools without writing a WAF rule. The agent receives each request's
headers and answers `403 Forbidden` when the client IP, the path or the
User-Agent matches a rule, and allows everything else. An allowlist of IPs and
ranges takes precedence over IP deny rules, so a default-deny setup is one flag
away. If the agent is unreachable, the filter's `failure-mode` decides: `closed`
(as below) rejects the request, `open` forwards it unchecked.

## Quick start

```bash
zentinel bundle install denylist

zentinel-denylist-agent --socket /tmp/zentinel-denylist.sock \
  --block-ips "192.0.2.10,198.51.100.0/24" \
  --block-paths "/admin,/.env,/.git" \
  --block-user-agents "sqlmap,nikto"
```

```kdl
system {
    worker-threads 0
}

listeners {
    listener "http" {
        address "0.0.0.0:8080"
        protocol "http"
    }
}

upstreams {
    upstream "backend" {
        target "127.0.0.1:3000"
    }
}

agents {
    agent "denylist" type="custom" {
        unix-socket "/tmp/zentinel-denylist.sock"
        events "request_headers"
        timeout-ms 100
    }
}

filters {
    filter "denylist" {
        type "agent"
        agent "denylist"
        failure-mode "closed"
    }
}

routes {
    route "default" {
        matches { path-prefix "/" }
        upstream "backend"
        filters "denylist"
    }
}
```

```bash
zentinel test -c zentinel.kdl
zentinel -c zentinel.kdl
```

## Install

### Bundle (recommended)

```bash
zentinel bundle install denylist
```

Downloads the release binary pinned in Zentinel's bundle lock and installs it as `zentinel-denylist-agent`. See [Bundle installation](https://docs.zentinelproxy.io/deployment/bundle/).

### Release binaries

Tarballs for `linux-x86_64`, `linux-aarch64` and `darwin-aarch64` are attached to each [release](https://github.com/zentinelproxy/zentinel-agent-denylist/releases):

```bash
VERSION=0.3.0
PLATFORM=linux-x86_64   # or linux-aarch64, darwin-aarch64
curl -fsSL -o zentinel-denylist-agent.tar.gz \
  "https://github.com/zentinelproxy/zentinel-agent-denylist/releases/download/v${VERSION}/zentinel-denylist-agent-${VERSION}-${PLATFORM}.tar.gz"
tar -xzf zentinel-denylist-agent.tar.gz
sudo install -m 0755 zentinel-denylist-agent /usr/local/bin/
```

### From source

```bash
cargo install --git https://github.com/zentinelproxy/zentinel-agent-denylist
```

Installs `zentinel-denylist-agent`. Needs Rust 1.94.1 or later and `protoc` (the agent protocol crate compiles its gRPC definitions).

## Configuration

The agent is configured with command-line flags; it reads no config file.
List flags take comma-separated values.

| Option | Default | Meaning |
|---|---|---|
| `-s`, `--socket` | `/tmp/zentinel-denylist.sock` | Unix socket to listen on. Ignored when `--grpc-address` is set. |
| `--grpc-address` | none | Listen for gRPC on this address (for example `0.0.0.0:50051`) instead of the Unix socket. |
| `--block-ips` | none | IP addresses or CIDR ranges to block. Invalid entries are skipped with a warning. |
| `--allow-ips` | none | IP addresses or CIDR ranges that are never blocked by an IP rule, even if they match `--block-ips`. |
| `--block-paths` | none | Path prefixes to block. Case-sensitive prefix match on the request URI. |
| `--block-user-agents` | none | Substrings to block in the `User-Agent` header. Case-insensitive. |
| `-v`, `--verbose` | off | Log at `debug`. Without it the log level comes from `RUST_LOG` (default `info`). |

The agent also accepts the same lists over the protocol (`on_configure`, keys
`block-ips`, `allow-ips`, `block-paths`, `block-user-agents`), but Zentinel
0.6.50 does not forward an `agent { config { ... } }` block, so set them here.

Full reference: <https://registry.zentinelproxy.io/denylist/>

### Default deny

Block both address families and allow only what should get through:

```bash
zentinel-denylist-agent \
  --block-ips "0.0.0.0/0,::/0" \
  --allow-ips "203.0.113.10,198.51.100.0/24"
```

## How it works

For each request the agent checks, in order, and stops at the first match:

1. **Client IP.** Plain addresses (`192.0.2.10`, `2001:db8::1`) and CIDR ranges
   (`192.0.2.0/24`, `2001:db8::/32`) are accepted. An `--allow-ips` match wins
   over any `--block-ips` match. IPv4 and IPv6 are separate: `0.0.0.0/0` covers
   IPv4 only, add `::/0` for IPv6.
2. **Path.** The request URI starts with a `--block-paths` entry. The URI
   includes the query string; entries are compared as given, without
   normalization.
3. **User-Agent.** The first `User-Agent` value contains a
   `--block-user-agents` entry, ignoring case.

`--allow-ips` exempts an address from IP rules only; path and User-Agent rules
still apply to it. A blocked request gets `403 Forbidden` with a plain-text
body naming the rule (for example `IP 192.0.2.10 is blocked`), and the reason
is attached as `deny_reason` routing metadata. Rules are fixed at startup;
restart the agent to change them. The agent reports
`denylist_requests_total` and `denylist_requests_blocked_total` through the
protocol's metrics.

## Development

```bash
cargo build
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

Needs Rust 1.94.1 or later (`rust-version` in `Cargo.toml`) and `protoc`.

```bash
cargo run -- --socket /tmp/zentinel-denylist.sock --block-ips 127.0.0.1 --verbose
```

## Related

- [Registry page](https://registry.zentinelproxy.io/denylist/)
- [Agent configuration](https://docs.zentinelproxy.io/configuration/agents/)
- [Agent protocol v2](https://docs.zentinelproxy.io/agents/v2/)
- [Zentinel](https://github.com/zentinelproxy/zentinel)
- [IP reputation agent](https://github.com/zentinelproxy/zentinel-agent-ip-reputation), for blocklists fetched from threat feeds

## License

Apache-2.0, see [`LICENSE`](LICENSE).

---

<p align="center">
  <sub>Part of <a href="https://zentinelproxy.io">Zentinel</a>, the security-first reverse proxy. The shisa guards the gate.</sub>
</p>
