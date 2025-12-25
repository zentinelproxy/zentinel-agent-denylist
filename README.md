# sentinel-agent-denylist

IP and pattern-based blocking agent for [Sentinel](https://github.com/raskell-io/sentinel) reverse proxy.

## Features

- Block requests by client IP address
- Block requests by URL path prefix
- Block requests by User-Agent pattern
- Real-time blocking with no restart required
- Configurable via CLI or config file

## Installation

### From crates.io

```bash
cargo install sentinel-agent-denylist
```

### From source

```bash
git clone https://github.com/raskell-io/sentinel-agent-denylist
cd sentinel-agent-denylist
cargo build --release
```

## Usage

```bash
sentinel-denylist-agent --socket /var/run/sentinel/denylist.sock \
  --block-ips "192.168.1.100,10.0.0.1" \
  --block-paths "/admin,/wp-admin" \
  --block-user-agents "bot,scanner"
```

### Command Line Options

| Option | Environment Variable | Description | Default |
|--------|---------------------|-------------|---------|
| `--socket` | `AGENT_SOCKET` | Unix socket path | `/tmp/sentinel-denylist.sock` |
| `--block-ips` | - | Comma-separated IPs to block | - |
| `--block-paths` | - | Comma-separated path prefixes to block | - |
| `--block-user-agents` | - | Comma-separated User-Agent patterns to block | - |
| `--verbose` | `RUST_LOG` | Enable verbose logging | `false` |

## Configuration

### Sentinel Proxy Configuration

Add to your Sentinel `config.kdl`:

```kdl
agents {
    agent "denylist" {
        type "custom"
        transport "unix_socket" {
            path "/var/run/sentinel/denylist.sock"
        }
        events ["request_headers"]
        timeout-ms 10
        failure-mode "open"
    }
}

routes {
    route "all" {
        matches { path-prefix "/" }
        upstream "backend"
        agents ["denylist"]
    }
}
```

## Response

When a request is blocked, the agent returns:
- **HTTP 403 Forbidden**
- Body with the block reason

## Example Scenarios

### Block known bad IPs

```bash
sentinel-denylist-agent \
  --block-ips "1.2.3.4,5.6.7.8,192.168.0.0/24"
```

### Block admin paths

```bash
sentinel-denylist-agent \
  --block-paths "/admin,/wp-admin,/.env,/.git"
```

### Block malicious bots

```bash
sentinel-denylist-agent \
  --block-user-agents "sqlmap,nikto,nessus,acunetix"
```

## Development

```bash
# Run with debug logging
RUST_LOG=debug cargo run -- --socket /tmp/test.sock --block-ips "127.0.0.1"

# Run tests
cargo test
```

## License

MIT OR Apache-2.0
