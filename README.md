# Sovereign Privacy Widget

**Cross-Platform Privacy Monitoring and Enforcement System**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/sovereign/widget)
[![Coq](https://img.shields.io/badge/proof-Coq-green.svg)](https://coq.inria.fr/)

## Overview

The Sovereign Privacy Widget is a formally verified, cross-platform privacy monitoring and enforcement system designed to protect users from unauthorized data access, hidden processes, and privacy violations. It operates at the kernel level to monitor system calls, network connections, and process behavior, providing real-time alerts and automatic blocking of violating processes.

### Key Features

- **Formally Verified Core**: STLC (Simply Typed Lambda Calculus) policy engine extracted from Coq proofs
- **Cross-Platform**: Linux (eBPF), macOS (Endpoint Security), Windows (WFP)
- **WebAssembly Runtime**: Portable execution environment for policy modules
- **UCAN Authorization**: Decentralized capability-based access control
- **IPFS Distribution**: Content-addressed, censorship-resistant distribution
- **Direct Framebuffer UI**: No dependency on OS GUI frameworks
- **Hidden Process Detection**: Cross-verification to detect rootkit-style hiding

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    User Interface Layer                      │
│              (Framebuffer / Console / IPC)                   │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                  Policy Enforcement Layer                    │
│         (STLC Core / UCAN / WebAssembly Runtime)             │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                Platform Monitoring Layer                     │
│    Linux eBPF / macOS ESF / Windows WFP / Seccomp BPF       │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                    Kernel / System Layer                     │
│         (Syscalls / Network Stack / Process Table)           │
└─────────────────────────────────────────────────────────────┘
```

## ABSOLUTE Architecture Blueprint

A detailed Russian-language architecture blueprint for the next-generation ABSOLUTE platform is available at:

- [`docs/ABSOLUTE_ARCHITECTURE_RU.md`](docs/ABSOLUTE_ARCHITECTURE_RU.md)

This document expands the current core into a deployment, trust, update, search, and audit-encyclopedia architecture with explicit legal/privacy constraints.

### Implemented ABSOLUTE Foundation Artifacts

The following concrete contracts/templates are now included under `absolute/` to move from blueprint to implementation:

- Event contract schema: `absolute/core/event-bus/absolute-event.schema.json`
- Terminal command interface (WIT): `absolute/apps/terminal/terminal.wit`
- UCAN capability taxonomy seed: `absolute/core/policy-engine/capabilities.json`
- Update trust scaffolding: `absolute/update/tuf/roles.json`, `absolute/update/rekor/rekor-entry-template.json`
- Vault format specification: `absolute/core/vault/vault-format.md`

### Working ABSOLUTE Runtime (No Stubs)

A runnable MVP runtime is available at `absolute/apps/guide/absolute_runtime.py` and includes:

- real unified-event validation against the machine-readable contract,
- real capability policy evaluation with deny-overrides,
- real whitelisted command execution with timeout and argument guardrails,
- real append-only hash-chained audit logging.

Quick start:

```bash
python absolute/apps/guide/absolute_runtime.py validate-event --event absolute/apps/guide/event.example.json
python absolute/apps/guide/absolute_runtime.py check-access --rules absolute/apps/guide/policies.example.json --capability filesystem:read --scope path:/workspace/ABSOLUTE/README.md
python absolute/apps/guide/absolute_runtime.py run-command --command-id show-date
python absolute/apps/guide/absolute_runtime.py append-audit --record absolute/apps/guide/audit-record.example.json
```

Run tests:

```bash
python -m unittest absolute.apps.guide.test_runtime -v
```

## Installation

### Prerequisites

**Linux:**
```bash
# Debian/Ubuntu
sudo apt-get install build-essential linux-headers-$(uname -r) clang libbpf-dev

# Fedora
sudo dnf install kernel-devel clang libbpf-devel

# Optional: libsodium for production crypto
sudo apt-get install libsodium-dev
```

**macOS:**
```bash
# Install Xcode Command Line Tools
xcode-select --install

# Install dependencies via Homebrew
brew install llvm libsodium
```

**Windows (Cross-compile from Linux):**
```bash
sudo apt-get install mingw-w64
```

### Building from Source

```bash
# Clone repository
git clone https://github.com/sovereign/widget.git
cd sovereign-widget

# Build debug version
./build.sh debug

# Build optimized release
./build.sh release

# Run tests
./build.sh test

# Install system-wide (requires root)
sudo ./build.sh install
```

### Binary Installation

Pre-built binaries are available for:
- Linux x86_64 (with eBPF support)
- Linux ARM64
- macOS x86_64
- macOS ARM64 (Apple Silicon)
- Windows x86_64

Download from [Releases](https://github.com/sovereign/widget/releases)

## Usage

### Basic Usage

```bash
# Run in foreground with UI
sudo sovereign-widget --notify

# Run as daemon
sudo sovereign-widget --daemon

# Monitor specific process
sudo sovereign-widget --pid 1234 --notify

# Block mode (terminate violations)
sudo sovereign-widget --block --notify
```

### Configuration

Create `/etc/sovereign-widget/sovereign-widget.conf`:

```ini
[logging]
level = info
file = /var/log/sovereign-widget/sovereign-widget.log
max_size_mb = 100
rotation_count = 5

[daemon]
enabled = false

[ui]
enabled = true

[monitoring]
ebpf = true
wasm = true
ucan = true
event_buffer_size = 10000

[policy]
file = /etc/sovereign-widget/policy.json
ontology_file = /etc/sovereign-widget/ontology.json
refresh_interval_sec = 300

[enforcement]
block_unknown = false
alert_on_violation = true
auto_block_violations = false
```

### Systemd Service (Linux)

```bash
# Enable auto-start
sudo systemctl enable sovereign-widget

# Start service
sudo systemctl start sovereign-widget

# Check status
sudo systemctl status sovereign-widget

# View logs
sudo journalctl -u sovereign-widget -f
```

## Policy Language

Policies are written in a domain-specific language based on Simply Typed Lambda Calculus:

```json
{
  "version": "1.0",
  "policies": [
    {
      "name": "block_unknown_camera_access",
      "description": "Block camera access from unknown processes",
      "rule": {
        "resource": "camera",
        "action": "access",
        "condition": {
          "not": {
            "has_capability": "camera:read"
          }
        },
        "effect": "deny"
      }
    },
    {
      "name": "alert_network_connections",
      "description": "Alert on suspicious network connections",
      "rule": {
        "resource": "network",
        "action": "connect",
        "condition": {
          "remote_port": {
            "in": [4444, 5555, 6666]
          }
        },
        "effect": "alert"
      }
    }
  ]
}
```

## UCAN Authorization

The widget uses UCAN (User-Controlled Authorization Networks) for decentralized capability delegation:

```bash
# Generate owner DID
sovereign-widget --generate-did

# Delegate capability to application
sovereign-widget --delegate \
  --to did:key:z6MkhaXg... \
  --capability "filesystem:read:/home/user/documents" \
  --expiry 86400

# Revoke delegation
sovereign-widget --revoke did:key:z6MkhaXg...
```

## WebAssembly Modules

Policy modules can be distributed as WebAssembly for cross-platform execution:

```bash
# Load custom policy module
sovereign-widget --wasm policy_module.wasm

# Fetch policy from IPFS
sovereign-widget --cid QmXxxx...
```

## API

### C API

```c
#include <sovereign/widget.h>

// Initialize widget
widget_t* widget = widget_init();

// Set violation callback
widget_on_violation(widget, my_callback);

// Add policy
widget_add_policy(widget, policy_json);

// Start monitoring
widget_start(widget);

// Cleanup
widget_destroy(widget);
```

### IPC Interface

The widget exposes a Unix socket for external control:

```bash
# Query status
echo '{"cmd": "status"}' | nc -U /var/run/sovereign-widget.sock

# Add temporary policy
echo '{"cmd": "add_policy", "policy": {...}}' | nc -U /var/run/sovereign-widget.sock

# Get process list
echo '{"cmd": "list_processes"}' | nc -U /var/run/sovereign-widget.sock
```

## Security Considerations

### Threat Model

The widget protects against:
- Unauthorized access to sensitive resources (camera, microphone, location)
- Hidden processes and rootkits
- Certificate pinning violations
- Network exfiltration
- Process injection

### Limitations

- Requires root/administrator privileges for kernel monitoring
- Cannot protect against hardware-level attacks
- Limited protection against kernel-level rootkits
- Framebuffer UI may not work on all systems

### Formal Verification

The STLC core has been formally verified in Coq:

```coq
Theorem preservation : forall Gamma t t' T,
  Gamma |- t : T ->
  t --> t' ->
  Gamma |- t' : T.

Theorem progress : forall Gamma t T,
  Gamma |- t : T ->
  value t \/ exists t', t --> t'.
```

## Development

### Project Structure

```
sovereign-widget/
├── core/              # STLC policy engine (Coq-extracted)
├── platform/          # Platform-specific implementations
│   ├── linux/         # eBPF, seccomp
│   ├── macos/         # Endpoint Security
│   └── windows/       # WFP
├── wasm/              # WebAssembly runtime
├── ucan/              # UCAN authorization
├── ui/                # Framebuffer UI
├── enforcement/       # Process blocking
├── distribution/      # IPFS distribution
├── utils/             # Utilities
└── main.c             # Main entry point
```

### Running Tests

```bash
# Run all tests
./build.sh test

# Run specific test
make test TEST=stlc_types

# Memory safety check
valgrind --leak-check=full ./sovereign-widget --help
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

Please ensure:
- Code follows the existing style
- Tests pass
- New features include tests
- Documentation is updated

## License

MIT License - See [LICENSE](LICENSE) for details

## Acknowledgments

- Coq proof assistant for formal verification
- eBPF community for kernel tracing infrastructure
- WebAssembly community for portable execution
- IPFS community for decentralized distribution
- UCAN working group for capability authorization

## Disclaimer

This software is provided as-is for privacy protection and research purposes. Users are responsible for complying with local laws and regulations. The authors assume no liability for misuse or damages arising from use of this software.

## Contact

- GitHub: https://github.com/sovereign/widget
- Matrix: #sovereign:matrix.org
- Email: contact@sovereign-privacy.org

---

**Protect your digital sovereignty.**
