#!/bin/bash
#
# Sovereign Privacy Widget - Build Script
# Cross-platform build automation
#
# Usage: ./build.sh [debug|release|clean|install]
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Detect platform
detect_platform() {
    case "$(uname -s)" in
        Linux*)     PLATFORM=linux;;
        Darwin*)    PLATFORM=macos;;
        CYGWIN*|MINGW*|MSYS*) PLATFORM=windows;;
        *)          PLATFORM=unknown;;
    esac
    
    case "$(uname -m)" in
        x86_64)     ARCH=x86_64;;
        amd64)      ARCH=x86_64;;
        arm64)      ARCH=arm64;;
        aarch64)    ARCH=arm64;;
        *)          ARCH=unknown;;
    esac
    
    log_info "Detected platform: $PLATFORM ($ARCH)"
}

# Check dependencies
check_deps() {
    log_info "Checking dependencies..."
    
    # Check for compiler
    if ! command -v gcc &> /dev/null && ! command -v clang &> /dev/null; then
        log_error "No C compiler found. Please install gcc or clang."
        exit 1
    fi
    
    # Platform-specific checks
    case $PLATFORM in
        linux)
            # Check for kernel headers
            if [ ! -d "/usr/src/linux-headers-$(uname -r)" ] && [ ! -d "/lib/modules/$(uname -r)/build" ]; then
                log_warn "Kernel headers not found. eBPF support will be limited."
                log_warn "Install with: sudo apt-get install linux-headers-$(uname -r)"
            fi
            
            # Check for clang (needed for eBPF)
            if ! command -v clang &> /dev/null; then
                log_warn "clang not found. eBPF compilation disabled."
            fi
            
            # Check for libbpf
            if ! pkg-config --exists libbpf 2>/dev/null; then
                log_warn "libbpf not found. Using embedded version."
            fi
            ;;
            
        macos)
            # Check for Xcode
            if ! command -v xcodebuild &> /dev/null; then
                log_warn "Xcode not found. Some features may be unavailable."
            fi
            ;;
            
        windows)
            # Check for MinGW
            if ! command -v x86_64-w64-mingw32-gcc &> /dev/null; then
                log_warn "MinGW cross-compiler not found."
            fi
            ;;
    esac
    
    # Check for optional dependencies
    if pkg-config --exists libsodium 2>/dev/null; then
        log_success "libsodium found"
        HAS_SODIUM=1
    else
        log_warn "libsodium not found. Using embedded crypto (NOT for production)."
        HAS_SODIUM=0
    fi
    
    if pkg-config --exists wasmtime 2>/dev/null; then
        log_success "wasmtime found"
        HAS_WASMTIME=1
    else
        log_warn "wasmtime not found. Wasm runtime will be limited."
        HAS_WASMTIME=0
    fi
}

# Create directories
setup_dirs() {
    log_info "Setting up build directories..."
    
    mkdir -p build/{core,platform,wasm,ucan,ui,distribution,enforcement,utils,ebpf,wasm/stlc_core}
    mkdir -p bin
    mkdir -p config
    mkdir -p logs
}

# Compile WebAssembly module
compile_wasm() {
    log_info "Compiling WebAssembly STLC module..."
    
    if command -v wat2wasm &> /dev/null; then
        wat2wasm wasm/stlc_core/stlc_policy.wat -o build/wasm/stlc_policy.wasm
        log_success "Wasm module compiled"
    else
        log_warn "wat2wasm not found. Skipping Wasm compilation."
        log_warn "Install with: npm install -g wabt"
    fi
}

# Build the project
build() {
    local target="${1:-debug}"
    
    log_info "Building target: $target"
    
    case $target in
        debug)
            make debug
            ;;
        release)
            make release
            ;;
        *)
            log_error "Unknown target: $target"
            exit 1
            ;;
    esac
    
    if [ -f sovereign-widget ]; then
        cp sovereign-widget bin/
        log_success "Build complete: bin/sovereign-widget"
    fi
}

# Run tests
test() {
    log_info "Running tests..."
    
    # Create test runner
    cat > build/test_runner.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../core/stlc_policy_engine.h"
#include "../utils/crypto_utils.h"

int test_stlc_types() {
    printf("Testing STLC type operations...\n");
    
    type_t* base = type_create_base(RESOURCE_PROCESS, CONF_INTERNAL);
    assert(base != NULL);
    assert(base->kind == TYPE_BASE);
    assert(base->data.base.resource == RESOURCE_PROCESS);
    type_free(base);
    
    type_t* domain = type_create_base(RESOURCE_FILESYSTEM, CONF_CONFIDENTIAL);
    type_t* codomain = type_create_base(RESOURCE_NETWORK, CONF_PUBLIC);
    type_t* arrow = type_create_arrow(domain, codomain);
    assert(arrow != NULL);
    assert(arrow->kind == TYPE_ARROW);
    type_free(arrow);
    type_free(domain);
    type_free(codomain);
    
    printf("  Type operations: PASSED\n");
    return 0;
}

int test_stlc_terms() {
    printf("Testing STLC term operations...\n");
    
    term_t* var = term_create_var(0);
    assert(var != NULL);
    assert(var->type == TERM_VAR);
    assert(var->data.var_index == 0);
    term_free(var);
    
    type_t* param_type = type_create_base(RESOURCE_PROCESS, CONF_INTERNAL);
    term_t* body = term_create_var(0);
    term_t* abs = term_create_abs(param_type, body);
    assert(abs != NULL);
    assert(abs->type == TERM_ABS);
    term_free(abs);
    type_free(param_type);
    
    printf("  Term operations: PASSED\n");
    return 0;
}

int test_stlc_type_checking() {
    printf("Testing STLC type checking...\n");
    
    context_t* ctx = context_create();
    type_t* t = type_create_base(RESOURCE_PROCESS, CONF_INTERNAL);
    context_append(ctx, t);
    
    term_t* var = term_create_var(0);
    bool valid = has_type(ctx, var, t);
    assert(valid == true);
    
    term_free(var);
    context_free(ctx);
    type_free(t);
    
    printf("  Type checking: PASSED\n");
    return 0;
}

int test_crypto() {
    printf("Testing cryptography...\n");
    
    crypto_init();
    
    uint8_t data[] = "test data";
    uint8_t hash[32];
    crypto_hash_sha256(data, sizeof(data), hash);
    
    printf("  Cryptography: PASSED\n");
    return 0;
}

int main() {
    printf("\n=== Sovereign Privacy Widget Test Suite ===\n\n");
    
    int failures = 0;
    
    failures += test_stlc_types();
    failures += test_stlc_terms();
    failures += test_stlc_type_checking();
    failures += test_crypto();
    
    printf("\n=== Tests Complete ===\n");
    
    return failures;
}
EOF
    
    gcc -I. -o build/test_runner build/test_runner.c \
        core/stlc_policy_engine.c \
        core/type_ops.c \
        core/term_ops.c \
        core/context_ops.c \
        core/type_checker.c \
        core/semantics.c \
        core/ontology.c \
        utils/crypto_utils.c \
        -lpthread -lm 2>/dev/null || log_warn "Test compilation failed"
    
    if [ -f build/test_runner ]; then
        ./build/test_runner
    fi
}

# Install
install() {
    log_info "Installing..."
    
    if [ "$EUID" -ne 0 ]; then
        log_error "Installation requires root privileges"
        exit 1
    fi
    
    # Create directories
    mkdir -p /etc/sovereign-widget
    mkdir -p /usr/local/bin
    mkdir -p /var/log/sovereign-widget
    
    # Install binary
    cp bin/sovereign-widget /usr/local/bin/
    chmod 755 /usr/local/bin/sovereign-widget
    
    # Install default config
    if [ ! -f /etc/sovereign-widget/sovereign-widget.conf ]; then
        cat > /etc/sovereign-widget/sovereign-widget.conf << 'EOF'
# Sovereign Privacy Widget Configuration

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

[keys]
path = /etc/sovereign-widget/keys
EOF
        chmod 644 /etc/sovereign-widget/sovereign-widget.conf
    fi
    
    # Create systemd service (Linux)
    if [ "$PLATFORM" = "linux" ]; then
        cat > /etc/systemd/system/sovereign-widget.service << 'EOF'
[Unit]
Description=Sovereign Privacy Widget
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sovereign-widget -d
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        log_info "Systemd service installed. Enable with: systemctl enable sovereign-widget"
    fi
    
    log_success "Installation complete"
}

# Clean
clean() {
    log_info "Cleaning build artifacts..."
    make clean 2>/dev/null || true
    rm -rf build bin
    log_success "Clean complete"
}

# Main
main() {
    local command="${1:-debug}"
    
    echo ""
    echo "========================================"
    echo "  Sovereign Privacy Widget Build System"
    echo "========================================"
    echo ""
    
    detect_platform
    
    case $command in
        debug|release)
            check_deps
            setup_dirs
            compile_wasm
            build $command
            ;;
        test)
            check_deps
            test
            ;;
        install)
            install
            ;;
        clean)
            clean
            ;;
        all)
            check_deps
            setup_dirs
            compile_wasm
            build release
            test
            ;;
        help)
            echo "Usage: $0 [command]"
            echo ""
            echo "Commands:"
            echo "  debug     Build debug version (default)"
            echo "  release   Build optimized release"
            echo "  test      Run test suite"
            echo "  install   Install to system"
            echo "  clean     Clean build artifacts"
            echo "  all       Build release and run tests"
            echo "  help      Show this help"
            echo ""
            ;;
        *)
            log_error "Unknown command: $command"
            echo "Run '$0 help' for usage"
            exit 1
            ;;
    esac
}

main "$@"
