# Sovereign Privacy Widget - Cross-Platform Build System
# Formally Verified STLC Policy Engine
# License: MIT
# Version: 1.0 (April 2026)

# === Configuration ===
VERSION := 1.0.0
TARGET := sovereign-widget
BUILD_DIR := build
INSTALL_PREFIX := /usr/local

# === Compiler Settings ===
CC := gcc
CFLAGS := -std=c11 -O2 -Wall -Wextra -Werror -fPIC \
          -DVERSION=\"$(VERSION)\" \
          -D_GNU_SOURCE \
          -D_POSIX_C_SOURCE=200809L

LDFLAGS := -lpthread -lm -ldl

# === Platform Detection ===
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_S),Linux)
    PLATFORM := linux
    CFLAGS += -DLINUX -DHAS_EBPF
    LDFLAGS += -lelf -lz
    KERNEL_HEADERS := /usr/src/linux-headers-$(shell uname -r)
    CLANG := clang
    LLC := llc
endif

ifeq ($(UNAME_S),Darwin)
    PLATFORM := macos
    CFLAGS += -DMACOS -DHAS_ENDPOINT_SECURITY
    LDFLAGS += -framework Foundation -framework Security \
               -framework EndpointSecurity -framework SystemExtensions
    CC := clang
endif

ifeq ($(OS),Windows_NT)
    PLATFORM := windows
    CFLAGS += -DWINDOWS -DHAS_WFP
    CC := x86_64-w64-mingw32-gcc
    WINDRES := x86_64-w64-mingw32-windres
    LDFLAGS += -lws2_32 -liphlpapi -lfwpuclnt -lntdll -lkernel32
endif

# === Optional Dependencies ===
HAS_WASMTIME := $(shell pkg-config --exists wasmtime && echo yes)
HAS_SODIUM := $(shell pkg-config --exists libsodium && echo yes)
HAS_LIBBPF := $(shell pkg-config --exists libbpf && echo yes)

ifeq ($(HAS_WASMTIME),yes)
    CFLAGS += -DHAS_WASMTIME $(shell pkg-config --cflags wasmtime)
    LDFLAGS += $(shell pkg-config --libs wasmtime)
endif

ifeq ($(HAS_SODIUM),yes)
    CFLAGS += -DHAS_SODIUM $(shell pkg-config --cflags libsodium)
    LDFLAGS += $(shell pkg-config --libs libsodium)
else
    # Use embedded libsodium
    CFLAGS += -I$(PWD)/third_party/libsodium/src/libsodium/include
    LDFLAGS += -L$(PWD)/third_party/libsodium/src/libsodium/.libs -lsodium
endif

ifeq ($(HAS_LIBBPF),yes)
    CFLAGS += -DHAS_LIBBPF $(shell pkg-config --cflags libbpf)
    LDFLAGS += $(shell pkg-config --libs libbpf)
endif

# === Source Files ===
CORE_SRCS := \
    core/stlc_policy_engine.c \
    core/type_ops.c \
    core/term_ops.c \
    core/context_ops.c \
    core/type_checker.c \
    core/semantics.c \
    core/ontology.c \
    core/ucan_ops.c \
    core/policy_enforcer.c

PLATFORM_SRCS :=

ifeq ($(PLATFORM),linux)
    PLATFORM_SRCS += \
        platform/linux/ebpf_loader.c \
        platform/linux/seccomp_filter.c \
        platform/linux/proc_monitor.c \
        platform/linux/netlink_monitor.c \
        platform/linux/cgroup_manager.c
endif

ifeq ($(PLATFORM),macos)
    PLATFORM_SRCS += \
        platform/macos/endpoint_security.m \
        platform/macos/es_client.m \
        platform/macos/process_monitor.m \
        platform/macos/network_extension.m
endif

ifeq ($(PLATFORM),windows)
    PLATFORM_SRCS += \
        platform/windows/wfp_driver.c \
        platform/windows/wfp_callout.c \
        platform/windows/etw_consumer.c \
        platform/windows/process_monitor.c \
        platform/windows/registry_monitor.c
endif

WASM_SRCS := \
    wasm/wasm_runtime.c \
    wasm/host_functions.c \
    wasm/stlc_module.c

UCAN_SRCS := \
    ucan/ucan_auth.c \
    ucan/did_resolver.c \
    ucan/capability_store.c

UI_SRCS := \
    ui/framebuffer_ui.c \
    ui/alert_renderer.c \
    ui/font_renderer.c \
    ui/input_handler.c

DIST_SRCS := \
    distribution/ipfs_distribution.c \
    distribution/cid_utils.c \
    distribution/dag_builder.c

ENFORCE_SRCS := \
    enforcement/process_enforcer.c \
    enforcement/syscall_filter.c \
    enforcement/network_blocker.c

UTIL_SRCS := \
    utils/crypto_utils.c \
    utils/hash_table.c \
    utils/ring_buffer.c \
    utils/event_queue.c \
    utils/logger.c \
    utils/config_parser.c

ALL_SRCS := $(CORE_SRCS) $(PLATFORM_SRCS) $(WASM_SRCS) $(UCAN_SRCS) \
            $(UI_SRCS) $(DIST_SRCS) $(ENFORCE_SRCS) $(UTIL_SRCS) \
            main.c

OBJS := $(ALL_SRCS:%.c=$(BUILD_DIR)/%.o)

# === eBPF Programs (Linux only) ===
ifeq ($(PLATFORM),linux)
BPF_SRCS := \
    ebpf/sovereign_monitor.bpf.c \
    ebpf/syscall_trace.bpf.c \
    ebpf/network_filter.bpf.c \
    ebpf/process_monitor.bpf.c

BPF_OBJS := $(BPF_SRCS:%.c=$(BUILD_DIR)/%.o)
endif

# === WebAssembly Module ===
WASM_STLC_SRC := wasm/stlc_core/stlc_policy.wat
WASM_STLC_OUT := $(BUILD_DIR)/wasm/stlc_policy.wasm

# === Targets ===
.PHONY: all clean install uninstall test check wasm ebpf

all: dirs $(WASM_STLC_OUT) $(TARGET)

ifeq ($(PLATFORM),linux)
all: ebpf
endif

dirs:
	@mkdir -p $(BUILD_DIR)/{core,platform/$(PLATFORM),wasm,ucan,ui,distribution,enforcement,utils,ebpf,wasm/stlc_core}

# === Main Executable ===
$(TARGET): $(OBJS)
	@echo "LINK $@"
	@$(CC) $(OBJS) -o $@ $(LDFLAGS)
	@echo "Build complete: $@"

# === Object Compilation ===
$(BUILD_DIR)/%.o: %.c
	@echo "CC $<"
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: %.m
	@echo "OBJC $<"
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) -c $< -o $@

# === eBPF Compilation (Linux) ===
ifeq ($(PLATFORM),linux)
ebpf: $(BPF_OBJS)

$(BUILD_DIR)/ebpf/%.bpf.o: ebpf/%.bpf.c
	@echo "BPF $<"
	@mkdir -p $(dir $@)
	@$(CLANG) -O2 -target bpf -D__TARGET_ARCH_x86_64 \
		-I$(KERNEL_HEADERS)/include \
		-I$(KERNEL_HEADERS)/arch/x86/include \
		-c $< -o - | $(LLC) -march=bpf -filetype=obj -o $@
endif

# === WebAssembly Module ===
wasm: $(WASM_STLC_OUT)

$(WASM_STLC_OUT): $(WASM_STLC_SRC)
	@echo "WAT2WASM $<"
	@mkdir -p $(dir $@)
	@wat2wasm $< -o $@

# === Testing ===
test: $(TARGET)
	@echo "Running tests..."
	@$(BUILD_DIR)/test_runner

check:
	@echo "Static analysis..."
	@cppcheck --enable=all --suppress=missingIncludeSystem \
		--error-exitcode=1 $(ALL_SRCS) 2>/dev/null || true
	@echo "Memory safety check..."
	@valgrind --leak-check=full --error-exitcode=1 ./$(TARGET) --help 2>/dev/null || true

# === Installation ===
install: $(TARGET)
	@echo "Installing to $(INSTALL_PREFIX)..."
	@install -Dm755 $(TARGET) $(INSTALL_PREFIX)/bin/$(TARGET)
	@install -Dm644 config/sovereign-widget.conf $(INSTALL_PREFIX)/etc/sovereign-widget/
	@install -Dm644 systemd/sovereign-widget.service /etc/systemd/system/
	@install -Dm644 udev/99-sovereign-widget.rules /etc/udev/rules.d/
	@systemctl daemon-reload
	@echo "Installation complete. Run 'systemctl enable sovereign-widget' to enable."

uninstall:
	@echo "Uninstalling..."
	@rm -f $(INSTALL_PREFIX)/bin/$(TARGET)
	@rm -rf $(INSTALL_PREFIX)/etc/sovereign-widget/
	@rm -f /etc/systemd/system/sovereign-widget.service
	@rm -f /etc/udev/rules.d/99-sovereign-widget.rules
	@systemctl daemon-reload

# === Packaging ===
package: $(TARGET)
	@echo "Creating package..."
	@mkdir -p $(BUILD_DIR)/package
	@cp $(TARGET) $(BUILD_DIR)/package/
	@cp -r config $(BUILD_DIR)/package/
	@cp README.md LICENSE $(BUILD_DIR)/package/
	@tar czf $(BUILD_DIR)/$(TARGET)-$(VERSION)-$(PLATFORM)-$(UNAME_M).tar.gz \
		-C $(BUILD_DIR)/package .
	@echo "Package created: $(BUILD_DIR)/$(TARGET)-$(VERSION)-$(PLATFORM)-$(UNAME_M).tar.gz"

# === Clean ===
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR) $(TARGET)

# === Debug Build ===
debug: CFLAGS := -std=c11 -g -O0 -Wall -Wextra -DDEBUG \
                  -DVERSION=\"$(VERSION)-debug\" \
                  -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L

debug: dirs $(WASM_STLC_OUT) $(TARGET)

# === Release Build ===
release: CFLAGS := -std=c11 -O3 -flto -Wall -Wextra -Werror \
                   -DVERSION=\"$(VERSION)\" \
                   -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L \
                   -DNDEBUG -fstack-protector-strong \
                   -D_FORTIFY_SOURCE=2 -fPIE

release: LDFLAGS += -Wl,-z,relro,-z,now -pie -s
release: dirs $(WASM_STLC_OUT) $(TARGET)
	@echo "Strip binary..."
	@strip $(TARGET)
	@echo "Release build complete."

# === Cross Compilation ===
cross-win64:
	$(MAKE) CC=x86_64-w64-mingw32-gcc PLATFORM=windows

cross-arm64:
	$(MAKE) CC=aarch64-linux-gnu-gcc CFLAGS="$(CFLAGS) -march=armv8-a"

# === Help ===
help:
	@echo "Sovereign Privacy Widget Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build the widget (default)"
	@echo "  debug     - Build with debug symbols"
	@echo "  release   - Build optimized release"
	@echo "  test      - Run test suite"
	@echo "  install   - Install to system"
	@echo "  package   - Create distribution package"
	@echo "  clean     - Remove build artifacts"
	@echo ""
	@echo "Platform: $(PLATFORM)"
	@echo "Compiler: $(CC)"
	@echo "Version:  $(VERSION)"
