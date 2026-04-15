/*
 * eBPF Loader - Userspace component
 * Loads and manages eBPF programs for kernel monitoring
 * 
 * License: MIT
 * Version: 1.0 (April 2026)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "sovereign_monitor.skel.h"
#include "../core/stlc_policy_engine.h"

/* === Configuration === */

#define RING_BUFFER_SIZE (256 * 1024)
#define POLL_TIMEOUT_MS 100

/* === Global State === */

static volatile bool running = true;
static struct sovereign_monitor_bpf *skel = NULL;
static struct ring_buffer *rb = NULL;

/* Callback to STLC policy engine */
static void (*policy_callback)(void *event, size_t size) = NULL;

/* === Signal Handling === */

static void sig_handler(int sig) {
    running = false;
}

/* === Ring Buffer Callback === */

static int handle_event(void *ctx, void *data, size_t size) {
    (void)ctx;
    
    if (policy_callback) {
        policy_callback(data, size);
    }
    
    /* Also print to console for debugging */
    struct {
        __u32 type;
        __u32 pid;
        __u64 timestamp;
    } *header = data;
    
    const char* event_types[] = {
        "UNKNOWN", "SYSCALL", "EXEC", "CONNECT", 
        "OPEN", "HIDDEN_PROC", "CERT", "VIOLATION"
    };
    
    if (header->type < 8) {
        printf("[eBPF] %s PID=%u\n", event_types[header->type], header->pid);
    }
    
    return 0;
}

/* === eBPF Loading === */

int ebpf_init(void (*callback)(void*, size_t)) {
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    int err;
    
    /* Set up signal handlers */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    /* Remove memory limit for eBPF */
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        fprintf(stderr, "Failed to set rlimit: %s\n", strerror(errno));
        return -1;
    }
    
    /* Store callback */
    policy_callback = callback;
    
    /* Open and load BPF skeleton */
    skel = sovereign_monitor_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return -1;
    }
    
    /* Load and verify BPF programs */
    err = sovereign_monitor_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }
    
    /* Attach tracepoints */
    err = sovereign_monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }
    
    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), 
                          handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = -1;
        goto cleanup;
    }
    
    printf("[SOVEREIGN] eBPF monitoring active\n");
    
    return 0;
    
cleanup:
    sovereign_monitor_bpf__destroy(skel);
    skel = NULL;
    return err;
}

void ebpf_poll(void) {
    if (!rb) return;
    
    /* Poll for events with timeout */
    ring_buffer__poll(rb, POLL_TIMEOUT_MS);
}

void ebpf_cleanup(void) {
    running = false;
    
    if (rb) {
        ring_buffer__free(rb);
        rb = NULL;
    }
    
    if (skel) {
        sovereign_monitor_bpf__destroy(skel);
        skel = NULL;
    }
    
    printf("[SOVEREIGN] eBPF monitoring stopped\n");
}

bool ebpf_is_running(void) {
    return running;
}

/* === Process Enforcement === */

int ebpf_block_process(uint32_t pid) {
    if (!skel) return -1;
    
    /* Add to blocked list in BPF map */
    __u32 key = pid;
    __u8 value = 1;
    
    int fd = bpf_map__fd(skel->maps.processes);
    if (fd < 0) return -1;
    
    return bpf_map_update_elem(fd, &key, &value, BPF_ANY);
}

int ebpf_whitelist_syscall(uint32_t pid, uint64_t syscall_mask) {
    if (!skel) return -1;
    
    int fd = bpf_map__fd(skel->maps.syscall_whitelist);
    if (fd < 0) return -1;
    
    return bpf_map_update_elem(fd, &pid, &syscall_mask, BPF_ANY);
}

/* === Certificate Cache === */

int ebpf_cache_certificate(uint32_t ip, const uint8_t *hash) {
    if (!skel) return -1;
    
    int fd = bpf_map__fd(skel->maps.cert_cache);
    if (fd < 0) return -1;
    
    return bpf_map_update_elem(fd, &ip, hash, BPF_ANY);
}
