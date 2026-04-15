/*
 * Sovereign Privacy Monitor - eBPF Kernel Probes
 * Ring 0 monitoring for Linux kernel
 * 
 * Monitors system calls, network connections, process creation
 * and hidden process detection
 * 
 * License: GPL-2.0 (required for eBPF)
 * Version: 1.0 (April 2026)
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* === Constants === */

#define TASK_COMM_LEN 16
#define MAX_PROCESSES 1024
#define MAX_PATH_LEN 256
#define MAX_CMD_LEN 128

/* Event types */
#define EVENT_SYSCALL     1
#define EVENT_EXEC        2
#define EVENT_CONNECT     3
#define EVENT_OPEN        4
#define EVENT_HIDDEN_PROC 5
#define EVENT_CERT        6
#define EVENT_VIOLATION   7

/* Syscall numbers (x86_64) */
#define __NR_read        0
#define __NR_write       1
#define __NR_open        2
#define __NR_close       3
#define __NR_socket      41
#define __NR_connect     42
#define __NR_accept      43
#define __NR_sendto      44
#define __NR_recvfrom    45
#define __NR_execve      59
#define __NR_exit        60
#define __NR_kill        62
#define __NR_openat      257
#define __NR_execveat    322

/* === Data Structures === */

/* Process information */
struct process_info {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    char comm[TASK_COMM_LEN];
    __u64 start_time;
    __u8 is_hidden;
    __u8 is_system;
    __u8 padding[6];
};

/* Syscall event */
struct syscall_event {
    __u32 type;
    __u32 pid;
    __u32 ppid;
    __u64 timestamp;
    __u64 syscall_nr;
    __u64 arg0;
    __u64 arg1;
    __u64 arg2;
    __u64 arg3;
    __u64 arg4;
    __u64 arg5;
    char comm[TASK_COMM_LEN];
    char path[MAX_PATH_LEN];
};

/* Network event */
struct network_event {
    __u32 type;
    __u32 pid;
    __u64 timestamp;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 protocol;
    __u8 is_encrypted;
    __u8 cert_hash[32];
    char comm[TASK_COMM_LEN];
    char domain[128];
};

/* Violation event */
struct violation_event {
    __u32 type;
    __u32 pid;
    __u64 timestamp;
    __u32 violation_type;
    __u32 severity;
    char comm[TASK_COMM_LEN];
    char description[256];
    char resource[128];
};

/* Hidden process detection */
struct hidden_proc_event {
    __u32 type;
    __u32 detected_pid;
    __u64 timestamp;
    char comm[TASK_COMM_LEN];
    __u8 has_network_activity;
    __u8 has_file_activity;
    __u8 not_in_procfs;
    __u8 padding;
};

/* === Maps === */

/* Ring buffer for events to userspace */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* 256KB */
} events SEC(".maps");

/* Process tracking */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PROCESSES);
    __type(key, __u32);
    __type(value, struct process_info);
} processes SEC(".maps");

/* Syscall whitelist per process */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PROCESSES);
    __type(key, __u32);
    __type(value, __u64); /* Bitmap of allowed syscalls */
} syscall_whitelist SEC(".maps");

/* Network connection tracking */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, __u64); /* pid + socket */
    __type(value, struct network_event);
} connections SEC(".maps");

/* Hidden process candidates */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PROCESSES);
    __type(key, __u32);
    __type(value, __u64); /* Last activity timestamp */
} hidden_candidates SEC(".maps");

/* Certificate cache */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1000);
    __type(key, __u32); /* IP address */
    __type(value, __u8[32]); /* Certificate hash */
} cert_cache SEC(".maps");

/* === Helper Functions === */

static __always_inline __u64 get_timestamp(void) {
    return bpf_ktime_get_ns();
}

static __always_inline struct task_struct *get_current_task(void) {
    return (struct task_struct *)bpf_get_current_task();
}

static __always_inline void get_task_info(struct task_struct *task,
                                          struct process_info *info) {
    info->pid = BPF_CORE_READ(task, tgid);
    info->ppid = BPF_CORE_READ(task, real_parent, tgid);
    info->uid = BPF_CORE_READ(task, cred, uid.val);
    info->gid = BPF_CORE_READ(task, cred, gid.val);
    bpf_get_current_comm(&info->comm, sizeof(info->comm));
    info->start_time = BPF_CORE_READ(task, start_time);
}

static __always_inline bool is_system_process(__u32 pid) {
    /* System processes typically have PID < 1000 */
    return pid < 1000;
}

static __always_inline void submit_event(void *ctx, void *data, __u64 size) {
    bpf_ringbuf_output(&events, data, size, 0);
}

/* === Syscall Tracing === */

/* Trace enter to any syscall */
SEC("tp/raw_syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event event = {};
    struct task_struct *task = get_current_task();
    
    event.type = EVENT_SYSCALL;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.ppid = BPF_CORE_READ(task, real_parent, tgid);
    event.timestamp = get_timestamp();
    event.syscall_nr = ctx->id;
    event.arg0 = ctx->args[0];
    event.arg1 = ctx->args[1];
    event.arg2 = ctx->args[2];
    event.arg3 = ctx->args[3];
    event.arg4 = ctx->args[4];
    event.arg5 = ctx->args[5];
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    /* Check if syscall is whitelisted */
    __u64 *whitelist = bpf_map_lookup_elem(&syscall_whitelist, &event.pid);
    if (whitelist) {
        __u64 syscall_bit = 1ULL << ctx->id;
        if (!(*whitelist & syscall_bit)) {
            /* Syscall not whitelisted - potential violation */
            struct violation_event viol = {};
            viol.type = EVENT_VIOLATION;
            viol.pid = event.pid;
            viol.timestamp = event.timestamp;
            viol.violation_type = 1; /* Unauthorized syscall */
            viol.severity = 3; /* HIGH */
            __builtin_memcpy(&viol.comm, &event.comm, sizeof(event.comm));
            bpf_probe_read_kernel_str(&viol.description, sizeof(viol.description),
                                      "Unauthorized syscall detected");
            submit_event(ctx, &viol, sizeof(viol));
        }
    }
    
    /* Track hidden process candidates */
    __u64 *last_activity = bpf_map_lookup_elem(&hidden_candidates, &event.pid);
    if (last_activity) {
        *last_activity = event.timestamp;
    }
    
    submit_event(ctx, &event, sizeof(event));
    
    return 0;
}

/* === Process Execution Monitoring === */

SEC("tp/sched/sched_process_exec")
int trace_sched_exec(void *ctx) {
    struct syscall_event event = {};
    struct task_struct *task = get_current_task();
    
    event.type = EVENT_EXEC;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.ppid = BPF_CORE_READ(task, real_parent, tgid);
    event.timestamp = get_timestamp();
    event.syscall_nr = __NR_execve;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    /* Update process tracking */
    struct process_info info = {};
    get_task_info(task, &info);
    info.is_system = is_system_process(info.pid);
    bpf_map_update_elem(&processes, &info.pid, &info, BPF_ANY);
    
    /* Check for hidden process indicators */
    if (!is_system_process(info.pid)) {
        /* Check if parent is system process (possible injection) */
        if (is_system_process(info.ppid)) {
            struct violation_event viol = {};
            viol.type = EVENT_VIOLATION;
            viol.pid = event.pid;
            viol.timestamp = event.timestamp;
            viol.violation_type = 2; /* Suspicious parent */
            viol.severity = 2; /* MEDIUM */
            __builtin_memcpy(&viol.comm, &event.comm, sizeof(event.comm));
            bpf_probe_read_kernel_str(&viol.description, sizeof(viol.description),
                                      "User process spawned from system process");
            submit_event(ctx, &viol, sizeof(viol));
        }
    }
    
    submit_event(ctx, &event, sizeof(event));
    
    return 0;
}

/* === Process Fork Monitoring === */

SEC("tp/sched/sched_process_fork")
int trace_sched_fork(struct trace_event_raw_sched_process_fork *ctx) {
    __u32 parent_pid = ctx->parent_pid;
    __u32 child_pid = ctx->child_pid;
    
    /* Track parent-child relationship */
    struct process_info *parent = bpf_map_lookup_elem(&processes, &parent_pid);
    if (parent) {
        struct process_info child = {};
        child.pid = child_pid;
        child.ppid = parent_pid;
        child.uid = parent->uid;
        child.gid = parent->gid;
        __builtin_memcpy(&child.comm, &parent->comm, sizeof(child.comm));
        child.start_time = get_timestamp();
        child.is_system = parent->is_system;
        
        bpf_map_update_elem(&processes, &child_pid, &child, BPF_ANY);
    }
    
    /* Add to hidden candidates for tracking */
    __u64 timestamp = get_timestamp();
    bpf_map_update_elem(&hidden_candidates, &child_pid, &timestamp, BPF_ANY);
    
    return 0;
}

/* === Network Connection Monitoring === */

SEC("kprobe/tcp_connect")
int trace_tcp_connect(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    
    struct network_event event = {};
    event.type = EVENT_CONNECT;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.timestamp = get_timestamp();
    event.protocol = 6; /* TCP */
    
    /* Read socket info */
    BPF_CORE_READ_INTO(&event.saddr, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&event.daddr, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&event.sport, sk, __sk_common.skc_num);
    BPF_CORE_READ_INTO(&event.dport, sk, __sk_common.skc_dport);
    event.dport = bpf_ntohs(event.dport);
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    /* Check for encrypted connection (port 443, 993, etc.) */
    event.is_encrypted = (event.dport == 443 || event.dport == 993 ||
                          event.dport == 995 || event.dport == 465);
    
    /* Check certificate cache */
    __u8 *cert_hash = bpf_map_lookup_elem(&cert_cache, &event.daddr);
    if (cert_hash) {
        __builtin_memcpy(&event.cert_hash, cert_hash, 32);
    }
    
    /* Track connection */
    __u64 key = ((__u64)event.pid << 32) | (__u64)event.daddr;
    bpf_map_update_elem(&connections, &key, &event, BPF_ANY);
    
    /* Check for suspicious connections */
    struct process_info *proc = bpf_map_lookup_elem(&processes, &event.pid);
    if (proc && !proc->is_system) {
        /* User process making network connection - check if hidden */
        __u64 *last_activity = bpf_map_lookup_elem(&hidden_candidates, &event.pid);
        if (last_activity) {
            /* Process has network activity - update tracking */
            *last_activity = event.timestamp;
        }
    }
    
    submit_event(ctx, &event, sizeof(event));
    
    return 0;
}

/* === File Open Monitoring === */

SEC("kprobe/do_sys_openat2")
int trace_sys_openat2(struct pt_regs *ctx) {
    struct syscall_event event = {};
    
    event.type = EVENT_OPEN;
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.timestamp = get_timestamp();
    event.syscall_nr = __NR_openat;
    
    /* Read filename */
    struct filename *name = (struct filename *)PT_REGS_PARM2(ctx);
    if (name) {
        bpf_probe_read_kernel_str(&event.path, sizeof(event.path),
                                  name->name);
    }
    
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    
    /* Check for sensitive file access */
    if (bpf_strncmp(event.path, 15, "/etc/shadow") == 0 ||
        bpf_strncmp(event.path, 12, "/etc/passwd") == 0 ||
        bpf_strncmp(event.path, 18, "/etc/ssl/private") == 0) {
        
        struct violation_event viol = {};
        viol.type = EVENT_VIOLATION;
        viol.pid = event.pid;
        viol.timestamp = event.timestamp;
        viol.violation_type = 3; /* Sensitive file access */
        viol.severity = 4; /* CRITICAL */
        __builtin_memcpy(&viol.comm, &event.comm, sizeof(event.comm));
        bpf_probe_read_kernel_str(&viol.description, sizeof(viol.description),
                                  "Access to sensitive system file detected");
        bpf_probe_read_kernel_str(&viol.resource, sizeof(viol.resource),
                                  event.path);
        submit_event(ctx, &viol, sizeof(viol));
    }
    
    submit_event(ctx, &event, sizeof(event));
    
    return 0;
}

/* === Hidden Process Detection === */

/* Periodic check for hidden processes */
SEC("tp/timer/timer_expire")
int trace_timer_expire(void *ctx) {
    __u32 pid = 0;
    __u64 now = get_timestamp();
    __u64 timeout = 5ULL * 1000000000ULL; /* 5 seconds in ns */
    
    /* Iterate through hidden candidates */
    __u32 key = 0;
    __u64 *last_activity;
    
    /* Check for processes with activity but not in procfs */
    /* This is a simplified check - full implementation would
       cross-reference with actual /proc entries */
    
    return 0;
}

/* === Process Exit Monitoring === */

SEC("tp/sched/sched_process_exit")
int trace_sched_exit(void *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    /* Clean up process tracking */
    bpf_map_delete_elem(&processes, &pid);
    bpf_map_delete_elem(&syscall_whitelist, &pid);
    bpf_map_delete_elem(&hidden_candidates, &pid);
    
    return 0;
}

/* === Enforcement Functions === */

/* Block a syscall by returning error */
SEC("kprobe/__x64_sys_kill")
int BPF_KPROBE(enforce_kill, pid_t pid, int sig) {
    __u32 current_pid = bpf_get_current_pid_tgid() >> 32;
    
    /* Check if target is a protected process */
    struct process_info *target = bpf_map_lookup_elem(&processes, &pid);
    if (target && target->is_system) {
        /* Block kill of system processes */
        bpf_printk("SOVEREIGN: Blocked kill of system process %d by %d", 
                   pid, current_pid);
        
        struct violation_event viol = {};
        viol.type = EVENT_VIOLATION;
        viol.pid = current_pid;
        viol.timestamp = get_timestamp();
        viol.violation_type = 4; /* Attempted system process kill */
        viol.severity = 4; /* CRITICAL */
        bpf_get_current_comm(&viol.comm, sizeof(viol.comm));
        bpf_probe_read_kernel_str(&viol.description, sizeof(viol.description),
                                  "Attempted to kill system process");
        submit_event(ctx, &viol, sizeof(viol));
        
        /* Override return value to indicate failure */
        bpf_override_return2(ctx, -EPERM);
    }
    
    return 0;
}

/* === License === */

char LICENSE[] SEC("license") = "GPL";
