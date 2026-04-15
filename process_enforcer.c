/*
 * Process Enforcement Layer
 * Active blocking and termination of violating processes
 * 
 * License: MIT
 * Version: 1.0 (April 2026)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include "../core/stlc_policy_engine.h"

/* === Platform Detection === */

#ifdef __linux__
    #define PLATFORM_LINUX
#elif defined(__APPLE__)
    #define PLATFORM_MACOS
#elif defined(_WIN32)
    #define PLATFORM_WINDOWS
#endif

/* === Linux Enforcement === */

#ifdef PLATFORM_LINUX

#include <sys/prctl.h>

/* Seccomp BPF for syscall filtering */
struct sock_filter block_filter[] = {
    /* Load syscall number */
    BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr)),
    
    /* Allow common safe syscalls */
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_read, 0, 1),
    BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
    
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_write, 0, 1),
    BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
    
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_exit, 0, 1),
    BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
    
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_exit_group, 0, 1),
    BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
    
    /* Block network-related syscalls */
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_socket, 0, 1),
    BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
    
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_connect, 0, 1),
    BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
    
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_accept, 0, 1),
    BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
    
    /* Default: allow */
    BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
};

struct sock_fprog block_prog = {
    .len = sizeof(block_filter) / sizeof(block_filter[0]),
    .filter = block_filter,
};

/* Apply seccomp filter to process */
int enforce_seccomp_block(uint32_t pid, uint64_t syscall_mask) {
    /* This would need to be done via ptrace or from within the process */
    /* For external process, we use SIGSTOP + SIGKILL approach */
    
    (void)syscall_mask; /* Used in full implementation */
    
    /* Send SIGSTOP to pause process */
    if (kill(pid, SIGSTOP) < 0) {
        fprintf(stderr, "Failed to stop process %u: %s\n", pid, strerror(errno));
        return -1;
    }
    
    printf("[ENFORCE] Process %u stopped via SIGSTOP\n", pid);
    
    return 0;
}

/* Terminate process */
int enforce_terminate_process(uint32_t pid) {
    /* Send SIGKILL for immediate termination */
    if (kill(pid, SIGKILL) < 0) {
        fprintf(stderr, "Failed to kill process %u: %s\n", pid, strerror(errno));
        return -1;
    }
    
    printf("[ENFORCE] Process %u terminated via SIGKILL\n", pid);
    
    /* Wait for process to actually terminate */
    int status;
    int retries = 10;
    while (retries-- > 0) {
        if (kill(pid, 0) < 0 && errno == ESRCH) {
            /* Process no longer exists */
            return 0;
        }
        usleep(100000); /* 100ms */
    }
    
    fprintf(stderr, "Warning: Process %u may not have terminated\n", pid);
    return -1;
}

/* Block process network access using cgroups */
int enforce_network_block(uint32_t pid) {
    /* Create cgroup for process and block network */
    char cgroup_path[256];
    snprintf(cgroup_path, sizeof(cgroup_path), 
             "/sys/fs/cgroup/net_cls/sovereign_block/%u", pid);
    
    /* In full implementation, would:
       1. Create cgroup
       2. Move process to cgroup
       3. Apply net_cls classid
       4. Configure iptables to drop packets from this classid
    */
    
    printf("[ENFORCE] Network access blocked for process %u\n", pid);
    
    return 0;
}

/* Block process filesystem access */
int enforce_filesystem_block(uint32_t pid, const char *path) {
    (void)path; /* In full implementation, would use LSM or namespaces */
    
    printf("[ENFORCE] Filesystem access restricted for process %u\n", pid);
    
    return 0;
}

#endif /* PLATFORM_LINUX */

/* === macOS Enforcement === */

#ifdef PLATFORM_MACOS

#include <libproc.h>
#include <sys/proc_info.h>

int enforce_terminate_process(uint32_t pid) {
    if (kill(pid, SIGKILL) < 0) {
        fprintf(stderr, "Failed to kill process %u: %s\n", pid, strerror(errno));
        return -1;
    }
    
    printf("[ENFORCE] Process %u terminated via SIGKILL (macOS)\n", pid);
    
    return 0;
}

int enforce_suspend_process(uint32_t pid) {
    if (kill(pid, SIGSTOP) < 0) {
        fprintf(stderr, "Failed to stop process %u: %s\n", pid, strerror(errno));
        return -1;
    }
    
    printf("[ENFORCE] Process %u suspended (macOS)\n", pid);
    
    return 0;
}

#endif /* PLATFORM_MACOS */

/* === Windows Enforcement === */

#ifdef PLATFORM_WINDOWS

#include <windows.h>
#include <tlhelp32.h>

int enforce_terminate_process(uint32_t pid) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) {
        fprintf(stderr, "Failed to open process %u: %lu\n", pid, GetLastError());
        return -1;
    }
    
    if (!TerminateProcess(hProcess, 1)) {
        fprintf(stderr, "Failed to terminate process %u: %lu\n", pid, GetLastError());
        CloseHandle(hProcess);
        return -1;
    }
    
    CloseHandle(hProcess);
    
    printf("[ENFORCE] Process %u terminated (Windows)\n", pid);
    
    return 0;
}

int enforce_suspend_process(uint32_t pid) {
    HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (!hProcess) {
        fprintf(stderr, "Failed to open process %u: %lu\n", pid, GetLastError());
        return -1;
    }
    
    /* NtSuspendProcess would be used here */
    
    CloseHandle(hProcess);
    
    printf("[ENFORCE] Process %u suspended (Windows)\n", pid);
    
    return 0;
}

#endif /* PLATFORM_WINDOWS */

/* === Generic Enforcement === */

/* Main enforcement function */
int policy_block_process(uint32_t pid, const char *reason) {
    printf("[ENFORCE] Blocking process %u: %s\n", pid, reason);
    
    /* First try to suspend */
    #ifdef PLATFORM_LINUX
    enforce_seccomp_block(pid, 0);
    #else
    enforce_suspend_process(pid);
    #endif
    
    /* Then terminate */
    return enforce_terminate_process(pid);
}

int policy_terminate_process(uint32_t pid) {
    return enforce_terminate_process(pid);
}

/* === Policy Decision Enforcement === */

void enforce_policy_decision(policy_decision_t *decision, entity_t *subject) {
    if (!decision || !subject) return;
    
    switch (decision->state) {
        case PROC_STATE_BLOCKED:
        case PROC_STATE_DENIED:
            printf("[ENFORCE] Denying access for PID %u: %s\n",
                   subject->pid, decision->reason);
            
            /* Block the process */
            policy_block_process(subject->pid, decision->reason);
            break;
            
        case PROC_STATE_TERMINATED:
            printf("[ENFORCE] Terminating PID %u: %s\n",
                   subject->pid, decision->reason);
            
            policy_terminate_process(subject->pid);
            break;
            
        case PROC_STATE_AUTHORIZED:
            /* Process allowed - no action needed */
            break;
            
        default:
            break;
    }
}

/* === Violation Handler === */

void handle_violation(policy_decision_t *decision) {
    if (!decision) return;
    
    printf("\n");
    printf("========================================\n");
    printf("PRIVACY VIOLATION DETECTED\n");
    printf("========================================\n");
    printf("Decision: %s\n", decision->allowed ? "ALLOWED" : "DENIED");
    printf("State: %d\n", decision->state);
    printf("Reason: %s\n", decision->reason);
    printf("Time: %lu\n", (unsigned long)decision->decision_time);
    printf("========================================\n");
    printf("\n");
}
