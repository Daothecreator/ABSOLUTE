/*
 * macOS Endpoint Security Framework Integration
 * User-space system monitoring and policy enforcement for macOS
 * 
 * Part of Sovereign Privacy Widget
 * License: MIT
 */

#ifdef MACOS

#import <EndpointSecurity/EndpointSecurity.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <sys/sysctl.h>
#import <libproc.h>
#import <mach/mach.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "../../core/stlc_policy_engine.h"
#include "endpoint_security.h"

/* Endpoint Security client */
static es_client_t* g_es_client = NULL;
static es_event_callback_t g_event_callback = NULL;
static void* g_callback_context = NULL;
static dispatch_queue_t g_es_queue = NULL;

/* Monitored process tracking */
typedef struct {
    pid_t pid;
    pid_t ppid;
    char name[PROC_PIDPATHINFO_MAXSIZE];
    char bundle_id[256];
    char signing_id[256];
    uint64_t hash;
    bool is_blocked;
    bool is_hidden;
    audit_token_t audit_token;
} es_process_info_t;

static es_process_info_t* g_monitored_processes = NULL;
static size_t g_process_count = 0;
static pthread_mutex_t g_process_lock = PTHREAD_MUTEX_INITIALIZER;

/* Network connection tracking */
typedef struct {
    pid_t pid;
    struct sockaddr_storage local_addr;
    struct sockaddr_storage remote_addr;
    int protocol;
    bool blocked;
} es_connection_info_t;

static es_connection_info_t* g_tracked_connections = NULL;
static size_t g_connection_count = 0;
static pthread_mutex_t g_connection_lock = PTHREAD_MUTEX_INITIALIZER;

/* === Endpoint Security Client Management === */

int es_init(void) {
    es_new_client_result_t result;
    
    /* Create dispatch queue for ES events */
    g_es_queue = dispatch_queue_create("com.sovereign.es_queue", DISPATCH_QUEUE_SERIAL);
    if (!g_es_queue) {
        fprintf(stderr, "Failed to create ES dispatch queue\n");
        return -1;
    }
    
    /* Create Endpoint Security client */
    result = es_new_client(&g_es_client, ^(es_client_t* client, const es_message_t* message) {
        es_handle_event(message);
    });
    
    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
        fprintf(stderr, "Failed to create ES client: %d\n", result);
        dispatch_release(g_es_queue);
        g_es_queue = NULL;
        return -1;
    }
    
    printf("Endpoint Security client created successfully\n");
    return 0;
}

void es_cleanup(void) {
    if (g_es_client) {
        es_unsubscribe_all(g_es_client);
        es_delete_client(g_es_client);
        g_es_client = NULL;
    }
    
    if (g_es_queue) {
        dispatch_release(g_es_queue);
        g_es_queue = NULL;
    }
    
    pthread_mutex_lock(&g_process_lock);
    free(g_monitored_processes);
    g_monitored_processes = NULL;
    g_process_count = 0;
    pthread_mutex_unlock(&g_process_lock);
    
    pthread_mutex_lock(&g_connection_lock);
    free(g_tracked_connections);
    g_tracked_connections = NULL;
    g_connection_count = 0;
    pthread_mutex_unlock(&g_connection_lock);
    
    printf("Endpoint Security client cleaned up\n");
}

/* === Event Subscription === */

int es_subscribe_process_events(void) {
    if (!g_es_client) {
        fprintf(stderr, "ES client not initialized\n");
        return -1;
    }
    
    es_event_type_t events[] = {
        ES_EVENT_TYPE_AUTH_EXEC,
        ES_EVENT_TYPE_NOTIFY_EXEC,
        ES_EVENT_TYPE_AUTH_FORK,
        ES_EVENT_TYPE_NOTIFY_FORK,
        ES_EVENT_TYPE_NOTIFY_EXIT,
        ES_EVENT_TYPE_AUTH_SIGNAL,
        ES_EVENT_TYPE_NOTIFY_SIGNAL
    };
    
    es_return_t result = es_subscribe(g_es_client, events, sizeof(events)/sizeof(events[0]));
    if (result != ES_RETURN_SUCCESS) {
        fprintf(stderr, "Failed to subscribe to process events\n");
        return -1;
    }
    
    printf("Subscribed to process events\n");
    return 0;
}

int es_subscribe_file_events(void) {
    if (!g_es_client) {
        fprintf(stderr, "ES client not initialized\n");
        return -1;
    }
    
    es_event_type_t events[] = {
        ES_EVENT_TYPE_AUTH_OPEN,
        ES_EVENT_TYPE_NOTIFY_OPEN,
        ES_EVENT_TYPE_AUTH_CREATE,
        ES_EVENT_TYPE_NOTIFY_CREATE,
        ES_EVENT_TYPE_AUTH_UNLINK,
        ES_EVENT_TYPE_NOTIFY_UNLINK,
        ES_EVENT_TYPE_AUTH_RENAME,
        ES_EVENT_TYPE_NOTIFY_RENAME,
        ES_EVENT_TYPE_AUTH_MMAP
    };
    
    es_return_t result = es_subscribe(g_es_client, events, sizeof(events)/sizeof(events[0]));
    if (result != ES_RETURN_SUCCESS) {
        fprintf(stderr, "Failed to subscribe to file events\n");
        return -1;
    }
    
    printf("Subscribed to file events\n");
    return 0;
}

int es_subscribe_network_events(void) {
    if (!g_es_client) {
        fprintf(stderr, "ES client not initialized\n");
        return -1;
    }
    
    /* Note: Network events require Network Extension framework on macOS */
    /* For now, we'll use socket filtering via NEFilterDataProvider */
    
    printf("Network event subscription requires Network Extension\n");
    return 0;
}

/* === Event Handling === */

void es_handle_event(const es_message_t* message) {
    if (!message) return;
    
    es_event_t event = {0};
    event.timestamp = message->time->tv_sec * 1000000000ULL + message->time->tv_nsec;
    event.pid = audit_token_to_pid(message->process->audit_token);
    
    switch (message->event_type) {
        case ES_EVENT_TYPE_AUTH_EXEC:
        case ES_EVENT_TYPE_NOTIFY_EXEC: {
            event.type = (message->event_type == ES_EVENT_TYPE_AUTH_EXEC) 
                         ? ES_EVENT_PROCESS_EXEC_AUTH : ES_EVENT_PROCESS_EXEC;
            
            const es_event_exec_t* exec = &message->event.exec;
            es_process_info_t proc_info = {0};
            
            /* Extract process information */
            proc_info.pid = event.pid;
            proc_info.ppid = message->process->original_ppid;
            proc_info.audit_token = message->process->audit_token;
            
            /* Get process name */
            if (message->process->executable) {
                strncpy(proc_info.name, message->process->executable->path.data,
                        MIN(message->process->executable->path.length, sizeof(proc_info.name) - 1));
            }
            
            /* Get signing info */
            es_get_code_signature(&proc_info);
            
            /* Check policy */
            es_auth_result_t auth_result = es_check_exec_policy(&proc_info);
            
            /* Respond to AUTH events */
            if (message->event_type == ES_EVENT_TYPE_AUTH_EXEC) {
                es_respond_auth_result(g_es_client, message, auth_result, false);
            }
            
            /* Store process info */
            es_add_monitored_process(&proc_info);
            
            /* Notify callback */
            if (g_event_callback) {
                strncpy(event.data.exec.path, proc_info.name, sizeof(event.data.exec.path));
                strncpy(event.data.exec.signing_id, proc_info.signing_id, sizeof(event.data.exec.signing_id));
                event.data.exec.allowed = (auth_result == ES_AUTH_RESULT_ALLOW);
                g_event_callback(&event, g_callback_context);
            }
            break;
        }
        
        case ES_EVENT_TYPE_AUTH_FORK:
        case ES_EVENT_TYPE_NOTIFY_FORK: {
            event.type = ES_EVENT_PROCESS_FORK;
            event.data.fork.child_pid = audit_token_to_pid(message->event.fork.child->audit_token);
            
            if (g_event_callback) {
                g_event_callback(&event, g_callback_context);
            }
            break;
        }
        
        case ES_EVENT_TYPE_NOTIFY_EXIT: {
            event.type = ES_EVENT_PROCESS_EXIT;
            event.data.exit.exit_code = message->event.exit.stat;
            
            es_remove_monitored_process(event.pid);
            
            if (g_event_callback) {
                g_event_callback(&event, g_callback_context);
            }
            break;
        }
        
        case ES_EVENT_TYPE_AUTH_OPEN:
        case ES_EVENT_TYPE_NOTIFY_OPEN: {
            event.type = ES_EVENT_FILE_OPEN;
            
            if (message->event.open.file) {
                strncpy(event.data.file.path, message->event.open.file->path.data,
                        MIN(message->event.open.file->path.length, sizeof(event.data.file.path) - 1));
            }
            
            event.data.file.flags = message->event.open.fflag;
            
            /* Check file access policy */
            es_auth_result_t auth_result = es_check_file_policy(event.pid, event.data.file.path, event.data.file.flags);
            
            if (message->event_type == ES_EVENT_TYPE_AUTH_OPEN) {
                es_respond_auth_result(g_es_client, message, auth_result, false);
            }
            
            event.data.file.allowed = (auth_result == ES_AUTH_RESULT_ALLOW);
            
            if (g_event_callback) {
                g_event_callback(&event, g_callback_context);
            }
            break;
        }
        
        default:
            break;
    }
}

/* === Code Signature Verification === */

int es_get_code_signature(es_process_info_t* proc_info) {
    if (!proc_info) return -1;
    
    /* Get code signature using Security framework */
    SecCodeRef code = NULL;
    SecStaticCodeRef static_code = NULL;
    CFURLRef path_url = NULL;
    OSStatus status;
    
    path_url = CFURLCreateFromFileSystemRepresentation(NULL, 
                (const UInt8*)proc_info->name, strlen(proc_info->name), false);
    if (!path_url) return -1;
    
    status = SecStaticCodeCreateWithPath(path_url, kSecCSDefaultFlags, &static_code);
    CFRelease(path_url);
    
    if (status != errSecSuccess) return -1;
    
    /* Get signing information */
    CFDictionaryRef signing_info = NULL;
    status = SecCodeCopySigningInformation(static_code, 
                kSecCSSigningInformation | kSecCSRequirementInformation, &signing_info);
    
    if (status == errSecSuccess && signing_info) {
        CFStringRef signing_id = CFDictionaryGetValue(signing_info, kSecCodeInfoIdentifier);
        if (signing_id) {
            CFStringGetCString(signing_id, proc_info->signing_id, 
                               sizeof(proc_info->signing_id), kCFStringEncodingUTF8);
        }
        
        CFStringRef bundle_id = CFDictionaryGetValue(signing_info, kSecCodeInfoIdentifier);
        if (bundle_id) {
            CFStringGetCString(bundle_id, proc_info->bundle_id,
                               sizeof(proc_info->bundle_id), kCFStringEncodingUTF8);
        }
        
        CFRelease(signing_info);
    }
    
    CFRelease(static_code);
    return 0;
}

/* === Policy Enforcement === */

es_auth_result_t es_check_exec_policy(const es_process_info_t* proc_info) {
    if (!proc_info) return ES_AUTH_RESULT_DENY;
    
    /* Check against blocked list */
    /* TODO: Integrate with STLC policy engine */
    
    /* Check for hidden processes */
    if (proc_info->is_hidden) {
        return ES_AUTH_RESULT_DENY;
    }
    
    /* Check code signature validity */
    if (strlen(proc_info->signing_id) == 0) {
        /* Unsigned binary - require explicit user consent */
        /* For now, allow but log */
    }
    
    return ES_AUTH_RESULT_ALLOW;
}

es_auth_result_t es_check_file_policy(pid_t pid, const char* path, uint32_t flags) {
    if (!path) return ES_AUTH_RESULT_DENY;
    
    /* Protect sensitive system paths */
    const char* protected_paths[] = {
        "/System/Library/Extensions",
        "/Library/Extensions",
        "/private/var/db",
        "/var/db",
        "/.fseventsd",
        NULL
    };
    
    for (int i = 0; protected_paths[i]; i++) {
        if (strncmp(path, protected_paths[i], strlen(protected_paths[i])) == 0) {
            /* Check if this is a system process */
            if (!es_is_system_process(pid)) {
                return ES_AUTH_RESULT_DENY;
            }
        }
    }
    
    return ES_AUTH_RESULT_ALLOW;
}

/* === Process Management === */

void es_add_monitored_process(const es_process_info_t* proc_info) {
    if (!proc_info) return;
    
    pthread_mutex_lock(&g_process_lock);
    
    /* Check if already exists */
    for (size_t i = 0; i < g_process_count; i++) {
        if (g_monitored_processes[i].pid == proc_info->pid) {
            pthread_mutex_unlock(&g_process_lock);
            return;
        }
    }
    
    /* Add new entry */
    es_process_info_t* new_array = realloc(g_monitored_processes,
                                           (g_process_count + 1) * sizeof(es_process_info_t));
    if (new_array) {
        g_monitored_processes = new_array;
        memcpy(&g_monitored_processes[g_process_count], proc_info, sizeof(es_process_info_t));
        g_process_count++;
    }
    
    pthread_mutex_unlock(&g_process_lock);
}

void es_remove_monitored_process(pid_t pid) {
    pthread_mutex_lock(&g_process_lock);
    
    for (size_t i = 0; i < g_process_count; i++) {
        if (g_monitored_processes[i].pid == pid) {
            /* Remove by shifting */
            memmove(&g_monitored_processes[i], &g_monitored_processes[i + 1],
                    (g_process_count - i - 1) * sizeof(es_process_info_t));
            g_process_count--;
            break;
        }
    }
    
    pthread_mutex_unlock(&g_process_lock);
}

/* === Hidden Process Detection === */

int es_detect_hidden_processes(void) {
    /* Compare ES process list with kernel process list */
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    struct kinfo_proc* procs = NULL;
    size_t size = 0;
    
    if (sysctl(mib, 4, NULL, &size, NULL, 0) < 0) {
        return -1;
    }
    
    procs = malloc(size);
    if (!procs) return -1;
    
    if (sysctl(mib, 4, procs, &size, NULL, 0) < 0) {
        free(procs);
        return -1;
    }
    
    int proc_count = size / sizeof(struct kinfo_proc);
    int hidden_count = 0;
    
    pthread_mutex_lock(&g_process_lock);
    
    for (int i = 0; i < proc_count; i++) {
        pid_t pid = procs[i].kp_proc.p_pid;
        bool found_in_es = false;
        
        for (size_t j = 0; j < g_process_count; j++) {
            if (g_monitored_processes[j].pid == pid) {
                found_in_es = true;
                break;
            }
        }
        
        if (!found_in_es && pid > 0) {
            /* Hidden process detected */
            printf("Hidden process detected: PID %d\n", pid);
            hidden_count++;
            
            if (g_event_callback) {
                es_event_t event = {0};
                event.type = ES_EVENT_HIDDEN_PROCESS_DETECTED;
                event.pid = pid;
                g_event_callback(&event, g_callback_context);
            }
        }
    }
    
    pthread_mutex_unlock(&g_process_lock);
    
    free(procs);
    return hidden_count;
}

/* === Utilities === */

bool es_is_system_process(pid_t pid) {
    /* Check if process is a system process */
    if (pid == 0 || pid == 1) return true;
    
    struct kinfo_proc kp;
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
    size_t size = sizeof(kp);
    
    if (sysctl(mib, 4, &kp, &size, NULL, 0) < 0) {
        return false;
    }
    
    /* Check if process has uid 0 and is system-launched */
    return (kp.kp_eproc.e_ucred.cr_uid == 0);
}

pid_t es_get_parent_pid(pid_t pid) {
    struct kinfo_proc kp;
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
    size_t size = sizeof(kp);
    
    if (sysctl(mib, 4, &kp, &size, NULL, 0) < 0) {
        return -1;
    }
    
    return kp.kp_eproc.e_ppid;
}

void es_set_event_callback(es_event_callback_t callback, void* context) {
    g_event_callback = callback;
    g_callback_context = context;
}

#endif /* MACOS */
