/*
 * macOS Endpoint Security Framework Header
 * 
 * Part of Sovereign Privacy Widget
 * License: MIT
 */

#ifndef ENDPOINT_SECURITY_H
#define ENDPOINT_SECURITY_H

#ifdef MACOS

#include <EndpointSecurity/EndpointSecurity.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* === Event Types === */

typedef enum {
    ES_EVENT_PROCESS_EXEC,
    ES_EVENT_PROCESS_EXEC_AUTH,
    ES_EVENT_PROCESS_FORK,
    ES_EVENT_PROCESS_EXIT,
    ES_EVENT_PROCESS_BLOCKED,
    ES_EVENT_FILE_OPEN,
    ES_EVENT_FILE_CREATE,
    ES_EVENT_FILE_DELETE,
    ES_EVENT_FILE_RENAME,
    ES_EVENT_NETWORK_CONNECT,
    ES_EVENT_NETWORK_ACCEPT,
    ES_EVENT_CERTIFICATE_VIOLATION,
    ES_EVENT_HIDDEN_PROCESS_DETECTED
} es_event_type_t;

typedef struct {
    es_event_type_t type;
    pid_t pid;
    pid_t ppid;
    uint64_t timestamp;
    union {
        struct {
            char path[1024];
            char signing_id[256];
            char team_id[256];
            bool allowed;
        } exec;
        struct {
            pid_t child_pid;
        } fork;
        struct {
            int exit_code;
        } exit;
        struct {
            char path[1024];
            uint32_t flags;
            bool allowed;
        } file;
        struct {
            struct sockaddr_storage local_addr;
            struct sockaddr_storage remote_addr;
            bool allowed;
        } network;
        struct {
            char cert_hash[64];
            char violation[256];
        } certificate;
    } data;
    char reason[512];
} es_event_t;

typedef void (*es_event_callback_t)(const es_event_t* event, void* context);

/* === Function Declarations === */

/* Client management */
int es_init(void);
void es_cleanup(void);

/* Event subscription */
int es_subscribe_process_events(void);
int es_subscribe_file_events(void);
int es_subscribe_network_events(void);

/* Event handling */
void es_handle_event(const es_message_t* message);

/* Code signature */
int es_get_code_signature(struct es_process_info_s* proc_info);
es_auth_result_t es_check_exec_policy(const struct es_process_info_s* proc_info);
es_auth_result_t es_check_file_policy(pid_t pid, const char* path, uint32_t flags);

/* Process management */
void es_add_monitored_process(const struct es_process_info_s* proc_info);
void es_remove_monitored_process(pid_t pid);
int es_terminate_process(pid_t pid);
int es_suspend_process(pid_t pid);
int es_resume_process(pid_t pid);

/* Hidden process detection */
int es_detect_hidden_processes(void);

/* Utilities */
bool es_is_system_process(pid_t pid);
pid_t es_get_parent_pid(pid_t pid);
uint64_t es_get_process_hash(pid_t pid);
void es_set_event_callback(es_event_callback_t callback, void* context);

#ifdef __cplusplus
}
#endif

#endif /* MACOS */
#endif /* ENDPOINT_SECURITY_H */
