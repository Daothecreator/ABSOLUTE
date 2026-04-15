/*
 * Windows Filtering Platform (WFP) Driver Header
 * 
 * Part of Sovereign Privacy Widget
 * License: MIT
 */

#ifndef WFP_DRIVER_H
#define WFP_DRIVER_H

#ifdef WINDOWS

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* === Event Types === */

typedef enum {
    WFP_EVENT_CONNECTION_ATTEMPT,
    WFP_EVENT_CONNECTION_ESTABLISHED,
    WFP_EVENT_CONNECTION_BLOCKED,
    WFP_EVENT_PROCESS_CREATED,
    WFP_EVENT_PROCESS_TERMINATED,
    WFP_EVENT_PROCESS_BLOCKED,
    WFP_EVENT_CERTIFICATE_VIOLATION,
    WFP_EVENT_HIDDEN_PROCESS_DETECTED
} wfp_event_type_t;

typedef struct {
    wfp_event_type_t type;
    DWORD pid;
    DWORD ppid;
    union {
        struct {
            uint8_t local_addr[16];
            uint8_t remote_addr[16];
            uint16_t local_port;
            uint16_t remote_port;
            uint8_t protocol;
            bool blocked;
        } connection;
        struct {
            char process_name[MAX_PATH];
            char command_line[1024];
            uint64_t create_time;
        } process;
        struct {
            char cert_subject[256];
            char cert_issuer[256];
            uint32_t violation_type;
        } certificate;
    } data;
    char reason[512];
    uint64_t timestamp;
} wfp_event_t;

typedef void (*wfp_event_callback_t)(const wfp_event_t* event, void* context);

/* === Function Declarations === */

/* Engine management */
int wfp_init(void);
void wfp_cleanup(void);

/* Filter installation */
int wfp_install_network_filters(void);
int wfp_install_process_monitor(void);

/* Enforcement */
int wfp_block_connection(const struct connection_info_s* conn);
int wfp_terminate_process(DWORD pid);
BOOL wfp_suspend_process(DWORD pid);
BOOL wfp_resume_process(DWORD pid);

/* Event handling */
void wfp_set_event_callback(wfp_event_callback_t callback, void* context);

/* Utilities */
const char* wfp_get_process_name(DWORD pid);
BOOL wfp_is_system_process(DWORD pid);
DWORD wfp_get_parent_pid(DWORD pid);
uint64_t wfp_get_process_hash(DWORD pid);

/* Certificate monitoring */
int wfp_install_cert_monitor(void);
BOOL wfp_check_certificate(const char* cert_thumbprint);

/* Hidden process detection */
int wfp_detect_hidden_processes(void);

#ifdef __cplusplus
}
#endif

#endif /* WINDOWS */
#endif /* WFP_DRIVER_H */
