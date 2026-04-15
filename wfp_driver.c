/*
 * Windows Filtering Platform (WFP) Driver Integration
 * Kernel-level network and process monitoring for Windows
 * 
 * Part of Sovereign Privacy Widget
 * License: MIT
 */

#ifdef WINDOWS

#define INITGUID
#include <windows.h>
#include <fwpmu.h>
#include <fwpmtypes.h>
#include <netiodef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../core/stlc_policy_engine.h"
#include "wfp_driver.h"

/* WFP GUIDs */
DEFINE_GUID(SOVEREIGN_SUBLAYER_GUID, 
    0x12345678, 0x1234, 0x1234, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0);
DEFINE_GUID(SOVEREIGN_CALLOUT_CONNECT_V4,
    0x12345678, 0x1234, 0x1234, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf1);
DEFINE_GUID(SOVEREIGN_CALLOUT_CONNECT_V6,
    0x12345678, 0x1234, 0x1234, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf2);
DEFINE_GUID(SOVEREIGN_CALLOUT_PROCESS,
    0x12345678, 0x1234, 0x1234, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf3);
DEFINE_GUID(SOVEREIGN_FILTER_CONNECT_V4,
    0x12345678, 0x1234, 0x1234, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf4);
DEFINE_GUID(SOVEREIGN_FILTER_CONNECT_V6,
    0x12345678, 0x1234, 0x1234, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf5);

/* WFP engine handle */
static HANDLE g_engine_handle = NULL;
static wfp_event_callback_t g_event_callback = NULL;
static void* g_callback_context = NULL;

/* Process monitoring state */
typedef struct {
    DWORD pid;
    WCHAR process_name[MAX_PATH];
    UINT64 create_time;
    BOOL is_blocked;
} process_info_t;

static process_info_t* g_monitored_processes = NULL;
static size_t g_process_count = 0;
static CRITICAL_SECTION g_process_lock;

/* Network connection tracking */
typedef struct {
    UINT64 filter_id;
    UINT8 local_addr[16];
    UINT8 remote_addr[16];
    UINT16 local_port;
    UINT16 remote_port;
    UINT8 protocol;
    DWORD pid;
    BOOL blocked;
} connection_info_t;

static connection_info_t* g_tracked_connections = NULL;
static size_t g_connection_count = 0;
static CRITICAL_SECTION g_connection_lock;

/* === WFP Engine Management === */

int wfp_init(void) {
    DWORD result;
    FWPM_SESSION0 session = {0};
    
    InitializeCriticalSection(&g_process_lock);
    InitializeCriticalSection(&g_connection_lock);
    
    /* Open WFP engine */
    result = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &g_engine_handle);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to open WFP engine: 0x%08X\n", result);
        return -1;
    }
    
    /* Add sovereign sublayer */
    FWPM_SUBLAYER0 sublayer = {0};
    sublayer.subLayerKey = SOVEREIGN_SUBLAYER_GUID;
    sublayer.displayData.name = L"Sovereign Privacy Widget";
    sublayer.displayData.description = L"Formally verified privacy enforcement";
    sublayer.flags = 0;
    sublayer.weight = 0x100;
    
    result = FwpmSubLayerAdd0(g_engine_handle, &sublayer, NULL);
    if (result != ERROR_SUCCESS && result != FWP_E_ALREADY_EXISTS) {
        fprintf(stderr, "Failed to add sublayer: 0x%08X\n", result);
        wfp_cleanup();
        return -1;
    }
    
    printf("WFP engine initialized successfully\n");
    return 0;
}

void wfp_cleanup(void) {
    if (g_engine_handle) {
        /* Remove all filters */
        FwpmFilterDeleteByKey0(g_engine_handle, &SOVEREIGN_FILTER_CONNECT_V4);
        FwpmFilterDeleteByKey0(g_engine_handle, &SOVEREIGN_FILTER_CONNECT_V6);
        
        /* Remove callouts */
        FwpmCalloutDeleteByKey0(g_engine_handle, &SOVEREIGN_CALLOUT_CONNECT_V4);
        FwpmCalloutDeleteByKey0(g_engine_handle, &SOVEREIGN_CALLOUT_CONNECT_V6);
        FwpmCalloutDeleteByKey0(g_engine_handle, &SOVEREIGN_CALLOUT_PROCESS);
        
        /* Remove sublayer */
        FwpmSubLayerDeleteByKey0(g_engine_handle, &SOVEREIGN_SUBLAYER_GUID);
        
        /* Close engine */
        FwpmEngineClose0(g_engine_handle);
        g_engine_handle = NULL;
    }
    
    DeleteCriticalSection(&g_process_lock);
    DeleteCriticalSection(&g_connection_lock);
    
    free(g_monitored_processes);
    free(g_tracked_connections);
    
    printf("WFP engine cleaned up\n");
}

/* === Network Filtering === */

int wfp_install_network_filters(void) {
    DWORD result;
    
    if (!g_engine_handle) {
        fprintf(stderr, "WFP engine not initialized\n");
        return -1;
    }
    
    /* Register IPv4 connect callout */
    FWPM_CALLOUT0 callout_v4 = {0};
    callout_v4.calloutKey = SOVEREIGN_CALLOUT_CONNECT_V4;
    callout_v4.displayData.name = L"Sovereign Connect Callout v4";
    callout_v4.displayData.description = L"Monitors IPv4 connections";
    callout_v4.flags = 0;
    callout_v4.providerKey = NULL;
    callout_v4.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    callout_v4.calloutId = 0;
    
    result = FwpmCalloutAdd0(g_engine_handle, &callout_v4, NULL, NULL);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to add IPv4 callout: 0x%08X\n", result);
        return -1;
    }
    
    /* Register IPv6 connect callout */
    FWPM_CALLOUT0 callout_v6 = {0};
    callout_v6.calloutKey = SOVEREIGN_CALLOUT_CONNECT_V6;
    callout_v6.displayData.name = L"Sovereign Connect Callout v6";
    callout_v6.displayData.description = L"Monitors IPv6 connections";
    callout_v6.flags = 0;
    callout_v6.providerKey = NULL;
    callout_v6.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    callout_v6.calloutId = 0;
    
    result = FwpmCalloutAdd0(g_engine_handle, &callout_v6, NULL, NULL);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to add IPv6 callout: 0x%08X\n", result);
        return -1;
    }
    
    /* Add IPv4 filter */
    FWPM_FILTER0 filter_v4 = {0};
    filter_v4.filterKey = SOVEREIGN_FILTER_CONNECT_V4;
    filter_v4.displayData.name = L"Sovereign IPv4 Connect Filter";
    filter_v4.displayData.description = L"Filters IPv4 connections based on policy";
    filter_v4.flags = FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT;
    filter_v4.providerKey = NULL;
    filter_v4.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter_v4.subLayerKey = SOVEREIGN_SUBLAYER_GUID;
    filter_v4.weight.type = FWP_UINT8;
    filter_v4.weight.uint8 = 0xFF;
    filter_v4.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter_v4.action.calloutKey = SOVEREIGN_CALLOUT_CONNECT_V4;
    filter_v4.filterCondition = NULL;
    filter_v4.numFilterConditions = 0;
    
    UINT64 filter_id_v4;
    result = FwpmFilterAdd0(g_engine_handle, &filter_v4, NULL, &filter_id_v4);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to add IPv4 filter: 0x%08X\n", result);
        return -1;
    }
    
    /* Add IPv6 filter */
    FWPM_FILTER0 filter_v6 = {0};
    filter_v6.filterKey = SOVEREIGN_FILTER_CONNECT_V6;
    filter_v6.displayData.name = L"Sovereign IPv6 Connect Filter";
    filter_v6.displayData.description = L"Filters IPv6 connections based on policy";
    filter_v6.flags = FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT;
    filter_v6.providerKey = NULL;
    filter_v6.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    filter_v6.subLayerKey = SOVEREIGN_SUBLAYER_GUID;
    filter_v6.weight.type = FWP_UINT8;
    filter_v6.weight.uint8 = 0xFF;
    filter_v6.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter_v6.action.calloutKey = SOVEREIGN_CALLOUT_CONNECT_V6;
    filter_v6.filterCondition = NULL;
    filter_v6.numFilterConditions = 0;
    
    UINT64 filter_id_v6;
    result = FwpmFilterAdd0(g_engine_handle, &filter_v6, NULL, &filter_id_v6);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to add IPv6 filter: 0x%08X\n", result);
        return -1;
    }
    
    printf("Network filters installed successfully\n");
    return 0;
}

/* === Process Monitoring === */

int wfp_install_process_monitor(void) {
    DWORD result;
    
    if (!g_engine_handle) {
        fprintf(stderr, "WFP engine not initialized\n");
        return -1;
    }
    
    /* Register process callout */
    FWPM_CALLOUT0 callout_proc = {0};
    callout_proc.calloutKey = SOVEREIGN_CALLOUT_PROCESS;
    callout_proc.displayData.name = L"Sovereign Process Callout";
    callout_proc.displayData.description = L"Monitors process creation/termination";
    callout_proc.flags = 0;
    callout_proc.providerKey = NULL;
    callout_proc.applicableLayer = FWPM_LAYER_ALE_AUTH_LISTEN_V4;
    callout_proc.calloutId = 0;
    
    result = FwpmCalloutAdd0(g_engine_handle, &callout_proc, NULL, NULL);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to add process callout: 0x%08X\n", result);
        return -1;
    }
    
    printf("Process monitor installed successfully\n");
    return 0;
}

/* === Connection Blocking === */

int wfp_block_connection(const connection_info_t* conn) {
    if (!g_engine_handle || !conn) {
        return -1;
    }
    
    /* Add to tracked connections */
    EnterCriticalSection(&g_connection_lock);
    
    size_t new_count = g_connection_count + 1;
    connection_info_t* new_array = realloc(g_tracked_connections, 
                                            new_count * sizeof(connection_info_t));
    if (!new_array) {
        LeaveCriticalSection(&g_connection_lock);
        return -1;
    }
    
    g_tracked_connections = new_array;
    memcpy(&g_tracked_connections[g_connection_count], conn, sizeof(connection_info_t));
    g_tracked_connections[g_connection_count].blocked = TRUE;
    g_connection_count++;
    
    LeaveCriticalSection(&g_connection_lock);
    
    /* Create specific block filter */
    FWPM_FILTER_CONDITION0 conditions[4];
    FWPM_FILTER0 block_filter = {0};
    GUID filter_guid;
    UuidCreate(&filter_guid);
    
    block_filter.filterKey = filter_guid;
    block_filter.displayData.name = L"Sovereign Block Filter";
    block_filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    block_filter.subLayerKey = SOVEREIGN_SUBLAYER_GUID;
    block_filter.weight.type = FWP_UINT8;
    block_filter.weight.uint8 = 0xFF;
    block_filter.action.type = FWP_ACTION_BLOCK;
    
    /* Set conditions based on connection info */
    memset(conditions, 0, sizeof(conditions));
    
    conditions[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    conditions[0].matchType = FWP_MATCH_EQUAL;
    conditions[0].conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
    memcpy(conditions[0].conditionValue.byteArray16->byteArray16, 
           conn->remote_addr, 16);
    
    conditions[1].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
    conditions[1].matchType = FWP_MATCH_EQUAL;
    conditions[1].conditionValue.type = FWP_UINT16;
    conditions[1].conditionValue.uint16 = conn->remote_port;
    
    block_filter.filterCondition = conditions;
    block_filter.numFilterConditions = 2;
    
    UINT64 filter_id;
    DWORD result = FwpmFilterAdd0(g_engine_handle, &block_filter, NULL, &filter_id);
    
    if (result == ERROR_SUCCESS) {
        printf("Connection blocked: PID %lu -> %u.%u.%u.%u:%u\n",
               conn->pid,
               conn->remote_addr[0], conn->remote_addr[1],
               conn->remote_addr[2], conn->remote_addr[3],
               ntohs(conn->remote_port));
    }
    
    return (result == ERROR_SUCCESS) ? 0 : -1;
}

/* === Process Termination === */

int wfp_terminate_process(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) {
        fprintf(stderr, "Failed to open process %lu: %lu\n", pid, GetLastError());
        return -1;
    }
    
    BOOL result = TerminateProcess(hProcess, 1);
    CloseHandle(hProcess);
    
    if (result) {
        printf("Process %lu terminated\n", pid);
        
        /* Update monitored processes list */
        EnterCriticalSection(&g_process_lock);
        for (size_t i = 0; i < g_process_count; i++) {
            if (g_monitored_processes[i].pid == pid) {
                g_monitored_processes[i].is_blocked = TRUE;
                break;
            }
        }
        LeaveCriticalSection(&g_process_lock);
        
        /* Notify callback */
        if (g_event_callback) {
            wfp_event_t event = {0};
            event.type = WFP_EVENT_PROCESS_TERMINATED;
            event.pid = pid;
            g_event_callback(&event, g_callback_context);
        }
    }
    
    return result ? 0 : -1;
}

/* === Event Handling === */

void wfp_set_event_callback(wfp_event_callback_t callback, void* context) {
    g_event_callback = callback;
    g_callback_context = context;
}

/* === Utility Functions === */

const char* wfp_get_process_name(DWORD pid) {
    static char name[MAX_PATH];
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    
    if (hProcess) {
        WCHAR wname[MAX_PATH];
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(hProcess, 0, wname, &size)) {
            WideCharToMultiByte(CP_UTF8, 0, wname, -1, name, MAX_PATH, NULL, NULL);
        } else {
            snprintf(name, MAX_PATH, "pid:%lu", pid);
        }
        CloseHandle(hProcess);
    } else {
        snprintf(name, MAX_PATH, "pid:%lu", pid);
    }
    
    return name;
}

BOOL wfp_is_system_process(DWORD pid) {
    /* Check if process is a critical system process */
    if (pid <= 4) return TRUE;  /* System and Idle */
    
    const char* name = wfp_get_process_name(pid);
    const char* system_procs[] = {
        "svchost.exe", "csrss.exe", "smss.exe", "services.exe",
        "lsass.exe", "winlogon.exe", "wininit.exe", "crss.exe",
        "System", "Registry", "Memory Compression"
    };
    
    for (size_t i = 0; i < sizeof(system_procs)/sizeof(system_procs[0]); i++) {
        if (strstr(name, system_procs[i]) != NULL) {
            return TRUE;
        }
    }
    
    return FALSE;
}

#endif /* WINDOWS */
