/*
 * Configuration Parser Header
 * 
 * Part of Sovereign Privacy Widget
 * License: MIT
 */

#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

#include <stdbool.h>
#include <stddef.h>
#include "logger.h"

#ifdef __cplusplus
extern "C" {
#endif

/* === Configuration Structure === */

typedef struct {
    /* Logging */
    log_level_t log_level;
    char* log_file;
    int max_log_size_mb;
    int log_rotation_count;
    
    /* Daemon mode */
    bool daemon_mode;
    
    /* UI */
    bool enable_ui;
    
    /* Monitoring components */
    bool enable_ebpf;
    bool enable_wasm;
    bool enable_ucan;
    int event_buffer_size;
    
    /* Policy files */
    char* policy_file;
    char* ontology_file;
    int policy_refresh_interval_sec;
    
    /* Enforcement */
    bool block_unknown;
    bool alert_on_violation;
    bool auto_block_violations;
    
    /* Keys */
    char* ucan_key_path;
    
    /* Lists */
    char** blocked_processes;
    size_t blocked_process_count;
    char** blocked_domains;
    size_t blocked_domain_count;
    char** trusted_cas;
    size_t trusted_ca_count;
} config_t;

/* === Config Loading === */
config_t* config_load(const char* filepath);
void config_free(config_t* config);
int config_save(const config_t* config, const char* filepath);

/* === Config Accessors === */
const char* config_get_string(const config_t* config, const char* key, const char* default_val);
int config_get_int(const config_t* config, const char* key, int default_val);
bool config_get_bool(const config_t* config, const char* key, bool default_val);

/* === Config Modification === */
int config_add_blocked_process(config_t* config, const char* process_name);
int config_add_blocked_domain(config_t* config, const char* domain);
int config_add_trusted_ca(config_t* config, const char* ca_hash);

#ifdef __cplusplus
}
#endif

#endif /* CONFIG_PARSER_H */
