/*
 * Configuration Parser
 * INI-style configuration file parser
 * 
 * Part of Sovereign Privacy Widget
 * License: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "config_parser.h"
#include "logger.h"

/* === Helper Functions === */

static char* trim_whitespace(char* str) {
    if (!str) return NULL;
    
    /* Trim leading whitespace */
    while (isspace((unsigned char)*str)) str++;
    
    if (*str == '\0') return str;
    
    /* Trim trailing whitespace */
    char* end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    
    return str;
}

static bool parse_bool(const char* value) {
    if (!value) return false;
    
    return (strcasecmp(value, "true") == 0 ||
            strcasecmp(value, "yes") == 0 ||
            strcasecmp(value, "1") == 0 ||
            strcasecmp(value, "on") == 0);
}

static int parse_int(const char* value) {
    if (!value) return 0;
    return (int)strtol(value, NULL, 10);
}

/* === Config File Loading === */

config_t* config_load(const char* filepath) {
    if (!filepath) return NULL;
    
    config_t* config = calloc(1, sizeof(config_t));
    if (!config) return NULL;
    
    /* Set defaults */
    config->log_level = LOG_INFO;
    config->log_file = NULL;
    config->daemon_mode = false;
    config->enable_ui = true;
    config->enable_ebpf = true;
    config->enable_wasm = true;
    config->enable_ucan = true;
    config->policy_file = strdup("/etc/sovereign-widget/policy.json");
    config->ontology_file = strdup("/etc/sovereign-widget/ontology.json");
    config->ucan_key_path = strdup("/etc/sovereign-widget/keys");
    config->block_unknown = false;
    config->alert_on_violation = true;
    config->auto_block_violations = false;
    config->max_log_size_mb = 100;
    config->log_rotation_count = 5;
    config->event_buffer_size = 10000;
    config->policy_refresh_interval_sec = 300;
    
    FILE* fp = fopen(filepath, "r");
    if (!fp) {
        LOGF_WARN("Config file not found: %s, using defaults", filepath);
        return config;
    }
    
    char line[1024];
    char current_section[64] = "";
    
    while (fgets(line, sizeof(line), fp)) {
        char* trimmed = trim_whitespace(line);
        
        /* Skip empty lines and comments */
        if (*trimmed == '\0' || *trimmed == '#' || *trimmed == ';') {
            continue;
        }
        
        /* Section header */
        if (*trimmed == '[') {
            char* end = strchr(trimmed, ']');
            if (end) {
                *end = '\0';
                strncpy(current_section, trimmed + 1, sizeof(current_section) - 1);
            }
            continue;
        }
        
        /* Key-value pair */
        char* equals = strchr(trimmed, '=');
        if (!equals) continue;
        
        *equals = '\0';
        char* key = trim_whitespace(trimmed);
        char* value = trim_whitespace(equals + 1);
        
        /* Remove quotes from value */
        if ((*value == '"' || *value == '\'') && strlen(value) > 1) {
            value++;
            char* end = value + strlen(value) - 1;
            if (*end == '"' || *end == '\'') {
                *end = '\0';
            }
        }
        
        /* Parse based on section and key */
        if (strcasecmp(current_section, "logging") == 0) {
            if (strcasecmp(key, "level") == 0) {
                config->log_level = logger_level_from_string(value);
            } else if (strcasecmp(key, "file") == 0) {
                free(config->log_file);
                config->log_file = strdup(value);
            } else if (strcasecmp(key, "max_size_mb") == 0) {
                config->max_log_size_mb = parse_int(value);
            } else if (strcasecmp(key, "rotation_count") == 0) {
                config->log_rotation_count = parse_int(value);
            }
        }
        else if (strcasecmp(current_section, "daemon") == 0) {
            if (strcasecmp(key, "enabled") == 0) {
                config->daemon_mode = parse_bool(value);
            }
        }
        else if (strcasecmp(current_section, "ui") == 0) {
            if (strcasecmp(key, "enabled") == 0) {
                config->enable_ui = parse_bool(value);
            }
        }
        else if (strcasecmp(current_section, "monitoring") == 0) {
            if (strcasecmp(key, "ebpf") == 0) {
                config->enable_ebpf = parse_bool(value);
            } else if (strcasecmp(key, "wasm") == 0) {
                config->enable_wasm = parse_bool(value);
            } else if (strcasecmp(key, "ucan") == 0) {
                config->enable_ucan = parse_bool(value);
            } else if (strcasecmp(key, "event_buffer_size") == 0) {
                config->event_buffer_size = parse_int(value);
            }
        }
        else if (strcasecmp(current_section, "policy") == 0) {
            if (strcasecmp(key, "file") == 0) {
                free(config->policy_file);
                config->policy_file = strdup(value);
            } else if (strcasecmp(key, "ontology_file") == 0) {
                free(config->ontology_file);
                config->ontology_file = strdup(value);
            } else if (strcasecmp(key, "refresh_interval_sec") == 0) {
                config->policy_refresh_interval_sec = parse_int(value);
            }
        }
        else if (strcasecmp(current_section, "enforcement") == 0) {
            if (strcasecmp(key, "block_unknown") == 0) {
                config->block_unknown = parse_bool(value);
            } else if (strcasecmp(key, "alert_on_violation") == 0) {
                config->alert_on_violation = parse_bool(value);
            } else if (strcasecmp(key, "auto_block_violations") == 0) {
                config->auto_block_violations = parse_bool(value);
            }
        }
        else if (strcasecmp(current_section, "keys") == 0) {
            if (strcasecmp(key, "path") == 0) {
                free(config->ucan_key_path);
                config->ucan_key_path = strdup(value);
            }
        }
    }
    
    fclose(fp);
    LOGF_INFO("Loaded configuration from: %s", filepath);
    
    return config;
}

void config_free(config_t* config) {
    if (!config) return;
    
    free(config->log_file);
    free(config->policy_file);
    free(config->ontology_file);
    free(config->ucan_key_path);
    
    /* Free blocked processes list */
    for (size_t i = 0; i < config->blocked_process_count; i++) {
        free(config->blocked_processes[i]);
    }
    free(config->blocked_processes);
    
    /* Free blocked domains list */
    for (size_t i = 0; i < config->blocked_domain_count; i++) {
        free(config->blocked_domains[i]);
    }
    free(config->blocked_domains);
    
    /* Free trusted CAs list */
    for (size_t i = 0; i < config->trusted_ca_count; i++) {
        free(config->trusted_cas[i]);
    }
    free(config->trusted_cas);
    
    free(config);
}

/* === Config Accessors === */

const char* config_get_string(const config_t* config, const char* key, const char* default_val) {
    if (!config || !key) return default_val;
    
    if (strcasecmp(key, "log_file") == 0) return config->log_file ? config->log_file : default_val;
    if (strcasecmp(key, "policy_file") == 0) return config->policy_file ? config->policy_file : default_val;
    if (strcasecmp(key, "ontology_file") == 0) return config->ontology_file ? config->ontology_file : default_val;
    if (strcasecmp(key, "ucan_key_path") == 0) return config->ucan_key_path ? config->ucan_key_path : default_val;
    
    return default_val;
}

int config_get_int(const config_t* config, const char* key, int default_val) {
    if (!config || !key) return default_val;
    
    if (strcasecmp(key, "log_level") == 0) return config->log_level;
    if (strcasecmp(key, "max_log_size_mb") == 0) return config->max_log_size_mb;
    if (strcasecmp(key, "log_rotation_count") == 0) return config->log_rotation_count;
    if (strcasecmp(key, "event_buffer_size") == 0) return config->event_buffer_size;
    if (strcasecmp(key, "policy_refresh_interval_sec") == 0) return config->policy_refresh_interval_sec;
    
    return default_val;
}

bool config_get_bool(const config_t* config, const char* key, bool default_val) {
    if (!config || !key) return default_val;
    
    if (strcasecmp(key, "daemon_mode") == 0) return config->daemon_mode;
    if (strcasecmp(key, "enable_ui") == 0) return config->enable_ui;
    if (strcasecmp(key, "enable_ebpf") == 0) return config->enable_ebpf;
    if (strcasecmp(key, "enable_wasm") == 0) return config->enable_wasm;
    if (strcasecmp(key, "enable_ucan") == 0) return config->enable_ucan;
    if (strcasecmp(key, "block_unknown") == 0) return config->block_unknown;
    if (strcasecmp(key, "alert_on_violation") == 0) return config->alert_on_violation;
    if (strcasecmp(key, "auto_block_violations") == 0) return config->auto_block_violations;
    
    return default_val;
}

/* === Config Modification === */

int config_add_blocked_process(config_t* config, const char* process_name) {
    if (!config || !process_name) return -1;
    
    char** new_list = realloc(config->blocked_processes,
                              (config->blocked_process_count + 1) * sizeof(char*));
    if (!new_list) return -1;
    
    config->blocked_processes = new_list;
    config->blocked_processes[config->blocked_process_count] = strdup(process_name);
    config->blocked_process_count++;
    
    return 0;
}

int config_add_blocked_domain(config_t* config, const char* domain) {
    if (!config || !domain) return -1;
    
    char** new_list = realloc(config->blocked_domains,
                              (config->blocked_domain_count + 1) * sizeof(char*));
    if (!new_list) return -1;
    
    config->blocked_domains = new_list;
    config->blocked_domains[config->blocked_domain_count] = strdup(domain);
    config->blocked_domain_count++;
    
    return 0;
}

int config_add_trusted_ca(config_t* config, const char* ca_hash) {
    if (!config || !ca_hash) return -1;
    
    char** new_list = realloc(config->trusted_cas,
                              (config->trusted_ca_count + 1) * sizeof(char*));
    if (!new_list) return -1;
    
    config->trusted_cas = new_list;
    config->trusted_cas[config->trusted_ca_count] = strdup(ca_hash);
    config->trusted_ca_count++;
    
    return 0;
}

/* === Config Save === */

int config_save(const config_t* config, const char* filepath) {
    if (!config || !filepath) return -1;
    
    FILE* fp = fopen(filepath, "w");
    if (!fp) return -1;
    
    fprintf(fp, "# Sovereign Privacy Widget Configuration\n");
    fprintf(fp, "# Generated automatically - edit with care\n\n");
    
    fprintf(fp, "[logging]\n");
    fprintf(fp, "level = %s\n", logger_level_to_string(config->log_level));
    fprintf(fp, "file = %s\n", config->log_file ? config->log_file : "");
    fprintf(fp, "max_size_mb = %d\n", config->max_log_size_mb);
    fprintf(fp, "rotation_count = %d\n\n", config->log_rotation_count);
    
    fprintf(fp, "[daemon]\n");
    fprintf(fp, "enabled = %s\n\n", config->daemon_mode ? "true" : "false");
    
    fprintf(fp, "[ui]\n");
    fprintf(fp, "enabled = %s\n\n", config->enable_ui ? "true" : "false");
    
    fprintf(fp, "[monitoring]\n");
    fprintf(fp, "ebpf = %s\n", config->enable_ebpf ? "true" : "false");
    fprintf(fp, "wasm = %s\n", config->enable_wasm ? "true" : "false");
    fprintf(fp, "ucan = %s\n", config->enable_ucan ? "true" : "false");
    fprintf(fp, "event_buffer_size = %d\n\n", config->event_buffer_size);
    
    fprintf(fp, "[policy]\n");
    fprintf(fp, "file = %s\n", config->policy_file ? config->policy_file : "");
    fprintf(fp, "ontology_file = %s\n", config->ontology_file ? config->ontology_file : "");
    fprintf(fp, "refresh_interval_sec = %d\n\n", config->policy_refresh_interval_sec);
    
    fprintf(fp, "[enforcement]\n");
    fprintf(fp, "block_unknown = %s\n", config->block_unknown ? "true" : "false");
    fprintf(fp, "alert_on_violation = %s\n", config->alert_on_violation ? "true" : "false");
    fprintf(fp, "auto_block_violations = %s\n\n", config->auto_block_violations ? "true" : "false");
    
    fprintf(fp, "[keys]\n");
    fprintf(fp, "path = %s\n", config->ucan_key_path ? config->ucan_key_path : "");
    
    fclose(fp);
    return 0;
}
