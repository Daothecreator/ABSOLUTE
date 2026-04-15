/*
 * Logging System
 * Structured logging with severity levels and rotation
 * 
 * Part of Sovereign Privacy Widget
 * License: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <pthread.h>

#include "logger.h"

/* === Global State === */
static FILE* g_log_file = NULL;
static log_level_t g_min_level = LOG_INFO;
static bool g_use_colors = true;
static bool g_use_syslog = false;
static pthread_mutex_t g_log_lock = PTHREAD_MUTEX_INITIALIZER;

static const char* level_strings[] = {
    "TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"
};

static const char* level_colors[] = {
    "\x1b[90m",  /* TRACE - gray */
    "\x1b[36m",  /* DEBUG - cyan */
    "\x1b[32m",  /* INFO - green */
    "\x1b[33m",  /* WARN - yellow */
    "\x1b[31m",  /* ERROR - red */
    "\x1b[35m"   /* FATAL - magenta */
};

static const char* color_reset = "\x1b[0m";

/* === Initialization === */

int logger_init(const char* log_file_path, log_level_t min_level) {
    pthread_mutex_lock(&g_log_lock);
    
    g_min_level = min_level;
    
    if (log_file_path) {
        g_log_file = fopen(log_file_path, "a");
        if (!g_log_file) {
            pthread_mutex_unlock(&g_log_lock);
            fprintf(stderr, "Failed to open log file: %s\n", log_file_path);
            return -1;
        }
    }
    
    /* Disable colors if not writing to terminal */
    if (!isatty(fileno(stdout))) {
        g_use_colors = false;
    }
    
    pthread_mutex_unlock(&g_log_lock);
    
    logger_log(LOG_INFO, "Logger initialized", __FILE__, __LINE__);
    return 0;
}

void logger_cleanup(void) {
    pthread_mutex_lock(&g_log_lock);
    
    if (g_log_file) {
        logger_log(LOG_INFO, "Logger shutting down", __FILE__, __LINE__);
        fclose(g_log_file);
        g_log_file = NULL;
    }
    
    pthread_mutex_unlock(&g_log_lock);
}

/* === Logging Functions === */

void logger_log(log_level_t level, const char* message, 
                const char* file, int line) {
    if (level < g_min_level) return;
    
    pthread_mutex_lock(&g_log_lock);
    
    /* Get current timestamp */
    time_t now;
    time(&now);
    struct tm* tm_info = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    /* Format: [TIMESTAMP] [LEVEL] [file:line] message */
    
    /* Console output with colors */
    if (g_use_colors) {
        fprintf(stdout, "%s[%s]%s %s%-5s%s \x1b[90m[%s:%d]\x1b[0m %s\n",
                level_colors[level],
                timestamp,
                color_reset,
                level_colors[level],
                level_strings[level],
                color_reset,
                file, line,
                message);
    } else {
        fprintf(stdout, "[%s] %-5s [%s:%d] %s\n",
                timestamp,
                level_strings[level],
                file, line,
                message);
    }
    
    /* File output (no colors) */
    if (g_log_file) {
        fprintf(g_log_file, "[%s] %-5s [%s:%d] %s\n",
                timestamp,
                level_strings[level],
                file, line,
                message);
        fflush(g_log_file);
    }
    
    pthread_mutex_unlock(&g_log_lock);
}

void logger_logf(log_level_t level, const char* file, int line,
                 const char* format, ...) {
    if (level < g_min_level) return;
    
    char message[4096];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    
    logger_log(level, message, file, line);
}

/* === Structured Logging === */

void logger_structured(log_level_t level, const char* event_type,
                       const char* file, int line,
                       const char* key1, const char* val1, ...) {
    if (level < g_min_level) return;
    
    pthread_mutex_lock(&g_log_lock);
    
    time_t now;
    time(&now);
    struct tm* tm_info = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", tm_info);
    
    /* JSON format */
    fprintf(stdout, "{\"timestamp\":\"%s\",\"level\":\"%s\",\"event\":\"%s\","
            "\"source\":\"%s:%d\"",
            timestamp, level_strings[level], event_type, file, line);
    
    /* Add key-value pairs */
    va_list args;
    va_start(args, val1);
    const char* key = key1;
    const char* val = val1;
    
    while (key && val) {
        fprintf(stdout, ",\"%s\":\"%s\"", key, val);
        key = va_arg(args, const char*);
        if (key) val = va_arg(args, const char*);
    }
    va_end(args);
    
    fprintf(stdout, "}\n");
    
    if (g_log_file) {
        /* Same output to file */
        fprintf(g_log_file, "{\"timestamp\":\"%s\",\"level\":\"%s\",\"event\":\"%s\","
                "\"source\":\"%s:%d\"",
                timestamp, level_strings[level], event_type, file, line);
        
        va_start(args, val1);
        key = key1;
        val = val1;
        while (key && val) {
            fprintf(g_log_file, ",\"%s\":\"%s\"", key, val);
            key = va_arg(args, const char*);
            if (key) val = va_arg(args, const char*);
        }
        va_end(args);
        
        fprintf(g_log_file, "}\n");
        fflush(g_log_file);
    }
    
    pthread_mutex_unlock(&g_log_lock);
}

/* === Configuration === */

void logger_set_level(log_level_t level) {
    pthread_mutex_lock(&g_log_lock);
    g_min_level = level;
    pthread_mutex_unlock(&g_log_lock);
}

void logger_set_colors(bool use_colors) {
    pthread_mutex_lock(&g_log_lock);
    g_use_colors = use_colors;
    pthread_mutex_unlock(&g_log_lock);
}

log_level_t logger_level_from_string(const char* str) {
    if (!str) return LOG_INFO;
    
    if (strcasecmp(str, "trace") == 0) return LOG_TRACE;
    if (strcasecmp(str, "debug") == 0) return LOG_DEBUG;
    if (strcasecmp(str, "info") == 0) return LOG_INFO;
    if (strcasecmp(str, "warn") == 0) return LOG_WARN;
    if (strcasecmp(str, "error") == 0) return LOG_ERROR;
    if (strcasecmp(str, "fatal") == 0) return LOG_FATAL;
    
    return LOG_INFO;
}

const char* logger_level_to_string(log_level_t level) {
    if (level >= 0 && level <= LOG_FATAL) {
        return level_strings[level];
    }
    return "UNKNOWN";
}
