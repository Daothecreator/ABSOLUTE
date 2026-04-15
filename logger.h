/*
 * Logging System Header
 * 
 * Part of Sovereign Privacy Widget
 * License: MIT
 */

#ifndef LOGGER_H
#define LOGGER_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* === Log Levels === */
typedef enum {
    LOG_TRACE = 0,
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR,
    LOG_FATAL
} log_level_t;

/* === Initialization === */
int logger_init(const char* log_file_path, log_level_t min_level);
void logger_cleanup(void);

/* === Basic Logging === */
void logger_log(log_level_t level, const char* message, 
                const char* file, int line);
void logger_logf(log_level_t level, const char* file, int line,
                 const char* format, ...);

/* === Structured Logging === */
void logger_structured(log_level_t level, const char* event_type,
                       const char* file, int line,
                       const char* key1, const char* val1, ...);

/* === Configuration === */
void logger_set_level(log_level_t level);
void logger_set_colors(bool use_colors);
log_level_t logger_level_from_string(const char* str);
const char* logger_level_to_string(log_level_t level);

/* === Convenience Macros === */
#define LOG_TRACE(msg) logger_log(LOG_TRACE, msg, __FILE__, __LINE__)
#define LOG_DEBUG(msg) logger_log(LOG_DEBUG, msg, __FILE__, __LINE__)
#define LOG_INFO(msg) logger_log(LOG_INFO, msg, __FILE__, __LINE__)
#define LOG_WARN(msg) logger_log(LOG_WARN, msg, __FILE__, __LINE__)
#define LOG_ERROR(msg) logger_log(LOG_ERROR, msg, __FILE__, __LINE__)
#define LOG_FATAL(msg) logger_log(LOG_FATAL, msg, __FILE__, __LINE__)

#define LOGF_TRACE(fmt, ...) logger_logf(LOG_TRACE, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOGF_DEBUG(fmt, ...) logger_logf(LOG_DEBUG, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOGF_INFO(fmt, ...) logger_logf(LOG_INFO, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOGF_WARN(fmt, ...) logger_logf(LOG_WARN, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOGF_ERROR(fmt, ...) logger_logf(LOG_ERROR, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOGF_FATAL(fmt, ...) logger_logf(LOG_FATAL, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define LOG_STRUCT(level, event, ...) \
    logger_structured(level, event, __FILE__, __LINE__, __VA_ARGS__, NULL)

#ifdef __cplusplus
}
#endif

#endif /* LOGGER_H */
