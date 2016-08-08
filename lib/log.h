#ifndef LOG_H
#define LOG_H

#include <log4c.h>

typedef log4c_category_t    log_t;

#define log_get(...)        log4c_category_get(__VA_ARGS__)
#define log_delete(...)     log4c_category_delete(__VA_ARGS__)

#define __LOG_PRIO(prio, cat, msg, args...) { \
        const log4c_location_info_t locinfo = LOG4C_LOCATION_INFO_INITIALIZER(NULL); \
        log4c_category_log_locinfo(cat, &locinfo, prio, msg, ##args); \
    }

#define LOG_FATAL(cat, msg, args...)  __LOG_PRIO(LOG4C_PRIORITY_FATAL, cat, msg, ##args)
#define LOG_ALERT(cat, msg, args...)  __LOG_PRIO(LOG4C_PRIORITY_ALERT, cat, msg, ##args)
#define LOG_CRIT(cat, msg, args...)   __LOG_PRIO(LOG4C_PRIORITY_CRIT, cat, msg, ##args)
#define LOG_ERROR(cat, msg, args...)  __LOG_PRIO(LOG4C_PRIORITY_ERROR, cat, msg, ##args)
#define LOG_WARN(cat, msg, args...)   __LOG_PRIO(LOG4C_PRIORITY_WARN, cat, msg, ##args)
#define LOG_NOTICE(cat, msg, args...) __LOG_PRIO(LOG4C_PRIORITY_NOTICE, cat, msg, ##args)
#define LOG_INFO(cat, msg, args...)   __LOG_PRIO(LOG4C_PRIORITY_INFO, cat, msg, ##args)
#define LOG_DEBUG(cat, msg, args...)  __LOG_PRIO(LOG4C_PRIORITY_DEBUG, cat, msg, ##args)
#define LOG_TRACE(cat, msg, args...)  __LOG_PRIO(LOG4C_PRIORITY_TRACE, cat, msg, ##args)

#endif // LOG_H
