/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2002 Jeremie Miller, Thomas Muldowney,
 *                    Ryan Eatmon, Robert Norris
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA02111-1307USA
 */

#include "util.h"

#define MAX_LOG_LINE (1024)

#ifdef DEBUG
static int debug_flag;
#endif

static const char *_log_level[] =
{
    "emergency",
    "alert",
    "critical",
    "error",
    "warning",
    "notice",
    "info",
    "debug"
};

static log_facility_t _log_facilities[] = {
    { "local0", LOG_LOCAL0 },
    { "local1", LOG_LOCAL1 },
    { "local2", LOG_LOCAL2 },
    { "local3", LOG_LOCAL3 },
    { "local4", LOG_LOCAL4 },
    { "local5", LOG_LOCAL5 },
    { "local6", LOG_LOCAL6 },
    { "local7", LOG_LOCAL7 },
    { NULL, -1 }
};

static int _log_facility(const char *facility) {
    log_facility_t *lp;

    if (facility == NULL) {
        return -1;
    }
    for (lp = _log_facilities; lp->facility; lp++) {
        if (!strcasecmp(lp->facility, facility)) {
            break;
        }
    }
    return lp->number;
}

log_t log_new(log_type_t type, const char *ident, const char *facility)
{
    log_t log;
    int fnum = 0;

    log = (log_t) calloc(1, sizeof(struct log_st));

    log->type = type;

    if(type == log_SYSLOG) {
        fnum = _log_facility(facility);
        if (fnum < 0)
            fnum = LOG_LOCAL7;
        openlog(ident, LOG_PID, fnum);
        return log;
    }

    else if(type == log_STDOUT) {
        log->file = stdout;
        return log;
    }

    log->file = fopen(ident, "a+");
    if(log->file == NULL)
    {
        fprintf(stderr,
            "ERROR: couldn't open logfile: %s\n"
            "       logging will go to stdout instead\n", strerror(errno));
        log->type = log_STDOUT;
        log->file = stdout;
    }

    return log;
}

void log_write(log_t log, int level, const char *msgfmt, ...)
{
    va_list ap;
    char *pos, message[MAX_LOG_LINE+1];
    int sz, len;
    time_t t;

    if(log->type == log_SYSLOG) {
        va_start(ap, msgfmt);
#ifdef HAVE_VSYSLOG
        vsyslog(level, msgfmt, ap);
#else
        len = vsnprintf(message, MAX_LOG_LINE, msgfmt, ap);
        if (len > MAX_LOG_LINE)
            message[MAX_LOG_LINE] = '\0';
        else
            message[len] = '\0';
        syslog(level, "%s", message);
#endif
        va_end(ap);

#ifndef DEBUG
        return;
#endif
    }

    /* timestamp */
    t = time(NULL);
    pos = ctime(&t);
    sz = strlen(pos);
    /* chop off the \n */
    pos[sz-1]=' ';

    /* insert the header */
    len = snprintf(message, MAX_LOG_LINE, "%s[%s] ", pos, _log_level[level]);
    if (len > MAX_LOG_LINE)
        message[MAX_LOG_LINE] = '\0';
    else
        message[len] = '\0';

    /* find the end and attach the rest of the msg */
    for (pos = message; *pos != '\0'; pos++); /*empty statement */
    sz = pos - message;
    va_start(ap, msgfmt);
    vsnprintf(pos, MAX_LOG_LINE - sz, msgfmt, ap);
    va_end(ap);
#ifdef DEBUG
    if(log->type != log_SYSLOG) {
#endif
        fprintf(log->file,"%s", message);
        fprintf(log->file, "\n");
        fflush(log->file);
#ifdef DEBUG
    }
#endif

#ifdef DEBUG
    /* If we are in debug mode we want everything copied to the stdout */
    if (get_debug_flag() && log->type != log_STDOUT) {
        fprintf(stdout, "%s\n", message);
        fflush(stdout);
    }
#endif /*DEBUG*/
}

void log_free(log_t log) {
    if(log->type == log_SYSLOG)
        closelog();
    else if(log->type == log_FILE)
        fclose(log->file);

    free(log);
}

#ifdef DEBUG
/** debug logging */
void debug_log(const char *file, int line, const char *msgfmt, ...)
{
    va_list ap;
    char *pos, message[MAX_DEBUG];
    int sz;
    time_t t;

    /* timestamp */
    t = time(NULL);
    pos = ctime(&t);
    sz = strlen(pos);
    /* chop off the \n */
    pos[sz-1]=' ';

    /* insert the header */
    snprintf(message, MAX_DEBUG, "%s%s:%d ", pos, file, line);

    /* find the end and attach the rest of the msg */
    for (pos = message; *pos != '\0'; pos++); /*empty statement */
    sz = pos - message;
    va_start(ap, msgfmt);
    vsnprintf(pos, MAX_DEBUG - sz, msgfmt, ap);
    va_end(ap);
    fprintf(stderr,"%s", message);
    fprintf(stderr, "\n");
    fflush(stderr);
}

int get_debug_flag(void)
{
    return debug_flag;
}

void set_debug_flag(int v)
{
    debug_flag = v;
}
#else /* DEBUG */
void debug_log(const char *file, int line, const char *msgfmt, ...)
{ }
#endif
