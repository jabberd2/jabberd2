/*
 * Copyright (C) 2001  Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL
 * INTERNET SOFTWARE CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: syslog.c,v 1.5 2005/06/02 04:48:25 zion Exp $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#if !defined(HAVE_SYSLOG_H) && defined(HAVE_REPORTEVENT)

#include <stdio.h>
#include <windows.h>
#include <string.h>
#include <stdlib.h>

#include "syslog.h"

static HANDLE hAppLog = NULL;
static FILE *log_stream;
static int debug_level = 0;

static struct dsn_c_pvt_sfnt {
        int val;
        const char *strval;
} facilities[] = {
        { LOG_KERN,             "kern" },
        { LOG_USER,             "user" },
        { LOG_MAIL,             "mail" },
        { LOG_DAEMON,           "daemon" },
        { LOG_AUTH,             "auth" },
        { LOG_SYSLOG,           "syslog" },
        { LOG_LPR,              "lpr" },
#ifdef LOG_NEWS
        { LOG_NEWS,             "news" },
#endif
#ifdef LOG_UUCP
        { LOG_UUCP,             "uucp" },
#endif
#ifdef LOG_CRON
        { LOG_CRON,             "cron" },
#endif
#ifdef LOG_AUTHPRIV
        { LOG_AUTHPRIV,         "authpriv" },
#endif
#ifdef LOG_FTP
        { LOG_FTP,              "ftp" },
#endif
        { LOG_LOCAL0,           "local0"},
        { LOG_LOCAL1,           "local1"},
        { LOG_LOCAL2,           "local2"},
        { LOG_LOCAL3,           "local3"},
        { LOG_LOCAL4,           "local4"},
        { LOG_LOCAL5,           "local5"},
        { LOG_LOCAL6,           "local6"},
        { LOG_LOCAL7,           "local7"},
        { LOG_USER,             "log_user"},
        { 0,                    NULL }
};

/*
 * Log to the NT Event Log
 */
void
syslog(int level, const char *fmt, ...) {
        va_list ap;
        char buf[1024];
        const char *str[1];

        str[0] = buf;

        va_start(ap, fmt);
        vsprintf(buf, fmt, ap);
        va_end(ap);

        /* Make sure that the channel is open to write the event */
        if (hAppLog != NULL) {
                switch (level) {
                case LOG_INFO:
                case LOG_NOTICE:
                case LOG_DEBUG:
                        ReportEvent(hAppLog, EVENTLOG_INFORMATION_TYPE, 0,
                                    0, NULL, 1, 0, str, NULL);
                        break;
                case LOG_WARNING:
                        ReportEvent(hAppLog, EVENTLOG_WARNING_TYPE, 0,
                                    0, NULL, 1, 0, str, NULL);
                        break;
                default:
                        ReportEvent(hAppLog, EVENTLOG_ERROR_TYPE, 0,
                                    0, NULL, 1, 0, str, NULL);
                        break;
                }
        }
}

/*
 * Initialize event logging
 */
void
openlog(const char *name, int flags, ...) {
        /* Get a handle to the Application event log */
        hAppLog = RegisterEventSource(NULL, name);
}

/*
 * Close the Handle to the application Event Log
 * We don't care whether or not we succeeded so ignore return values
 * In fact if we failed then we would have nowhere to put the message
 */
void
closelog() {
        DeregisterEventSource(hAppLog);
}

#endif
