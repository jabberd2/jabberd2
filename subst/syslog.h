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

/* $Id: syslog.h,v 1.5 2005/06/02 04:48:25 zion Exp $ */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

/* jabberd2 Windows DLL */
#ifndef JABBERD2_API
# ifdef _WIN32
#  ifdef JABBERD2_EXPORTS
#   define JABBERD2_API  __declspec(dllexport)
#  else /* JABBERD2_EXPORTS */
#   define JABBERD2_API  __declspec(dllimport)
#  endif /* JABBERD2_EXPORTS */
# else /* _WIN32 */
#  define JABBERD2_API extern
# endif /* _WIN32 */
#endif /* JABBERD2_API */

#ifndef HAVE_SYSLOG_H

#ifndef _SYSLOG_H
#define _SYSLOG_H

#include <stdio.h>

/* Constant definitions for openlog() */
#define LOG_PID         1
#define LOG_CONS        2
/* NT event log does not support facility level */
#define LOG_KERN        0
#define LOG_USER        0
#define LOG_MAIL        0
#define LOG_DAEMON      0
#define LOG_AUTH        0
#define LOG_SYSLOG      0
#define LOG_LPR         0
#define LOG_LOCAL0      0
#define LOG_LOCAL1      0
#define LOG_LOCAL2      0
#define LOG_LOCAL3      0
#define LOG_LOCAL4      0
#define LOG_LOCAL5      0
#define LOG_LOCAL6      0
#define LOG_LOCAL7      0

#define LOG_EMERG       0       /* system is unusable */
#define LOG_ALERT       1       /* action must be taken immediately */
#define LOG_CRIT        2       /* critical conditions */
#define LOG_ERR         3       /* error conditions */
#define LOG_WARNING     4       /* warning conditions */
#define LOG_NOTICE      5       /* normal but signification condition */
#define LOG_INFO        6       /* informational */
#define LOG_DEBUG       7       /* debug-level messages */

JABBERD2_API void
syslog(int level, const char *fmt, ...);

JABBERD2_API void
openlog(const char *, int, ...);

JABBERD2_API void
closelog(void);

#endif

#endif
