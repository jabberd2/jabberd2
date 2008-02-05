/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2002-2004 Jeremie Miller, Thomas Muldowney,
 *                         Ryan Eatmon, Robert Norris
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA02111-1307USA
 */

/* substituted functions */

#ifndef INCL_SUBST_H
#define INCL_SUBST_H 1

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#if defined (HAVE_STDARG_H)
#include <stdarg.h>
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

#if !defined(HAVE_SNPRINTF) || defined(HAVE_BROKEN_SNPRINTF)
  JABBERD2_API int ap_snprintf(char *, size_t, const char *, ...);
# define snprintf ap_snprintf
#endif

#if !defined(HAVE_VSNPRINTF) || defined(HAVE_BROKEN_VSNPRINTF)
  JABBERD2_API int ap_vsnprintf(char *, size_t, const char *, va_list ap);
# define vsnprintf ap_vsnprintf
#endif

#ifndef HAVE_GETOPT
# include "getopt.h"
#endif

#ifndef HAVE_SYSLOG_H
# include "syslog.h"
#endif

#ifndef HAVE_GETTIMEOFDAY

# if defined(HAVE_SYS_TIME_H)
#  include <sys/time.h>
# elif defined(HAVE_SYS_TIMEB_H)
#  include <sys/timeb.h>
# endif

struct timezone {
    int tz_minuteswest;
    int tz_dsttime;
};

JABBERD2_API int gettimeofday(struct timeval *tp, struct timezone *tz);
#endif

#ifdef HAVE_WINSOCK2_H
# include <winsock2.h>
# include "ip6_misc.h"

# define    EWOULDBLOCK     WSAEWOULDBLOCK
# define    ECONNREFUSED    WSAECONNREFUSED
# define    EINPROGRESS     WSAEINPROGRESS
#endif

#ifndef HAVE_INET_ATON
JABBERD2_API int inet_aton(const char *cp, struct in_addr *addr);
#endif
#ifndef HAVE_INET_NTOP
JABBERD2_API const char *inet_ntop(int af, const void *src, char *dst, size_t size);
#endif
#ifndef HAVE_INET_PTON
JABBERD2_API int inet_pton(int af, const char *src, void *dst);
#endif

#ifndef HAVE_IN_PORT_T
typedef uint16_t in_port_t;
#endif

#ifdef HAVE__MKDIR
# define mkdir(a,b) _mkdir(a)
#endif

#ifndef HAVE_STRNDUP
JABBERD2_API char *strndup(char *str, size_t len);
#endif

#ifndef HAVE_TIMEGM
#include <time.h>
JABBERD2_API time_t timegm (struct tm *tm);
#endif

#endif
