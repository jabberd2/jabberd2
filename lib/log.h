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

/** @file util/log.h
  * @brief logging functions
  * @author Robert Norris
  * $Revision: 1.1 $
  * $Date: 2004/04/30 00:53:54 $
  */

#ifndef INCL_UTIL_LOG_H
#define INCL_UTIL_LOG_H 1

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#ifdef HAVE_SYSLOG_H
# include <syslog.h>
#endif

#include "pool.h"

typedef enum {
    log_STDOUT,
    log_SYSLOG,
    log_FILE
} log_type_t;

/* opaque decl */
typedef struct _log_st *log_t;

JABBERD2_API log_t    log_new(pool_t p, log_type_t type, const char *ident, const char *facility);
JABBERD2_API void     log_write(log_t log, int level, const char *msgfmt, ...);

/* debug logging */
#if defined(DEBUG) && 0
JABBERD2_API int      log_debug_flag;
void            log_debug(char *file, int line, const char *subsys, const char *msgfmt, ...);

# define        log_debug_get_flag()    log_debug_flag
# define        log_debug_set_flag(f)   (log_debug_flag = f ? 1 : 0)
# define        log_debug(...)          if(log_debug_flag) __log_debug(__FILE__,__LINE__,0,__VA_ARGS__)
# define        log_debug_subsys(...)   if(log_debug_flag) __log_debug(__FILE__,__LINE__,__VA_ARGS__)
#else
# define        log_debug_get_flag()    (0)
# define        log_debug_set_flag(f)
# define        log_debug(...)
# define        log_debug_subsys(...)
#endif

#endif
