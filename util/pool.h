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

/** @file util/pool.h
  * @brief memory pools
  * $Revision: 1.2 $
  * $Date: 2004/05/05 23:49:38 $
  */

#ifndef INCL_UTIL_POOL_H
#define INCL_UTIL_POOL_H 1

#ifdef HAVE_CONFIG_H
# include <config.h>
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

/* opaque decl */
typedef struct _pool_st *pool_t;

typedef void (*pool_cleanup_t)(void *arg);


#ifdef POOL_DEBUG
# define pool_new() _pool_new(__FILE__,__LINE__) 
# define pool_heap(i) _pool_new_heap(i,__FILE__,__LINE__) 
#else
# define pool_heap(i) _pool_new_heap(i,NULL,0) 
# define pool_new() _pool_new(NULL,0)
#endif

JABBERD2_API pool_t _pool_new(char *file, int line); /* new pool_t :) */
JABBERD2_API pool_t _pool_new_heap(int size, char *file, int line); /* creates a new memory pool_t with an initial heap size */
JABBERD2_API void *pmalloc(pool_t p, int size); /* wrapper around malloc, takes from the pool, cleaned up automatically */
JABBERD2_API void *pmalloc_x(pool_t p, int size, char c); /* Wrapper around pmalloc which prefils buffer with c */
JABBERD2_API void *pmalloco(pool_t p, int size); /* YAPW for zeroing the block */
JABBERD2_API char *pstrdup(pool_t p, const char *src); /* wrapper around strdup, gains mem from pool_t */
JABBERD2_API void pool_stat(int full); /* print to stderr the changed pools and reset */
JABBERD2_API char *pstrdupx(pool_t p, const char *src, int len); /* use given len */
JABBERD2_API void pool_cleanup(pool_t p, pool_cleanup_t fn, void *arg); /* calls f(arg) before the pool_t is freed during cleanup */
JABBERD2_API void pool_clear(pool_t p);
JABBERD2_API void pool_free(pool_t p); /* calls the cleanup functions, frees all the data on the pool, and deletes the pool_t itself */
JABBERD2_API int pool_size(pool_t p); /* returns total bytes allocated in this pool_t */


#endif
