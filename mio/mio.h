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

#ifndef INCL_MIO_H
#define INCL_MIO_H

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include "util/inaddr.h"
#include "ac-stdint.h"

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

#ifdef _WIN32
# define MIO_MAXFD FD_SETSIZE
#else
# define MIO_MAXFD 1024
#endif

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#endif

#ifdef HAVE_SYS_FILIO_H
# include <sys/filio.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file mio/mio.h
 * @brief mio - manage i/o
 * 
 * This is the most simple fd wrapper possible. It is also customized
 * per-app and may be limited/extended depending on needs.
 *
 * It's basically our own implementation of libevent or libev.
 * 
 * Usage is pretty simple:
 *  - create a manager
 *  - add fds or tell it to listen
 *  - assign an action handler
 *  - tell mio to read or write with a fd
 *  - process accept, read, write, and close requests
 * 
 * Note: normal fd's don't get events unless the app calls mio_read/write() first!
 */

/** the master mio mama */
struct mio_st;

typedef struct mio_fd_st
{
    int fd;
} *mio_fd_t;

/** these are the actions and a handler type assigned by the applicaiton using mio */
typedef enum { action_ACCEPT, action_READ, action_WRITE, action_CLOSE } mio_action_t;
typedef int (*mio_handler_t) (struct mio_st **m, mio_action_t a, struct mio_fd_st *fd, void* data, void *arg);

typedef struct mio_st
{
  void (*mio_free)(struct mio_st **m);

  struct mio_fd_st *(*mio_listen)(struct mio_st **m, int port, const char *sourceip,
				  mio_handler_t app, void *arg);

  struct mio_fd_st *(*mio_connect)(struct mio_st **m, int port, const char *hostip,
				   const char *srcip, mio_handler_t app, void *arg);

  struct mio_fd_st *(*mio_register)(struct mio_st **m, int fd,
				   mio_handler_t app, void *arg);

  void (*mio_app)(struct mio_st **m, struct mio_fd_st *fd,
		  mio_handler_t app, void *arg);

  void (*mio_close)(struct mio_st **m, struct mio_fd_st *fd);

  void (*mio_write)(struct mio_st **m, struct mio_fd_st *fd);

  void (*mio_read)(struct mio_st **m, struct mio_fd_st *fd);

  void (*mio_run)(struct mio_st **m, int timeout);
} **mio_t;

/** create/free the mio subsytem */
JABBERD2_API mio_t mio_new(int maxfd); /* returns NULL if failed */

#define mio_free(m) (*m)->mio_free(m)

/** for creating a new listen socket in this mio (returns new fd or <0) */
#define mio_listen(m, port, sourceip, app, arg) \
    (*m)->mio_listen(m, port, sourceip, app, arg)

/** for creating a new socket connected to this ip:port (returns new fd or <0, use mio_read/write first) */
#define mio_connect(m, port, hostip, srcip, app, arg) \
    (*m)->mio_connect(m, port, hostip, srcip, app, arg)

/** for adding an existing socket connected to this mio */
#define mio_register(m, fd, app, arg) \
    (*m)->mio_register(m, fd, app, arg)

/** re-set the app handler */
#define mio_app(m, fd, app, arg) (*m)->mio_app(m, fd, app, arg)

/** request that mio close this fd */
#define mio_close(m, fd) (*m)->mio_close(m, fd)

/** mio should try the write action on this fd now */
#define mio_write(m, fd) (*m)->mio_write(m, fd)

/** process read events for this fd */
#define mio_read(m, fd) (*m)->mio_read(m, fd)

/** give some cpu time to mio to check it's sockets, 0 is non-blocking */
#define mio_run(m, timeout) (*m)->mio_run(m, timeout)

/** all MIO related routines should use those for error reporting */
#ifndef _WIN32
# define MIO_ERROR       errno
# define MIO_SETERROR(e) (errno = e)
# define MIO_STRERROR(e) strerror(e)
# define MIO_WOULDBLOCK  (errno == EWOULDBLOCK || errno == EINTR || errno == EAGAIN)
#else /* _WIN32 */
JABBERD2_API char *mio_strerror(int code);
# define MIO_ERROR       WSAGetLastError()
# define MIO_SETERROR(e) WSASetLastError(e)
# define MIO_STRERROR(e) mio_strerror(e)
# define MIO_WOULDBLOCK  (WSAGetLastError() == WSAEWOULDBLOCK)
#endif /* _WIN32 */

#ifdef __cplusplus
}
#endif

#endif  /* INCL_MIO_H */

