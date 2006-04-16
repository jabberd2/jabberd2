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

#include "ac-stdint.h"

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
 * This used to be something large and all inclusive for 1.2/1.4,
 * but for 1.5 and beyond it is the most simple fd wrapper possible.
 * It is also customized per-app and may be limited/extended depending on needs.
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

/** the master mio mama, defined internally */
typedef struct mio_st *mio_t;

/** these are the actions and a handler type assigned by the applicaiton using mio */
typedef enum { action_ACCEPT, action_READ, action_WRITE, action_CLOSE } mio_action_t;
typedef int (*mio_handler_t) (mio_t m, mio_action_t a, int fd, void* data, void *arg);

/** create/free the mio subsytem */
mio_t mio_new(int maxfd); /* returns NULL if failed */
void mio_free(mio_t m);

/** for creating a new listen socket in this mio (returns new fd or <0) */
int mio_listen(mio_t m, int port, char *sourceip, mio_handler_t app, void *arg);

/** for creating a new socket connected to this ip:port (returns new fd or <0, use mio_read/write first) */
int mio_connect(mio_t m, int port, char *hostip, mio_handler_t app, void *arg);

/** tell mio to track this fd (returns new fd or <0) */
int mio_fd(mio_t m, int fd, mio_handler_t app, void *arg);

/** re-set the app handler */
void mio_app(mio_t m, int fd, mio_handler_t app, void *arg);

/** request that mio close this fd */
void mio_close(mio_t m, int fd);

/** mio should try the write action on this fd now */
void mio_write(mio_t m, int fd);

/** process read events for this fd */
void mio_read(mio_t m, int fd);

/** give some cpu time to mio to check it's sockets, 0 is non-blocking */
void mio_run(mio_t m, int timeout);

#ifdef __cplusplus
}
#endif

#endif  /* INCL_MIO_H */

