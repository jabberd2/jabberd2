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

/* MIO backend for poll() */

#ifdef HAVE_POLL_H
# include <poll.h>
#endif

#define MIO_FUNCS \
    static void _mio_pfds_init(mio_t m)                                 \
    {                                                                   \
        int fd;                                                         \
        for(fd = 0; fd < m->maxfd; fd++)                                \
            m->pfds[fd].fd = -1;                                        \
    }                                                                   \
                                                                        \
    static int _mio_poll(mio_t m, int t)                                \
    {                                                                   \
        return poll(m->pfds, m->highfd + 1, t*1000);                    \
    }

#define MIO_VARS \
    struct pollfd *pfds;

#define MIO_INIT_VARS(m) \
    do {                                                                \
        if((m->pfds = malloc(sizeof(struct pollfd) * maxfd)) == NULL)   \
        {                                                               \
            mio_debug(ZONE, "internal error creating new mio");         \
            free(m->fds);                                               \
            free(m);                                                    \
            return NULL;                                                \
        }                                                               \
        memset(m->pfds, 0, sizeof(struct pollfd) * maxfd);              \
        _mio_pfds_init(m);                                              \
    } while(0)
#define MIO_FREE_VARS(m)        free(m->pfds)

#define MIO_INIT_FD(m, pfd)     m->pfds[pfd].fd = pfd; m->pfds[pfd].events = 0

#define MIO_REMOVE_FD(m, pfd)   m->pfds[pfd].fd = -1

#define MIO_CHECK(m, t)         _mio_poll(m, t)

#define MIO_SET_READ(m, fd)     m->pfds[fd].events |= POLLIN
#define MIO_SET_WRITE(m, fd)    m->pfds[fd].events |= POLLOUT

#define MIO_UNSET_READ(m, fd)   m->pfds[fd].events &= ~POLLIN
#define MIO_UNSET_WRITE(m, fd)  m->pfds[fd].events &= ~POLLOUT

#define MIO_CAN_READ(m, fd)     m->pfds[fd].revents & (POLLIN|POLLERR|POLLHUP|POLLNVAL)
#define MIO_CAN_WRITE(m, fd)    m->pfds[fd].revents & POLLOUT

#define MIO_ERROR(m)            errno
