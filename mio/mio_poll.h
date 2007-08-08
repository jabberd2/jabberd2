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
    static void _mio_fds_init(mio_priv_t m)                             \
    {                                                                   \
        int fd;                                                         \
        for(fd = 0; fd < m->maxfd; fd++)                                \
        {                                                               \
            m->pfds[fd].fd = -1;                                        \
            m->fds[fd].mio_fd.fd = fd;                                  \
        }                                                               \
        m->highfd = 0;                                                  \
    }                                                                   \
                                                                        \
    static mio_fd_t _mio_alloc_fd(mio_priv_t m, int fd)                 \
    {                                                                   \
        m->pfds[fd].fd = fd;                                            \
        m->pfds[fd].events = 0;                                         \
        if(fd > m->highfd) m->highfd = fd;                              \
        return &m->fds[fd].mio_fd;                                      \
    }                                                                   \
                                                                        \
    static int _mio_poll(mio_priv_t m, int t)                           \
    {                                                                   \
        return poll(m->pfds, m->highfd + 1, t*1000);                    \
    }

#define MIO_FD_VARS

#define MIO_VARS \
    struct mio_priv_fd_st *fds;                                         \
    int highfd;                                                         \
    struct pollfd *pfds;

#define MIO_INIT_VARS(m) \
    do {                                                                \
        if((MIO(m)->fds = malloc(sizeof(struct mio_priv_fd_st) * maxfd)) == NULL) \
        {                                                               \
            mio_debug(ZONE,"internal error creating new mio");          \
            free(m);                                                    \
            return NULL;                                                \
        }                                                               \
        memset(MIO(m)->fds, 0, sizeof(struct mio_priv_fd_st) * maxfd);  \
                                                                        \
        if((MIO(m)->pfds = malloc(sizeof(struct pollfd) * maxfd)) == NULL) \
        {                                                               \
            mio_debug(ZONE, "internal error creating new mio");         \
            free(MIO(m)->fds);                                          \
            free(m);                                                    \
            return NULL;                                                \
        }                                                               \
        memset(MIO(m)->pfds, 0, sizeof(struct pollfd) * maxfd);         \
                                                                        \
        _mio_fds_init(MIO(m));                                          \
    } while(0)

#define MIO_FREE_VARS(m) \
    do {                                                                \
        free(MIO(m)->fds);                                              \
        free(MIO(m)->pfds);                                             \
    } while (0)

#define MIO_ALLOC_FD(m, rfd)    _mio_alloc_fd(MIO(m), rfd)
#define MIO_FREE_FD(m, mfd)

#define MIO_REMOVE_FD(m, mfd)   MIO(m)->pfds[mfd->mio_fd.fd].fd = -1

#define MIO_CHECK(m, t)         _mio_poll(MIO(m), t)

#define MIO_SET_READ(m, mfd)    MIO(m)->pfds[mfd->mio_fd.fd].events |= POLLIN
#define MIO_SET_WRITE(m, mfd)   MIO(m)->pfds[mfd->mio_fd.fd].events |= POLLOUT

#define MIO_UNSET_READ(m, mfd)  MIO(m)->pfds[mfd->mio_fd.fd].events &= ~POLLIN
#define MIO_UNSET_WRITE(m, mfd) MIO(m)->pfds[mfd->mio_fd.fd].events &= ~POLLOUT


#define MIO_CAN_READ(m, iter) \
    (MIO(m)->pfds[iter].revents & (POLLIN|POLLERR|POLLHUP|POLLNVAL))
#define MIO_CAN_WRITE(m, iter)  (MIO(m)->pfds[iter].revents & POLLOUT)
#define MIO_CAN_FREE(m)         1


#define MIO_INIT_ITERATOR(iter) \
    int iter

#define MIO_ITERATE_RESULTS(m, retval, iter) \
    for(iter = 0; iter <= MIO(m)->highfd; iter++)

#define MIO_ITERATOR_FD(m, iter) \
    (&MIO(m)->fds[iter].mio_fd)
