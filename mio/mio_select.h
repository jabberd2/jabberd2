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

/* MIO backend for select() */

#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif

#define MIO_FUNCS \
    static void _mio_fds_init(mio_priv_t m)                             \
    {                                                                   \
        int fd;                                                         \
        for(fd = 0; fd < m->maxfd; fd++)                                \
        {                                                               \
            m->fds[fd].mio_fd.fd = fd;                                  \
        }                                                               \
        m->highfd = 0;                                                  \
        m->lowfd = m->maxfd;                                            \
    }                                                                   \
                                                                        \
    static mio_fd_t _mio_alloc_fd(mio_priv_t m, int fd)                 \
    {                                                                   \
        if(fd > m->highfd) m->highfd = fd;                              \
        if(fd < m->lowfd) m->lowfd = fd;                                \
        return &m->fds[fd].mio_fd;                                      \
    }                                                                   \
                                                                        \
    static int _mio_select(mio_priv_t m, int t)                         \
    {                                                                   \
        struct timeval tv;                                              \
                                                                        \
        m->rfds_out = m->rfds_in;                                       \
        m->wfds_out = m->wfds_in;                                       \
                                                                        \
        tv.tv_sec = t;                                                  \
        tv.tv_usec = 0;                                                 \
        return select(m->highfd + 1, &m->rfds_out, &m->wfds_out, NULL, &tv); \
    }

#define MIO_FD_VARS

#define MIO_VARS \
    struct mio_priv_fd_st *fds;                                         \
    int lowfd;                                                          \
    int highfd;                                                         \
    fd_set rfds_in, wfds_in, rfds_out, wfds_out;

#define MIO_INIT_VARS(m) \
    do {                                                                \
        if (maxfd > FD_SETSIZE)                                         \
        {                                                               \
            mio_debug(ZONE,"wanted MIO larger than %d file descriptors", FD_SETSIZE); \
            free(m);                                                    \
            return NULL;                                                \
        }                                                               \
                                                                        \
        if((MIO(m)->fds = calloc(1, sizeof(struct mio_priv_fd_st) * maxfd)) == NULL) \
        {                                                               \
            mio_debug(ZONE,"internal error creating new mio");          \
            free(m);                                                    \
            return NULL;                                                \
        }                                                               \
                                                                        \
        _mio_fds_init(MIO(m));                                          \
        FD_ZERO(&MIO(m)->rfds_in);                                      \
        FD_ZERO(&MIO(m)->wfds_in);                                      \
    } while(0)

#define MIO_FREE_VARS(m)        free(MIO(m)->fds)

#define MIO_ALLOC_FD(m, rfd)    _mio_alloc_fd(MIO(m), rfd)
#define MIO_FREE_FD(m, mfd)

#define MIO_REMOVE_FD(m, mfd) \
    do {                                                                \
        FD_CLR(mfd->mio_fd.fd, &MIO(m)->rfds_in);                       \
        FD_CLR(mfd->mio_fd.fd, &MIO(m)->wfds_in);                       \
    } while(0)

#define MIO_CHECK(m, t)         _mio_select(MIO(m), t)

#define MIO_SET_READ(m, mfd)    FD_SET(mfd->mio_fd.fd, &MIO(m)->rfds_in)
#define MIO_SET_WRITE(m, mfd)   FD_SET(mfd->mio_fd.fd, &MIO(m)->wfds_in)

#define MIO_UNSET_READ(m, mfd)  FD_CLR(mfd->mio_fd.fd, &MIO(m)->rfds_in)
#define MIO_UNSET_WRITE(m, mfd) FD_CLR(mfd->mio_fd.fd, &MIO(m)->wfds_in)

#define MIO_CAN_READ(m, iter)   FD_ISSET(iter, &MIO(m)->rfds_out)
#define MIO_CAN_WRITE(m, iter)  FD_ISSET(iter, &MIO(m)->wfds_out)
#define MIO_CAN_FREE(m)         1


#define MIO_INIT_ITERATOR(iter) \
    int iter

#define MIO_ITERATE_RESULTS(m, retval, iter) \
    for(iter = MIO(m)->lowfd; iter <= MIO(m)->highfd; iter++)

#define MIO_ITERATOR_FD(m, iter) \
    (&MIO(m)->fds[iter].mio_fd)
