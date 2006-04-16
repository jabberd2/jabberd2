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
    static int _mio_select(mio_t m, int t)                                          \
    {                                                                               \
        struct timeval tv;                                                          \
                                                                                    \
        m->rfds_out = m->rfds_in;                                                   \
        m->wfds_out = m->wfds_in;                                                   \
                                                                                    \
        tv.tv_sec = t;                                                              \
        tv.tv_usec = 0;                                                             \
        return select(m->highfd + 1, &m->rfds_out, &m->wfds_out, NULL, &tv);        \
    }

#define MIO_VARS \
    fd_set rfds_in, wfds_in, rfds_out, wfds_out;

#define MIO_INIT_VARS(m) \
    FD_ZERO(&m->rfds_in); \
    FD_ZERO(&m->wfds_in);

#define MIO_FREE_VARS(m)

#define MIO_INIT_FD(m, fd)

#define MIO_REMOVE_FD(m, fd)    do { FD_CLR(fd, &m->rfds_in); FD_CLR(fd, &m->wfds_in); } while(0)

#define MIO_CHECK(m, t)         _mio_select(m, t)

#define MIO_SET_READ(m, fd)     FD_SET(fd, &m->rfds_in)
#define MIO_SET_WRITE(m, fd)    FD_SET(fd, &m->wfds_in)

#define MIO_UNSET_READ(m, fd)   FD_CLR(fd, &m->rfds_in)
#define MIO_UNSET_WRITE(m, fd)  FD_CLR(fd, &m->wfds_in)

#define MIO_CAN_READ(m, fd)     FD_ISSET(fd, &m->rfds_out)
#define MIO_CAN_WRITE(m, fd)    FD_ISSET(fd, &m->wfds_out)

#define MIO_ERROR(m)            errno
