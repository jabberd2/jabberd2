/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2002 Jeremie Miller, Thomas Muldowney,
 *                    Ryan Eatmon, Robert Norris, Christof Meerwald
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

/*
 * MIO backend for kqueue
 * Written by Jiang Hong <jh@6.cn>
 *
 */

#error kqueue is currently unfinished and will eat your CPU alive. If you intend to use it, you need to fix it first.

#include <sys/types.h>
#include <sys/time.h>
#include <sys/event.h>

#define KE_INC_SIZE 64
#define KE_FLAG_READ (1 << 1)
#define KE_FLAG_WRITE (1 << 2)

#define KE_ENSURE(x) ((x) && (x) != -1)

// _mio_set_events() borrows ideas from squid-2.7 comm_kqueue.c

#define MIO_FUNCS \
    static int _mio_poll(mio_t m, int t) \
    { \
		struct timespec timeout; \
		int r; \
		timeout.tv_sec = t / 1000; \
		timeout.tv_nsec = (t % 1000) * 1000000; \
		r = kevent(MIO(m)->kqueue_fd, MIO(m)->kqlst, MIO(m)->kqoff, MIO(m)->ke, MIO(m)->kqmax, &timeout); \
		MIO(m)->kqoff = 0; \
		if (r >= MIO(m)->kqmax) { \
			MIO(m)->kqmax = MIO(m)->kqmax + KE_INC_SIZE; \
			MIO(m)->kqlst = realloc(MIO(m)->kqlst, sizeof(struct kevent) * MIO(m)->kqmax); \
			MIO(m)->ke = realloc(MIO(m)->ke, sizeof(struct kevent) * MIO(m)->kqmax); \
		} \
		return r; \
    } \
	static void \
	_mio_set_events(void* m, int fd, int need_read, int need_write, void* data) \
	{ \
	    struct kevent *kep; \
		int st_new_r = (need_read == 1) ? KE_FLAG_READ : ((need_read == 0) ? 0 : MIO(m)->kqueue_state[fd] & KE_FLAG_READ); \
		int st_new_w = (need_write == 1) ? KE_FLAG_WRITE : ((need_write == 0) ? 0 : MIO(m)->kqueue_state[fd] & KE_FLAG_WRITE); \
	    int st_new = st_new_r | st_new_w; \
	    int st_change; \
	 \
	    st_change = MIO(m)->kqueue_state[fd] ^ st_new; \
	    if (!st_change) return; \
	 \
	    if (MIO(m)->kqoff >= MIO(m)->kqmax - 2) { \
			MIO(m)->kqmax = MIO(m)->kqmax + KE_INC_SIZE; \
			MIO(m)->kqlst = realloc(MIO(m)->kqlst, sizeof(struct kevent) * MIO(m)->kqmax); \
			MIO(m)->ke = realloc(MIO(m)->ke, sizeof(struct kevent) * MIO(m)->kqmax); \
	    } \
	    kep = MIO(m)->kqlst + MIO(m)->kqoff; \
	 \
	    if (st_change & KE_FLAG_READ) { \
	    	EV_SET(kep, (uintptr_t) fd, EVFILT_READ, KE_ENSURE(need_read) ? EV_ADD : EV_DELETE, 0, 0, data); \
		    MIO(m)->kqoff++; \
			kep++; \
	    } \
	    if (st_change & KE_FLAG_WRITE) { \
		    EV_SET(kep, (uintptr_t) fd, EVFILT_WRITE, KE_ENSURE(need_write) ? EV_ADD : EV_DELETE, 0, 0, data); \
		    MIO(m)->kqoff++; \
			kep++; \
	    } \
	    MIO(m)->kqueue_state[fd] = st_new; \
	} \
    static mio_fd_t _mio_alloc_fd(mio_t m, int fd)                      \
    {                                                                   \
		struct kevent event; \
        mio_priv_fd_t priv_fd = malloc(sizeof (struct mio_priv_fd_st)); \
        memset(priv_fd, 0, sizeof (struct mio_priv_fd_st));             \
                                                                        \
        priv_fd->mio_fd.fd = fd;                                        \
        priv_fd->events = 0;                                            \
		_mio_set_events(m, fd, 1, 1, priv_fd); \
        return (mio_fd_t)priv_fd;                                       \
    }
	

#define MIO_FD_VARS \
    uint32_t events;

#define MIO_VARS \
    int defer_free; \
    int kqueue_fd; \
	unsigned char *kqueue_state; \
    struct kevent* kqlst; \
	struct kevent* ke; \
	int kqmax; \
	int kqoff;

#define MIO_INIT_VARS(m) \
    do {                                                                \
        MIO(m)->defer_free = 0;                                         \
        if ((MIO(m)->kqueue_fd = kqueue()) < 0)               			\
        {                                                               \
            mio_debug(ZONE,"unable to initialize kqueue mio");			\
            free(m);                                                    \
            return NULL;                                                \
        }                                                               \
		MIO(m)->kqmax = KE_INC_SIZE; \
		MIO(m)->kqlst = malloc(sizeof(struct kevent) * MIO(m)->kqmax); \
		MIO(m)->ke = malloc(sizeof(struct kevent) * MIO(m)->kqmax); \
		MIO(m)->kqueue_state = calloc(65536, sizeof(char)); \
    } while(0)
#define MIO_FREE_VARS(m) \
    do { \
        close(MIO(m)->kqueue_fd); \
		free(MIO(m)->kqueue_state); \
		free(MIO(m)->kqlst); \
		free(MIO(m)->ke); \
    } while(0)

#define MIO_ALLOC_FD(m, rfd) _mio_alloc_fd(m,rfd)
#define MIO_FREE_FD(m, mfd)     free(mfd)
#define MIO_REMOVE_FD(m, mfd) _mio_set_events(m, mfd->mio_fd.fd, 0, 0, NULL)
#define MIO_CHECK(m, t)         _mio_poll(m, t)

#define MIO_SET_READ(m, mfd) _mio_set_events(m, mfd->mio_fd.fd, 1, 0, NULL)
#define MIO_SET_WRITE(m, mfd) _mio_set_events(m, mfd->mio_fd.fd, 0, 1, NULL)
#define MIO_UNSET_READ(m, mfd) _mio_set_events(m, mfd->mio_fd.fd, 0, -1, NULL)
#define MIO_UNSET_WRITE(m, mfd) _mio_set_events(m, mfd->mio_fd.fd, -1, 0, NULL)

#define MIO_CAN_READ(m,iter) \
    (MIO(m)->ke[iter].filter == EVFILT_READ)

#define MIO_CAN_WRITE(m,iter) \
    (MIO(m)->ke[iter].filter == EVFILT_WRITE)

#define MIO_CAN_FREE(m)         (!MIO(m)->defer_free)

#define MIO_INIT_ITERATOR(iter) \
    int iter;

#define MIO_ITERATE_RESULTS(m, retval, iter) \
    for(MIO(m)->defer_free = 1, iter = 0; (iter < retval) || ((MIO(m)->defer_free = 0)); iter++)

#define MIO_ITERATOR_FD(m, iter) \
    (MIO(m)->ke[iter].udata)
