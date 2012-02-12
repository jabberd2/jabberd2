/* MIO backend for kqueue() */

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_EVENT_H
#include <sys/event.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#define MIO_FUNCS \
 \
  mio_priv_t dbjdebug; \
    static mio_fd_t \
    _mio_alloc_fd(mio_t m, int fd) \
    { \
        struct kevent events[2]; \
        mio_priv_fd_t priv_fd; \
        dbjdebug = m; \
        priv_fd = malloc(sizeof(*priv_fd)); \
        memset(priv_fd, 0, sizeof(*priv_fd)); \
        priv_fd->mio_fd.fd = fd; \
        EV_SET(&events[0], fd, EVFILT_READ, EV_ADD|EV_DISABLE, 0, 0, priv_fd); \
        EV_SET(&events[1], fd, EVFILT_WRITE, EV_ADD|EV_DISABLE, 0, 0, priv_fd); \
        if (kevent(MIO(m)->kq, events, sizeof(events)/sizeof(events[0]), NULL, 0, NULL) == -1) { \
            mio_debug(ZONE,"error creating kevents on fd %d (%d)", fd, errno); \
		} \
        return (mio_fd_t)priv_fd; \
    } \
     \
	static void \
    _mio_free_fd(mio_t m, mio_fd_t mfd) \
	{ \
      int i; \
      /* Unfortunately, the mio_impl.h api is a bit broken in that it \
       * assumes that we can defer free until the end of the current iteration. \
       * Unfortunately, with kqueue, a given fd may appear in the iteration loop \
       * more than once, so we need to both defer free and also clear out any \
       * other instances of the current fd in the return data.  Fortunately, the \
       * amount of data we ask for in each call to kevent is small and constant. \
       */ \
      for (i = 0; i < MIO(m)->nevents; i++) {  \
        if (MIO(m)->events[i].udata == mfd) { \
          MIO(m)->events[i].udata = &MIO(m)->dummy; \
	    } \
	    } \
      memset(mfd, 0x5a, sizeof(mio_priv_fd_t)); /* debugging only */ \
      free(mfd); \
	} \
                                                                        \
    static int \
    _mio_check(mio_t m, int timeout) \
    { \
      struct timespec ts; \
      int ret; \
      ts.tv_nsec = 0; \
      ts.tv_sec = timeout; \
      ret = kevent(MIO(m)->kq, NULL, 0, MIO(m)->events, sizeof(MIO(m)->events)/sizeof(MIO(m)->events[0]), &ts); \
      if (ret >= 0) \
        MIO(m)->nevents = ret; \
      return ret; \
    }
	
#define MIO_FD_VARS

#define MIO_VARS \
    int kq; \
    int nevents; \
    struct kevent events[32]; \
    struct mio_priv_fd_st dummy;

#define MIO_INIT_VARS(m) \
    do {                                                                \
        MIO(m)->nevents = 0;						\
        MIO(m)->dummy.type = type_CLOSED; \
        if ((MIO(m)->kq = kqueue()) == -1) {                            \
             mio_debug(ZONE,"internal error creating kqueue (%d)", errno); \
            return NULL;                                                \
        }                                                               \
    } while(0)

#define MIO_FREE_VARS(m) close(MIO(m)->kq)

#define MIO_ALLOC_FD(m, rfd) _mio_alloc_fd(m,rfd)
#define MIO_CAN_FREE(m)         (MIO(m)->nevents == 0)
#define MIO_FREE_FD(m, mfd)     _mio_free_fd(m, mfd)

#define MIO_REMOVE_FD(m, mfd) \
    do { \
        struct kevent events[2]; \
        EV_SET(&events[0], mfd->mio_fd.fd, EVFILT_READ, EV_DELETE, 0, 0, mfd); \
        EV_SET(&events[1], mfd->mio_fd.fd, EVFILT_WRITE, EV_DELETE, 0, 0, mfd); \
        if (kevent(MIO(m)->kq, events, sizeof(events)/sizeof(events[0]), NULL, 0, NULL) == -1) { \
           mio_debug(ZONE,"error deleting kevents on fd %d (%d)", mfd->mio_fd.fd, errno); \
        } \
    } while (0)

/*
 * This could be tweaked to be more efficient and only apply filter changes
 * once every loop, but that can be done if testing shows it to be helpful
 */
#define MIO_SET_READ(m, mfd)    \
    do { \
        struct kevent changelist; \
        EV_SET(&changelist, mfd->mio_fd.fd, EVFILT_READ, EV_ENABLE, 0, 0, mfd); \
        if (kevent(MIO(m)->kq, &changelist, 1, NULL, 0, NULL) == -1) { \
           mio_debug(ZONE,"error setting kevent EVFILT_READ on fd %d (%d)", mfd->mio_fd.fd, errno); \
        } \
    } while (0)

#define MIO_SET_WRITE(m, mfd) \
    do { \
        struct kevent changelist; \
        EV_SET(&changelist, mfd->mio_fd.fd, EVFILT_WRITE, EV_ENABLE, 0, 0, mfd); \
        if (kevent(MIO(m)->kq, &changelist, 1, NULL, 0, NULL) == -1) { \
           mio_debug(ZONE,"error setting kevent EVFILT_WRITE on fd %d (%d)", mfd->mio_fd.fd, errno); \
        } \
    } while (0)

#define MIO_UNSET_READ(m, mfd)    \
    do { \
        struct kevent changelist; \
        EV_SET(&changelist, mfd->mio_fd.fd, EVFILT_READ, EV_DISABLE, 0, 0, mfd); \
        if (kevent(MIO(m)->kq, &changelist, 1, NULL, 0, NULL) == -1) { \
           mio_debug(ZONE,"error setting kevent EVFILT_READ on fd %d (%d)", mfd->mio_fd.fd, errno); \
        } \
    } while (0)

#define MIO_UNSET_WRITE(m, mfd) \
    do { \
        struct kevent changelist; \
        EV_SET(&changelist, mfd->mio_fd.fd, EVFILT_WRITE, EV_DISABLE, 0, 0, mfd); \
        if (kevent(MIO(m)->kq, &changelist, 1, NULL, 0, NULL) == -1) { \
           mio_debug(ZONE,"error setting kevent EVFILT_WRITE on fd %d (%d)", mfd->mio_fd.fd, errno); \
        } \
    } while (0)

#define MIO_INIT_ITERATOR(iter) \
    int iter;

#define MIO_ITERATE_RESULTS(m, retval, iter) \
    for(iter = 0; (iter < retval) || ((MIO(m)->nevents = 0)); iter++)

#define MIO_CAN_READ(m, iter)  (MIO((m))->events[(iter)].filter == EVFILT_READ)
#define MIO_CAN_WRITE(m, iter) (MIO((m))->events[(iter)].filter == EVFILT_WRITE)

#define MIO_ITERATOR_FD(m, iter) ((mio_fd_t)(MIO(m)->events[(iter)].udata))

#define MIO_CHECK(m, t) _mio_check(m, t)