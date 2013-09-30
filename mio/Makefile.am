LIBTOOL += --quiet
AM_CPPFLAGS = -I@top_srcdir@

noinst_LTLIBRARIES = libmio.la

noinst_HEADERS = mio.h mio_impl.h mio_epoll.h mio_poll.h mio_select.h mio_kqueue.h mio_wsasync.h

libmio_la_SOURCES = mio.c mio_epoll.c mio_poll.c mio_select.c mio_kqueue.c mio_wsasync.c
libmio_la_LIBADD = @LDFLAGS@
