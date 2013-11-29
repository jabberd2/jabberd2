LIBTOOL += --quiet
AM_CPPFLAGS = -I@top_srcdir@

noinst_LTLIBRARIES = libsx.la
noinst_HEADERS = plugins.h sasl.h sx.h

libsx_la_SOURCES = callback.c chain.c client.c env.c error.c io.c server.c sx.c sasl.c ack.c
libsx_la_LIBADD = @LDFLAGS@

if HAVE_SSL
libsx_la_SOURCES += ssl.c
endif

if HAVE_LIBZ
libsx_la_SOURCES += compress.c
endif
