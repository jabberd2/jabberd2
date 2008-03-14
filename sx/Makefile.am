noinst_LTLIBRARIES = libsx.la
noinst_HEADERS = plugins.h sasl.h sx.h

SUBDIRS =

libsx_la_SOURCES = callback.c chain.c client.c env.c error.c io.c server.c sx.c
libsx_la_LIBADD = @LDFLAGS@

if SASL_GSASL
libsx_la_SOURCES += sasl_gsasl.c
endif

if SASL_CYRUS
libsx_la_SOURCES += sasl_cyrus.c
endif

if SASL_SCOD
SUBDIRS += scod
libsx_la_SOURCES += sasl_scod.c
libsx_la_LIBADD += scod/libscod.la
endif

if HAVE_SSL
libsx_la_SOURCES += ssl.c
endif

if HAVE_LIBZ
libsx_la_SOURCES += compress.c
endif

if ENABLE_EXPERIMENTAL
libsx_la_SOURCES += ack.c
endif
