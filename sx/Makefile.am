noinst_LTLIBRARIES = libsx.la

noinst_HEADERS = sasl.h ssl.h sx.h
libsx_la_SOURCES = callback.c chain.c client.c env.c error.c io.c server.c ssl.c sx.c
libsx_la_LIBADD = @LDFLAGS@

if SASL_GSASL
libsx_la_SOURCES += sasl_gsasl.c
libsx_la_CPPFLAGS = -DSASL_GSASL
endif

if SASL_CYRUS
libsx_la_SOURCES += sasl_cyrus.c
libsx_la_CPPFLAGS = -DSASL_CYRUS
endif
