LIBTOOL += --quiet
AM_CPPFLAGS = -I@top_srcdir@

noinst_LTLIBRARIES = libsx.la
noinst_HEADERS = plugins.h sasl.h sx.h

libsx_la_SOURCES = callback.c chain.c client.c compress.c env.c error.c io.c server.c sx.c sasl.c ack.c
libsx_la_LIBADD = @LDFLAGS@ $(EXPAT_LIBS) $(GSASL_LIBS) $(LOG4C_LIBS) $(SSL_LIBS)

if HAVE_SSL
libsx_la_SOURCES += ssl.c
endif

if USE_WEBSOCKET
libsx_la_SOURCES += websocket.c
endif
