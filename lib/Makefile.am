LIBTOOL += --quiet
AM_CPPFLAGS = -I@top_srcdir@

noinst_LTLIBRARIES = libutil.la

noinst_HEADERS = inaddr.h md5.h sha1.h util.h util_compat.h xdata.h nad.h pool.h xhash.h uri.h jid.h base64.h datetime.h log.h crypt_blowfish.h

libutil_la_SOURCES = access.c base64.c config.c datetime.c hex.c inaddr.c jid.c jqueue.c jsignal.c log.c md5.c nad.c pool.c rate.c serial.c sha1.c stanza.c str.c xdata.c xhash.c crypt_blowfish.c

libutil_la_LIBADD = @LDFLAGS@