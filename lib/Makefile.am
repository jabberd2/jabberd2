LIBTOOL += --quiet
AM_CPPFLAGS = -I@top_srcdir@ -DMINIZ_NO_STDIO -DMINIZ_NO_ARCHIVE_APIS -DMINIZ_NO_TIME -DMINIZ_NO_ZLIB_APIS -DMINIZ_NO_MALLOC

noinst_LTLIBRARIES = libutil.la libvendor.la

noinst_HEADERS = access.h base64.h config.h crypt_blowfish.h datetime.h hex.h inaddr.h jid.h jqueue.h jsignal.h log.h md5.h miniz.h nad.h pool.h rate.h sds.h sdsalloc.h serial.h sha1.h stanza.h str.h uri.h util.h xdata.h xhash.h

libutil_la_SOURCES = access.c base64.c config.c datetime.c hex.c inaddr.c jid.c jqueue.c jsignal.c md5.c nad.c pool.c rate.c serial.c sha1.c stanza.c str.c xdata.c xhash.c

libutil_la_LIBADD = @LDFLAGS@ $(EXPAT_LIBS) $(IDN_LIBS) $(LOG4C_LIBS) $(SSL_LIBS)

libvendor_la_SOURCES = crypt_blowfish.c miniz.c sds.c
