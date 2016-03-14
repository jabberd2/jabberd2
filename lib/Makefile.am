LIBTOOL += --quiet
AM_CPPFLAGS = -I@top_srcdir@ -DMINIZ_NO_STDIO -DMINIZ_NO_ARCHIVE_APIS -DMINIZ_NO_TIME -DMINIZ_NO_ZLIB_APIS -DMINIZ_NO_MALLOC

noinst_LTLIBRARIES = libutil.la

noinst_HEADERS = access.h base64.h crypt_blowfish.h datetime.h hex.h inaddr.h jid.h jqueue.h jsignal.h log.h md5.h miniz.h nad.h rate.h sds.h sdsalloc.h serial.h sha1.h stanza.h str.h uri.h util.h xconfig.h xhash.h
noinst_HEADERS += uv_nn.h

libutil_la_SOURCES = access.c base64.c crypt_blowfish.c datetime.c hex.c inaddr.c jid.c jqueue.c jsignal.c md5.c miniz.c nad.c rate.c sds.c serial.c sha1.c stanza.c str.c xconfig.c xhash.c
libutil_la_SOURCES += uv_nn.c

libutil_la_LIBADD = @LDFLAGS@ $(EXPAT_LIBS) $(GC_LIBS) $(IDN_LIBS) $(LOG4C_LIBS) $(SSL_LIBS)
