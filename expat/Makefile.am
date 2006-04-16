CFLAGS=-DHAVE_EXPAT_CONFIG_H

noinst_LTLIBRARIES = libexpat.la

noinst_HEADERS = ascii.h \
                 asciitab.h \
                 expat.h \
                 expat_config.h \
                 iasciitab.h \
                 internal.h \
                 latin1tab.h \
                 nametab.h \
                 utf8tab.h \
                 xmlrole.h \
                 xmltok.h \
                 xmltok_impl.h \
                 winconfig.h

libexpat_la_SOURCES = xmlparse.c xmlrole.c xmltok.c
libexpat_la_LIBADD = @LDFLAGS@

EXTRA_DIST = xmltok_impl.c xmltok_ns.c
