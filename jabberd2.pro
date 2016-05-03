DEFINES += HAVE_CONFIG_H
DEFINES += USE_WEBSOCKET HAVE_SSL HAVE_LIBZ HAVE_CRYPT
DEFINES += STORAGE_LDAP
HEADERS += config.h \
           $$files(c2s/*.h) \
           $$files(mio/*.h) \
           $$files(router/*.h) \
           $$files(s2s/*.h) \
           $$files(sm/*.h) \
           $$files(storage/*.h) \
           $$files(subst/*.h) \
           $$files(sx/*.h) \
           $$files(util/*.h)
SOURCES += $$files(c2s/*.c) \
           $$files(mio/*.c) \
           $$files(router/*.c) \
           $$files(s2s/*.c) \
           $$files(sm/*.c) \
           $$files(storage/*.c) \
           $$files(subst/*.c) \
           $$files(sx/*.c) \
           $$files(tests/*.c) \
           $$files(util/*.c)
INCLUDEPATH += $$PWD
CONFIG += depend_includepath
OTHER_FILES += configure.ac \
               Makefile.am \
               c2s/Makefile.am \
               mio/Makefile.am \
               router/Makefile.am \
               s2s/Makefile.am \
               sm/Makefile.am \
               storage/Makefile.am \
               sx/Makefile.am \
               tests/Makefile.am \
               util/Makefile.am \
               $$files(etc/*) \
               Doxyfile.in \
               NEWS \
               TODO \
               README.md
