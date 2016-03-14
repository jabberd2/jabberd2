TARGET = src/jabberd
DEFINES += HAVE_CONFIG_H MOD_NAME=""
HEADERS += $$files(lib/*.h) \
           $$files(sx/*.h) \
           $$files(src/*.h) \
           $$files(mod/*.h)
SOURCES += $$files(lib/*.c) \
           $$files(sx/*.c) \
           $$files(src/*.c) \
           $$files(mod/*.c) \
           $$files(tests/*.c)
INCLUDEPATH += $$PWD
CONFIG += depend_includepath
OTHER_FILES += configure.ac \
               Makefile.am \
               lib/Makefile.am \
               sx/Makefile.am \
               src/Makefile.am \
               mod/Makefile.am \
               tests/Makefile.am \
               $$files(etc/*) \
               Doxyfile.in \
               NEWS \
               README.md
