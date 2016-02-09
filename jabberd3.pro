DEFINES += HAVE_CONFIG_H
HEADERS += $$files(lib/*.h) \
           $$files(sx/*.h)
SOURCES += $$files(lib/*.c) \
           $$files(sx/*.c) \
           $$files(src/*.c) \
           $$files(tests/*.c)
INCLUDEPATH += lib
OTHER_FILES += configure.ac \
               Makefile.am \
               lib/Makefile.am \
               sx/Makefile.am \
               src/Makefile.am \
               tests/Makefile.am \
               $$files(etc/*) \
               Doxyfile.in \
               NEWS \
               README.md \
