LIBTOOL += --quiet

noinst_LTLIBRARIES = libsubst.la

noinst_HEADERS = dirent.h getopt.h ip6_misc.h subst.h syslog.h

libsubst_la_SOURCES = dirent.c getopt.c gettimeofday.c inet_aton.c inet_ntop.c inet_pton.c snprintf.c syslog.c strndup.c timegm.c
libsubst_la_LIBADD = @LDFLAGS@
libsubst_la_LDFLAGS = -export-dynamic
