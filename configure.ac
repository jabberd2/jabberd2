# jabberd configure script
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([jabberd],[3.x.dev],[jabberd2@lists.xiaoka.com],[jabberd],[http://github.com/jabberd2])
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])
AM_INIT_AUTOMAKE
AM_SILENT_RULES([yes])
LT_PREREQ([2.4.6])
LT_INIT([shared disable-static dlopen])
AC_SUBST([LIBTOOL_DEPS])

# Quit if it is an in-source build
if test ${srcdir} == "." ; then
  AC_MSG_ERROR([In-source build is not allowed. Please configure from a separate build directory.])
fi

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_STDC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

# Colorized build output
AX_CHECK_COMPILE_FLAG([-fdiagnostics-color], [CFLAGS="${CFLAGS} -fdiagnostics-color"],
    [AX_CHECK_COMPILE_FLAG([-fcolor-diagnostics], [CFLAGS="${CFLAGS} -fcolor-diagnostics"])])

# Checks for packages
PKG_CHECK_MODULES([EXPAT], [expat >= 2])
PKG_CHECK_MODULES([IDN], [libidn >= 0.3])
PKG_CHECK_MODULES([GSASL], [libgsasl >= 1.4])
PKG_CHECK_MODULES([LOG4C], [log4c >= 1.2.4])
PKG_CHECK_MODULES([UV], [libuv >= 1.6])
PKG_CHECK_MODULES([GC], [bdw-gc >= 7.4])
PKG_CHECK_MODULES([NANOMSG], [libnanomsg >= 4])

# Checks for libraries.
# crypt
AC_CHECK_FUNC([crypt], ,[AC_CHECK_LIB([crypt], [crypt])])
if test "x$ac_cv_lib_crypt_crypt" = "xyes"; then
  AC_DEFINE(HAVE_CRYPT, 1, [Define to 1 if you have the crypt() function])
fi

# udns
AC_CHECK_LIB(udns, dns_init)
if test "x-$ac_cv_lib_udns_dns_init" != "x-yes" ; then
    AC_MSG_ERROR([UDNS library not found])
fi

# optional libraries
AC_ARG_WITH([ssl], AS_HELP_STRING([--with-ssl], [enable SSL/TLS support]))
AS_IF([test "x$enable_ssl" != "xno"], [
   PKG_CHECK_MODULES([SSL], [openssl >= 1.0.1 libcrypto], AC_DEFINE(HAVE_SSL,1,[Define to 1 if OpenSSL is available.]))
])
AM_CONDITIONAL(HAVE_SSL, [test -n "$SSL_LIBS"])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h inttypes.h netinet/in.h stddef.h stdlib.h string.h sys/socket.h sys/time.h unistd.h utime.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_STRUCT_TIMEZONE
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([ptrdiff_t])

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_FUNC_REALLOC
AC_CHECK_FUNCS([dup2 gethostname getpagesize gettimeofday inet_ntoa memchr memmove memset mkdir mkfifo regcomp strcasecmp strchr strcspn strdup strerror strncasecmp strndup strrchr strspn strstr strtol tzset uname utime])

# conditional features
AC_ARG_ENABLE(websocket, AS_HELP_STRING([--enable-websocket],[enable WebSocket support on C2S port (no)]),
              want_websocket=$enableval, want_websocket=no)
if test "x-$want_websocket" = "x-yes" ; then
    AC_CHECK_LIB([http_parser], [http_parser_init])
    if test "x-$ac_cv_lib_http_parser_http_parser_init" != "x-yes" ; then
        AC_MSG_ERROR([http_parser not found])
    else
        AC_DEFINE(USE_WEBSOCKET,1,[Define to 1 if you want to have WebSocket support in C2S.])
    fi
fi
AM_CONDITIONAL(USE_WEBSOCKET, [test "x-$want_websocket" = "x-yes"])

AC_ARG_ENABLE(superseded, AS_HELP_STRING([--enable-superseded],[enable superseded XEP support (yes)]),
              want_superseded=$enableval, want_superseded=no)
if test "x-$want_superseded" = "x-yes" ; then
    AC_DEFINE(ENABLE_SUPERSEDED,1,[Define to 1 if you want to compile-in superseded XEP handlers.])
fi

AC_ARG_ENABLE(experimental, AS_HELP_STRING([--enable-experimental],[enable experimental features (yes)]),
              want_experimental=$enableval, want_experimental=no)
if test "x-$want_experimental" = "x-yes" ; then
    AC_DEFINE(ENABLE_EXPERIMENTAL,1,[Define to 1 if you want to compile-in experimental features.])
fi
AM_CONDITIONAL(ENABLE_EXPERIMENTAL, [test "x-$want_experimental" = "x-yes"])

AC_ARG_ENABLE(tests, AS_HELP_STRING([--enable-tests],[enable tests (yes)]),
              want_tests=$enableval, want_tests=yes)
if test "x-$want_tests" = "x-yes" ; then
    PKG_CHECK_MODULES([CHECK], [check >= 0.9.4], [want_tests=yes], [want_tests=no])
fi
AM_CONDITIONAL(ENABLE_TESTS, [test "x-$want_tests" = "x-yes"])

AC_ARG_ENABLE([werror], AS_HELP_STRING([--enable-werror],[Treat all warnings as error]),
              CFLAGS="-Wall -Werror $CFLAGS")

AC_CONFIG_FILES([Makefile
                 etc/Makefile
                 etc/templates/Makefile
                 lib/Makefile
                 sx/Makefile
                 src/Makefile
                 mod/Makefile
                 tests/Makefile])
AC_OUTPUT
