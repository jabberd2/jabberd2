AM_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -I@top_srcdir@

LIBTOOL += --quiet

bin_PROGRAMS =  router

noinst_HEADERS = router.h
router_SOURCES = aci.c main.c router.c user.c filter.c

router_LDADD = $(top_builddir)/sx/libsx.la \
               $(top_builddir)/mio/libmio.la \
               $(top_builddir)/util/libutil.la
if USE_LIBSUBST
router_LDADD += $(top_builddir)/subst/libsubst.la
endif
