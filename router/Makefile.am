INCLUDES = -DCONFIG_DIR=\"$(sysconfdir)\"

bin_PROGRAMS =  router

noinst_HEADERS = router.h
router_SOURCES = aci.c main.c router.c user.c

router_LDADD = $(top_builddir)/sx/libsx.la \
               $(top_builddir)/mio/libmio.la \
               $(top_builddir)/util/libutil.la \
               $(top_builddir)/subst/libsubst.la \
               $(top_builddir)/expat/libexpat.la
