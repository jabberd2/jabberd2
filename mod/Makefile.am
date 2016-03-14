LIBTOOL += --quiet
AM_CFLAGS = -I@top_srcdir@
LIBADD = @LDFLAGS@ $(GC_LIBS) $(LOG4C_LIBS) $(NANOMSG_LIBS) $(UV_LIBS)

pkglib_LTLIBRARIES = mod_example.la mod_bus.la

mod_example_la_SOURCES = example.c
mod_example_la_CPPFLAGS = -DMOD_NAME=\"example\"
mod_example_la_LDFLAGS = -module -export-dynamic

mod_bus_la_SOURCES = bus.c
mod_bus_la_CPPFLAGS = -DMOD_NAME=\"bus\"
mod_bus_la_LDFLAGS = -module -export-dynamic

