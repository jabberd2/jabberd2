LIBTOOL += --quiet

bin_PROGRAMS = sm

pkglib_LTLIBRARIES = mod_active.la \
                  mod_announce.la \
                  mod_amp.la \
                  mod_deliver.la \
                  mod_disco.la \
                  mod_echo.la \
                  mod_help.la \
                  mod_iq-last.la \
                  mod_iq-ping.la \
                  mod_iq-private.la \
                  mod_iq-time.la \
                  mod_iq-vcard.la \
                  mod_iq-version.la \
                  mod_offline.la \
                  mod_pep.la \
                  mod_presence.la \
                  mod_privacy.la \
                  mod_roster.la \
                  mod_roster-publish.la \
                  mod_session.la \
                  mod_status.la \
                  mod_template-roster.la \
                  mod_vacation.la \
                  mod_validate.la

noinst_HEADERS = sm.h

sm_SOURCES = aci.c \
             dispatch.c \
             feature.c \
             main.c \
             mm.c \
             pkt.c \
             pres.c \
             sess.c \
             sm.c \
             user.c

sm_CPPFLAGS = -DCONFIG_DIR=\"$(sysconfdir)\" -DLIBRARY_DIR=\"$(pkglibdir)\" -I@top_srcdir@
sm_LDFLAGS = -export-dynamic
sm_LDADD = $(top_builddir)/sx/libsx.la \
           $(top_builddir)/mio/libmio.la \
           $(top_builddir)/util/libutil.la \
           $(top_builddir)/storage/libstorage.la
if USE_LIBSUBST
sm_LDADD += $(top_builddir)/subst/libsubst.la
endif

mod_active_la_SOURCES = mod_active.c
mod_active_la_LDFLAGS = -module -export-dynamic
if USE_LIBSUBST
mod_active_la_LIBADD = $(top_builddir)/subst/libsubst.la
endif

mod_announce_la_SOURCES = mod_announce.c
mod_announce_la_LDFLAGS = -module -export-dynamic
if USE_LIBSUBST
mod_announce_la_LIBADD = $(top_builddir)/subst/libsubst.la
endif

mod_amp_la_SOURCES = mod_amp.c
mod_amp_la_LDFLAGS = -module -export-dynamic
if USE_LIBSUBST
mod_amp_la_LIBADD = $(top_builddir)/subst/libsubst.la
endif

mod_deliver_la_SOURCES = mod_deliver.c
mod_deliver_la_LDFLAGS = -module -export-dynamic
if USE_LIBSUBST
mod_deliver_la_LIBADD = $(top_builddir)/subst/libsubst.la
endif

mod_disco_la_SOURCES = mod_disco.c
mod_disco_la_LDFLAGS = -module -export-dynamic
if USE_LIBSUBST
mod_disco_la_LIBADD = $(top_builddir)/subst/libsubst.la
endif

mod_echo_la_SOURCES = mod_echo.c
mod_echo_la_LDFLAGS = -module -export-dynamic
if USE_LIBSUBST
mod_echo_la_LIBADD = $(top_builddir)/subst/libsubst.la
endif

mod_help_la_SOURCES = mod_help.c
mod_help_la_LDFLAGS = -module -export-dynamic
if USE_LIBSUBST
mod_help_la_LIBADD = $(top_builddir)/subst/libsubst.la
endif

mod_iq_last_la_SOURCES = mod_iq_last.c
mod_iq_last_la_LDFLAGS = -module -export-dynamic
if USE_LIBSUBST
mod_iq_last_la_LIBADD = $(top_builddir)/subst/libsubst.la
endif

mod_iq_ping_la_SOURCES = mod_iq_ping.c
mod_iq_ping_la_LDFLAGS = -module -export-dynamic
if USE_LIBSUBST
mod_iq_ping_la_LIBADD = $(top_builddir)/subst/libsubst.la
endif

mod_iq_private_la_SOURCES = mod_iq_private.c
mod_iq_private_la_LDFLAGS = -module -export-dynamic
if USE_LIBSUBST
mod_iq_private_la_LIBADD = $(top_builddir)/subst/libsubst.la
endif

mod_iq_time_la_SOURCES = mod_iq_time.c
mod_iq_time_la_LDFLAGS = -module -export-dynamic
if USE_LIBSUBST
mod_iq_time_la_LIBADD = $(top_builddir)/subst/libsubst.la
endif

mod_iq_vcard_la_SOURCES = mod_iq_vcard.c
mod_iq_vcard_la_LDFLAGS = -module -export-dynamic
if USE_LIBSUBST
mod_iq_vcard_la_LIBADD = $(top_builddir)/subst/libsubst.la
endif

mod_iq_version_la_SOURCES = mod_iq_version.c
mod_iq_version_la_LDFLAGS = -module -export-dynamic
if USE_LIBSUBST
mod_iq_version_la_LIBADD = $(top_builddir)/subst/libsubst.la
endif

mod_offline_la_SOURCES = mod_offline.c
mod_offline_la_LDFLAGS = -module -export-dynamic
if USE_LIBSUBST
mod_offline_la_LIBADD = $(top_builddir)/subst/libsubst.la
endif

mod_pep_la_SOURCES = mod_pep.c
mod_pep_la_LDFLAGS = -module -export-dynamic
if USE_LIBSUBST
mod_pep_la_LIBADD = $(top_builddir)/subst/libsubst.la
endif

mod_presence_la_SOURCES = mod_presence.c
mod_presence_la_LDFLAGS = -module -export-dynamic
if USE_LIBSUBST
mod_presence_la_LIBADD = $(top_builddir)/subst/libsubst.la
endif

mod_privacy_la_SOURCES = mod_privacy.c
mod_privacy_la_LDFLAGS = -module -export-dynamic
if USE_LIBSUBST
mod_privacy_la_LIBADD = $(top_builddir)/subst/libsubst.la
endif

mod_roster_la_SOURCES = mod_roster.c
mod_roster_la_LDFLAGS = -module -export-dynamic
if USE_LIBSUBST
mod_roster_la_LIBADD = $(top_builddir)/subst/libsubst.la
endif

mod_roster_publish_la_SOURCES = mod_roster_publish.c
mod_roster_publish_la_LDFLAGS = -module -export-dynamic
if USE_LIBSUBST
mod_roster_publish_la_LIBADD = $(top_builddir)/subst/libsubst.la
endif

mod_session_la_SOURCES = mod_session.c
mod_session_la_LDFLAGS = -module -export-dynamic
if USE_LIBSUBST
mod_session_la_LIBADD = $(top_builddir)/subst/libsubst.la
endif

mod_status_la_SOURCES = mod_status.c
mod_status_la_LDFLAGS = -module -export-dynamic
if USE_LIBSUBST
mod_status_la_LIBADD = $(top_builddir)/subst/libsubst.la
endif

mod_template_roster_la_SOURCES = mod_template_roster.c
mod_template_roster_la_LDFLAGS = -module -export-dynamic
if USE_LIBSUBST
mod_template_roster_la_LIBADD = $(top_builddir)/subst/libsubst.la
endif

mod_vacation_la_SOURCES = mod_vacation.c
mod_vacation_la_LDFLAGS = -module -export-dynamic
if USE_LIBSUBST
mod_vacation_la_LIBADD = $(top_builddir)/subst/libsubst.la
endif

mod_validate_la_SOURCES = mod_validate.c
mod_validate_la_LDFLAGS = -module -export-dynamic
if USE_LIBSUBST
mod_validate_la_LIBADD = $(top_builddir)/subst/libsubst.la
endif

