INCLUDES = -DCONFIG_DIR=\"$(sysconfdir)\" \
           -DLIBRARY_DIR=\"$(pkglibdir)\" \
		   $(MYSQL_CFLAGS)
		   $(PGSQL_CFLAGS)

bin_PROGRAMS = sm
pkglib_LTLIBRARIES = mod_active.la \
                  mod_announce.la \
                  mod_amp.la \
                  mod_deliver.la \
                  mod_disco.la \
                  mod_disco-publish.la \
                  mod_echo.la \
                  mod_help.la \
                  mod_iq-last.la \
                  mod_iq-private.la \
                  mod_iq-time.la \
                  mod_iq-vcard.la \
                  mod_iq-version.la \
                  mod_offline.la \
                  mod_presence.la \
                  mod_privacy.la \
                  mod_roster.la \
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
             object.c \
             pkt.c \
             pres.c \
             sess.c \
             sm.c \
             user.c \
             storage.c \
             storage_db.c \
             storage_fs.c \
             storage_oracle.c

sm_LDFLAGS = -Wl,-export-dynamic
sm_LDADD = $(top_builddir)/sx/libsx.la \
           $(top_builddir)/mio/libmio.la \
           $(top_builddir)/util/libutil.la \
           $(top_builddir)/subst/libsubst.la \
           $(MYSQL_LIBS)    \
           $(PGSQL_LIBS)    \
           $(SQLITE_LIBS)

if STORAGE_MYSQL
sm_SOURCES += storage_mysql.c
endif

if STORAGE_PGSQL
sm_SOURCES += storage_pgsql.c
endif

if STORAGE_SQLITE
sm_SOURCES += storage_sqlite.c
endif

mod_active_la_SOURCES = mod_active.c
mod_active_la_LDFLAGS = -module -avoid-version

mod_announce_la_SOURCES = mod_announce.c
mod_announce_la_LDFLAGS = -module -avoid-version

mod_amp_la_SOURCES = mod_amp.c
mod_amp_la_LDFLAGS = -module -avoid-version

mod_deliver_la_SOURCES = mod_deliver.c
mod_deliver_la_LDFLAGS = -module -avoid-version

mod_disco_la_SOURCES = mod_disco.c
mod_disco_la_LDFLAGS = -module -avoid-version

mod_disco_publish_la_SOURCES = mod_disco_publish.c
mod_disco_publish_la_LDFLAGS = -module -avoid-version

mod_echo_la_SOURCES = mod_echo.c
mod_echo_la_LDFLAGS = -module -avoid-version

mod_help_la_SOURCES = mod_help.c
mod_help_la_LDFLAGS = -module -avoid-version

mod_iq_last_la_SOURCES = mod_iq_last.c
mod_iq_last_la_LDFLAGS = -module -avoid-version

mod_iq_private_la_SOURCES = mod_iq_private.c
mod_iq_private_la_LDFLAGS = -module -avoid-version

mod_iq_time_la_SOURCES = mod_iq_time.c
mod_iq_time_la_LDFLAGS = -module -avoid-version

mod_iq_vcard_la_SOURCES = mod_iq_vcard.c
mod_iq_vcard_la_LDFLAGS = -module -avoid-version

mod_iq_version_la_SOURCES = mod_iq_version.c
mod_iq_version_la_LDFLAGS = -module -avoid-version

mod_offline_la_SOURCES = mod_offline.c
mod_offline_la_LDFLAGS = -module -avoid-version

mod_presence_la_SOURCES = mod_presence.c
mod_presence_la_LDFLAGS = -module -avoid-version

mod_privacy_la_SOURCES = mod_privacy.c
mod_privacy_la_LDFLAGS = -module -avoid-version

mod_roster_la_SOURCES = mod_roster.c
mod_roster_la_LDFLAGS = -module -avoid-version

mod_session_la_SOURCES = mod_session.c
mod_session_la_LDFLAGS = -module -avoid-version

mod_status_la_SOURCES = mod_status.c
mod_status_la_LDFLAGS = -module -avoid-version

mod_template_roster_la_SOURCES = mod_template_roster.c
mod_template_roster_la_LDFLAGS = -module -avoid-version

mod_vacation_la_SOURCES = mod_vacation.c
mod_vacation_la_LDFLAGS = -module -avoid-version

mod_validate_la_SOURCES = mod_validate.c
mod_validate_la_LDFLAGS = -module -avoid-version
