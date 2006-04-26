INCLUDES = -DCONFIG_DIR=\"$(sysconfdir)\"

bin_PROGRAMS = sm
lib_LTLIBRARIES = libmod_active.la \
                  libmod_announce.la \
                  libmod_amp.la \
                  libmod_deliver.la \
                  libmod_disco.la \
                  libmod_disco-publish.la \
                  libmod_echo.la \
                  libmod_help.la \
                  libmod_iq-last.la \
                  libmod_iq-private.la \
                  libmod_iq-time.la \
                  libmod_iq-vcard.la \
                  libmod_iq-version.la \
                  libmod_offline.la \
                  libmod_presence.la \
                  libmod_privacy.la \
                  libmod_roster.la \
                  libmod_session.la \
                  libmod_status.la \
                  libmod_template-roster.la \
                  libmod_vacation.la \
                  libmod_validate.la

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
             storage_mysql.c \
             storage_pgsql.c \
	     storage_oracle.c \
             storage_sqlite.c 

sm_LDFLAGS = -Wl,-export-dynamic
sm_LDADD = $(top_builddir)/sx/libsx.la \
           $(top_builddir)/mio/libmio.la \
           $(top_builddir)/util/libutil.la \
           $(top_builddir)/subst/libsubst.la \
           $(top_builddir)/expat/libexpat.la

libmod_active_la_SOURCES = mod_active.c
libmod_active_la_LDFLAGS = -shared -E

libmod_announce_la_SOURCES = mod_announce.c
libmod_announce_la_LDFLAGS = -shared -E

libmod_amp_la_SOURCES = mod_amp.c
libmod_amp_la_LDFLAGS = -shared -E

libmod_deliver_la_SOURCES = mod_deliver.c
libmod_deliver_la_LDFLAGS = -shared -E

libmod_disco_la_SOURCES = mod_disco.c
libmod_disco_la_LDFLAGS = -shared -E

libmod_disco_publish_la_SOURCES = mod_disco_publish.c
libmod_disco_publish_la_LDFLAGS = -shared -E

libmod_echo_la_SOURCES = mod_echo.c
libmod_echo_la_LDFLAGS = -shared -E

libmod_help_la_SOURCES = mod_help.c
libmod_help_la_LDFLAGS = -shared -E

libmod_iq_last_la_SOURCES = mod_iq_last.c
libmod_iq_last_la_LDFLAGS = -shared -E

libmod_iq_private_la_SOURCES = mod_iq_private.c
libmod_iq_private_la_LDFLAGS = -shared -E

libmod_iq_time_la_SOURCES = mod_iq_time.c
libmod_iq_time_la_LDFLAGS = -shared -E

libmod_iq_vcard_la_SOURCES = mod_iq_vcard.c
libmod_iq_vcard_la_LDFLAGS = -shared -E

libmod_iq_version_la_SOURCES = mod_iq_version.c
libmod_iq_version_la_LDFLAGS = -shared -E

libmod_offline_la_SOURCES = mod_offline.c
libmod_offline_la_LDFLAGS = -shared -E

libmod_presence_la_SOURCES = mod_presence.c
libmod_presence_la_LDFLAGS = -shared -E

libmod_privacy_la_SOURCES = mod_privacy.c
libmod_privacy_la_LDFLAGS = -shared -E

libmod_roster_la_SOURCES = mod_roster.c
libmod_roster_la_LDFLAGS = -shared -E

libmod_session_la_SOURCES = mod_session.c
libmod_session_la_LDFLAGS = -shared -E

libmod_status_la_SOURCES = mod_status.c
libmod_status_la_LDFLAGS = -shared -E

libmod_template_roster_la_SOURCES = mod_template_roster.c
libmod_template_roster_la_LDFLAGS = -shared -E

libmod_vacation_la_SOURCES = mod_vacation.c
libmod_vacation_la_LDFLAGS = -shared -E

libmod_validate_la_SOURCES = mod_validate.c
libmod_validate_la_LDFLAGS = -shared -E
