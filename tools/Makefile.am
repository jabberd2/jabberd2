LIBTOOL += --quiet

bin_SCRIPTS = jabberd
EXTRA_DIST = db-setup.mysql db-update.mysql db-setup.pgsql db-update.pgsql db-setup.oracle db-setup.sqlite db-update.sqlite \
			 jabberd.in jabberd.rc pipe-auth.pl jabberd-authpipe-pam-0.1.pl pam_jabberd jabberd2.schema \
			 db-jd14-2-jd2.sql migrate-jd14dir-2-sqlite.pl migrate.pl \
			 bdb2mysql.rb bdbdump.pl

edit = sed \
	-e 's,@sysconfdir\@,$(sysconfdir),g' \
	-e 's,@VERSION\@,$(VERSION),g' \
	-e 's,@bindir\@,$(bindir),g' \
	-e 's,@libexecdir\@,$(libexecdir),g'

$(bin_SCRIPTS): $(EXTRA_DIST)
	@echo "generating $@ from $@.in"; \
	rm -f $@ $@.tmp; \
	$(edit) < @srcdir@/$@.in > $@.tmp; \
	chmod +x $@.tmp; \
	mv $@.tmp $@

clean-local:
	rm -f $(bin_SCRIPTS)
