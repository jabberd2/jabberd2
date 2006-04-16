bin_SCRIPTS = jabberd
EXTRA_DIST = db-setup.mysql db-setup.pgsql jabberd.in jabberd.rc pipe-auth.pl migrate.pl db-update.mysql db-setup.oracle

edit = sed \
	-e 's,@sysconfdir\@,$(sysconfdir),g' \
	-e 's,@VERSION\@,$(VERSION),g' \
	-e 's,@bindir\@,$(bindir),g'

$(bin_SCRIPTS): $(EXTRA_DIST)
	@echo "generating $@ from $@.in"; \
	rm -f $@ $@.tmp; \
	$(edit) < $@.in > $@.tmp; \
	chmod +x $@.tmp; \
	mv $@.tmp $@

clean-local:
	rm -f $(bin_SCRIPTS)
