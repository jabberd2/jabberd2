LIBTOOL += --quiet

sysconf_DATA = c2s.xml.dist router.xml.dist s2s.xml.dist sm.xml.dist router-users.xml.dist router-filter.xml.dist
EXTRA_DIST = $(sysconf_DATA:%.dist=%.dist.in)
configs = $(sysconf_DATA)

SUBDIRS = templates

edit = sed \
	-e 's,@package\@,$(PACKAGE),g' \
	-e 's,@sysconfdir\@,$(sysconfdir),g' \
	-e 's,@localstatedir\@,$(localstatedir),g' \
	-e 's,@bindir\@,$(bindir),g' \
	-e 's,@libdir\@,$(libdir),g' \
	-e 's,@pkglibdir\@,$(pkglibdir),g'

$(configs): $(sysconf_DATA:%.dist=@srcdir@/%.dist.in)
	@echo "generating $@ from $@.in"; \
	edit='$(edit)'; \
	rm -f $@ $@.tmp; \
	eval "$$edit < @srcdir@/$@.in > $@.tmp"; \
	mv $@.tmp $@

install-data-hook:
	@list='$(sysconf_DATA)'; for p in $$list; do \
	dest=`echo $$p | sed -e s/.dist//`; \
	  if test -f $(DESTDIR)$(sysconfdir)/$$dest; then \
	echo "$@ will not overwrite existing $(DESTDIR)$(sysconfdir)/$$dest"; \
	else \
	    echo " $(INSTALL_DATA) $$p $(DESTDIR)$(sysconfdir)/$$dest"; \
	    $(INSTALL_DATA) $$p $(DESTDIR)$(sysconfdir)/$$dest; \
	  fi; \
	done

clean-local:
	rm -f $(configs)
