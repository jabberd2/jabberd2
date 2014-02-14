LIBTOOL += --quiet

sysconf_DATA = c2s.xml.dist router.xml.dist s2s.xml.dist sm.xml.dist jabberd.cfg.dist router-users.xml.dist router-filter.xml.dist
initdir = $(prefix)/etc/init
init_DATA = jabberd-c2s.conf jabberd-router.conf jabberd-s2s.conf jabberd-sm.conf
systemddir = $(prefix)/lib/systemd/system
systemd_DATA = jabberd-sm.service jabberd.service jabberd-s2s.service jabberd-router.service jabberd-c2s.service
configs = $(sysconf_DATA) $(init_DATA) $(systemd_DATA)
EXTRA_DIST = $(sysconf_DATA:%.dist=%.dist.in) $(init_DATA:%.conf=%.conf.in) $(systemd_DATA:%.service=%.service.in)

SUBDIRS = templates

jabberd_bin = router sm s2s c2s

edit = sed \
	-e 's,@package\@,$(PACKAGE),g' \
	-e 's,@sysconfdir\@,$(sysconfdir),g' \
	-e 's,@localstatedir\@,$(localstatedir),g' \
	-e 's,@bindir\@,$(bindir),g' \
	-e 's,@libdir\@,$(libdir),g' \
	-e 's,@pkglibdir\@,$(pkglibdir),g'

$(configs): $(sysconf_DATA:%.dist=@srcdir@/%.dist.in) $(init_DATA:%.conf=@srcdir@/%.conf.in) $(systemd_DATA:%.service=%.service.in)
	@echo "generating $@ from $@.in"; \
    edit='$(edit)'; \
    list='$(jabberd_bin)'; for p in $$list; do \
      bin=`echo "$$p" | sed 's,^.*/,,;$(transform);s/$$/$(EXEEXT)/'`; \
      edit="$$edit -e s,@jabberd_$$p\_bin\\@,$$bin,g"; \
    done; \
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
