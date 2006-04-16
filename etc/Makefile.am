sysconf_DATA = c2s.xml.dist resolver.xml.dist router.xml.dist s2s.xml.dist sm.xml.dist jabberd.cfg.dist router-users.xml.dist
EXTRA_DIST = c2s.xml.dist.in resolver.xml.dist.in router.xml.dist.in s2s.xml.dist.in sm.xml.dist.in jabberd.cfg.dist.in router-users.xml.dist.in

SUBDIRS = templates

jabberd_bin = router resolver sm s2s c2s

edit = sed \
	-e 's,@sysconfdir\@,$(sysconfdir),g' \
	-e 's,@localstatedir\@,$(localstatedir),g' \
	-e 's,@bindir\@,$(bindir),g'

$(sysconf_DATA):
	@echo "generating $@ from $@.in"; \
    edit='$(edit)'; \
    list='$(jabberd_bin)'; for p in $$list; do \
      bin=`echo "$$p" | sed 's,^.*/,,;$(transform);s/$$/$(EXEEXT)/'`; \
      edit="$$edit -e s,@jabberd_$$p\_bin\\@,$$bin,g"; \
    done; \
	rm -f $@ $@.tmp; \
	eval "$$edit < $@.in > $@.tmp"; \
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
	rm -f $(sysconf_DATA)
