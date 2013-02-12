templatesdir = $(sysconfdir)/templates

LIBTOOL += --quiet

templates_DATA = roster.xml.dist
EXTRA_DIST = roster.xml.dist.in

edit = sed \
	-e 's,@sysconfdir\@,$(sysconfdir),g' \
	-e 's,@localstatedir\@,$(localstatedir),g' \
	-e 's,@bindir\@,$(bindir),g'

$(templates_DATA):
	@echo "generating $@ from $@.in"; \
	rm -f $@ $@.tmp; \
	$(edit) < @srcdir@/$@.in > $@.tmp; \
	mv $@.tmp $@
    
install-data-hook:
	@list='$(templates_DATA)'; for p in $$list; do \
      dest=`echo $$p | sed -e s/.dist//`; \
	  if test -f $(DESTDIR)$(templatesdir)/$$dest; then \
        echo "$@ will not overwrite existing $(DESTDIR)$(templatesdir)/$$dest"; \
      else \
	    echo " $(INSTALL_DATA) $$p $(DESTDIR)$(templatesdir)/$$dest"; \
	    $(INSTALL_DATA) $$p $(DESTDIR)$(templatesdir)/$$dest; \
	  fi; \
	done

clean-local:
	rm -f $(templates_DATA)
