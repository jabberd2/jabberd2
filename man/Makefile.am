man_MANS = jabberd.8 c2s.8 router.8 s2s.8 sm.8
EXTRA_DIST = jabberd.8.in c2s.8.in router.8.in s2s.8.in sm.8.in

LIBTOOL += --quiet

jabberd_bin = router sm s2s c2s

edit = sed \
	-e 's,@sysconfdir\@,$(sysconfdir),g' \
	-e 's,@VERSION\@,$(VERSION),g'

$(man_MANS):
	@echo "generating $@ from $@.in"; \
    edit='$(edit)'; \
    list='$(jabberd_bin)'; for p in $$list; do \
      bin=`echo "$$p" | sed 's,^.*/,,;$(transform);s/$$/$(EXEEXT)/'`; \
      edit="$$edit -e s,@jabberd_$$p\_bin\\@,$$bin,g"; \
    done; \
	rm -f $@ $@.tmp; \
	eval "$$edit < @srcdir@/$@.in > $@.tmp"; \
	mv $@.tmp $@ 
    
clean-local:
	rm -f $(man_MANS)
