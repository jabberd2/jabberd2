/* This is a VERY CRUDE "test" infrastructure.
 * But still, it is better than testing the live server ;-)
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "util/util.h"

void s2s_wrap()
{
    char *buf;
    int len, ns, sns, elem;

    char *nadtxt = "<presence to='test@chrome.pl' from='test%gmail.com@jabber.chrome.pl/gmail.EBAFDAF7'>"
        "<priority>24</priority>"
        "<caps:c xmlns:caps='http://jabber.org/protocol/caps' xmlns='jabber:client' node='http://mail.google.com/xmpp/client/caps' ext='pmuc-v1 sms-v1 vavinvite-v1' ver='1.1'/>"
        "<status>Your faith is what you believe, not what you know.</status>"
        "<x xmlns='vcard-temp:x:update'><photo>f272aa57eae74d4be9f99758d2fed636c30548cb</photo></x>"
    "</presence>";

    nad_t nad = nad_parse(nadtxt, 0);

    nad_print(nad, 0, &buf, &len);
    fprintf(stdout, "Parsed:\n%.*s\n", len, buf);

    /* rewrite server packets into client packets */
    ns = nad_find_namespace(nad, 0, uri_SERVER, NULL);
    if(ns >= 0) {
        if(nad->elems[0].ns == ns)
            nad->elems[0].ns = nad->nss[nad->elems[0].ns].next;
        else {
            for(sns = nad->elems[0].ns; sns >= 0 && nad->nss[sns].next == ns; sns = nad->nss[sns].next);
            nad->nss[sns].next = nad->nss[nad->nss[sns].next].next;
        }
        nad_print(nad, 0, &buf, &len);
        fprintf(stdout, "Removed "uri_SERVER" namespace:\n%.*s\n", len, buf);

    }

    /*
     * If stanza is not in any namespace (either because we removed the
     * jabber:server namespace above or because it's in the default
     * namespace for this stream) then this packet is intended to be
     * handled by sm (and not just routed through the server), so set the
     * jabber:client namespace.
     */
    if(ns >= 0 || nad->elems[0].ns < 0) {
        ns = nad_add_namespace(nad, uri_CLIENT, NULL);
        for(elem = 0; elem < nad->ecur; elem++)
            if(nad->elems[elem].ns == ns)
                nad->elems[elem].ns = nad->nss[nad->elems[elem].ns].next;
        nad->nss[ns].next = nad->elems[0].ns;
        nad->elems[0].ns = ns;
        nad->scope = -1;

        nad_print(nad, 0, &buf, &len);
        fprintf(stdout, "Added "uri_CLIENT" namespace:\n%.*s\n", len, buf);
    }

    nad->elems[0].my_ns = nad->elems[0].ns;

    nad_print(nad, 0, &buf, &len);
    fprintf(stdout, "Changed my_ns:\n%.*s\n", len, buf);

    /* wrap up the packet */
    ns = nad_add_namespace(nad, uri_COMPONENT, NULL);

    nad_print(nad, 0, &buf, &len);
    fprintf(stdout, "Added "uri_COMPONENT" namespace:\n%.*s\n", len, buf);

    nad_wrap_elem(nad, 0, ns, "route");

    nad_print(nad, 0, &buf, &len);
    fprintf(stdout, "Wrapped in 'route' element:\n%.*s\n", len, buf);

    nad_set_attr(nad, 0, -1, "to", "sm", 0);
    nad_set_attr(nad, 0, -1, "from", "s2s", 0);

    nad_print(nad, 0, &buf, &len);
    fprintf(stdout, "Mangled packet:\n%.*s\n", len, buf);
}

int main(int argc, char* arcgv[])
{
    fprintf(stdout, "Testing s2s incoming packet wrapper\n");
    s2s_wrap();

    exit(EXIT_SUCCESS);
}
