/* This is a VERY CRUDE "test" infrastructure.
 * But still, it is better than testing the live server ;-)
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include "util/util.h"

#define NADTXT_COUNT 2

void s2s_wrap()
{
    char *buf;
    int i, len, ns, sns, elem;

	char *nadtxt[NADTXT_COUNT];
    nadtxt[0] = "<presence to='test@chrome.pl' from='test%gmail.com@jabber.chrome.pl/gmail.EBAFDAF7'>"
        "<priority>24</priority>"
        "<caps:c xmlns:caps='http://jabber.org/protocol/caps' xmlns='jabber:client' node='http://mail.google.com/xmpp/client/caps' ext='pmuc-v1 sms-v1 vavinvite-v1' ver='1.1'/>"
        "<status>Your faith is what you believe, not what you know.</status>"
        "<x xmlns='vcard-temp:x:update'><photo>f272aa57eae74d4be9f99758d2fed636c30548cb</photo></x>"
    "</presence>";
    nadtxt[1] = "<message type='chat' to='mad5ci@chrome.pl' from='update@identi.ca/xmpp001daemon'><body>magicdrums: RT @mateamargonerds: Cursos !Linux avanzado http://twitpic.com/2c3lnj !mateamargonerds | jajajaj !fb [45259404]</body><html xmlns='http://jabber.org/protocol/xhtml-im'><body xmlns='http://www.w3.org/1999/xhtml'><a href='http://identi.ca/magicdrums'>magicdrums</a>: RT @<span class='vcard'><a title='Mate Amargo {Nerds}' class='url' href='http://identi.ca/user/119986'><span class='fn nickname'>mateamargonerds</span></a></span>: Cursos !<span class='vcard'><a title='GNU/Linux (linux)' class='url' href='http://identi.ca/group/56/id'><span class='fn nickname'>Linux</span></a></span> avanzado <a rel='external' title='http://twitpic.com/2c3lnj' href='http://twitpic.com/2c3lnj'>http://twitpic.com/2c3lnj</a> !mateamargonerds | jajajaj !fb <a href='http://identi.ca/conversation/44928627#notice-45259404'>[45259404]</a></body></html> <entry xmlns='http://www.w3.org/2005/Atom'>"
     "<source>"
      "<id>http://identi.ca/magicdrums</id>"
      "<title>magicdrums - Identi.ca</title>"
      "<link href='http://identi.ca/magicdrums'/>"
      "<link rel='self' type='application/atom+xml' href='http://identi.ca/magicdrums'/>"
      "<link rel='license' href='http://creativecommons.org/licenses/by/3.0/'/>"
      "<icon>http://avatar.identi.ca/46122-96-20100607195425.png</icon>"
      "<updated>2010-08-06T13:52:15+00:00</updated>"
    "</source>"
     "<title>RT @mateamargonerds: Cursos !Linux avanzado http://twitpic.com/2c3lnj !mateamargonerds | jajajaj !fb</title>"
    "<author>"
     "<name>magicdrums</name>"
     "<uri>http://identi.ca/user/46122</uri>"
    "</author>"
    "<actor xmlns='http://activitystrea.ms/spec/1.0/'>"
     "<object-type>http://activitystrea.ms/schema/1.0/person</object-type>"
     "<id xmlns='http://www.w3.org/2005/Atom'>http://identi.ca/user/46122</id>"
     "<title xmlns='http://www.w3.org/2005/Atom'>Victor Pereira</title>"
     "<link rel='alternate' type='text/html' href='http://identi.ca/magicdrums' xmlns='http://www.w3.org/2005/Atom'/>"
     "<link rel='avatar' type='image/png' xmlns:ns1='http://purl.org/syndication/atommedia' ns1:height='163' xmlns:ns2='http://purl.org/syndication/atommedia' ns2:width='163' href='http://avatar.identi.ca/46122-163-20100607195425.png' xmlns='http://www.w3.org/2005/Atom'/>"
     "<link rel='avatar' type='image/png' xmlns:ns1='http://purl.org/syndication/atommedia' ns1:height='96' xmlns:ns2='http://purl.org/syndication/atommedia' ns2:width='96' href='http://avatar.identi.ca/46122-96-20100607195425.png' xmlns='http://www.w3.org/2005/Atom'/>"
     "<link rel='avatar' type='image/png' xmlns:ns1='http://purl.org/syndication/atommedia' ns1:height='48' xmlns:ns2='http://purl.org/syndication/atommedia' ns2:width='48' href='http://avatar.identi.ca/46122-48-20100607195425.png' xmlns='http://www.w3.org/2005/Atom'/>"
     "<link rel='avatar' type='image/png' xmlns:ns1='http://purl.org/syndication/atommedia' ns1:height='24' xmlns:ns2='http://purl.org/syndication/atommedia' ns2:width='24' href='http://avatar.identi.ca/46122-24-20100607195425.png' xmlns='http://www.w3.org/2005/Atom'/>"
     "<point xmlns='http://www.georss.org/georss'>-33.4262838 -70.5665588</point>"
    "<preferredUsername xmlns='http://portablecontacts.net/spec/1.0'>magicdrums</preferredUsername>"
    "<displayName xmlns='http://portablecontacts.net/spec/1.0'>Victor Pereira</displayName>"
    "<note xmlns='http://portablecontacts.net/spec/1.0'>Padre, Esposo, IT Support, Intento de Geek, Hard Core, Ubuntero, Batero Frustado Linuxcero, Amante de mi Señora...</note>"
    "<address xmlns='http://portablecontacts.net/spec/1.0'>"
     "<formatted>ÜT: -33.527926,-70.655237</formatted>"
    "</address>"
    "<urls xmlns='http://portablecontacts.net/spec/1.0'>"
     "<type>homepage</type>"
     "<value>http://magicdrums.gnu-linux.cl</value>"
     "<primary>true</primary>"
    "</urls>"
    "</actor>"
     "<link rel='alternate' type='text/html' href='http://identi.ca/notice/45259404'/>"
     "<id>http://identi.ca/notice/45259404</id>"
     "<published>2010-08-06T13:52:15+00:00</published>"
     "<updated>2010-08-06T13:52:15+00:00</updated>"
     "<notice_info local_id='45259404' source='Viigo' xmlns='http://status.net/schema/api/1/'/>"
     "<link rel='related' href='http://identi.ca/notice/45255203'/>"
     "<in-reply-to ref='http://identi.ca/notice/45255203' href='http://identi.ca/notice/45255203' xmlns='http://purl.org/syndication/thread/1.0'/>"
     "<link rel='ostatus:conversation' href='http://identi.ca/conversation/44928627'/>"
     "<link rel='ostatus:attention' href='http://identi.ca/user/119986'/>"
     "<link rel='ostatus:attention' href='http://identi.ca/group/56/id'/>"
     "<content type='html'>RT @&lt;span class=&quot;vcard&quot;&gt;&lt;a href=&quot;http://identi.ca/user/119986&quot; class=&quot;url&quot; title=&quot;Mate Amargo {Nerds}&quot;&gt;&lt;span class=&quot;fn nickname&quot;&gt;mateamargonerds&lt;/span&gt;&lt;/a&gt;&lt;/span&gt;: Cursos !&lt;span class=&quot;vcard&quot;&gt;&lt;a href=&quot;http://identi.ca/group/56/id&quot; class=&quot;url&quot; title=&quot;GNU/Linux (linux)&quot;&gt;&lt;span class=&quot;fn nickname&quot;&gt;Linux&lt;/span&gt;&lt;/a&gt;&lt;/span&gt; avanzado &lt;a href=&quot;http://twitpic.com/2c3lnj&quot; title=&quot;http://twitpic.com/2c3lnj&quot; rel=&quot;external&quot;&gt;http://twitpic.com/2c3lnj&lt;/a&gt; !mateamargonerds | jajajaj !fb</content>"
     "<category term='fb'/>"
     "<category term='linux'/>"
     "<category term='mateamargonerds'/>"
     "<point xmlns='http://www.georss.org/georss'>-33.4262838 -70.5665588</point>"
    "</entry>"
    "</message>";

  for(i = 0; i < NADTXT_COUNT; i++) {
    nad_t nad = nad_parse(nadtxt[i], 0);

	fprintf(stdout, "Original:\n%s\n", nadtxt[i]);

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
	
	fprintf(stdout, "--------------------------------------------------------------\n");
  }
}

int main(int argc, char* arcgv[])
{
    fprintf(stdout, "Testing s2s incoming packet wrapper\n");
    s2s_wrap();

    exit(EXIT_SUCCESS);
}
