#include <check.h>

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdlib.h>

#include "util/util.h"

#define NADTXT_COUNT 4
char *nadtxt[NADTXT_COUNT] = {
"<presence to='test@chrome.pl' from='test%gmail.com@jabber.chrome.pl/gmail.EBAFDAF7'>"
    "<priority>24</priority>"
    "<caps:c xmlns:caps='http://jabber.org/protocol/caps' xmlns='jabber:client' node='http://mail.google.com/xmpp/client/caps' ext='pmuc-v1 sms-v1 vavinvite-v1' ver='1.1'/>"
    "<status>Your faith is what you believe, not what you know.</status>"
    "<x xmlns='vcard-temp:x:update'><photo>f272aa57eae74d4be9f99758d2fed636c30548cb</photo></x>"
"</presence>",

"<message type='chat' to='test@chrome.pl' from='update@identi.ca/xmpp001daemon'><body>magicdrums: RT @mateamargonerds: Cursos !Linux avanzado http://twitpic.com/2c3lnj !mateamargonerds | jajajaj !fb [45259404]</body><html xmlns='http://jabber.org/protocol/xhtml-im'><body xmlns='http://www.w3.org/1999/xhtml'><a href='http://identi.ca/magicdrums'>magicdrums</a>: RT @<span class='vcard'><a title='Mate Amargo {Nerds}' class='url' href='http://identi.ca/user/119986'><span class='fn nickname'>mateamargonerds</span></a></span>: Cursos !<span class='vcard'><a title='GNU/Linux (linux)' class='url' href='http://identi.ca/group/56/id'><span class='fn nickname'>Linux</span></a></span> avanzado <a rel='external' title='http://twitpic.com/2c3lnj' href='http://twitpic.com/2c3lnj'>http://twitpic.com/2c3lnj</a> !mateamargonerds | jajajaj !fb <a href='http://identi.ca/conversation/44928627#notice-45259404'>[45259404]</a></body></html> <entry xmlns='http://www.w3.org/2005/Atom'>"
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
"</message>",

"<message xmlns='jabber:server' from='blip@blip.pl/blip' to='test@chrome.pl' xml:lang='en' type='chat'>"
 "<body>Proponuję zmianę tematu. Porozmawiajmy o dinazaurach.</body>"
"</message>",

"<presence xmlns='jabber:client' to='test@chrome.pl' from='anon%majesticmedia.ca@gtalk.jrudevels.org/gmail.E1D35514'>"
 "<status/><show>away</show><priority>0</priority>"
 "<caps:c xmlns:caps='http://jabber.org/protocol/caps' xmlns='jabber:client' ver='1.1' ext='pmuc-v1 sms-v1 vavinvite-v1' node='http://mail.google.com/xmpp/client/caps'/>"
 "<x xmlns='vcard-temp:x:update'><photo>86f065b95e82036afa1eb2180f846e60085f3138</photo></x>"
"</presence>"
};

char *nadmangled[NADTXT_COUNT] = {
"<route xmlns='http://jabberd.jabberstudio.org/ns/component/1.0' from='s2s' to='sm'><presence xmlns='jabber:client' from='test%gmail.com@jabber.chrome.pl/gmail.EBAFDAF7' to='test@chrome.pl'><priority>24</priority><caps:c xmlns:caps='http://jabber.org/protocol/caps' ver='1.1' ext='pmuc-v1 sms-v1 vavinvite-v1' node='http://mail.google.com/xmpp/client/caps'/><status>Your faith is what you believe, not what you know.</status><x xmlns='vcard-temp:x:update'><photo>f272aa57eae74d4be9f99758d2fed636c30548cb</photo></x></presence></route>",

"<route xmlns='http://jabberd.jabberstudio.org/ns/component/1.0' from='s2s' to='sm'><message xmlns='jabber:client' from='update@identi.ca/xmpp001daemon' to='test@chrome.pl' type='chat'><body>magicdrums: RT @mateamargonerds: Cursos !Linux avanzado http://twitpic.com/2c3lnj !mateamargonerds | jajajaj !fb [45259404]</body><html xmlns='http://jabber.org/protocol/xhtml-im'><body xmlns='http://www.w3.org/1999/xhtml'><a href='http://identi.ca/magicdrums'>magicdrums</a>: RT @<span class='vcard'><a href='http://identi.ca/user/119986' class='url' title='Mate Amargo {Nerds}'><span class='fn nickname'>mateamargonerds</span></a></span>: Cursos !<span class='vcard'><a href='http://identi.ca/group/56/id' class='url' title='GNU/Linux (linux)'><span class='fn nickname'>Linux</span></a></span> avanzado <a href='http://twitpic.com/2c3lnj' title='http://twitpic.com/2c3lnj' rel='external'>http://twitpic.com/2c3lnj</a> !mateamargonerds | jajajaj !fb <a href='http://identi.ca/conversation/44928627#notice-45259404'>[45259404]</a></body></html> <entry xmlns='http://www.w3.org/2005/Atom'><source><id>http://identi.ca/magicdrums</id><title>magicdrums - Identi.ca</title><link href='http://identi.ca/magicdrums'/><link href='http://identi.ca/magicdrums' type='application/atom+xml' rel='self'/><link href='http://creativecommons.org/licenses/by/3.0/' rel='license'/><icon>http://avatar.identi.ca/46122-96-20100607195425.png</icon><updated>2010-08-06T13:52:15+00:00</updated></source><title>RT @mateamargonerds: Cursos !Linux avanzado http://twitpic.com/2c3lnj !mateamargonerds | jajajaj !fb</title><author><name>magicdrums</name><uri>http://identi.ca/user/46122</uri></author><actor xmlns='http://activitystrea.ms/spec/1.0/'><object-type>http://activitystrea.ms/schema/1.0/person</object-type><id xmlns='http://www.w3.org/2005/Atom'>http://identi.ca/user/46122</id><title xmlns='http://www.w3.org/2005/Atom'>Victor Pereira</title><link xmlns='http://www.w3.org/2005/Atom' href='http://identi.ca/magicdrums' type='text/html' rel='alternate'/><link xmlns:ns1='http://purl.org/syndication/atommedia' xmlns='http://www.w3.org/2005/Atom' href='http://avatar.identi.ca/46122-163-20100607195425.png' ns1:width='163' ns1:height='163' type='image/png' rel='avatar'/><link xmlns:ns1='http://purl.org/syndication/atommedia' xmlns='http://www.w3.org/2005/Atom' href='http://avatar.identi.ca/46122-96-20100607195425.png' ns1:width='96' ns1:height='96' type='image/png' rel='avatar'/><link xmlns:ns1='http://purl.org/syndication/atommedia' xmlns='http://www.w3.org/2005/Atom' href='http://avatar.identi.ca/46122-48-20100607195425.png' ns1:width='48' ns1:height='48' type='image/png' rel='avatar'/><link xmlns:ns1='http://purl.org/syndication/atommedia' xmlns='http://www.w3.org/2005/Atom' href='http://avatar.identi.ca/46122-24-20100607195425.png' ns1:width='24' ns1:height='24' type='image/png' rel='avatar'/><point xmlns='http://www.georss.org/georss'>-33.4262838 -70.5665588</point><preferredUsername xmlns='http://portablecontacts.net/spec/1.0'>magicdrums</preferredUsername><displayName xmlns='http://portablecontacts.net/spec/1.0'>Victor Pereira</displayName><note xmlns='http://portablecontacts.net/spec/1.0'>Padre, Esposo, IT Support, Intento de Geek, Hard Core, Ubuntero, Batero Frustado Linuxcero, Amante de mi Señora...</note><address xmlns='http://portablecontacts.net/spec/1.0'><formatted>ÜT: -33.527926,-70.655237</formatted></address><urls xmlns='http://portablecontacts.net/spec/1.0'><type>homepage</type><value>http://magicdrums.gnu-linux.cl</value><primary>true</primary></urls></actor><link href='http://identi.ca/notice/45259404' type='text/html' rel='alternate'/><id>http://identi.ca/notice/45259404</id><published>2010-08-06T13:52:15+00:00</published><updated>2010-08-06T13:52:15+00:00</updated><notice_info xmlns='http://status.net/schema/api/1/' source='Viigo' local_id='45259404'/><link href='http://identi.ca/notice/45255203' rel='related'/><in-reply-to xmlns='http://purl.org/syndication/thread/1.0' href='http://identi.ca/notice/45255203' ref='http://identi.ca/notice/45255203'/><link href='http://identi.ca/conversation/44928627' rel='ostatus:conversation'/><link href='http://identi.ca/user/119986' rel='ostatus:attention'/><link href='http://identi.ca/group/56/id' rel='ostatus:attention'/><content type='html'>RT @&lt;span class=&quot;vcard&quot;&gt;&lt;a href=&quot;http://identi.ca/user/119986&quot; class=&quot;url&quot; title=&quot;Mate Amargo {Nerds}&quot;&gt;&lt;span class=&quot;fn nickname&quot;&gt;mateamargonerds&lt;/span&gt;&lt;/a&gt;&lt;/span&gt;: Cursos !&lt;span class=&quot;vcard&quot;&gt;&lt;a href=&quot;http://identi.ca/group/56/id&quot; class=&quot;url&quot; title=&quot;GNU/Linux (linux)&quot;&gt;&lt;span class=&quot;fn nickname&quot;&gt;Linux&lt;/span&gt;&lt;/a&gt;&lt;/span&gt; avanzado &lt;a href=&quot;http://twitpic.com/2c3lnj&quot; title=&quot;http://twitpic.com/2c3lnj&quot; rel=&quot;external&quot;&gt;http://twitpic.com/2c3lnj&lt;/a&gt; !mateamargonerds | jajajaj !fb</content><category term='fb'/><category term='linux'/><category term='mateamargonerds'/><point xmlns='http://www.georss.org/georss'>-33.4262838 -70.5665588</point></entry></message></route>",

"<route xmlns='http://jabberd.jabberstudio.org/ns/component/1.0' from='s2s' to='sm'><message xmlns='jabber:client' type='chat' xml:lang='en' to='test@chrome.pl' from='blip@blip.pl/blip'><body>Proponuję zmianę tematu. Porozmawiajmy o dinazaurach.</body></message></route>",

"<route xmlns='http://jabberd.jabberstudio.org/ns/component/1.0' from='s2s' to='sm'><presence xmlns='jabber:client' from='anon%majesticmedia.ca@gtalk.jrudevels.org/gmail.E1D35514' to='test@chrome.pl'><status/><show>away</show><priority>0</priority><caps:c xmlns:caps='http://jabber.org/protocol/caps' xmlns='jabber:client' node='http://mail.google.com/xmpp/client/caps' ext='pmuc-v1 sms-v1 vavinvite-v1' ver='1.1'/><x xmlns='vcard-temp:x:update'><photo>86f065b95e82036afa1eb2180f846e60085f3138</photo></x></presence></route>"
};


START_TEST (check_s2s_wrap)
{
    const char *buf;
    int len, ns, sns, elem;

    nad_t nad = nad_parse(nadtxt[_i], 0);

	fprintf(stdout, "Original:\n%s\n", nadtxt[_i]);

    nad_print(nad, 0, &buf, &len);
    fprintf(stdout, "Parsed:\n%.*s\n", len, buf);

    /* rewrite server packets into client packets */
    ns = nad_find_namespace(nad, 0, uri_SERVER, NULL);
    if(ns >= 0) {
        if(nad->elems[0].ns == ns)
            nad->elems[0].ns = nad->nss[nad->elems[0].ns].next;
        else {
            for(sns = nad->elems[0].ns; sns >= 0 && nad->nss[sns].next != ns; sns = nad->nss[sns].next);
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

    ck_assert_int_eq (strlen(nadmangled[_i]), len);
	fail_if (strncmp(nadmangled[_i], buf, len));

	nad_free(nad);
}
END_TEST

START_TEST (check_leaf_path)
{
    const char *buf;
    int len, elem;

    const char *nad_test =
"<iq type='set'>\n\
    <pubsub node='node1' b='2'>\n\
        <options/>\n\
    </pubsub>\n\
    <test d='3'/>\n\
</iq>";

    nad_t nad = nad_parse(nad_test, 0);

    fprintf(stdout, "Original:\n%s\n", nad_test);

    nad_print(nad, 0, &buf, &len);
    fprintf(stdout, "Parsed:\n%.*s\n", len, buf);

    elem  = nad_find_elem_path(nad, 0, -1, "pubsub/options");

    ck_assert_int_eq(2, elem);

    nad_free(nad);
}
END_TEST

Suite* s2s_wrapper_suite (void)
{
    Suite *s = suite_create ("s2s incoming packet wrapper");

    TCase *tc_wrapper = tcase_create ("Wrapper");
    tcase_add_loop_test (tc_wrapper, check_s2s_wrap, 0, NADTXT_COUNT);
    suite_add_tcase (s, tc_wrapper);

    TCase *tc_nad_find_elem_path = tcase_create ("nad_find_elem_path");
    tcase_add_test (tc_nad_find_elem_path, check_leaf_path);
    suite_add_tcase (s, tc_nad_find_elem_path);


    return s;
}

int main (void)
{
    int number_failed;
    Suite *s = s2s_wrapper_suite ();
    SRunner *sr = srunner_create (s);
    srunner_run_all (sr, CK_NORMAL);
    number_failed = srunner_ntests_failed (sr);
    srunner_free (sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
