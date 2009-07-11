/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2002-2004 Jeremie Miller, Thomas Muldowney,
 *                         Ryan Eatmon, Robert Norris
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA02111-1307USA
 */

/** @file util/uri.h
  * @brief common URIs
  * @author Robert Norris
  * $Revision: 1.1 $
  * $Date: 2004/04/30 00:53:54 $
  */

#ifndef INCL_UTIL_URI_H
#define INCL_UTIL_URI_H 1

#define uri_XML         "http://www.w3.org/XML/1998/namespace"

/* known namespace uri */
#define uri_STREAMS     "http://etherx.jabber.org/streams"
#define uri_CLIENT      "jabber:client"
#define uri_SERVER      "jabber:server"
#define uri_DIALBACK    "jabber:server:dialback"
#define uri_DIALBACK_L	22	/* strlen(uri_DIALBACK) */
#define uri_URN_DIALBACK "urn:xmpp:features:dialback"
#define uri_TLS         "urn:ietf:params:xml:ns:xmpp-tls"
#define uri_SASL        "urn:ietf:params:xml:ns:xmpp-sasl"
#define uri_BIND        "urn:ietf:params:xml:ns:xmpp-bind"
#define uri_XSESSION    "urn:ietf:params:xml:ns:xmpp-session"
#define uri_COMPRESS    "http://jabber.org/protocol/compress"
#define uri_COMPRESS_FEATURE "http://jabber.org/features/compress"
#define uri_ACK         "http://www.xmpp.org/extensions/xep-0198.html#ns"
#define uri_IQAUTH      "http://jabber.org/features/iq-auth"
#define uri_IQREGISTER  "http://jabber.org/features/iq-register"
#define uri_STREAM_ERR  "urn:ietf:params:xml:ns:xmpp-streams"
#define uri_STANZA_ERR  "urn:ietf:params:xml:ns:xmpp-stanzas"
#define uri_COMPONENT   "http://jabberd.jabberstudio.org/ns/component/1.0"
#define uri_SESSION     "http://jabberd.jabberstudio.org/ns/session/1.0"
#define uri_RESOLVER    "http://jabberd.jabberstudio.org/ns/resolver/1.0"
#define uri_XDATA       "jabber:x:data"
#define uri_OOB         "jabber:x:oob"
#define uri_ADDRESS_FEATURE "http://affinix.com/jabber/address"
#define uri_ROSTERVER   "urn:xmpp:features:rosterver"

/* these are used by SM mainly */
#define uri_AUTH        "jabber:iq:auth"
#define uri_REGISTER    "jabber:iq:register"
#define uri_ROSTER      "jabber:iq:roster"
#define uri_AGENTS      "jabber:iq:agents"
#define uri_DELAY       "jabber:x:delay"
#define uri_URN_DELAY   "urn:xmpp:delay"
#define uri_TIME        "jabber:iq:time"
#define urn_TIME        "urn:xmpp:time"
#define uri_VERSION     "jabber:iq:version"
#define uri_BROWSE      "jabber:iq:browse"
#define uri_EVENT       "jabber:x:event"
#define uri_GATEWAY     "jabber:iq:gateway"
#define uri_EXPIRE      "jabber:x:expire"
#define uri_PRIVACY     "jabber:iq:privacy"
#define urn_BLOCKING    "urn:xmpp:blocking"
#define urn_BLOCKING_ERR "urn:xmpp:blocking:errors"
#define uri_SEARCH      "jabber:iq:search"
#define urn_PING        "urn:xmpp:ping"
#define uri_DISCO       "http://jabber.org/protocol/disco"
#define uri_DISCO_ITEMS "http://jabber.org/protocol/disco#items"
#define uri_DISCO_INFO  "http://jabber.org/protocol/disco#info"
#define uri_SERVERINFO  "http://jabber.org/network/serverinfo"
#define urn_SOFTWAREINFO "urn:xmpp:dataforms:softwareinfo"

#define uri_AMP                         "http://jabber.org/protocol/amp"
#define uri_AMP_ERRORS                  "http://jabber.org/protocol/amp#errors"
#define uri_AMP_ACTION_DROP             "http://jabber.org/protocol/amp?action=drop"
#define uri_AMP_ACTION_ERROR            "http://jabber.org/protocol/amp?action=error"
#define uri_AMP_ACTION_NOTIFY           "http://jabber.org/protocol/amp?action=notify"
#define uri_AMP_CONDITION_DELIVER       "http://jabber.org/protocol/amp?condition=deliver"
#define uri_AMP_CONDITION_EXPIREAT      "http://jabber.org/protocol/amp?condition=expire-at"
#define uri_AMP_CONDITION_MATCHRESOURCE "http://jabber.org/protocol/amp?condition=match-resource"

#endif
