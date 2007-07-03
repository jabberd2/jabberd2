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

/* known namespace uri */
#define uri_STREAMS     "http://etherx.jabber.org/streams"
#define uri_CLIENT      "jabber:client"
#define uri_SERVER      "jabber:server"
#define uri_DIALBACK    "jabber:server:dialback"
#define uri_TLS         "urn:ietf:params:xml:ns:xmpp-tls"
#define uri_SASL        "urn:ietf:params:xml:ns:xmpp-sasl"
#define uri_BIND        "urn:ietf:params:xml:ns:xmpp-bind"
#define uri_XSESSION    "urn:ietf:params:xml:ns:xmpp-session"
#define uri_STREAM_ERR  "urn:ietf:params:xml:ns:xmpp-streams"
#define uri_STANZA_ERR  "urn:ietf:params:xml:ns:xmpp-stanzas"
#define uri_COMPONENT   "http://jabberd.jabberstudio.org/ns/component/1.0"
#define uri_SESSION     "http://jabberd.jabberstudio.org/ns/session/1.0"
#define uri_RESOLVER    "http://jabberd.jabberstudio.org/ns/resolver/1.0"
#define uri_XDATA       "jabber:x:data"
#define uri_XML         "http://www.w3.org/XML/1998/namespace"

#endif
