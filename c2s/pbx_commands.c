/* vim: set noet ts=4 sw=4: */
/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2009 Tomasz Sterna
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

/** @file c2s/pbx_commands.c
  * @brief PBX integration commands interpreter
  * @author Tomasz Sterna
  * $Date$
  * $Revision$
  */

/**
 * Available commands:
 * START jid/resource [[priority ]status] [description]  - opens PBX resource session
 * STOP jid/resource [description]                       - closes PBX resource session
 * STATUS                                                - dumps list of currently open PBX sessions
 *
 * [status] in: CHAT, ONLINE, DND, AWAY, XA
 */

#include "c2s.h"

static int _pbx_command_part_len(const char *cmd)
{
	int i;
	for(i=0; *cmd != ' ' && *cmd != '\t' && *cmd != '\n' && *cmd != '\0'; cmd++, i++);
	return i;
}

static nad_t _pbx_presence_nad(int available, const char *cmd)
{
	nad_t nad;
	int ns;
	char *show = NULL;

	nad = nad_new();
	ns = nad_add_namespace(nad, uri_CLIENT, NULL);
	nad_append_elem(nad, ns, "presence", 0);

	if(!available) {
		nad_append_attr(nad, -1, "type", "unavailable");
	}
	else {
		char *cont;
		long int priority;
		char prioritystr[5]; // -128 to +127 + \0

		priority = strtol(cmd, &cont, 10);
		log_debug(ZONE, "Read %ld priority", priority);
		if(cmd == cont) priority = -1; // use -1 priority if not given
		if(priority < -128) priority = -128;
		if(priority > 127) priority = 127;
		nad_append_elem(nad, -1, "priority", 1);
		snprintf(prioritystr, 5, "%ld", priority);
		nad_append_cdata(nad, prioritystr, strlen(prioritystr), 2);
		if(cmd != cont) {
			cmd = cont;
			while(*cmd == ' ') { cmd++; }
		}


		if(!strncmp("CHAT", cmd, 4)) {
			cmd += 4;
			show = "chat";
		}
		if(!strncmp("ONLINE", cmd, 6)) {
			cmd += 6;
		}
		if(!strncmp("DND", cmd, 3)) {
			cmd += 3;
			show = "dnd";
		}
		if(!strncmp("AWAY", cmd, 4)) {
			cmd += 4;
			show = "away";
		}
		if(!strncmp("XA", cmd, 2)) {
			cmd += 2;
			show = "xa";
		}
		if(show) {
			nad_append_elem(nad, -1, "show", 1);
			nad_append_cdata(nad, show, strlen(show), 2);
		}
	}

	while(*cmd == ' ') { cmd++; }

	if(*cmd != '\0' && *cmd != '\n') {
		int len = strlen(cmd);
		nad_append_elem(nad, -1, "status", 1);
		nad_append_cdata(nad, cmd, len - (cmd[len-1] == '\n' ? 1 : 0), 2);
	}

	return nad;
}

/**
 * process commandline
 * @return: 0 to indicate that output needs to be written
 */
int _pbx_process_command(c2s_t c2s, const char *cmd)
{
	jid_t jid;
	int action = 0, len;
	sess_t sess;
	char hashbuf[44] = "PBX";
	char *sesshash;

	sesshash = hashbuf+3;

	/* get command */
	if(!strncasecmp("START ", cmd, 6)) {
		cmd += 6;
		action = 1;
	}
	if(!strncasecmp("STOP ", cmd, 5)) {
		cmd += 5;
		action = 2;
	}
	if(action != 0) {
		len = _pbx_command_part_len(cmd);
		if(len > 0) {
			jid = jid_new(cmd, len);
			if(jid) {
				cmd += len;
				if(*cmd != '\0') cmd++;

				shahash_r(jid_full(jid), sesshash);
				sess = xhash_get(c2s->sessions, hashbuf);

				switch(action) {
					case 1:
						log_debug(ZONE, "STARTing session for %s/%s (%s) with commandline: %s", jid_user(jid), jid->resource, hashbuf, cmd);

						if(sess == NULL) {
						/* create new session */
							sess = (sess_t) calloc(1, sizeof(struct sess_st));
							sess->c2s = c2s;
							sess->last_activity = time(NULL);
							/* put into sessions hash */
							snprintf(sess->skey, sizeof(sess->skey), "%s", hashbuf);
							xhash_put(c2s->sessions, sess->skey, (void *) sess);
							/* generate bound resource */
							sess->resources = (bres_t) calloc(1, sizeof(struct bres_st));
							snprintf(sess->resources->c2s_id, sizeof(sess->resources->c2s_id), "%s", hashbuf);
							sess->resources->jid = jid;
							/* open SM session */
							log_write(sess->c2s->log, LOG_NOTICE, "[PBX] requesting session: jid=%s", jid_full(jid));
							sm_start(sess, sess->resources);

							/* generate presence packet to get session online */
							/* a bit hacky, but we need to emulate _some_ of the client behavior */
							sess->result = _pbx_presence_nad(1, cmd);
						}
						else {
							/* just send the presence */
							sm_packet(sess, sess->resources, _pbx_presence_nad(1, cmd));
						}

						break;

					case 2:
						log_debug(ZONE, "STOPping session for %s/%s with commandline: %s", jid_user(jid), jid->resource, cmd);

						if(sess != NULL) {
							/* send unavailable presence */
							sm_packet(sess, sess->resources, _pbx_presence_nad(0, cmd));
							/* end the session */
							sm_end(sess, sess->resources);
							xhash_zap(c2s->sessions, sess->skey);
							jqueue_push(c2s->dead_sess, (void *) sess, 0);
						}

						break;
				}

				/* TODO: respond with "OK", return 0 */
				return -1;
			}
		}
		/* TODO: generate "ERR" response, return 0 */
		return -1;
	}
	if(!strncasecmp("STATUS", cmd, 6)) {
		log_write(c2s->log, LOG_INFO, "STATUS PBX command not implemented yet");
		return -1;
	}
    return -1;
}
