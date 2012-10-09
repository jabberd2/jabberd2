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

/** @file c2s/pbx.c
  * @brief PBX integration
  * @author Tomasz Sterna
  * $Date$
  * $Revision$
  */

#include "c2s.h"

#define COMMANDLINE_LENGTH_MAX	2048
static void _pbx_close_pipe(c2s_t c2s);
static void _pbx_open_pipe(c2s_t c2s, int mode);
static void _pbx_read_pipe(c2s_t c2s);
static void _pbx_write_pipe(c2s_t c2s);
int _pbx_process_command(c2s_t c2s, const char *cmd);

static void _pbx_read_command(c2s_t c2s) {
	char buf[COMMANDLINE_LENGTH_MAX];
	char *bufp;

	bufp = (char*)&buf;
	while (read(c2s->pbx_pipe_fd, bufp, 1) > 0)
		if(bufp - ((char*)&buf) < COMMANDLINE_LENGTH_MAX-1) bufp++;
	*bufp = '\0';

	log_debug(ZONE, "command read: %s", buf);

	_pbx_close_pipe(c2s);

	if(_pbx_process_command(c2s, buf) == 0)
		_pbx_write_pipe(c2s);

	_pbx_read_pipe(c2s);
}

static int _pbx_mio_callback(mio_t m, mio_action_t a, mio_fd_t fd, void *data, void *arg) {
	c2s_t c2s = (c2s_t) arg;

    log_debug(ZONE, "action %s on PBX pipe", a==0?"action_ACCEPT":a==1?"action_READ":a==2?"action_WRITE":a==3?"action_CLOSE":"-unknown-");

    switch(a) {
        case action_READ:
            log_debug(ZONE, "read action on fd %d", fd->fd);
			_pbx_read_command(c2s);
			return 1; /* want to read again */

        case action_WRITE:
			/* write buffered lines from jqueue */
			_pbx_close_pipe(c2s);
			return 0;

		case action_CLOSE:
			c2s->pbx_pipe_mio_fd = 0;
			c2s->pbx_pipe_fd = -1;
			return 0;

        default:
            break;
    }

    return 0;
}

static void _pbx_close_pipe(c2s_t c2s) {
	log_debug(ZONE, "### close_pipe");
	if(c2s->pbx_pipe_mio_fd)
		mio_close(c2s->mio, c2s->pbx_pipe_mio_fd);
}

static void _pbx_open_pipe(c2s_t c2s, int mode) {
#ifdef WIN32
	log_debug(ZONE, "PBX is not supported under Windows");
	log_write(c2s->log, LOG_ERR, "PBX for Windows is not supported yet");
	exit(EXIT_FAILURE);
#else
	log_debug(ZONE, "### open_pipe");
	c2s->pbx_pipe_fd = open(c2s->pbx_pipe, mode | O_NONBLOCK);
	if(c2s->pbx_pipe_fd == -1) {
		c2s->pbx_pipe_mio_fd = 0;
		log_debug(ZONE, "error opening pipe: %d %s", errno, strerror(errno));
		log_write(c2s->log, LOG_ERR, "failed to open PBX named pipe %s for %s", c2s->pbx_pipe, mode==O_RDONLY?"reading":"writing");
		exit(EXIT_FAILURE);
	} else
		c2s->pbx_pipe_mio_fd = mio_register(c2s->mio, c2s->pbx_pipe_fd, _pbx_mio_callback, (void *) c2s);
#endif
}
/* open pipe for reading */
static void _pbx_read_pipe(c2s_t c2s) {
	log_debug(ZONE, "### read_pipe");
	_pbx_open_pipe(c2s, O_RDONLY);
	mio_read(c2s->mio, c2s->pbx_pipe_mio_fd);
}
/* trigger buffer write */
static void _pbx_write_pipe(c2s_t c2s) {
	log_debug(ZONE, "### write_pipe");
	_pbx_open_pipe(c2s, O_RDWR);
	mio_write(c2s->mio, c2s->pbx_pipe_mio_fd);
}

void c2s_pbx_init(c2s_t c2s) {
#ifdef WIN32
	log_debug(ZONE, "PBX is not supported under Windows");
	log_write(c2s->log, LOG_ERR, "PBX for Windows is not supported yet");
	exit(EXIT_FAILURE);
#else
	struct stat sb;

	/* create the FIFO */
	if(stat(c2s->pbx_pipe, &sb) == -1) {
		if(mkfifo(c2s->pbx_pipe, S_IRUSR | S_IWUSR | S_IRGRP) == -1) {
			log_write(c2s->log, LOG_ERR, "failed to create PBX named pipe: %s", c2s->pbx_pipe);
			exit(EXIT_FAILURE);
		}
	}else{
		if(!S_ISFIFO(sb.st_mode)) {
			log_write(c2s->log, LOG_ERR, "file %s exists but is not a named pipe", c2s->pbx_pipe);
			exit(EXIT_FAILURE);
		}
	}

	_pbx_read_pipe(c2s);
#endif
}
