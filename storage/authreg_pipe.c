/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2002 Jeremie Miller, Thomas Muldowney,
 *                    Ryan Eatmon, Robert Norris
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA02111-1307USA
 */

/*
 * this is the fabled pipe authenticator. it forks and executes a
 * script, and talks to it via stdio. this is a great way to take
 * advantage of existing code (in any language) to do authentication and
 * registration.
 *
 * there is an example script, tools/pipe-auth.pl, which can be used to
 * get started writing a pipe module. the protocol is documented in
 * docs/dev/c2s-pipe-authenticator
 */

/*
 * !!! this is highly experimental - be prepared for random acts of weirdness
 *     if you decide to use this.
 */

#include "c2s.h"
#include <sys/wait.h>

/** internal structure, holds our data */
typedef struct moddata_st {
    const char    *exec;
    
    pid_t   child;

    int     in, out;
} *moddata_t;

static int _ar_pipe_write(authreg_t ar, int fd, const char *msgfmt, ...)
{
    va_list args;
    char buf[1024];
    int ret;

    va_start(args, msgfmt);
    vsnprintf(buf, 1024, msgfmt, args);
    va_end(args);

    log_debug(ZONE, "writing to pipe: %s", buf);

    ret = write(fd, buf, strlen(buf));
    if(ret < 0)
        log_write(ar->c2s->log, LOG_ERR, "pipe: write to pipe failed: %s", strerror(errno));

    return ret;
}

static int _ar_pipe_read(authreg_t ar, int fd, char *buf, int buflen)
{
    int ret;
    char *c;

    ret = read(fd, buf, buflen);
    if(ret == 0)
        log_write(ar->c2s->log, LOG_ERR, "pipe: got EOF from pipe");
    if(ret < 0)
        log_write(ar->c2s->log, LOG_ERR, "pipe: read from pipe failed: %s", strerror(errno));
    if(ret <= 0)
        return ret;

    buf[ret] = '\0';
    c = strchr(buf, '\n');
    if(c != NULL)
        *c = '\0';
        
    log_debug(ZONE, "read from pipe: %s", buf);

    return ret;
}

static int _ar_pipe_user_exists(authreg_t ar, sess_t sess, const char *username, const char *realm)
{
    moddata_t data = (moddata_t) ar->private;
    char buf[1024];

    if(_ar_pipe_write(ar, data->out, "USER-EXISTS %s %s\n", username, realm) < 0)
        return 0;

    if(_ar_pipe_read(ar, data->in, buf, 1023) <= 0)
        return 0;

    if(buf[0] != 'O' || buf[1] != 'K')
        return 0;

    return 1;
}

static int _ar_pipe_get_password(authreg_t ar, sess_t sess, const char *username, const char *realm, char password[257])
{
    moddata_t data = (moddata_t) ar->private;
    char buf[1024];

    if(_ar_pipe_write(ar, data->out, "GET-PASSWORD %s %s\n", username, realm) < 0)
        return 1;

    if(_ar_pipe_read(ar, data->in, buf, 1023) <= 0)
        return 1;

    if(buf[0] != 'O' || buf[1] != 'K')
        return 1;

    if(buf[2] != ' ' || buf[3] == '\0')
    {
        log_debug(ZONE, "malformed response from pipe");
        return 1;
    }

    if(apr_base64_decode_len(&buf[3], strlen(&buf[3])) >= 256) {
        log_debug(ZONE, "decoded password longer than buffer");
        return 1;
    }

    apr_base64_decode(password, &buf[3], strlen(&buf[3]));

    log_debug(ZONE, "got password: %s", password);

    return 0;
}

static int _ar_pipe_check_password(authreg_t ar, sess_t sess, const char *username, const char *realm, char password[257])
{
    moddata_t data = (moddata_t) ar->private;
    char buf[1024];
    int plen;

    plen = strlen(password);

    if(apr_base64_encode_len(plen) >= 1023) {
        log_debug(ZONE, "unable to encode password");
        return 1;
    }

    apr_base64_encode(buf, password, plen);
    
    if(_ar_pipe_write(ar, data->out, "CHECK-PASSWORD %s %s %s\n", username, buf, realm) < 0)
        return 1;

    if(_ar_pipe_read(ar, data->in, buf, 1023) <= 0)
        return 1;

    if(buf[0] != 'O' || buf[1] != 'K')
        return 1;

    return 0;
}

static int _ar_pipe_set_password(authreg_t ar, sess_t sess, const char *username, const char *realm, char password[257])
{
    moddata_t data = (moddata_t) ar->private;
    char buf[1024];
    int plen;

    plen = strlen(password);

    if(apr_base64_encode_len(plen) >= 1023) {
        log_debug(ZONE, "unable to encode password");
        return 1;
    }

    apr_base64_encode(buf, password, plen);

    if(_ar_pipe_write(ar, data->out, "SET-PASSWORD %s %s %s\n", username, buf, realm) < 0)
        return 1;

    if(_ar_pipe_read(ar, data->in, buf, 1023) <= 0)
        return 1;

    if(buf[0] != 'O' || buf[1] != 'K')
        return 1;

    return 0;
}

static int _ar_pipe_create_user(authreg_t ar, sess_t sess, const char *username, const char *realm)
{
    moddata_t data = (moddata_t) ar->private;
    char buf[1024];

    if(_ar_pipe_write(ar, data->out, "CREATE-USER %s %s\n", username, realm) < 0)
        return 1;

    if(_ar_pipe_read(ar, data->in, buf, 1023) <= 0)
        return 1;

    if(buf[0] != 'O' || buf[1] != 'K')
        return 1;

    return 0;
}

static int _ar_pipe_delete_user(authreg_t ar, sess_t sess, const char *username, const char *realm)
{
    moddata_t data = (moddata_t) ar->private;
    char buf[1024];

    if(_ar_pipe_write(ar, data->out, "DELETE-USER %s %s\n", username, realm) < 0)
        return 1;

    if(_ar_pipe_read(ar, data->in, buf, 1023) <= 0)
        return 1;

    if(buf[0] != 'O' || buf[1] != 'K')
        return 1;

    return 0;
}

static void _ar_pipe_free(authreg_t ar)
{
    moddata_t data = (moddata_t) ar->private;

    if(_ar_pipe_write(ar, data->out, "FREE\n") < 0)
        return;

    close(data->in);
    close(data->out);

    free(data);

    return;
}

static void _ar_pipe_signal(int signum)
{
    wait(NULL);

    /* !!! attempt to restart the pipe, or shutdown c2s */
}

/** start me up */
int ar_init(authreg_t ar)
{
    moddata_t data;
    int to[2], from[2], ret;
    char buf[1024], *tok, *c;

    data = (moddata_t) calloc(1, sizeof(struct moddata_st));

    data->exec = config_get_one(ar->c2s->config, "authreg.pipe.exec", 0);
    if(data->exec == NULL)
    {
        log_write(ar->c2s->log, LOG_ERR, "pipe: no executable specified in config file");
        free(data);
        return 1;
    }

    if(pipe(to) < 0)
    {
        log_write(ar->c2s->log, LOG_ERR, "pipe: failed to create pipe: %s", strerror(errno));
        free(data);
        return 1;
    }

    if(pipe(from) < 0)
    {
        log_write(ar->c2s->log, LOG_ERR, "pipe: failed to create pipe: %s", strerror(errno));
        close(to[0]);
        close(to[1]);
        free(data);
        return 1;
    }

    signal(SIGCHLD, _ar_pipe_signal);

    log_debug(ZONE, "attempting to fork");

    data->child = fork();
    if(data->child < 0)
    {
        log_write(ar->c2s->log, LOG_ERR, "pipe: failed to fork: %s", strerror(errno));
        close(to[0]);
        close(to[1]);
        close(from[0]);
        close(from[1]);
        free(data);
        return 1;
    }

    /* child */
    if(data->child == 0)
    {
        log_debug(ZONE, "executing %s", data->exec);

        close(STDIN_FILENO);
        close(STDOUT_FILENO);

        dup2(to[0], STDIN_FILENO);
        dup2(from[1], STDOUT_FILENO);

        close(to[0]);
        close(to[1]);
        close(from[0]);
        close(from[1]);
        
        execl(data->exec, data->exec, NULL);

        log_write(ar->c2s->log, LOG_ERR, "pipe: failed to execute %s: %s", data->exec, strerror(errno));

        free(data);

        exit(1);
    }

    log_write(ar->c2s->log, LOG_NOTICE, "pipe authenticator %s running (pid %d)", data->exec, data->child);

    /* parent */
    close(to[0]);
    close(from[1]);

    data->in = from[0];
    data->out = to[1];

    ret = _ar_pipe_read(ar, data->in, buf, 1023);
    if(ret <= 0)
    {
        close(data->in);
        close(data->out);
        free(data);
        return 1;
    }

    c = buf;
    while(c != NULL)
    {
        tok = c;

        c = strchr(c, ' ');
        if(c != NULL)
        {
            *c = '\0';
            c++;
        }

        /* first token must be OK */
        if(tok == buf)
        {
            if(strcmp(tok, "OK") == 0)
                continue;

            log_write(ar->c2s->log, LOG_ERR, "pipe: pipe authenticator failed to initialise");
            kill(data->child, SIGTERM);
            close(data->in);
            close(data->out);
            free(data);
            return 1;
        }

        /* its an option */
        log_debug(ZONE, "module feature: %s", tok);

        if(strcmp(tok, "USER-EXISTS") == 0)
            ar->user_exists = _ar_pipe_user_exists;
        else if(strcmp(tok, "GET-PASSWORD") == 0)
            ar->get_password = _ar_pipe_get_password;
        else if(strcmp(tok, "CHECK-PASSWORD") == 0)
            ar->check_password = _ar_pipe_check_password;
        else if(strcmp(tok, "SET-PASSWORD") == 0)
            ar->set_password = _ar_pipe_set_password;
        else if(strcmp(tok, "CREATE-USER") == 0)
            ar->create_user = _ar_pipe_create_user;
        else if(strcmp(tok, "DELETE-USER") == 0)
            ar->delete_user = _ar_pipe_delete_user;
        else if(strcmp(tok, "FREE") == 0)
            ar->free = _ar_pipe_free;
    }

    ar->private = (void *) data;

    return 0;
}
