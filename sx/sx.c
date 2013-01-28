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

#include "sx.h"

sx_t sx_new(sx_env_t env, int tag, sx_callback_t cb, void *arg) {
    sx_t s;
    int i;

    assert((int) (cb != NULL));

    s = (sx_t) calloc(1, sizeof(struct _sx_st));

    s->env = env;
    s->tag = tag;
    s->cb = cb;
    s->cb_arg = arg;

    s->expat = XML_ParserCreateNS(NULL, '|');
    XML_SetReturnNSTriplet(s->expat, 1);
    XML_SetUserData(s->expat, (void *) s);
    /* Prevent the "billion laughs" attack against expat by disabling
     * internal entity expansion.  With 2.x, forcibly stop the parser
     * if an entity is declared - this is safer and a more obvious
     * failure mode.  With older versions, simply prevent expenansion
     * of such entities. */
#ifdef HAVE_XML_STOPPARSER
    XML_SetEntityDeclHandler(s->expat, (void *) _sx_entity_declaration);
#else
    XML_SetDefaultHandler(s->expat, NULL);
#endif

#ifdef HAVE_XML_SETHASHSALT
    XML_SetHashSalt(s->expat, rand());
#endif

    s->wbufq = jqueue_new();
    s->rnadq = jqueue_new();

    if(env != NULL) {
        s->plugin_data = (void **) calloc(1, sizeof(void *) * env->nplugins);

        for(i = 0; i < env->nplugins; i++)
            if(env->plugins[i]->new != NULL)
                (env->plugins[i]->new)(s, env->plugins[i]);
    }

    _sx_debug(ZONE, "allocated new sx for %d", tag);

    return s;
}

void sx_free(sx_t s) {
    sx_buf_t buf;
    nad_t nad;
    int i;
    _sx_chain_t scan, next;

    if (s == NULL)
        return;

    /* we are not reentrant */
    assert(!s->reentry);

    _sx_debug(ZONE, "freeing sx for %d", s->tag);

    if(s->ns != NULL) free((void*)s->ns);

    if(s->req_to != NULL) free((void*)s->req_to);
    if(s->req_from != NULL) free((void*)s->req_from);
    if(s->req_version != NULL) free((void*)s->req_version);

    if(s->res_to != NULL) free((void*)s->res_to);
    if(s->res_from != NULL) free((void*)s->res_from);
    if(s->res_version != NULL) free((void*)s->res_version);

    if(s->id != NULL) free((void*)s->id);

    while((buf = jqueue_pull(s->wbufq)) != NULL)
        _sx_buffer_free(buf);
    if (s->wbufpending != NULL)
        _sx_buffer_free(s->wbufpending);

    while((nad = jqueue_pull(s->rnadq)) != NULL)
        nad_free(nad);

    jqueue_free(s->wbufq);
    jqueue_free(s->rnadq);

    XML_ParserFree(s->expat);

    if(s->nad != NULL) nad_free(s->nad);

    if(s->auth_method != NULL) free((void*)s->auth_method);
    if(s->auth_id != NULL) free((void*)s->auth_id);

    if(s->env != NULL) {
        _sx_debug(ZONE, "freeing %d env plugins", s->env->nplugins);
        for(i = 0; i < s->env->nplugins; i++)
            if(s->env->plugins[i]->free != NULL)
                (s->env->plugins[i]->free)(s, s->env->plugins[i]);

        scan = s->wio;
        while(scan != NULL) {
            next = scan->wnext;
            free(scan);
            scan = next;
        }

        scan = s->wnad;
        while(scan != NULL) {
            next = scan->wnext;
            free(scan);
            scan = next;
        }

        free(s->plugin_data);
    }

    free(s);
}

/** force advance into auth state */
void sx_auth(sx_t s, const char *auth_method, const char *auth_id) {
    assert((int) (s != NULL));

    _sx_debug(ZONE, "authenticating stream (method=%s; id=%s)", auth_method, auth_id);

    if(auth_method != NULL) s->auth_method = strdup(auth_method);
    if(auth_id != NULL) s->auth_id = strdup(auth_id);

    _sx_state(s, state_OPEN);
    _sx_event(s, event_OPEN, NULL);
}

/** utility; reset stream state */
void _sx_reset(sx_t s) {
    struct _sx_st temp;
    sx_t new;

    _sx_debug(ZONE, "resetting stream state");

    /* we want to reset the contents of s, but we can't free s because
     * the caller (and others) hold references. so, we make a new sx_t,
     * copy the contents (only pointers), free it (which will free strings
     * and queues), then make another new one, and copy the contents back
     * into s */

    temp.env = s->env;
    temp.tag = s->tag;
    temp.cb = s->cb;
    temp.cb_arg = s->cb_arg;

    temp.ip = s->ip;
    temp.port = s->port;
    temp.flags = s->flags;
    temp.reentry = s->reentry;
    temp.ssf = s->ssf;
    temp.compressed = s->compressed;
    temp.wio = s->wio;
    temp.rio = s->rio;
    temp.wnad = s->wnad;
    temp.rnad = s->rnad;
    temp.rbytesmax = s->rbytesmax;
    temp.plugin_data = s->plugin_data;

    s->reentry = 0;

    s->env = NULL;  /* we get rid of this, because we don't want plugin data to be freed */

    new = (sx_t) malloc(sizeof(struct _sx_st));
    memcpy(new, s, sizeof(struct _sx_st));
    sx_free(new);

    new = sx_new(NULL, temp.tag, temp.cb, temp.cb_arg);
    memcpy(s, new, sizeof(struct _sx_st));
    free(new);

    /* massaged expat into shape */
    XML_SetUserData(s->expat, (void *) s);

    s->env = temp.env;
    s->ip = temp.ip;
    s->port = temp.port;
    s->flags = temp.flags;
    s->reentry = temp.reentry;
    s->ssf = temp.ssf;
    s->compressed = temp.compressed;
    s->wio = temp.wio;
    s->rio = temp.rio;
    s->wnad = temp.wnad;
    s->rnad = temp.rnad;
    s->rbytesmax = temp.rbytesmax;
    s->plugin_data = temp.plugin_data;

    s->has_reset = 1;

    _sx_debug(ZONE, "finished resetting stream state");
}

/** utility: make a new buffer
   if len>0 but data is NULL, the buffer will contain that many bytes
   of garbage, to be overwritten by caller. otherwise, data pointed to
   by 'data' will be copied into buf */
sx_buf_t _sx_buffer_new(const char *data, int len, _sx_notify_t notify, void *notify_arg) {
    sx_buf_t buf;

    buf = (sx_buf_t) calloc(1, sizeof(struct _sx_buf_st));

    if (len <= 0) {
        buf->data = buf->heap = NULL;
        buf->len = 0;
    } else {
        buf->data = buf->heap = (char *) malloc(sizeof(char) * len);
        if(data != NULL)
            memcpy(buf->data, data, len);
        else
            memset(buf->data, '$', len);  /* catch uninitialized use */
        buf->len = len;
    }

    buf->notify = notify;
    buf->notify_arg = notify_arg;

    return buf;
}

/** utility: kill a buffer */
void _sx_buffer_free(sx_buf_t buf) {
    if(buf->heap != NULL)
        free(buf->heap);

    free(buf);
}

/** utility: clear out a buffer, but don't deallocate it */
void _sx_buffer_clear(sx_buf_t buf) {
    if(buf->heap != NULL) {
        free(buf->heap);
        buf->heap = NULL;
    }
    buf->data = NULL;
    buf->len = 0;
}

/** utility: ensure a certain amount of allocated space adjacent to buf->data */
void _sx_buffer_alloc_margin(sx_buf_t buf, int before, int after)
{
    char *new_heap;

    assert( before >= 0 );
    assert( after >= 0 );

    /* If there wasn't any data in the buf, we can just allocate space for the margins */
    if (buf->data == NULL || buf->len == 0) {
        if (buf->heap != NULL)
            buf->heap = realloc(buf->heap, before+after);
        else
            buf->heap = malloc(before+after);
        buf->data = buf->heap + before;
        return;
    }

    if (buf->heap != NULL) {
        int old_leader = buf->data - buf->heap;
        /* Hmmm, maybe we can just call realloc() ? */
        if (old_leader >= before && old_leader <= (before * 4)) {
            buf->heap = realloc(buf->heap, before + buf->len + after);
            buf->data = buf->heap + old_leader;
            return;
        }
    }

    /* Most general case --- allocate a new buffer, copy stuff over, free the old one. */
    new_heap = malloc(before + buf->len + after);
    memcpy(new_heap + before, buf->data, buf->len);
    if (buf->heap != NULL)
        free(buf->heap);
    buf->heap = new_heap;
    buf->data = new_heap + before;
}

/** utility: reset a sx_buf_t's contents. If newheap is non-NULL it is assumed to be 'data's malloc block and ownership of the block is taken by the buffer. If newheap is NULL then the data is copied. */
void _sx_buffer_set(sx_buf_t buf, char* newdata, int newlength, char* newheap)
{
    if (newheap == NULL) {
        buf->len = 0;
        _sx_buffer_alloc_margin(buf, 0, newlength);
        if (newlength > 0)
            memcpy(buf->data, newdata, newlength);
        buf->len = newlength;
        return;
    }

    _sx_buffer_clear(buf);
    buf->data = newdata;
    buf->len = newlength;
    buf->heap = newheap;
}

/** debug macro helpers */
void __sx_debug(const char *file, int line, const char *msgfmt, ...) {
    va_list ap;
    char *pos, message[MAX_DEBUG];
    int sz;

    /* insert the header */
    snprintf(message, MAX_DEBUG, "sx (%s:%d) ", file, line);

    /* find the end and attach the rest of the msg */
    for (pos = message; *pos != '\0'; pos++); /*empty statement */
    sz = pos - message;
    va_start(ap, msgfmt);
    vsnprintf(pos, MAX_DEBUG - sz, msgfmt, ap);
    va_end(ap);
    fprintf(stderr,"%s", message);
    fprintf(stderr, "\n");
    fflush(stderr);
}

int __sx_event(const char *file, int line, sx_t s, sx_event_t e, void *data) {
    int ret;

    _sx_debug(file, line, "tag %d event %d data 0x%x", s->tag, e, data);

    s->reentry++;
    ret = (s->cb)(s, e, data, s->cb_arg);
    s->reentry--;

    return ret;
}
