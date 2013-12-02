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

#include "storage.h"

/** @file storage/object.c
  * @brief object sets
  * @author Robert Norris
  * $Date: 2005/06/02 04:48:24 $
  * $Revision: 1.10 $
  */

/* union for xhash_iter_get to comply with strict-alias rules for gcc3 */
union xhashv
{
  void **val;
  os_field_t *osf_val;
};

os_t os_new(void) {
    pool_t p;
    os_t os;

    p = pool_new();
    os = (os_t) pmalloco(p, sizeof(struct os_st));

    os->p = p;

    return os;
}

void os_free(os_t os) {
    pool_free(os->p);
}

int os_count(os_t os) {
    return os->count;
}

int os_iter_first(os_t os) {
    os->iter = os->head;

    if(os->iter == NULL)
        return 0;

    return 1;
}

int os_iter_next(os_t os) {
    if(os->iter == NULL)
        return 0;

    os->iter = os->iter->next;

    if(os->iter == NULL)
        return 0;

    return 1;
}

os_object_t os_iter_object(os_t os) {
    return os->iter;
}

os_object_t os_object_new(os_t os) {
    os_object_t o;

    log_debug(ZONE, "creating new object");

    o = (os_object_t) pmalloco(os->p, sizeof(struct os_object_st));
    o->os = os;

    o->hash = xhash_new(51);

    /* make sure that the hash gets freed when the os pool gets freed */
    pool_cleanup(os->p, (pool_cleanup_t) xhash_free, (void *)(o->hash) );

    /* insert at the end, we have to preserve order */
    o->prev = os->tail;
    if(os->tail != NULL) os->tail->next = o;
    os->tail = o;
    if(os->head == NULL) os->head = o;
    
    os->count++;

    return o;
}

void os_object_free(os_object_t o) {
    log_debug(ZONE, "dropping object");

    if(o->prev != NULL)
        o->prev->next = o->next;
    if(o->next != NULL)
        o->next->prev = o->prev;

    if(o->os->head == o)
        o->os->head = o->next;
    if(o->os->tail == o)
        o->os->tail = o->prev;

    if(o->os->iter == o)
        o->os->iter = o->next;

    o->os->count--;
}

/* wrappers for os_object_put to avoid breaking strict-aliasing rules in gcc3 */

void os_object_put_time(os_object_t o, const char *key, const time_t *val) {
    void *ptr = (void *) val;
    os_object_put(o, key, ptr, os_type_INTEGER);
}

void os_object_put(os_object_t o, const char *key, const void *val, os_type_t type) {
    os_field_t osf;
    nad_t nad;

    log_debug(ZONE, "adding field %s (val %x type %d) to object", key, val, type);

    osf = pmalloco(o->os->p, sizeof(struct os_field_st));
    osf->key = pstrdup(o->os->p, key);

    switch(type) {
        case os_type_BOOLEAN:
        case os_type_INTEGER:
            osf->val = (void *) (intptr_t) (* (int *) val);
            break;

        case os_type_STRING:
            osf->val = (void *) pstrdup(o->os->p, (char *) val);
            break;

        case os_type_NAD:
            nad = nad_copy((nad_t) val);

            /* make sure that the nad gets freed when the os pool gets freed */
            pool_cleanup(o->os->p, (pool_cleanup_t) nad_free, (void *) nad);

            osf->val = (void *) nad;
            break;

        case os_type_UNKNOWN:
            break;
    }

    osf->type = type;

    xhash_put(o->hash, osf->key, (void *) osf);
}

/* wrappers for os_object_get to avoid breaking strict-aliasing rules in gcc3 */
int os_object_get_nad(os_t os, os_object_t o, const char *key, nad_t *val) {
    void *ptr = (void *) val;
    int ret;

    ret = os_object_get(os, o, key, &ptr, os_type_NAD, NULL);
    *val = (nad_t) ptr;

    return ret;
}

int os_object_get_str(os_t os, os_object_t o, const char *key, char **val) {
    void *ptr = (void *) val;
    int ret;

    ret = os_object_get(os, o, key, &ptr, os_type_STRING, NULL);
    *val = (char *) ptr;

    return ret;
}

int os_object_get_int(os_t os, os_object_t o, const char *key, int *val) {
    void *ptr = (void *) val;
    int ret;

    ret = os_object_get(os, o, key, &ptr, os_type_INTEGER, NULL);
    *val = (int) (long) ptr;

    return ret;
}

int os_object_get_bool(os_t os, os_object_t o, const char *key, int *val) {
    void *ptr = (void *) val;
    int ret;

    ret = os_object_get(os, o, key, &ptr, os_type_INTEGER, NULL);
    *val = (int) (long) ptr;

    return ret;
}

int os_object_get_time(os_t os, os_object_t o, const char *key, time_t *val) {
    void *ptr = (void *) val;
    int ret;

    ret = os_object_get(os, o, key, &ptr, os_type_INTEGER, NULL);
    *val = (time_t) ptr;

    return ret;
}

int os_object_get(os_t os, os_object_t o, const char *key, void **val, os_type_t type, os_type_t *ot) {
    os_field_t osf;
    nad_t nad;

   /* Type complexity is to deal with string/NADs. If an object contains xml, it will only be 
      parsed and returned as a NAD if type == os_type_NAD, otherwise if type == os_type_UNKNOWN
      it will be returned as string, unless it's already been converted to a NAD */

    osf = (os_field_t) xhash_get(o->hash, key);
    if(osf == NULL) {
        *val = NULL;
        return 0;
    }

    if (ot != NULL)
      *ot = osf->type; 

    if (type == os_type_UNKNOWN)
      type = osf->type;

    if (type == os_type_UNKNOWN)
      type = osf->type; 

    switch(type) {
        case os_type_BOOLEAN:
        case os_type_INTEGER:
            * (int *) val = (int) (intptr_t) osf->val;
            break;

        case os_type_STRING:
            *val = osf->val;
            break;

        case os_type_NAD:
            /* check to see whether it's already a NAD */
            if (osf->type == os_type_NAD) {
                   *val = osf->val;  
            } else {
                   /* parse the string into a NAD */
                   nad = nad_parse(((char *) osf->val) + 3, strlen(osf->val) - 3); 
                   if(nad == NULL) {
                            /* unparseable NAD */
                            log_debug(ZONE, "cell returned from storage for key %s has unparseable XML content (%lu bytes)", key, strlen(osf->val)-3);
                            *val = NULL;
                            return 0;
                   } 

                   /* replace the string with a NAD */
                   osf->val = (void *) nad;

                   pool_cleanup(os->p, (pool_cleanup_t) nad_free, (void *) nad);

                   *val = osf->val;
                   osf->type = os_type_NAD;

            }
            break;

        default:
            *val = NULL;
    }

    log_debug(ZONE, "got field %s (val %x type %d) to object", key, *val, type);

    return 1;
}

int os_object_iter_first(os_object_t o) {
    return xhash_iter_first(o->hash);
}

int os_object_iter_next(os_object_t o) {
    return xhash_iter_next(o->hash);
}

void os_object_iter_get(os_object_t o, char **key, void **val, os_type_t *type) {
    os_field_t osf;
    union xhashv xhv;

    int keylen;
    xhv.osf_val = &osf;
    xhash_iter_get(o->hash, (const char **) key, &keylen, xhv.val);

    if(*key == NULL) {
        *val = NULL;
        return;
    }

    *type = osf->type;

    switch(osf->type) {
        case os_type_BOOLEAN:
        case os_type_INTEGER:
            * (int *) val = (int) (intptr_t) osf->val;
            break;

        case os_type_STRING:
        case os_type_NAD:
            *val = osf->val;
            break;

        default:
            *val = NULL;
    }
    
    log_debug(ZONE, "got iter field %s (val %x type %d) to object", *key, *val, *type);
}
