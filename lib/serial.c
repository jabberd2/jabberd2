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

/* these are useful utilities for data serialisation */

#include "util.h"

/*
 * ser_string_get() and ser_int_get() retrieve a string (null-terminated) or
 * an int (sizeof(int) chars) from source, and store it in dest. source is a
 * pointer into buf, and will be updated before the call returns.
 * buf is a pointer to the start of the source buffer, and len is the length
 * of the buffer. if retrieving the data would take us pass the end of the
 * array, a non-zero value will be returned. if the call succeeds, 0 is
 * returned.
 */

int ser_string_get(char **dest, int *source, const char *buf, int len)
{
    const char *end, *c;

    /* end of the buffer */
    end = buf + ((sizeof(char) * (len - 1)));

    /* make sure we have a \0 before the end of the buffer */
    c = &(buf[*source]);
    while(c <= end && *c != '\0') c++;
    if(c > end)
        /* we ran past the end, fail */
        return 1;

    /* copy the string */
    *dest = strdup(&(buf[*source]));

    /* and move the pointer */
    *source += strlen(*dest) + 1;

    return 0;
}

int ser_int_get(int *dest, int *source, const char *buf, int len)
{
    union
    {
        char c[sizeof(int)];
        int i;
    } u;
    int i;

    /* we need sizeof(int) bytes */
    if(&(buf[*source]) + sizeof(int) > buf + (sizeof(char) * len))
        return 1;

    /* copy the bytes into the union. we do it this way to avoid alignment problems */
    for(i = 0; i < sizeof(int); i++)
    {
        u.c[i] = buf[*source];
        (*source)++;
    }
    *dest = u.i;

    return 0;
}

/*
 * ser_string_set() and ser_int_set() stores the string or int referenced by
 * source into buf, starting at dest. len holds the current length of the
 * buffer. if storing the data would overrun the end of the buffer, the buffer
 * will be grown to accomodate. buf, dest and len will be updated.
 */

/* shamelessy stolen from nad.c */

#define BLOCKSIZE 1024

/** internal: do and return the math and ensure it gets realloc'd */
static int _ser_realloc(void **oblocks, int len)
{
    void *nblocks;
    int nlen;

    /* round up to standard block sizes */
    nlen = (((len-1)/BLOCKSIZE)+1)*BLOCKSIZE;

    /* keep trying till we get it */
    while((nblocks = realloc(*oblocks, nlen)) == NULL) sleep(1);
    *oblocks = nblocks;
    return nlen;
}

/** this is the safety check used to make sure there's always enough mem */
#define SER_SAFE(blocks, size, len) if((size) > len) len = _ser_realloc((void**)&(blocks),(size));

void ser_string_set(const char *source, int *dest, char **buf, int *len)
{
    int need = sizeof(char) * (strlen(source) + 1);

    /* make more space if necessary */
    SER_SAFE(*buf, *dest + need, *len);

    /* copy it in */
    strcpy(*buf + *dest, source);

    /* and shift the pointer */
    *dest += need;
}

void ser_int_set(int source, int *dest, char **buf, int *len)
{
    union
    {
        char c[sizeof(int)];
        int i;
    } u;
    int i;

    /* make more space if necessary */
    SER_SAFE(*buf, *dest + sizeof(int), *len)

    /* copy it in */
    u.i = source;
    for(i = 0; i < sizeof(int); i++)
        (*buf)[*dest + i] = u.c[i];

    /* and shift the pointer */
    *dest += sizeof(int);
}
