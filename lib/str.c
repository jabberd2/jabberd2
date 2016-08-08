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

#include "str.h"
#include "hex.h"
#include "sha1.h"
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>

#define BLOCKSIZE 128

/**
 * Reallocate the given buffer to make it larger.
 *
 * @param oblocks A pointer to a buffer that will be made larger.
 * @param len     The minimum size in bytes to make the buffer.  The
 *                actual size of the buffer will be rounded up to the
 *                nearest block of BLOCKSIZE bytes.
 *
 * @return The new size of the buffer in bytes.
 */
size_t _buf_realloc(void **oblocks, size_t len)
{
    size_t nlen;

    /* round up to standard block sizes */
    nlen = (((len-1)/BLOCKSIZE)+1)*BLOCKSIZE;

    /* get new or resize previous */
    *oblocks = *oblocks ? realloc(*oblocks, nlen) : malloc(nlen);
    return nlen;
}

char *j_strdup(const char *str)
{
    if (str == NULL)
        return NULL;
    else
        return strdup(str);
}

char *j_strcat(char *dest, const char *txt)
{
    if (!txt) return(dest);

    while (*txt)
        *dest++ = *txt++;
    *dest = '\0';

    return(dest);
}

int j_strcmp(const char *a, const char *b)
{
    if (a == NULL || b == NULL)
        return -1;

    while (*a == *b && *a != '\0' && *b != '\0') { a++; b++; }

    if (*a == *b) return 0;

    return -1;
}

int j_strcasecmp(const char *a, const char *b)
{
    if (a == NULL || b == NULL)
        return -1;
    else
        return strcasecmp(a, b);
}

int j_strncmp(const char *a, const char *b, int i)
{
    if (a == NULL || b == NULL)
        return -1;
    else
        return strncmp(a, b, i);
}

int j_strncasecmp(const char *a, const char *b, int i)
{
    if (a == NULL || b == NULL)
        return -1;
    else
        return strncasecmp(a, b, i);
}

size_t j_strlen(const char *a)
{
    if (a == NULL)
        return 0;
    else
        return strlen(a);
}

int j_atoi(const char *a, int def)
{
    if (a == NULL)
        return def;

    errno = 0;
    long temp = strtol(a, NULL, 10);
    return errno ? def : (int)temp;
}

char *j_attr(const char** atts, const char *attr)
{
    int i = 0;

    while (atts[i] != '\0')
    {
        if (j_strcmp(atts[i],attr) == 0) return (char*)atts[i+1];
        i += 2;
    }

    return NULL;
}

/** like strchr, but only searches n chars */
char *j_strnchr(const char *s, int c, int n) {
    int count;

    for (count = 0; count < n; count++)
        if (s[count] == (char) c)
            return &((char *)s)[count];

    return NULL;
}
