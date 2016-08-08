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

#ifndef INCL_UTIL_STR_H
#define INCL_UTIL_STR_H 1

#include "util.h"
#include <stddef.h>

/* Reallocate the given buffer to make it larger */
size_t _buf_realloc(void **oblocks, size_t len);
/** this is the safety check used to make sure there's always enough mem */
#define BUF_SAFE(blocks, size, len) if ((size) > len) len = _buf_realloc((void**)&(blocks),(size));

/* --------------------------------------------------------- */
/*                                                           */
/* String management routines                                */
/*                                                           */
/** --------------------------------------------------------- */
JABBERD2_API char *j_strdup(const char *str); /* provides NULL safe strdup wrapper */
JABBERD2_API char *j_strcat(char *dest, const char *txt); /* strcpy() clone */
JABBERD2_API int j_strcmp(const char *a, const char *b); /* provides NULL safe strcmp wrapper */
JABBERD2_API int j_strcasecmp(const char *a, const char *b); /* provides NULL safe strcasecmp wrapper */
JABBERD2_API int j_strncmp(const char *a, const char *b, int i); /* provides NULL safe strncmp wrapper */
JABBERD2_API int j_strncasecmp(const char *a, const char *b, int i); /* provides NULL safe strncasecmp wrapper */
JABBERD2_API size_t j_strlen(const char *a); /* provides NULL safe strlen wrapper */
JABBERD2_API int j_atoi(const char *a, int def); /* checks for NULL and uses default instead, convienence */
JABBERD2_API char *j_attr(const char** atts, const char *attr); /* decode attr's (from expat) */
JABBERD2_API char *j_strnchr(const char *s, int c, int n); /* like strchr, but only searches n chars */

#endif
