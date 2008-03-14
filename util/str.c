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

#include "pool.h"
#include "util.h"

char *j_strdup(const char *str)
{
    if(str == NULL)
        return NULL;
    else
        return strdup(str);
}

char *j_strcat(char *dest, char *txt)
{
    if(!txt) return(dest);

    while(*txt)
        *dest++ = *txt++;
    *dest = '\0';

    return(dest);
}

int j_strcmp(const char *a, const char *b)
{
    if(a == NULL || b == NULL)
        return -1;

    while(*a == *b && *a != '\0' && *b != '\0'){ a++; b++; }

    if(*a == *b) return 0;

    return -1;
}

int j_strcasecmp(const char *a, const char *b)
{
    if(a == NULL || b == NULL)
        return -1;
    else
        return strcasecmp(a, b);
}

int j_strncmp(const char *a, const char *b, int i)
{
    if(a == NULL || b == NULL)
        return -1;
    else
        return strncmp(a, b, i);
}

int j_strncasecmp(const char *a, const char *b, int i)
{
    if(a == NULL || b == NULL)
        return -1;
    else
        return strncasecmp(a, b, i);
}

int j_strlen(const char *a)
{
    if(a == NULL)
        return 0;
    else
        return strlen(a);
}

int j_atoi(const char *a, int def)
{
    if(a == NULL)
        return def;
    else
        return atoi(a);
}

char *j_attr(const char** atts, const char *attr)
{
    int i = 0;

    while(atts[i] != '\0')
    {
        if(j_strcmp(atts[i],attr) == 0) return (char*)atts[i+1];
        i += 2;
    }

    return NULL;
}

/** like strchr, but only searches n chars */
char *j_strnchr(const char *s, int c, int n) {
	int count;

	for(count = 0; count < n; count++)
		if(s[count] == (char) c)
			return &((char *)s)[count];
	
	return NULL;
}

spool spool_new(pool_t p)
{
    spool s;

    s = pmalloc(p, sizeof(struct spool_struct));
    s->p = p;
    s->len = 0;
    s->last = NULL;
    s->first = NULL;
    return s;
}

static void _spool_add(spool s, char *goodstr)
{
    struct spool_node *sn;

    sn = pmalloc(s->p, sizeof(struct spool_node));
    sn->c = goodstr;
    sn->next = NULL;

    s->len += strlen(goodstr);
    if(s->last != NULL)
        s->last->next = sn;
    s->last = sn;
    if(s->first == NULL)
        s->first = sn;
}

void spool_add(spool s, char *str)
{
    if(str == NULL || strlen(str) == 0)
        return;

    _spool_add(s, pstrdup(s->p, str));
}

void spool_escape(spool s, char *raw, int len)
{
    if(raw == NULL || len <= 0)
        return;

    _spool_add(s, strescape(s->p, raw, len));
}

void spooler(spool s, ...)
{
    va_list ap;
    char *arg = NULL;

    if(s == NULL)
        return;

    va_start(ap, s);

    /* loop till we hit our end flag, the first arg */
    while(1)
    {
        arg = va_arg(ap,char *);
        if((spool)arg == s)
            break;
        else
            spool_add(s, arg);
    }

    va_end(ap);
}

char *spool_print(spool s)
{
    char *ret,*tmp;
    struct spool_node *next;

    if(s == NULL || s->len == 0 || s->first == NULL)
        return NULL;

    ret = pmalloc(s->p, s->len + 1);
    *ret = '\0';

    next = s->first;
    tmp = ret;
    while(next != NULL)
    {
        tmp = j_strcat(tmp,next->c);
        next = next->next;
    }

    return ret;
}

/** convenience :) */
char *spools(pool_t p, ...)
{
    va_list ap;
    spool s;
    char *arg = NULL;

    if(p == NULL)
        return NULL;

    s = spool_new(p);

    va_start(ap, p);

    /* loop till we hit our end flag, the first arg */
    while(1)
    {
        arg = va_arg(ap,char *);
        if((pool_t)arg == p)
            break;
        else
            spool_add(s, arg);
    }

    va_end(ap);

    return spool_print(s);
}


char *strunescape(pool_t p, char *buf)
{
    int i,j=0;
    char *temp;

    if (buf == NULL) return(NULL);

    if (strchr(buf,'&') == NULL) return(buf);

    if(p != NULL)
        temp = pmalloc(p,strlen(buf)+1);
    else
        temp = malloc(strlen(buf)+1);

    if (temp == NULL) return(NULL);

    for(i=0;i<strlen(buf);i++)
    {
        if (buf[i]=='&')
        {
            if (strncmp(&buf[i],"&amp;",5)==0)
            {
                temp[j] = '&';
                i += 4;
            } else if (strncmp(&buf[i],"&quot;",6)==0) {
                temp[j] = '\"';
                i += 5;
            } else if (strncmp(&buf[i],"&apos;",6)==0) {
                temp[j] = '\'';
                i += 5;
            } else if (strncmp(&buf[i],"&lt;",4)==0) {
                temp[j] = '<';
                i += 3;
            } else if (strncmp(&buf[i],"&gt;",4)==0) {
                temp[j] = '>';
                i += 3;
            }
        } else {
            temp[j]=buf[i];
        }
        j++;
    }
    temp[j]='\0';
    return(temp);
}


char *strescape(pool_t p, char *buf, int len)
{
    int i,j,newlen = len;
    char *temp;

    if (buf == NULL || len < 0) return NULL;

    for(i=0;i<len;i++)
    {
        switch(buf[i])
        {
        case '&':
            newlen+=5;
            break;
        case '\'':
            newlen+=6;
            break;
        case '\"':
            newlen+=6;
            break;
        case '<':
            newlen+=4;
            break;
        case '>':
            newlen+=4;
            break;
        }
    }

    if(p != NULL)
        temp = pmalloc(p,newlen+1);
    else
        temp = malloc(newlen+1);
    if(newlen == len)
    {
        memcpy(temp,buf,len);
        temp[len] = '\0';
        return temp;
    }

    for(i=j=0;i<len;i++)
    {
        switch(buf[i])
        {
        case '&':
            memcpy(&temp[j],"&amp;",5);
            j += 5;
            break;
        case '\'':
            memcpy(&temp[j],"&apos;",6);
            j += 6;
            break;
        case '\"':
            memcpy(&temp[j],"&quot;",6);
            j += 6;
            break;
        case '<':
            memcpy(&temp[j],"&lt;",4);
            j += 4;
            break;
        case '>':
            memcpy(&temp[j],"&gt;",4);
            j += 4;
            break;
        default:
            temp[j++] = buf[i];
        }
    }
    temp[j] = '\0';
    return temp;
}

/** convenience (originally by Thomas Muldowney) */
void shahash_r(const char* str, char hashbuf[41]) {
    unsigned char hashval[20];
    
#ifdef HAVE_SSL
    /* use OpenSSL functions when available */
#   include <openssl/sha.h>
    SHA1((unsigned char *)str, strlen(str), hashval);
#else
    sha1_hash((unsigned char *)str, strlen(str), hashval);
#endif

    hex_from_raw(hashval, 20, hashbuf);
}
