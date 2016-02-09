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

/** @file util/nad.h
  * @brief Not A DOM
  * @author Jeremie Miller
  * @author Robert Norris
  * $Date: 2004/05/05 23:49:38 $
  * $Revision: 1.3 $
  * 
  * NAD is very simplistic, and requires all string handling to use a length.
  * Apps using this must be aware of the structure and access it directly for
  * most information. NADs can only be built by successively using the _append_
  * functions correctly. After built, they can be modified using other
  * functions, or by direct access. To access cdata on an elem or attr, use
  * nad->cdata + nad->xxx[index].ixxx for the start, and .lxxx for len.
  *
  * Namespace support seems to work, but hasn't been thoroughly tested. in
  * particular, editing the NAD after its creation might have quirks. use at
  * your own risk! Note that nad_add_namespace() brings a namespace into scope
  * for the next element added with nad_append_elem(), nad_insert_elem() or
  * nad_wrap_elem() (and by extension, any of its subelements). This is the
  * same way that Expat does things, so nad_add_namespace() can be driven from
  * Expat's StartNamespaceDeclHandler. See nad_parse() for an example of how to
  * use Expat to drive NAD.
  */

#ifndef INCL_UTIL_NAD_H
#define INCL_UTIL_NAD_H 1

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

/* jabberd2 Windows DLL */
#ifndef JABBERD2_API
# ifdef _WIN32
#  ifdef JABBERD2_EXPORTS
#   define JABBERD2_API  __declspec(dllexport)
#  else /* JABBERD2_EXPORTS */
#   define JABBERD2_API  __declspec(dllimport)
#  endif /* JABBERD2_EXPORTS */
# else /* _WIN32 */
#  define JABBERD2_API extern
# endif /* _WIN32 */
#endif /* JABBERD2_API */

struct nad_elem_st {
    int parent;
    int iname, lname;
    int icdata, lcdata; /* cdata within this elem (up to first child) */
    int itail, ltail; /* cdata after this elem */
    int attr;
    int ns;
    int my_ns;
    int depth;
};

struct nad_attr_st {
    int iname, lname;
    int ival, lval;
    int my_ns;
    int next;
};

struct nad_ns_st {
    int iuri, luri;
    int iprefix, lprefix;
    int next;
};

typedef struct nad_st
{
    struct nad_elem_st *elems;
    struct nad_attr_st *attrs;
    struct nad_ns_st *nss;
    char *cdata;
    int *depths; /* for tracking the last elem at a depth */

    /* The size in bytes of the elems, attrs, nss and cdata buffers, respectively. */
    int elen, alen, nlen, clen, dlen;

    /* The number of elements of each type of that data that are actually stored in the elems, attrs, nss and cdata buffers, respectively. */
    int ecur, acur, ncur, ccur;

    int scope; /* currently scoped namespaces, get attached to the next element */
    struct nad_st *next; /* for keeping a list of nads */
} *nad_t;

/** create a new nad */
JABBERD2_API nad_t nad_new(void);

/** copy a nad */
JABBERD2_API nad_t nad_copy(nad_t nad);

/** free that nad */
JABBERD2_API void nad_free(nad_t nad);

/** find the next element with this name/depth */
/** 0 for siblings, 1 for children and so on */
JABBERD2_API int nad_find_elem(nad_t nad, int elem, int ns, const char *name, int depth);

/** find the first matching attribute (and optionally value) */
JABBERD2_API int nad_find_attr(nad_t nad, int elem, int ns, const char *name, const char *val);

/** find the first matching namespace (and optionally prefix) */
JABBERD2_API int nad_find_namespace(nad_t nad, int elem, const char *uri, const char *prefix);

/** find a namespace in scope (and optionally prefix) */
JABBERD2_API int nad_find_scoped_namespace(nad_t nad, const char *uri, const char *prefix);

/** find elem using XPath like query
 *  name -- "name" for the child tag of that name
 *          "name/name" for a sub child (recurses)
 *          "?attrib" to match the first tag with that attrib defined
 *          "?attrib=value" to match the first tag with that attrib and value
 *          or any combination: "name/name/?attrib", etc
 */
JABBERD2_API int nad_find_elem_path(nad_t nad, int elem, int ns, const char *name);

/** reset or store the given attribute */
JABBERD2_API void nad_set_attr(nad_t nad, int elem, int ns, const char *name, const char *val, int vallen);

/** insert and return a new element as a child of this one */
JABBERD2_API int nad_insert_elem(nad_t nad, int elem, int ns, const char *name, const char *cdata);

/** remove an element (and its subelements) */
JABBERD2_API void nad_drop_elem(nad_t nad, int elem);

/** wrap an element with another element */
JABBERD2_API void nad_wrap_elem(nad_t nad, int elem, int ns, const char *name);

/** insert part of a nad into another nad */
JABBERD2_API int nad_insert_nad(nad_t dest, int delem, nad_t src, int selem);

/** append and return a new element */
JABBERD2_API int nad_append_elem(nad_t nad, int ns, const char *name, int depth);

/** append attribs to the last element */
JABBERD2_API int nad_append_attr(nad_t nad, int ns, const char *name, const char *val);

/** append more cdata to the last element */
JABBERD2_API void nad_append_cdata(nad_t nad, const char *cdata, int len, int depth);

/** add a namespace to the next element (ie, called when the namespace comes into scope) */
JABBERD2_API int nad_add_namespace(nad_t nad, const char *uri, const char *prefix);

/** declare a namespace on an already existing element */
JABBERD2_API int nad_append_namespace(nad_t nad, int elem, const char *uri, const char *prefix);

/** create a string representation of the given element (and children), point references to it */
JABBERD2_API void nad_print(nad_t nad, int elem, const char **xml, int *len);

/** serialize and deserialize a nad */
JABBERD2_API void nad_serialize(nad_t nad, char **buf, int *len);
JABBERD2_API nad_t nad_deserialize(const char *buf);

/** create a nad from raw xml */
JABBERD2_API nad_t nad_parse(const char *buf, int len);

/* these are some helpful macros */
#define NAD_ENAME(N,E) (N->cdata + N->elems[E].iname)
#define NAD_ENAME_L(N,E) (N->elems[E].lname)
#define NAD_CDATA(N,E) (N->cdata + N->elems[E].icdata)
#define NAD_CDATA_L(N,E) (N->elems[E].lcdata)
#define NAD_ANAME(N,A) (N->cdata + N->attrs[A].iname)
#define NAD_ANAME_L(N,A) (N->attrs[A].lname)
#define NAD_AVAL(N,A) (N->cdata + N->attrs[A].ival)
#define NAD_AVAL_L(N,A) (N->attrs[A].lval)
#define NAD_NURI(N,NS) (N->cdata + N->nss[NS].iuri)
#define NAD_NURI_L(N,NS) (N->nss[NS].luri)
#define NAD_NPREFIX(N,NS) (N->cdata + N->nss[NS].iprefix)
#define NAD_NPREFIX_L(N,NS) (N->nss[NS].lprefix)

#define NAD_ENS(N,E) (N->elems[E].my_ns)
#define NAD_ANS(N,A) (N->attrs[A].my_ns)

#endif
