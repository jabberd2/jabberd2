/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2002-2003 Jeremie Miller, Thomas Muldowney,
 *                         Ryan Eatmon, Robert Norris
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

/* prototypes for xdata */

#ifndef INCL_XDATA_H
#define INCL_XDATA_H

#include "util.h"

typedef struct _xdata_st        *xdata_t;
typedef struct _xdata_field_st  *xdata_field_t;
typedef struct _xdata_option_st *xdata_option_t;
typedef struct _xdata_item_st   *xdata_item_t;

typedef enum {
    xd_type_NONE,
    xd_type_FORM,
    xd_type_RESULT,
    xd_type_SUBMIT,
    xd_type_CANCEL
} xdata_type_t;

struct _xdata_st {
    pool_t              p;

    xdata_type_t        type;

    char                *title;
    char                *instructions;

    xdata_field_t       fields, flast;
    xdata_field_t       rfields, rflast;    /* reported fields */

    xdata_item_t        items, ilast;
};

typedef enum {
    xd_field_NONE,
    xd_field_BOOLEAN,
    xd_field_FIXED,
    xd_field_HIDDEN,
    xd_field_JID_MULTI,
    xd_field_JID_SINGLE,
    xd_field_LIST_MULTI,
    xd_field_LIST_SINGLE,
    xd_field_TEXT_MULTI,
    xd_field_TEXT_PRIVATE,
    xd_field_TEXT_SINGLE
} xdata_field_type_t;

struct _xdata_field_st {
    pool_t              p;

    xdata_field_type_t  type;

    char                *var;

    char                *label;

    char                *desc;

    int                 required;

    char                **values;
    int                 nvalues;

    xdata_option_t      options, olast;

    xdata_field_t       next;
};

struct _xdata_option_st {
    pool_t              p;

    char                *label;
    char                *value;

    xdata_option_t      next;
};

struct _xdata_item_st {
    pool_t              p;

    xdata_field_t       fields, flast;

    xdata_item_t        next;
};

/** creation */
JABBERD2_API xdata_t xdata_new(xdata_type_t type, const char *title, const char *instructions);
JABBERD2_API xdata_t xdata_parse(nad_t nad, int root);

/** new field */
JABBERD2_API xdata_field_t xdata_field_new(xdata_t xd, xdata_field_type_t type, const char *var, const char *label, const char *desc, int required);

/** new item */
JABBERD2_API xdata_item_t xdata_item_new(xdata_t xd);

/** field insertion */
JABBERD2_API void xdata_add_field(xdata_t xd, xdata_field_t xdf);
JABBERD2_API void xdata_add_rfield(xdata_t xd, xdata_field_t xdf);
JABBERD2_API void xdata_add_field_item(xdata_item_t item, xdata_field_t xdf);

/** item insertion */
JABBERD2_API void xdata_add_item(xdata_t xd, xdata_item_t xdi);

/** option insertion */
JABBERD2_API void xdata_add_option(xdata_field_t xdf, const char *value, int lvalue, const char *label, int llabel);

/** value insertion */
JABBERD2_API void xdata_add_value(xdata_field_t xdf, const char *value, int vlen);

#endif
