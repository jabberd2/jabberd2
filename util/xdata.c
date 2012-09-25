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

/* xdata, whee! */

#include "util.h"

/** creation */
xdata_t xdata_new(xdata_type_t type, const char *title, const char *instructions) {
    pool_t p;
    xdata_t xd;

    assert((int) type);

    p = pool_new();

    xd = pmalloco(p, sizeof(struct _xdata_st));

    xd->p = p;

    xd->type = type;

    if(title != NULL) xd->title = pstrdup(xd->p, title);
    if(instructions != NULL) xd->instructions = pstrdup(xd->p, instructions);

    log_debug(ZONE, "created new xd; title=%s, instructions=%s", title, instructions);

    return xd;
}

/** new field */
xdata_field_t xdata_field_new(xdata_t xd, xdata_field_type_t type, const char *var, const char *label, const char *desc, int required) {
    xdata_field_t xdf;

    assert((int) (xd != NULL));
    assert((int) type);
    assert((int) (var != NULL));

    xdf = pmalloco(xd->p, sizeof(struct _xdata_field_st));

    xdf->p = xd->p;

    xdf->type = type;

    xdf->var = pstrdup(xdf->p, var);

    if(label != NULL) xdf->label = pstrdup(xdf->p, label);
    if(desc != NULL) xdf->desc = pstrdup(xdf->p, desc);

    xdf->required = required;

    return xdf;
}

/** new item */
xdata_item_t xdata_item_new(xdata_t xd) {
    xdata_item_t xdi;

    assert((int) (xd != NULL));

    xdi = pmalloco(xd->p, sizeof(struct _xdata_item_st));

    xdi->p = xd->p;

    return xdi;
}

/** field insertion */
void xdata_add_field(xdata_t xd, xdata_field_t xdf) {
    assert((int) (xd != NULL));
    assert((int) (xdf != NULL));

    if(xd->fields == NULL)
        xd->fields = xd->flast = xdf;
    else {
        xd->flast->next = xdf;
        xd->flast = xdf;
    }
}

void xdata_add_rfield(xdata_t xd, xdata_field_t xdf) {
    assert((int) (xd != NULL));
    assert((int) (xdf != NULL));

    if(xd->rfields == NULL)
        xd->rfields = xd->rflast = xdf;
    else {
        xd->rflast->next = xdf;
        xd->rflast = xdf;
    }
}

void xdata_add_field_item(xdata_item_t xdi, xdata_field_t xdf) {
    assert((int) (xdi != NULL));
    assert((int) (xdf != NULL));

    if(xdi->fields == NULL)
        xdi->fields = xdi->flast = xdf;
    else {
        xdi->flast->next = xdf;
        xdi->flast = xdf;
    }
}

/** item insertion */
void xdata_add_item(xdata_t xd, xdata_item_t xdi) {
    assert((int) (xd != NULL));
    assert((int) (xdi != NULL));

    if(xd->items == NULL)
        xd->items = xd->ilast = xdi;
    else {
        xd->ilast->next = xdi;
        xd->ilast = xdi;
    }
}

/** option insertion */
static void xdata_option_new(xdata_field_t xdf, const char *value, int lvalue, const char *label, int llabel) {
    xdata_option_t xdo;

    assert((int) (xdf != NULL));
    assert((int) (value != NULL));

    xdo = pmalloco(xdf->p, sizeof(struct _xdata_option_st));

    xdo->p = xdf->p;

    if(lvalue <= 0) lvalue = strlen(value);
    xdo->value = pstrdupx(xdo->p, value, lvalue);

    if(label != NULL) {
        if(llabel <= 0) llabel = strlen(label);
        xdo->label = pstrdupx(xdo->p, label, llabel);
    }

    xdf->olast->next = xdo;
    xdf->olast = xdo;
    if(xdf->options == NULL) xdf->options = xdo;
}

/** value insertion */
void xdata_add_value(xdata_field_t xdf, const char *value, int vlen) {
    int first = 0;

    assert((int) (xdf != NULL));
    assert((int) (value != NULL));

    if(vlen <= 0) vlen = strlen(value);

    if(xdf->values == NULL)
        first = 1;

    xdf->values = (char **) realloc(xdf->values, sizeof(char *) * (xdf->nvalues + 1));
    xdf->values[xdf->nvalues] = pstrdupx(xdf->p, value, vlen);
    xdf->nvalues++;

    if(first)
        pool_cleanup(xdf->p, free, xdf->values);
}

/** rip out a field */
static xdata_field_t _xdata_field_parse(xdata_t xd, nad_t nad, int root) {
    xdata_field_t xdf;
    int attr, elem, eval;

    xdf = pmalloco(xd->p, sizeof(struct _xdata_field_st));

    xdf->p = xd->p;

    attr = nad_find_attr(nad, root, -1, "var", NULL);
    if(attr >= 0)
        xdf->var = pstrdupx(xdf->p, NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr));

    attr = nad_find_attr(nad, root, -1, "label", NULL);
    if(attr >= 0)
        xdf->label = pstrdupx(xdf->p, NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr));

    attr = nad_find_attr(nad, root, -1, "desc", NULL);
    if(attr >= 0)
        xdf->desc = pstrdupx(xdf->p, NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr));

    if(nad_find_elem(nad, root, NAD_ENS(nad, root), "required", 1) >= 0)
        xdf->required = 1;

    attr = nad_find_attr(nad, root, -1, "type", NULL);
    if(attr >= 0) {
        if(NAD_AVAL_L(nad, attr) == 7 && strncmp("boolean", NAD_AVAL(nad, attr), 7) == 0)
            xdf->type = xd_field_BOOLEAN;
        else if(NAD_AVAL_L(nad, attr) == 5 && strncmp("fixed", NAD_AVAL(nad, attr), 5) == 0)
            xdf->type = xd_field_FIXED;
        else if(NAD_AVAL_L(nad, attr) == 6 && strncmp("hidden", NAD_AVAL(nad, attr), 6) == 0)
            xdf->type = xd_field_HIDDEN;
        else if(NAD_AVAL_L(nad, attr) == 9 && strncmp("jid-multi", NAD_AVAL(nad, attr), 9) == 0)
            xdf->type = xd_field_JID_MULTI;
        else if(NAD_AVAL_L(nad, attr) == 10 && strncmp("jid-single", NAD_AVAL(nad, attr), 10) == 0)
            xdf->type = xd_field_JID_SINGLE;
        else if(NAD_AVAL_L(nad, attr) == 10 && strncmp("list-multi", NAD_AVAL(nad, attr), 10) == 0)
            xdf->type = xd_field_LIST_MULTI;
        else if(NAD_AVAL_L(nad, attr) == 11 && strncmp("list-single", NAD_AVAL(nad, attr), 11) == 0)
            xdf->type = xd_field_LIST_SINGLE;
        else if(NAD_AVAL_L(nad, attr) == 10 && strncmp("text-multi", NAD_AVAL(nad, attr), 10) == 0)
            xdf->type = xd_field_TEXT_MULTI;
        else if(NAD_AVAL_L(nad, attr) == 12 && strncmp("text-private", NAD_AVAL(nad, attr), 12) == 0)
            xdf->type = xd_field_TEXT_PRIVATE;
        else if(NAD_AVAL_L(nad, attr) == 11 && strncmp("text-single", NAD_AVAL(nad, attr), 11) == 0)
            xdf->type = xd_field_TEXT_SINGLE;
        else {
            log_debug(ZONE, "unknown field type '%.*s'", NAD_AVAL_L(nad, attr), NAD_AVAL(nad, attr));
            return NULL;
        }
    }

    elem = nad_find_elem(nad, root, NAD_ENS(nad, root), "value", 1);
    while(elem >= 0) {
        if(NAD_CDATA_L(nad, elem) <= 0) {
            log_debug(ZONE, "value element requires cdata");
            return NULL;
        }

        xdata_add_value(xdf, NAD_CDATA(nad, elem), NAD_CDATA_L(nad, elem));

        elem = nad_find_elem(nad, elem, NAD_ENS(nad, elem), "value", 0);
    }

    elem = nad_find_elem(nad, root, NAD_ENS(nad, root), "options", 1);
    while(elem >= 0) {
        eval = nad_find_elem(nad, elem, NAD_ENS(nad, elem), "value", 1);
        if(eval < 0) {
            log_debug(ZONE, "option requires value subelement");
            return NULL;
        }

        if(NAD_CDATA_L(nad, eval) <= 0) {
            log_debug(ZONE, "value element requires cdata");
            return NULL;
        }

        attr = nad_find_attr(nad, elem, -1, "label", NULL);
        if(attr < 0)
            xdata_option_new(xdf, NAD_CDATA(nad, eval), NAD_CDATA_L(nad, eval), NAD_AVAL(nad, eval), NAD_AVAL_L(nad, eval));
        else
            xdata_option_new(xdf, NAD_CDATA(nad, eval), NAD_CDATA_L(nad, eval), NULL, 0);

        elem = nad_find_elem(nad, elem, NAD_ENS(nad, elem), "options", 0);
    }

    return xdf;
}

/** parse a nad and build */
xdata_t xdata_parse(nad_t nad, int root) {
    xdata_t xd;
    int atype, elem, field;
    xdata_field_t xdf;

    assert((int) (nad != NULL));
    assert((int) (root >= 0));

    log_debug(ZONE, "building xd from nad");

    if(root >= nad->ecur || NAD_NURI_L(nad, NAD_ENS(nad, root)) != strlen(uri_XDATA) || strncmp(uri_XDATA, NAD_NURI(nad, NAD_ENS(nad, root)), strlen(uri_XDATA) != 0) || NAD_ENAME_L(nad, root) != 1 || (NAD_ENAME(nad, root))[0] != 'x') {
        log_debug(ZONE, "elem %d does not exist, or is not {x:data}x", root);
        return NULL;
    }

    atype = nad_find_attr(nad, root, -1, "type", NULL);
    if(atype < 0) {
        log_debug(ZONE, "no type attribute");
        return NULL;
    }

    if(NAD_AVAL_L(nad, atype) == 4 && strncmp("form", NAD_AVAL(nad, atype), NAD_AVAL_L(nad, atype)) == 0)
        xd = xdata_new(xd_type_FORM, NULL, NULL);
    else if(NAD_AVAL_L(nad, atype) == 6 && strncmp("result", NAD_AVAL(nad, atype), NAD_AVAL_L(nad, atype)) == 0)
        xd = xdata_new(xd_type_RESULT, NULL, NULL);
    else if(NAD_AVAL_L(nad, atype) == 6 && strncmp("submit", NAD_AVAL(nad, atype), NAD_AVAL_L(nad, atype)) == 0)
        xd = xdata_new(xd_type_SUBMIT, NULL, NULL);
    else if(NAD_AVAL_L(nad, atype) == 6 && strncmp("cancel", NAD_AVAL(nad, atype), NAD_AVAL_L(nad, atype)) == 0)
        xd = xdata_new(xd_type_CANCEL, NULL, NULL);
    else {
        log_debug(ZONE, "unknown xd type %.*s", NAD_AVAL_L(nad, atype), NAD_AVAL(nad, atype));
        return NULL;
    }

    elem = nad_find_elem(nad, root, NAD_ENS(nad, root), "title", 1);
    if(elem < 0 || NAD_CDATA_L(nad, elem) <= 0) {
        log_debug(ZONE, "no cdata on x/title element");
        pool_free(xd->p);
        return NULL;
    }

    xd->title = pmalloco(xd->p, sizeof(char) * (NAD_CDATA_L(nad, elem) + 1));
    strncpy(xd->title, NAD_CDATA(nad, elem), NAD_CDATA_L(nad, elem));

    elem = nad_find_elem(nad, root, NAD_ENS(nad, root), "instructions", 1);
    if(elem < 0 || NAD_CDATA_L(nad, elem) <= 0) {
        log_debug(ZONE, "no cdata on x/instructions element");
        pool_free(xd->p);
        return NULL;
    }

    xd->instructions = pstrdupx(xd->p, NAD_CDATA(nad, elem), NAD_CDATA_L(nad, elem));

    switch(xd->type) {
        case xd_type_FORM:
        case xd_type_SUBMIT:
            /* form and submit just have fields, one level */
            field = nad_find_elem(nad, root, NAD_ENS(nad, root), "field", 1);
            while(field >= 0) {
                xdf = _xdata_field_parse(xd, nad, field);
                if(xdf == NULL) {
                    log_debug(ZONE, "field parse failed");
                    pool_free(xd->p);
                    return NULL;
                }

                xdata_add_field(xd, xdf);

                field = nad_find_elem(nad, field, NAD_ENS(nad, root), "field", 0);
            }

            break;

        case xd_type_RESULT:
            /* result has reported and item */
            elem = nad_find_elem(nad, root, NAD_ENS(nad, root), "reported", 1);
            if(elem >= 0) {
                field = nad_find_elem(nad, elem, NAD_ENS(nad, root), "field", 1);
                while(field >= 0) {
                    xdf = _xdata_field_parse(xd, nad, field);
                    if(xdf == NULL) {
                        log_debug(ZONE, "field parse failed");
                        pool_free(xd->p);
                        return NULL;
                    }

                    xdata_add_field(xd, xdf);

                    field = nad_find_elem(nad, field, NAD_ENS(nad, root), "field", 0);
                }
            }

            elem = nad_find_elem(nad, root, NAD_ENS(nad, root), "item", 1);
            if(elem >= 0) {
                field = nad_find_elem(nad, elem, NAD_ENS(nad, root), "field", 1);
                while(field >= 0) {
                    xdf = _xdata_field_parse(xd, nad, field);
                    if(xdf == NULL) {
                        log_debug(ZONE, "field parse failed");
                        pool_free(xd->p);
                        return NULL;
                    }

                    xdata_add_field(xd, xdf);

                    field = nad_find_elem(nad, field, NAD_ENS(nad, root), "field", 0);
                }
            }

            break;

        case xd_type_CANCEL:
            /* nothing to do with cancel, its all based on context */
            break;

        case xd_type_NONE:
            break;
    }

    return xd;
}
