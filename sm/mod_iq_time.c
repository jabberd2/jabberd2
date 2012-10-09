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

#include "sm.h"

/** @file sm/mod_iq_time.c
  * @brief entity time
  * @author Robert Norris
  * $Date: 2005/08/17 07:48:28 $
  * $Revision: 1.14 $
  */

#ifdef ENABLE_SUPERSEDED
static int ns_TIME = 0;
#endif
static int ns_URN_TIME = 0;

#ifdef HAVE_TZNAME
extern char *tzname[];
#endif

static mod_ret_t _iq_time_pkt_sm(mod_instance_t mi, pkt_t pkt)
{
    time_t t;
    struct tm *tm;
    char buf[64];
    char *c;

    /* we only want to play with iq:time gets */
#ifdef ENABLE_SUPERSEDED
    if(pkt->type != pkt_IQ || (pkt->ns != ns_TIME && pkt->ns != ns_URN_TIME))
#else
    if(pkt->type != pkt_IQ || pkt->ns != ns_URN_TIME)
#endif
        return mod_PASS;

    t = time(NULL);
    tm = localtime(&t);
#ifdef HAVE_TZSET
    tzset();
#endif

#ifdef ENABLE_SUPERSEDED
    if(pkt->ns == ns_TIME) {
        datetime_out(t, dt_LEGACY, buf, 64);
        nad_insert_elem(pkt->nad, 2, NAD_ENS(pkt->nad, 1), "utc", buf);

        strcpy(buf, asctime(tm));
        c = strchr(buf, '\n');
        if(c != NULL)
            *c = '\0';
        nad_insert_elem(pkt->nad, 2, NAD_ENS(pkt->nad, 1), "display", buf);
#if defined(HAVE_STRUCT_TM_TM_ZONE)
        nad_insert_elem(pkt->nad, 2, NAD_ENS(pkt->nad, 1), "tz", (char *) tm->tm_zone);
#elif defined(HAVE_TZNAME)
        nad_insert_elem(pkt->nad, 2, NAD_ENS(pkt->nad, 1), "tz", tzname[0]);
#endif
    } else {
#endif /* ENABLE_SUPERSEDED */

    datetime_out(t, dt_DATETIME, buf, 64);
    nad_insert_elem(pkt->nad, 2, NAD_ENS(pkt->nad, 1), "utc", buf);
#ifdef HAVE_TZSET
    snprintf(buf, 64, "%+03d:%02d", -((int)timezone)/(60*60), -((int)timezone)%(60*60));
#else
    snprintf(buf, 64, "%+03d:%02d", (int) tm->tm_gmtoff/(60*60), (int) tm->tm_gmtoff%(60*60));
#endif
    nad_insert_elem(pkt->nad, 2, NAD_ENS(pkt->nad, 1), "tzo", buf);

#ifdef ENABLE_SUPERSEDED
    }
#endif
    /* tell them */
    nad_set_attr(pkt->nad, 1, -1, "type", "result", 6);
    pkt_router(pkt_tofrom(pkt));

    return mod_HANDLED;
}

static void _iq_time_free(module_t mod) {
     sm_unregister_ns(mod->mm->sm, uri_TIME);
     feature_unregister(mod->mm->sm, uri_TIME);
}

DLLEXPORT int module_init(mod_instance_t mi, const char *arg) {
    module_t mod = mi->mod;

    if(mod->init) return 0;

    mod->pkt_sm = _iq_time_pkt_sm;
    mod->free = _iq_time_free;

#ifdef ENABLE_SUPERSEDED
    ns_TIME = sm_register_ns(mod->mm->sm, uri_TIME);
    feature_register(mod->mm->sm, uri_TIME);
#endif
    ns_URN_TIME = sm_register_ns(mod->mm->sm, urn_TIME);
    feature_register(mod->mm->sm, urn_TIME);

    return 0;
}
