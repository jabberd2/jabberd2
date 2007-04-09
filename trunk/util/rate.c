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

/* rate controls (for implementing connect-limiting or karma) */

#include "util.h"

rate_t rate_new(int total, int seconds, int wait)
{
    rate_t rt = (rate_t) malloc(sizeof(struct rate_st));
    memset(rt, 0, sizeof(struct rate_st));

    rt->total = total;
    rt->seconds = seconds;
    rt->wait = wait;

    return rt;
}

void rate_free(rate_t rt)
{
    free(rt);
}

void rate_reset(rate_t rt)
{
    rt->time = 0;
    rt->count = 0;
    rt->bad = 0;
}

void rate_add(rate_t rt, int count)
{
    rt->count += count;

    /* first event, so set the time */
    if(rt->time == 0)
        rt->time = time(NULL);

    /* uhoh, they stuffed up */
    if(rt->count >= rt->total)
        rt->bad = time(NULL);
}

int rate_left(rate_t rt)
{
    /* if we're bad, then there's none left */
    if(rt->bad != 0)
        return 0;

    return rt->total - rt->count;
}

int rate_check(rate_t rt)
{
    time_t now;

    /* not tracking */
    if(rt->time == 0)
        return 1;

    /* under the limit */
    if(rt->count < rt->total)
        return 1;

    now = time(NULL);

    /* currently bad */
    if(rt->bad != 0)
    {
        /* wait over, they're good again */
        if(now - rt->bad >= rt->wait)
        {
            rate_reset(rt);
            return 1;
        }

        /* keep them waiting */
        return 0;
    }

    /* rate expired */
    if(time(NULL) - rt->time >= rt->seconds)
    {
        rate_reset(rt);
        return 1;
    }

    /* they're inside the time, and not bad yet */
    return 1;
}
