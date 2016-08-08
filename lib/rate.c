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

#include "rate.h"
#include <malloc.h>

rate_t *rate_new(int total, int seconds, int wait)
{
    rate_t *rt = new(struct rate_st);

    rt->total = total;
    rt->seconds = seconds;
    rt->wait = wait;

    return rt;
}

void rate_free(rate_t *rt)
{
    free(rt);
}

void rate_reset(rate_t *rt)
{
    rt->time = 0;
    rt->count = 0;
    rt->bad = 0;
}

void rate_add(rate_t *rt, int count)
{
    time_t now = time(NULL);

    /* rate expired */
    if (now - rt->time >= rt->seconds)
        rate_reset(rt);

    rt->count += count;

    /* first event, so set the time */
    if (rt->time == 0)
        rt->time = now;

    /* uhoh, they stuffed up */
    if (rt->count >= rt->total)
        rt->bad = now;
}

size_t rate_left(rate_t *rt)
{
    /* if we're bad, then there's none left */
    if (rt->bad != 0)
        return 0;

    return rt->total - rt->count;
}

bool rate_check(rate_t *rt)
{
    /* not tracking */
    if (rt->time == 0)
        return true;

    /* under the limit */
    if (rt->count < rt->total)
        return true;

    /* currently bad */
    if (rt->bad != 0)
    {
        /* wait over, they're good again */
        if (time(NULL) - rt->bad >= rt->wait)
        {
            rate_reset(rt);
            return true;
        }

        /* keep them waiting */
        return false;
    }

    /* they're inside the time, and not bad yet */
    return true;
}
