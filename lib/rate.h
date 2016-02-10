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

#ifndef INCL_UTIL_RATE_H
#define INCL_UTIL_RATE_H 1

#include "util.h"

#include <time.h>
#include <stdbool.h>

/*
 * rate limiting
 */

typedef struct rate_st
{
    int             total;      /* if we exceed this many events */
    int             seconds;    /* in this many seconds */
    int             wait;       /* then go bad for this many seconds */

    time_t          time;       /* time we started counting events */
    int             count;      /* event count */

    time_t          bad;        /* time we went bad, or 0 if we're not */
} rate_t;

JABBERD2_API rate_t     *rate_new(int total, int seconds, int wait);
JABBERD2_API void        rate_free(rate_t *rt);
JABBERD2_API void        rate_reset(rate_t *rt);

/**
 * Add a number of events to the counter.  This takes care of moving
 * the sliding window, if we've moved outside the previous window.
 */
JABBERD2_API void        rate_add(rate_t *rt, int count);

/**
 * @return The amount of events we have left before we hit the rate
 *         limit.  This could be number of bytes, or number of
 *         connection attempts, etc.
 */
JABBERD2_API size_t      rate_left(rate_t *rt);

/**
 * @return true if we're under the rate limit and everything is fine or
 *         false if the rate limit has been exceeded and we should throttle
 *         something.
 */
JABBERD2_API bool        rate_check(rate_t *rt);

#endif    /* INCL_UTIL_RATE_H */
