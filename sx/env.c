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

#include "sx.h"

sx_env_t sx_env_new(void) {
    sx_env_t env;

    env = (sx_env_t) calloc(1, sizeof(struct _sx_env_st));

    return env;
}

void sx_env_free(sx_env_t env) {
    int i;

    assert((int) (env != NULL));

    /* !!! usage counts */

    for(i = 0; i < env->nplugins; i++) {
        if(env->plugins[i]->unload != NULL)
            (env->plugins[i]->unload)(env->plugins[i]);
        free(env->plugins[i]);
    }

    free(env->plugins);
    free(env);
}

sx_plugin_t sx_env_plugin(sx_env_t env, sx_plugin_init_t init, ...) {
    sx_plugin_t p;
    int ret;
    va_list args;

    assert((int) (env != NULL));
    assert((int) (init != NULL));

    va_start(args, init);

    p = (sx_plugin_t) calloc(1, sizeof(struct _sx_plugin_st));

    p->env = env;
    p->index = env->nplugins;

    ret = (init)(env, p, args);
    va_end(args);

    if(ret != 0) {
        free(p);
        return NULL;
    }

    env->plugins = (sx_plugin_t *) realloc(env->plugins, sizeof(sx_plugin_t) * (env->nplugins + 1));
    env->plugins[env->nplugins] = p;
    env->nplugins++;

    _sx_debug(ZONE, "plugin initialised (index %d)", p->index);

    return p;
}
