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

#include "util.h"
#include "pool.h"

#ifdef POOL_DEBUG
int pool__total = 0;
int pool__ltotal = 0;
xht pool__disturbed = NULL;
void *_pool__malloc(size_t size)
{
    pool__total++;
    return malloc(size);
}
void _pool__free(void *block)
{
    pool__total--;
    free(block);
}
#else
#define _pool__malloc malloc
#define _pool__free free
#endif


/** make an empty pool */
pool_t _pool_new(char *zone, int line)
{
    pool_t p;
    while((p = _pool__malloc(sizeof(_pool))) == NULL) sleep(1);
    p->cleanup = NULL;
    p->heap = NULL;
    p->size = 0;

#ifdef POOL_DEBUG
    p->lsize = -1;
    p->zone[0] = '\0';
    snprintf(p->zone, sizeof(p->zone), "%s:%i", zone, line);
    sprintf(p->name,"%X",(int)p);

    if(pool__disturbed == NULL)
    {
        pool__disturbed = (xht)1; /* reentrancy flag! */
	pool__disturbed = xhash_new(POOL_NUM);
    }
    if(pool__disturbed != (xht)1)
        xhash_put(pool__disturbed,p->name,p);
#endif

    return p;
}

/** free a heap */
static void _pool_heap_free(void *arg)
{
    struct pheap *h = (struct pheap *)arg;

    _pool__free(h->block);
    _pool__free(h);
}

/** mem should always be freed last */
static void _pool_cleanup_append(pool_t p, struct pfree *pf)
{
    struct pfree *cur;

    if(p->cleanup == NULL)
    {
        p->cleanup = pf;
        p->cleanup_tail = pf;
        return;
    }

    /* append at end of list */
    cur = p->cleanup_tail; 
    cur->next = pf;
    p->cleanup_tail = pf;
}

/** create a cleanup tracker */
static struct pfree *_pool_free(pool_t p, pool_cleanup_t f, void *arg)
{
    struct pfree *ret;

    /* make the storage for the tracker */
    while((ret = _pool__malloc(sizeof(struct pfree))) == NULL) sleep(1);
    ret->f = f;
    ret->arg = arg;
    ret->next = NULL;

    return ret;
}

/** create a heap and make sure it get's cleaned up */
static struct pheap *_pool_heap(pool_t p, int size)
{
    struct pheap *ret;
    struct pfree *clean;

    /* make the return heap */
    while((ret = _pool__malloc(sizeof(struct pheap))) == NULL) sleep(1);
    while((ret->block = _pool__malloc(size)) == NULL) sleep(1);
    ret->size = size;
    p->size += size;
    ret->used = 0;

    /* append to the cleanup list */
    clean = _pool_free(p, _pool_heap_free, (void *)ret);
    clean->heap = ret; /* for future use in finding used mem for pstrdup */
    _pool_cleanup_append(p, clean);

    return ret;
}

pool_t _pool_new_heap(int size, char *zone, int line)
{
    pool_t p;
    p = _pool_new(zone, line);
    p->heap = _pool_heap(p,size);
    return p;
}

void *pmalloc(pool_t p, int size)
{
    void *block;

    if(p == NULL)
    {
        fprintf(stderr,"Memory Leak! [pmalloc received NULL pool, unable to track allocation, exiting]\n");
        abort();
    }

    /* if there is no heap for this pool or it's a big request, just raw, I like how we clean this :) */
    if(p->heap == NULL || size > (p->heap->size / 2))
    {
        while((block = _pool__malloc(size)) == NULL) sleep(1);
        p->size += size;
        _pool_cleanup_append(p, _pool_free(p, _pool__free, block));
        return block;
    }

    /* we have to preserve boundaries, long story :) */
    if(size >= 4)
        while(p->heap->used&7) p->heap->used++;

    /* if we don't fit in the old heap, replace it */
    if(size > (p->heap->size - p->heap->used))
        p->heap = _pool_heap(p, p->heap->size);

    /* the current heap has room */
    block = (char *)p->heap->block + p->heap->used;
    p->heap->used += size;
    return block;
}

void *pmalloc_x(pool_t p, int size, char c)
{
   void* result = pmalloc(p, size);
   if (result != NULL)
           memset(result, c, size);
   return result;
}  

/** easy safety utility (for creating blank mem for structs, etc) */
void *pmalloco(pool_t p, int size)
{
    void *block = pmalloc(p, size);
    memset(block, 0, size);
    return block;
}  

/** XXX efficient: move this to const char * and then loop throug the existing heaps to see if src is within a block in this pool */
char *pstrdup(pool_t p, const char *src)
{
    char *ret;

    if(src == NULL)
        return NULL;

    ret = pmalloc(p,strlen(src) + 1);
    strcpy(ret,src);

    return ret;
}

/** use given size */
char *pstrdupx(pool_t p, const char *src, int len)
{
    char *ret;

    if(src == NULL || len <= 0)
        return NULL;

    ret = pmalloc(p,len + 1);
    memcpy(ret,src,len);
    ret[len] = '\0';

    return ret;
}

int pool_size(pool_t p)
{
    if(p == NULL) return 0;

    return p->size;
}

void pool_free(pool_t p)
{
    struct pfree *cur, *stub;

    if(p == NULL) return;

    cur = p->cleanup;
    while(cur != NULL)
    {
        (*cur->f)(cur->arg);
        stub = cur->next;
        _pool__free(cur);
        cur = stub;
    }

#ifdef POOL_DEBUG
    if (pool__disturbed != NULL && pool__disturbed != (xht)1)
	xhash_zap(pool__disturbed,p->name);
#endif

    _pool__free(p);

}

/** public cleanup utils, insert in a way that they are run FIFO, before mem frees */
void pool_cleanup(pool_t p, pool_cleanup_t f, void *arg)
{
    struct pfree *clean;

    clean = _pool_free(p, f, arg);
    clean->next = p->cleanup;
    p->cleanup = clean;
}

#ifdef POOL_DEBUG
void _pool_stat(xht h, const char *key, void *val, void *arg)
{
    pool_t p = (pool)val;

    if(p->lsize == -1)
        fprintf(stderr, "POOL: %s: %s is a new pool\n",p->zone,p->name);
    else if(p->size > p->lsize)
        fprintf(stderr, "POOL: %s: %s grew %d\n",p->zone,p->name, p->size - p->lsize);
    else if((int)arg)
        fprintf(stderr, "POOL: %s: %s exists %d\n",p->zone,p->name, p->size);
    p->lsize = p->size;
}

void pool_stat(int full)
{
    if (pool__disturbed == NULL || pool__disturbed == (xht)1)
	return;
    xhash_walk(pool__disturbed,_pool_stat,(void *)full);
    if(pool__total != pool__ltotal)
        fprintf(stderr, "POOL: %d total missed mallocs\n",pool__total);
    pool__ltotal = pool__total;
    return;
}
#else
void pool_stat(int full)
{
    return;
}
#endif
