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

/** @file sm/storage_fs.c
  * @brief filesystem storage module
  * @author Robert Norris
  * $Date: 2005/06/02 04:48:25 $
  * $Revision: 1.15 $
  */

/*
 * WARNING: this uses lots of static buffers, and doesn't do all the bounds
 * checking that it should. it should not be used for anything other than
 * testing
 *
 * !!! fix everything that makes this a problem
 */

#include "storage.h"
#include <ctype.h>

#ifdef HAVE_DIRENT_H
# include <dirent.h>
# define NAMELEN(dirent) strlen((dirent)->d_name)
#else
# define dirent direct
# define NAMELEN(dirent) (dirent)->d_namelen
# ifdef HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# ifdef HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# ifdef HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif
#ifdef HAVE_SYS_STAT_H
#  include <sys/stat.h>
#endif

#define STORAGE_FS_READ_BLOCKSIZE 8192

/** internal structure, holds our data */
typedef struct drvdata_st {
    const char *path;
} *drvdata_t;

static st_ret_t _st_fs_add_type(st_driver_t drv, const char *type) {
    drvdata_t data = (drvdata_t) drv->private;
    char path[1024];
    struct stat sbuf;
    int ret;

    snprintf(path, 1024, "%s/%s", data->path, type);
    ret = stat(path, &sbuf);
    if(ret < 0) {
        if(errno != ENOENT) {
            log_write(drv->st->log, LOG_ERR, "fs: couldn't stat '%s': %s", path, strerror(errno));
            return st_FAILED;
        }

        log_debug(ZONE, "creating new type dir '%s'", path);

        ret = mkdir(path, 0755);
        if(ret < 0) {
            log_write(drv->st->log, LOG_ERR, "fs: couldn't create directory '%s': %s", path, strerror(errno));
            return st_FAILED;
        }
    }

    return st_SUCCESS;
}

static st_ret_t _st_fs_put(st_driver_t drv, const char *type, const char *owner, os_t os) {
    drvdata_t data = (drvdata_t) drv->private;
    char path[1024];
    struct stat sbuf;
    int ret;
    int file;
    FILE *f;
    os_object_t o;
    char *key;
    void *val;
    os_type_t ot;
    const char *xml;
    int len;

    if(os_count(os) == 0)
        return st_SUCCESS;

    snprintf(path, 1024, "%s/%s", data->path, type);
    ret = stat(path, &sbuf);
    if(ret < 0) {
        log_write(drv->st->log, LOG_ERR, "fs: couldn't stat '%s': %s", path, strerror(errno));
        return st_FAILED;
    }

    snprintf(path, 1024, "%s/%s/%s", data->path, type, owner);
    ret = stat(path, &sbuf);
    if(ret < 0) {
        if(errno != ENOENT) {
            log_write(drv->st->log, LOG_ERR, "fs: couldn't stat '%s': %s", path, strerror(errno));
            return st_FAILED;
        }

        log_debug(ZONE, "creating new collection dir '%s'", path);

        ret = mkdir(path, 0755);
        if(ret < 0) {
            log_write(drv->st->log, LOG_ERR, "fs: couldn't create directory '%s': %s", path, strerror(errno));
            return st_FAILED;
        }
    }

    file = -1;

    if(os_iter_first(os))
        do {
            for(file++; file < 999999; file++) {
                snprintf(path, 1024, "%s/%s/%s/%d", data->path, type, owner, file);

                ret = stat(path, &sbuf);
                if(ret < 0 && errno == ENOENT)
                    break;

                if(ret < 0) {
                    log_write(drv->st->log, LOG_ERR, "fs: couldn't stat '%s': %s", path, strerror(errno));
                    return st_FAILED;
                }
            }
                
            log_debug(ZONE, "will store object to %s", path);

            f = fopen(path, "w");
            if(f == NULL) {
                log_write(drv->st->log, LOG_ERR, "fs: couldn't open '%s' for writing: %s", path, strerror(errno));
                return st_FAILED;
            }

            o = os_iter_object(os);

            if(os_object_iter_first(o))
                do {
                    os_object_iter_get(o, &key, &val, &ot);

                    log_debug(ZONE, "writing field %s type %d", key, ot);

                    switch(ot) {
                        case os_type_BOOLEAN:
                            fprintf(f, "%s %d %d\n", key, ot, val ? 1 : 0);
                            break;
                            
                        case os_type_INTEGER:
                            fprintf(f, "%s %d %ld\n", key, ot, (long) val);
                            break;

                        case os_type_STRING:
                            fprintf(f, "%s %d %s\n", key, ot, (char *) val);
                            break;

                        case os_type_NAD:
                            nad_print((nad_t) val, 0, &xml, &len);
                            fprintf(f, "%s %d %.*s\n", key, ot, len, xml);
                            break;

                        case os_type_UNKNOWN:
                            break;
                    }

                } while(os_object_iter_next(o));

            fclose(f);

        } while(os_iter_next(os));

    return st_SUCCESS;
}

static st_ret_t _st_fs_get(st_driver_t drv, const char *type, const char *owner, const char *filter, os_t *os) {
    drvdata_t data = (drvdata_t) drv->private;
    char path[1024], file[1024];
    struct stat sbuf;
    int ret;
    DIR *dir;
    struct dirent *dirent;
    FILE *f;
    char buf[STORAGE_FS_READ_BLOCKSIZE], *otc, *val, *c;
    os_object_t o;
    os_type_t ot;
    int i, size;
    nad_t nad;
    st_filter_t sf;

    snprintf(path, 1024, "%s/%s/%s", data->path, type, owner);
    ret = stat(path, &sbuf);
    if(ret < 0) {
        if(errno == ENOENT)
            return st_NOTFOUND;
        log_write(drv->st->log, LOG_ERR, "fs: couldn't stat '%s': %s", path, strerror(errno));
        return st_FAILED;
    }

    dir = opendir(path);
    if(dir == NULL) {
        log_write(drv->st->log, LOG_ERR, "fs: couldn't open directory '%s': %s", path, strerror(errno));
        return st_FAILED;
    }

    *os = os_new();

    errno = 0;
    while((dirent = readdir(dir)) != NULL) {
        if(!(isdigit(dirent->d_name[0])))
            continue;

        snprintf(file, 1024, "%s/%s", path, dirent->d_name);
        f = fopen(file, "r");
        if(f == NULL) {
            log_write(drv->st->log, LOG_ERR, "fs: couldn't open '%s' for reading: %s", path, strerror(errno));
            os_free(*os);
            *os = NULL;
            *os = NULL;
            closedir(dir);
            return st_FAILED;
        }

        o = os_object_new(*os);

        while(fgets(buf, STORAGE_FS_READ_BLOCKSIZE, f) != NULL) {
            size = strlen(buf);

            otc = strchr(buf, ' ');
            *otc = '\0'; otc++;

            val = strchr(otc, ' ');
            *val = '\0'; val++;

            ot = (os_type_t) atoi(otc);

            switch(ot) {
                case os_type_BOOLEAN:
                case os_type_INTEGER:
                    i = atoi(val);
                    os_object_put(o, buf, &i, ot);

                    break;

                case os_type_STRING:
                    c = strchr(val, '\n');
                    if(c != NULL) *c = '\0';
                    os_object_put(o, buf, val, ot);

                    break;

                case os_type_NAD:
                    nad = nad_parse(val, 0);
                    if(nad == NULL) {
                        while(fgets(buf + size, STORAGE_FS_READ_BLOCKSIZE - size, f) != NULL
                              && nad == NULL && size < STORAGE_FS_READ_BLOCKSIZE) {
                            size += strlen(buf + size);
                            nad = nad_parse(val, 0);
                        }
                    }
                    if(nad == NULL) {
                        log_write(drv->st->log, LOG_ERR, "fs: unable to parse stored XML; type=%s, owner=%s", type, owner);
                        os_free(*os);
                        *os = NULL;
                        fclose(f);
                        closedir(dir);
                        return st_FAILED;
                    }
                    os_object_put(o, buf, nad, ot);
                    nad_free(nad);

                    break;

                case os_type_UNKNOWN:
                    break;
            }
        }

        if(!feof(f)) {
            log_write(drv->st->log, LOG_ERR, "fs: couldn't read from '%s': %s", path, strerror(errno));
            os_free(*os);
            *os = NULL;
            fclose(f);
            closedir(dir);
            return st_FAILED;
        }

        fclose(f);

        errno = 0;
    }

    if(errno != 0) {
        log_write(drv->st->log, LOG_ERR, "fs: couldn't read from directory '%s': %s", path, strerror(errno));
        closedir(dir);
        os_free(*os);
        *os = NULL;
        return st_FAILED;
    }

    closedir(dir);
    
    sf = storage_filter(filter);

    if(os_iter_first(*os))
        do {
            o = os_iter_object(*os);
            if(!storage_match(sf, o, *os))
                os_object_free(o);
        } while(os_iter_next(*os));

    if(sf != NULL) pool_free(sf->p);

    return st_SUCCESS;
}

static st_ret_t _st_fs_delete(st_driver_t drv, const char *type, const char *owner, const char *filter) {
    drvdata_t data = (drvdata_t) drv->private;
    char path[1024], file[1024];
    struct stat sbuf;
    int ret;
    DIR *dir;
    os_t os;
    struct dirent *dirent;
    FILE *f;
    char buf[STORAGE_FS_READ_BLOCKSIZE], *otc, *val, *c;
    os_object_t o;
    os_type_t ot;
    int i, size;
    nad_t nad;
    st_filter_t sf;

    snprintf(path, 1024, "%s/%s/%s", data->path, type, owner);
    ret = stat(path, &sbuf);
    if(ret < 0) {
        if(errno == ENOENT)
            return st_NOTFOUND;
        log_write(drv->st->log, LOG_ERR, "fs: couldn't stat '%s': %s", path, strerror(errno));
        return st_FAILED;
    }

    dir = opendir(path);
    if(dir == NULL) {
        log_write(drv->st->log, LOG_ERR, "fs: couldn't open directory '%s': %s", path, strerror(errno));
        return st_FAILED;
    }

    os = os_new();

    sf = storage_filter(filter);

    errno = 0;
    while((dirent = readdir(dir)) != NULL) {
        if(!(isdigit(dirent->d_name[0])))
            continue;

        snprintf(file, 1024, "%s/%s", path, dirent->d_name);
        f = fopen(file, "r");
        if(f == NULL) {
            log_write(drv->st->log, LOG_ERR, "fs: couldn't open '%s' for reading: %s", path, strerror(errno));
            os_free(os);
            closedir(dir);
            return st_FAILED;
        }

        o = os_object_new(os);

        while(fgets(buf, STORAGE_FS_READ_BLOCKSIZE, f) != NULL) {
            size = strlen(buf);

            otc = strchr(buf, ' ');
            *otc = '\0'; otc++;

            val = strchr(otc, ' ');
            *val = '\0'; val++;

            ot = (os_type_t) atoi(otc);

            switch(ot) {
                case os_type_BOOLEAN:
                case os_type_INTEGER:
                    i = atoi(val);
                    os_object_put(o, buf, &i, ot);

                    break;

                case os_type_STRING:
                    c = strchr(val, '\n');
                    if(c != NULL) *c = '\0';
                    os_object_put(o, buf, val, ot);

                    break;

                case os_type_NAD:
                    nad = nad_parse(val, 0);
                    if(nad == NULL) {
                        while(fgets(buf + size, STORAGE_FS_READ_BLOCKSIZE - size, f) != NULL
                              && nad == NULL && size < STORAGE_FS_READ_BLOCKSIZE) {
                            size += strlen(buf + size);
                            nad = nad_parse(val, 0);
                        }
                    }
                    if(nad == NULL)
                        log_write(drv->st->log, LOG_ERR, "fs: unable to parse stored XML; type=%s, owner=%s", type, owner);
                    else {
                        os_object_put(o, buf, nad, ot);
                        nad_free(nad);
                    }

                    break;
 
                case os_type_UNKNOWN:
                    break;
            }
        }

        if(!feof(f)) {
            log_write(drv->st->log, LOG_ERR, "fs: couldn't read from '%s': %s", path, strerror(errno));
            os_free(os);
            fclose(f);
            closedir(dir);
            return st_FAILED;
        }

        fclose(f);

        if(storage_match(sf, o, os)) {
            ret = unlink(file);
            if(ret < 0) {
                log_write(drv->st->log, LOG_ERR, "fs: couldn't unlink '%s': %s", path, strerror(errno));
                if(sf != NULL) pool_free(sf->p);
                os_free(os);
                closedir(dir);
                return st_FAILED;
            }
        }

        errno = 0;
    }

    if(errno != 0) {
        log_write(drv->st->log, LOG_ERR, "fs: couldn't read from directory '%s': %s", path, strerror(errno));
        closedir(dir);
        os_free(os);
        return st_FAILED;
    }

    if(sf != NULL) pool_free(sf->p);

    os_free(os);

    closedir(dir);

    return st_SUCCESS;
}

static st_ret_t _st_fs_replace(st_driver_t drv, const char *type, const char *owner, const char *filter, os_t os) {
    st_ret_t ret;

    ret = _st_fs_delete(drv, type, owner, filter);
    if(ret == st_SUCCESS || ret == st_NOTFOUND)
        ret = _st_fs_put(drv, type, owner, os);

    return ret;
}

static void _st_fs_free(st_driver_t drv) {
    drvdata_t data = (drvdata_t) drv->private;

    free(data);
}

st_ret_t st_init(st_driver_t drv) {
    const char *path;
    struct stat sbuf;
    int ret;
    drvdata_t data;

    path = config_get_one(drv->st->config, "storage.fs.path", 0);
    if(path == NULL) {
        log_write(drv->st->log, LOG_ERR, "fs: no path specified in config file");
        return st_FAILED;
    }

    ret = stat(path, &sbuf);
    if(ret < 0) {
        log_write(drv->st->log, LOG_ERR, "fs: couldn't stat path '%s': %s", path, strerror(errno));
        return st_FAILED;
    }

    data = (drvdata_t) calloc(1, sizeof(struct drvdata_st));

    data->path = path;

    drv->private = (void *) data;

    drv->add_type = _st_fs_add_type;
    drv->put = _st_fs_put;
    drv->get = _st_fs_get;
    drv->delete = _st_fs_delete;
    drv->replace = _st_fs_replace;
    drv->free = _st_fs_free;

    log_write(drv->st->log, LOG_WARNING, "fs: the filesystem storage driver should only be used for testing!");

    return st_SUCCESS;
}
