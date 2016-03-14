#ifndef INCL_MAIN_FUNCTIONS_H
#define INCL_MAIN_FUNCTIONS_H 1

/** @file src/functions.h
  * @brief main daemon API
  *
  * Miscleanous functions exported from main daemon runtime.
  */

#include <lib/log.h>
#include <lib/xhash.h>
#include <lib/xconfig.h>

void bus_listen(log_t *log, xht *connections, const char **addresses, unsigned int n_addresses);
void bus_connect(log_t *log, xht *connections, const char **addresses, unsigned int n_addresses);

#endif
