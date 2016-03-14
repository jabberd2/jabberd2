#include "functions.h"

void bus_listen(log_t *log, xht *connections, const char **addresses, unsigned int n_addresses)
{
    LOG_DEBUG(log, "bus_listen for %d addresses", n_addresses);
    for (unsigned int i = 0; i < n_addresses; i++) {
        LOG_DEBUG(log, "bus_listen %d:%s", i, addresses[i]);
    }
}

void bus_connect(log_t *log, xht *connections, const char **addresses, unsigned int n_addresses)
{
    LOG_DEBUG(log, "bus_connect for %d addresses", n_addresses);
}
