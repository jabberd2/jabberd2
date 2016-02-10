jabberd evolution
=================

This rebuild targets:

- increase maintainability and extensibility
- better fit for typical deployments
- decrease NIH and leverage well-known libraries


Building
--------

You will need the following libraries with their .pc files installed:

- bdw-gc
- check
- expat
- libidn
- libuv
- log4c
- nanomsg
- openssl

Build:

    ./configure && make

Run:

    LOG4C_APPENDER=stderr LOG4C_PRIORITY=trace src/jabberd


LOGGING STRATEGY
----------------
    fatal  - unrecoverable, aborting issue
    alert  - something requires your attention, continuing is unsafe
    crit   - critical error, continuing is unsafe
    error  - application level error
    warn   - aplication detected error
    notice - user generated error
    info   - user generated information
    debug  - application level information
    trace  - application flow tracing


COPYING
-------
> This program is free software; you can redistribute it and/or modify
> it under the terms of the GNU General Public License as published by
> the Free Software Foundation; either version 3 of the License, or
> (at your option) any later version.

