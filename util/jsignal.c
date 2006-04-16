/*
 * A compatible implementation of signal which relies of sigaction.
 * More or less taken from teh Stevens book.
 */

#include <signal.h>
#include <util.h>

jsighandler_t* jabber_signal(int signo,  jsighandler_t *func)
{
    struct sigaction act, oact;

    act.sa_handler = func;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
#ifdef SA_RESTART
    if (signo != SIGALRM)
        act.sa_flags |= SA_RESTART;
#endif
    if (sigaction(signo, &act, &oact) < 0)
        return (SIG_ERR);
    return (oact.sa_handler);
}
