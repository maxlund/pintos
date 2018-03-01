/* Executes and waits for a single child process. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void
test_main (void) 
{
    int pid = exec("child-simple");
    msg("Success! PID=%d\n", pid);
    wait (pid);
    msg ("Done!\n");
}
