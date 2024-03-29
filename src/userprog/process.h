#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include <stdint.h>
#include "threads/thread.h"
#include "threads/synch.h"

// initial exit status
#define CHILD_INIT_EXIT_STATUS 0xfa

// Keys to identify wether a thread is parent or child
#define THREAD_PARENT   0x02
#define THREAD_CHILD    0x01
#define THREAD_NONE     -1

// Stack word size
#define WORD_SIZE       0x04

// Convenience macro to start filling the stack at exactly PHYS_BASE - 1
#define BYTE_BELOW_PHYS_BASE(X) (X - 1)

struct child_arguments
{
   char * fn_copy;
   struct parent_child * parent_child_link;
   struct thread * parent_thread;
};

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
void process_log(const char * fmt, ...);

#endif /* userprog/process.h */
