#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include <stdint.h>
#include "threads/thread.h"
#include "threads/interrupt.h"

// initial exit status
#define CHILD_INIT_EXIT_STATUS 0xfa

// Keys to identify wether a thread is parent or child
#define THREAD_PARENT   0x02
#define THREAD_CHILD    0x01
#define THREAD_NONE     -1


/*
 * Function:	    get_index_of_thread_
 * Brief:	        Given a thread id, it returns the position of the parent-child
                    structure in 'parent-child-pairs' and determines if it corres-
                    ponds to a child or parent id in the named array..
 * @param child_id:	The thread ID to look for
 * Returns:	        The index in the array, or -1 if it was not found. is_parent is
 *                  updated accordingly
 */
int get_index_of_thread(tid_t id, int * is_parent);

typedef struct parent_child
{
    /* Child's exit status */
    int child_exit_status;
    /* Who is alive */
    int alive_count;
    /* Child's thread ID */
    tid_t child_id;
    /* Parent's thread structure */
    struct thread * parent_thread;
} pc_t;

/* Keep track of parent-child pairs */
pc_t * parent_child_pairs;

struct thread_param
{
   char * fn_copy;
   struct thread * parent;
   enum intr_level parent_intr_level;
};

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
