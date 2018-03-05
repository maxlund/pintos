#include "userprog/syscall.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/init.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "lib/syscall-nr.h"
#include "lib/kernel/stdio.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

/* Set it to 0 to run the tests */
#define     PRINT   0

static void syscall_handler (struct intr_frame *);
static struct lock l;

/*
 * Function:	is_valid_address
 * Brief:	    Given an address range, it checks the validity of each byte, i.e.,
 *              all bytes shall be in user space
 * @param addr:	The initial address in the range
 * @param nr_bytes:	The number of bytes to check
 * Returns:	    True if every byte in the range is valid, false otherwise
*/
static bool is_valid_address(const void * addr, size_t nr_bytes)
{
    for (size_t off = 0; off < nr_bytes + 1; ++off)
    {
        if ( is_kernel_vaddr(addr + off) || // Address if in kernel space -> bad!
                pagedir_get_page(thread_current()->pagedir, addr + off) == NULL ) // Address is unmapped -> bad!
            return false;
    }
    return true;
}

void syscall_init (void)
{
    intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init(&l);
}

static void syscall_handler (struct intr_frame *f UNUSED)
{
    const char *name;
    void * ptr; // ptr to hold the command to execute with exec
    int fd; // file descriptor
    int exit_code;
    tid_t child_id;

    void *stack_ptr = f->esp; // stack pointer
    int *call_code = (int*)stack_ptr; // the call code

    stack_ptr += sizeof(WORD_SIZE); // increment beyond syscall code

    switch (*call_code)
    {
        case SYS_HALT:
            power_off();
            break;
        case SYS_CREATE:
            name = (char *)*(int *)stack_ptr; // parse name from next stack word
            stack_ptr += sizeof(WORD_SIZE); // go to next word
            off_t initial_size = *(off_t*)stack_ptr; // get the number of bytes of file to

            if (name && initial_size >= 0)
            {
                // call the system call 'create' and push number of bytes created to eax
                f->eax = filesys_create(name, initial_size);
            }
            else
            {
                f->eax = 0; // False if failed
            }
            break;
        case SYS_OPEN:
            name = (char *)*(int *)stack_ptr; // parse name from next stack word
            struct file *file = filesys_open(name);
            if (!file)
            {
                f->eax = -1;
                break;
            }
            struct thread *ct = thread_current();fd = 2;
            while (fd < 128 && ct->file_arr[fd] != NULL)
                fd++; // find first available (less than 128)

            if (fd < 128) // there was avail space in file_arr
            {
                ct->file_arr[fd] = file; // file_arr at file descriptor set
                f->eax = fd; // file descriptor pushed to eax (returned to user)
            }
            else
            {
                f->eax = -1;
            }
            break;
        case SYS_CLOSE:
            fd = *(int *) stack_ptr;
            if (fd > 1 && fd < 128)
            {
                struct thread *ct = thread_current();
                struct file *file = ct->file_arr[fd];
                if (!file) break; // trying to close a NULL file*
                file_close(file);
                ct->file_arr[fd] = NULL;
            }
            break;
        case SYS_READ:
            // Parse fd
            fd = *(int *) stack_ptr;
            if ((fd > 1 && fd < 128) || fd == 0)
            {
                stack_ptr += sizeof(WORD_SIZE); // Increment stack ptr beyond the fd - 4bytes
                char * buf = (char *) * (int *)stack_ptr;  // dereference next stack word
                //to char*
                char * tmpbuf = buf; // Make a copy of this pointer
                stack_ptr += sizeof(WORD_SIZE); // Go to next stack word
                off_t size = *(int *)(stack_ptr); // Nr of chars to read
                off_t bytes_read = 0;
                if (fd == 0) // Read from stdin
                {
                    int i;
                    for (i=0; i<size; ++i)
                    {
                        *tmpbuf++ = input_getc();
                    }
                    f->eax = i; // Return nr of chars read
                }
                else // read from anywhere else
                {
                    struct thread *ct = thread_current();
                    struct file *file = ct->file_arr[fd];
                    if (file)
                    {
                        /*
                         * The return value (nr bytes read) is to be returned to userspace
                         * via eax register
                        */ 
                        bytes_read = file_read(file, buf, size);
                        // Write either the read bytes or -1 if we didn't read any bytes
                        f->eax = (bytes_read > 0 ? bytes_read : -1);
                    }
                    else
                    {
                        f->eax = -1; // the file was not read
                    }
                }
            }
            else
            {
                f->eax = -1; // not a valid file descriptor
            }

            break;
        case SYS_WRITE:
            // Parse fd
            fd = *(int *) stack_ptr;
            if (fd > 0 && fd < 128)
            {
                stack_ptr += sizeof(WORD_SIZE); // Increment stack ptr beyond the fd (next word)

                // dereference next stack word to char*
                const char * buf = (char *) * (int *)stack_ptr;

                stack_ptr += sizeof(WORD_SIZE); // Increment to next word
                off_t size = *(int *)(stack_ptr); // Bytes to write
                // Check if fd corresponds to stdout, in that case use putbuf() function
                if (fd == 1)
                {
                    // We have our buffer to write (buf) and the nr of bytes (size)
                    putbuf(buf, size);
                    f->eax = size;
                }
                else
                {
                    struct thread *ct = thread_current();
                    struct file *file = ct->file_arr[fd];
                    if (file) // is fd mapped to valid file* (i.e. not NULL)?
                    {
                        // The return value (nr bytes read) is to be returned to userspace via eax
                        register
                            off_t bytes_written = file_write(file, buf, size);
                        // Write either the actual bytes written or -1 if no bytes were written
                        f->eax = (bytes_written > 0 ? bytes_written : -1);
                    }
                    else
                    {
                        f->eax = -1; // file* not valid
                    }
                }
            }
            else
            {
                f->eax = -1;
            }
            break;
        case SYS_EXIT:         // Parse code, 4-byte integer
            exit_code = *(int *) stack_ptr;

            lock_acquire(&l);
            // First: check if the current thread has some children
            struct thread * cth         = thread_current();
            struct thread * my_parent   = cth->parent;
            tid_t my_tid                = cth->tid;
            struct list * this_threads_children = &cth->parent_children_list;
            pc_t * parent_child         = cth->parent_child_link;
            
#if PRINT
            printf("SYS_EXIT handler!\n");
            printf("I am                 :\t%p\n", (void *) cth);
            printf("My parent is         :\t%p\n", (void *) my_parent);
            printf("My Thread-ID is      :\t%d\n", my_tid);
            printf("My children list is  :\t%p\n", (void *)this_threads_children);
            printf(" |---->is it empty???:\t%s\n", (list_size(this_threads_children) == 0) ? "YES":"NO");
            printf("My thread status is  :\t%s\n",
                    (cth->status == THREAD_RUNNING ? "[running]" :
                     (cth->status == THREAD_READY ? "[ready]":
                      (cth->status == THREAD_BLOCKED ? "[blocked]":"[dying]"))));
            printf("My parent status is  :\t%s\n",
                    (my_parent->status == THREAD_RUNNING ? "[running]" :
                     (my_parent->status == THREAD_READY ? "[ready]":
                      (my_parent->status == THREAD_BLOCKED ? "[blocked]":"[dying]"))));
            printf("parent_child         :\t%p\n", (void *) parent_child);
          
#endif
            
            lock_release(&l);

            if (!list_empty(&this_threads_children))
            {
                // Then we need to free
            }
            // Only set the exit code if I have a valid parent
            if (parent_child) 
            {
                // Then we need to set the exit code and decrease the alive count of the parent
                parent_child->child_exit_status = exit_code;
                parent_child->alive_count--;
#if PRINT
                printf("Updated exit code to:\t%d. Alive count for this pair is:\t%u\n",
                        parent_child->child_exit_status, parent_child->alive_count);
#endif
            }


            // Important to pass the tests
            printf("%s: exit(%d)\n", thread_name(), exit_code);

            // Exit
            if (my_parent->tid == 1)
               if (my_parent->status == THREAD_BLOCKED)
                  thread_unblock(my_parent);
            
            if (cth->tid != 1)
               thread_exit();
            
            break;
        case SYS_EXEC:

            ptr = (void *) ( * (int *) stack_ptr);

            if (!ptr || ptr > PHYS_BASE)
            {
#if PRINT
                printf("Bad ptr received:\t%p\n", (void *) ptr);
#endif
                f->eax = -1;
            }
            else
            {
                f->eax = process_execute( (char *) ptr);
            }
            break;
        case SYS_WAIT:
            child_id = *(int *)stack_ptr;
#if PRINT
            printf("SYS_WAIT handler! Want to wait for child-ID %d to execute\n", child_id);
#endif
            if (child_id == TID_ERROR)
            {
                f->eax = -1;
            }
            else
            {
                f->eax = process_wait(child_id);
            }
            break;
    }
}

