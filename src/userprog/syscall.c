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
#include "lib/string.h"
#include "lib/stdio.h"
#include "lib/user/syscall.h"
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
    // First check: if addr NULL -> bad!
    if (addr == NULL) return false;
    // Check all bytes
    for (size_t off = 0; off < nr_bytes + 1; ++off)
    {
        if ( is_kernel_vaddr(addr + off) || // Address is in kernel space -> bad!
                pagedir_get_page(thread_current()->pagedir, addr + off) == NULL ) // Address is unmapped -> bad!
            return false;
    }
    return true;
}

/*
 * Function:	is_valid_string
 * Brief:	    Given a pointer to a string, it checks that all its bytes are
 *              valid and that the string is 0-terminated
 * @param str:	The string to check
 * Returns:	    True if all bytes are legit, false otherwise
*/
static bool is_valid_string(const char * str)
{
    // First check: if str is NULL -> bad!
    if (str == NULL) return false;

    // Address must be valid AND last byte must be 0
    return (is_valid_address((void *) str, strlen(str) + 1) &&
            *(str + strlen(str)) == '\0');
}

/*
 * Function:	cleanup
 * Brief:       Frees up the resources a process has	
 * @param code: The exit code
 * Returns:	    None.
 */
static void cleanup(int code)
{
    lock_acquire(&l);
    // First: check if the current thread has some children
    size_t i;
    struct thread * cth         = thread_current();
    struct thread * my_parent   = cth->parent;
    tid_t my_tid                = cth->tid;
    struct list * this_threads_children = &cth->parent_children_list;
    pc_t * link                 = cth->parent_child_link;

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
    printf("link         :\t%p\n", (void *) link);

#endif

    // Close all open files
    for (i = MIN_ALLOWED_FD; i < MAX_OPEN_FILES; ++i)
    {
        struct file * f = cth->file_arr[i];
        if (f)
        {
            file_close(f);
            cth->file_arr[i] = NULL;
        }
    }
    // Free all children list entries
    struct list_elem * e;

    //TODO: fix this, free crashes !!!
    for (e = list_begin(this_threads_children); e != list_end(this_threads_children); e = list_next(e))
    {
            // Free the current entry
            pc_t * entry = list_entry(e, pc_t, list_element);
#if PRINT
            printf("Freeing list entry %p\n", entry);
#endif
//             free( entry );
    }
    // Important to pass the tests
    printf("%s: exit(%d)\n", thread_name(), code);
    // Update my status in my parent's child structure
    if (link)
    {
        link->alive_count--;
        link->child_exit_status = code;
#if PRINT
        printf("Updated exit code to:\t%d. Alive count for this pair is:\t%u\n",
                link->child_exit_status, link->alive_count);
#endif
    }

    // Exit & unblock if my parent is the main thread
    if ( /*my_parent->tid == 1 && */my_parent->status == THREAD_BLOCKED)
        thread_unblock(my_parent);

    lock_release(&l);
    
    // And exit the thread
    thread_exit();
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
    void * address_to_check;

    void *stack_ptr = f->esp; // stack pointer
    int *call_code = (int*)stack_ptr; // the call code

#if PRINT
    printf("Stack ptr:\t%p\n", stack_ptr);
#endif

    if ( ! is_valid_address(stack_ptr, WORD_SIZE) )
    {
        cleanup(-1);
        NOT_REACHED();
    }

    stack_ptr += sizeof(WORD_SIZE); // increment beyond syscall code

    switch (*call_code)
    {
        case SYS_HALT:
            power_off();
            break;
        case SYS_CREATE:
            /* First, check the pointer. The first argument is a ptr. The second
             * one does not need checking since it is an integer */
            address_to_check = (void *) * (int * ) stack_ptr;
            if ( !is_valid_address(address_to_check, WORD_SIZE) || !is_valid_string((char *) address_to_check) )
            {
                cleanup(-1);
                NOT_REACHED();
            }
            else
            {
                name = (char *) address_to_check; // parse name from next stack word
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
            }
            break;
        case SYS_OPEN:
            /* First, check the pointer. The first argument is a ptr. The second
             * one does not need checking since it is an integer */
            address_to_check = (void *) * (int * ) stack_ptr;
            if ( !is_valid_address(address_to_check, WORD_SIZE) || !is_valid_string((char *) address_to_check) )
            {
                cleanup(-1);
                NOT_REACHED();
            }
            else
            {
                name = (char *) address_to_check; // parse name from next stack word
                struct file *file = filesys_open(name);
                if (!file)
                {
                    f->eax = -1;
                    break;
                }
                struct thread *ct = thread_current();
                fd = MIN_ALLOWED_FD;
                while (fd < MAX_OPEN_FILES && ct->file_arr[fd] != NULL)
                    fd++; // find first available (less than MAX_OPEN_FILES which is 130)

                if (fd < MAX_OPEN_FILES) // there was avail space in file_arr
                {
                    // 'file_arr' at file descriptor set
                    ct->file_arr[fd] = file;
                    f->eax = fd; // file descriptor pushed to eax (returned to user)
                }
                else
                {
                    f->eax = -1;
                }
            }
            break;
        case SYS_CLOSE:
            fd = *(int *) stack_ptr;
            if (fd > 1 && fd < MAX_OPEN_FILES)
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
            if ((fd > 1 && fd < MAX_OPEN_FILES) || fd == 0)
            {
                stack_ptr += sizeof(WORD_SIZE); // Increment stack ptr beyond the fd - 4bytes
                /* First, check the pointer. The first argument is a ptr. The second
                 * one does not need checking since it is an integer */
                address_to_check = (void *) * (int * ) stack_ptr;
                if ( !is_valid_address(address_to_check, WORD_SIZE) || !is_valid_string((char *) address_to_check) )
                {
                    cleanup(-1);
                    NOT_REACHED();
                }
                else
                {
                    char * buf = (char *) address_to_check;  // dereference next stack word
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
                            //f->eax = (bytes_read > 0 ? bytes_read : -1);
                            f->eax = bytes_read;
                        }
                        else
                        {
                            f->eax = -1; // the file was not read
                        }
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
            if (fd > 0 && fd < MAX_OPEN_FILES)
            {
                stack_ptr += WORD_SIZE; // Increment stack ptr beyond the fd (next word)

                /* First, check the pointer. The first argument is a ptr. The second
                 * one is the number of bytes to read, which must be checked as well */
                address_to_check = (void *) * (int * ) stack_ptr;
                unsigned bytes_to_check = * (int *)(stack_ptr + WORD_SIZE); // How many bytes we want to read?

                if ( !is_valid_address(address_to_check, bytes_to_check) || !is_valid_string((char *) address_to_check) )
                {
                    cleanup(-1);
                    NOT_REACHED();
                }
                else
                {
                    // dereference next stack word to char*
                    const char * buf = (char *) address_to_check;

                    stack_ptr += WORD_SIZE; // Increment to next word
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
                            // register
                            off_t bytes_written = file_write(file, buf, size);
                            // Write either the actual bytes written or -1 if no bytes were written
                            //f->eax = (bytes_written > 0 ? bytes_written : -1);
                            f->eax = bytes_written;
                        }
                        else
                        {
                            f->eax = -1; // file* not valid
                        }
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

            // Exit
            cleanup(exit_code);
            NOT_REACHED();

            break;
        case SYS_EXEC:
            ptr = (void *) ( * (int *) stack_ptr);

            if ( !is_valid_address(ptr, WORD_SIZE) || !is_valid_string((char *) ptr) )
            {
                cleanup(-1);
                NOT_REACHED();
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
       case SYS_SEEK:
       {
            ptr = (void *) stack_ptr; // Check the stack ptr before dereferencing anything
            if (!is_valid_address(ptr, 2 * WORD_SIZE)) // Want to dereference two int* ptrs -> 8 bytes from ptr
            {
                cleanup(-1);
                NOT_REACHED();
            }
            fd = *(int *) stack_ptr;
            stack_ptr += sizeof(WORD_SIZE);
            off_t pos = *(off_t*)stack_ptr;
            ptr = (void *) ( * (int *) stack_ptr);

            struct thread *ct = thread_current();
            file_seek(ct->file_arr[fd], pos);
            break;
       }
       case SYS_TELL:
       {
          fd = *(int *) stack_ptr;
          stack_ptr += sizeof(WORD_SIZE);
          address_to_check = (void *) * (int * ) stack_ptr;

          if (!is_valid_address(address_to_check, WORD_SIZE))
          {
              cleanup(-1);
              NOT_REACHED();
          }

          struct thread *cth = thread_current();
          f->eax = file_tell(cth->file_arr[fd]);
          break;
       }
       case SYS_FILESIZE:
       {
          fd = *(int *) stack_ptr;
          stack_ptr += sizeof(WORD_SIZE);
          address_to_check = (void *) * (int * ) stack_ptr;

          if (!is_valid_address(address_to_check, WORD_SIZE))
          {
              cleanup(-1);
              NOT_REACHED();
          }

          struct thread *cth = thread_current();
          f->eax = file_length(cth->file_arr[fd]);
          break;
       }
       case SYS_REMOVE:
       {
          address_to_check = (void *) * (int * ) stack_ptr;
          name = (char *) address_to_check;

          if (!is_valid_address(address_to_check, WORD_SIZE) ||  !is_valid_string((char *) address_to_check))
          {
             cleanup(-1);
             NOT_REACHED();
          }

          f->eax = filesys_remove(name);
          break;
       }
    }
}

