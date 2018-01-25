#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/init.h"
#include "lib/syscall-nr.h"
#include "lib/kernel/stdio.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

static void syscall_handler (struct intr_frame *);

void syscall_init (void) 
{
    intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler (struct intr_frame *f UNUSED)
{
    const char *name;
    int fd;
    int exit_code;

    void *stack_ptr = f->esp; // stack pointer
    int *call_code = (int*)stack_ptr; // the call code
    stack_ptr += sizeof(int); // increment beyond syscall code
    switch (*call_code)
    {
        case SYS_HALT:
            power_off();
            break;
        case SYS_CREATE:
            name = (char *)*(int *)stack_ptr; // char* points to start of filename
            stack_ptr += sizeof(int); // increment beyond the filename
            off_t initial_size = *(off_t*)stack_ptr; // get the size
            f->eax = filesys_create(name, initial_size); // call the system call 'create' and push return val to eax
            break;
        case SYS_OPEN:
            name = stack_ptr;
            struct file *fp = filesys_open(name);
            struct thread *ct = thread_current();
            fd = 2;
            while (fd < 128 && ct->file_arr[fd] != NULL) 
                fd++; // find first available (less than 128)

            if (fd < 128) // there was avail space in file_arr
            {
                ct->file_arr[fd] = fp; // file_arr at file descriptor set
                f->eax = fd; // file descriptor pushed to eax (returned to user)
            }
            break;
        case SYS_CLOSE:
            fd = *(int *) stack_ptr;
            if (fd > 2 && fd < 128)
            {
                struct thread *ct = thread_current();
                struct file *file = ct->file_arr[fd];
                file_close(file);
                ct->file_arr[fd] = NULL;
            }
            break;
        case SYS_READ:
            // Parse fd
            fd = *(int *) stack_ptr;
            if ((fd > 2 && fd < 128) || fd == 0)
            {
                stack_ptr += sizeof(int); // Increment stack ptr beyond the fd - 4bytes
                // At this point, stack_ptr points to the passed void * buffer from userspace
                char * buf = (char *) * (int *)stack_ptr;
                // Make a copy of this pointer
                char * tmpbuf = buf;
                stack_ptr += 4;
                off_t size = *(int *)(stack_ptr); // Next byte points to an integer with the desired size
                off_t bytes_read = 0;
                if (fd == 0)
                {
                    int i;
                    for (i=0; i<size; ++i)
                    {
                        *tmpbuf++ = input_getc();
                    }
                    f->eax = i;
                }
                else
                {
                    struct thread *ct = thread_current();
                    struct file *file = ct->file_arr[fd];
                    // The return value (nr bytes read) is to be returned to userspace via eax register
                    bytes_read = file_read(file, buf, size);
                    // Write either the read bytes or -1 if somewhing went wrong
                    f->eax = (bytes_read > 0 ? bytes_read : -1);
                }
            }
            break;
        case SYS_WRITE:
            // Parse fd
            fd = *(int *) stack_ptr;
            if ((fd > 2 && fd < 128) || fd == 1)
            {
                stack_ptr += sizeof(int); // Increment stack ptr beyond the fd - 4bytes
                const int *tmp = (int *)stack_ptr; // Ptr to the pointer to the buffer to write
                const char *buf = (char *) * tmp; // Char* cast to the dereferenced pointer of the stack
                stack_ptr += sizeof(int); // Increment stack ptr beyond the fd - 4bytes

                off_t size = *(int *)(stack_ptr); // Bytes to write
                // Check if fd corresponds to stdout, in that case use putbuf() function
                if (fd == 1)
                {
                    // We have our buffer to write (buf) and the nr of bytes (size)
                    putbuf(buf, size);
                    // And we don't need to return anything since we most probably use this via printf()
                    // , fprintf(stdout, "..."), ... function family - or not? :-)
                }
                else
                {
                    struct thread *ct = thread_current();
                    struct file *file = ct->file_arr[fd];
                    // The return value (nr bytes read) is to be returned to userspace via eax register
                    off_t bytes_written = file_write(file, buf, size);
                    // Write either the actual bytes written or -1 if no bytes were written
                    f->eax = (bytes_written > 0 ? bytes_written : -1);
                }
            }
            break;
        case SYS_EXIT:
            // Parse code, 4-byte integer
            exit_code = *(int *) stack_ptr;
            // Let's use process_exit() routine --- but error code ??
            process_exit();
            break;
    }
//     thread_exit ();
}



