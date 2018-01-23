#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/init.h"
#include "lib/syscall-nr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
    intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
    void *stack_ptr = f->esp; // stack pointer
    int *call_code = (int*)stack_ptr->esp; // the call code
    stack_ptr += sizeof(int); // increment beyond syscall code
    switch (*call_code)
    {
    case SYS_HALT:
	power_off();
	break;
    case SYS_CREATE:
	const char *name = stack_ptr; // char* points to start of filename
	stack_ptr++; // increment beyond the filename
        off_t initial_size = *(off_t*)stack_ptr; // get the size
	f->eax = filesys_create(name, initial_size); // call the system call 'create' and push return val to eax
	break;
    case SYS_OPEN:
	const char *name = stack_ptr;
	struct file *fp = filesys_open(name);
	struct thread *ct = thread_current();
        int fd = 2;
	while (fd < 128 && ct->file_arr[fd] != NULL) 
	    fd++; // find first available (less than 128)

	if (fd < 128) // there was avail space in file_arr
	{
	    ct->file_arr[fd] = fp; // file_arr at file descriptor set
	    f->eax = fd; // file descriptor pushed to eax (returned to user)
	}
	break;
    case SYS_CLOSE:
	int fd = *stack_ptr;
	if (fd > 2 && fd < 128)
	{
	    struct thread *ct = thread_current();
	    struct file *file = ct->file_arr[fd];
	    file_close(file);
	    ct->file_arr[fd] = NULL;
	}
	break;
    case SYS_READ:
	break;
    case SYS_WRITE:
	break;
    case SYS_EXIT:
	break;
    }
    printf ("system call!\n");
    thread_exit ();
}



