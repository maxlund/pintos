#include "userprog/process.h"
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <lib/string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

/* Change this macro to 1 to output some printouts */
#define     PROCESS_PRINT   0

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */

    tid_t
process_execute (const char *file_name)
{
    char *fn_copy;
    tid_t tid;
    struct thread * ct = thread_current();


    process_log("I am %p [name=%s], my list is: %p, and want to execute something: '%s'.\n",
            (void *) ct, thread_name(), (void *)&ct->parent_children_list, file_name);


    // Acquire lock
    lock_acquire(&ct->thread_lock);

    pc_t * parent_child_ptr = (pc_t *) malloc (sizeof *parent_child_ptr);

    parent_child_ptr->child_exit_status = CHILD_INIT_EXIT_STATUS;
    parent_child_ptr->alive_count = 0x02;
    // The main thread is the parent of the child to be created
    parent_child_ptr->parent_thread = ct;
    parent_child_ptr->has_exited = false;

    // Add it to the list
    list_push_back(&ct->parent_children_list, &parent_child_ptr->list_element);
    process_log("Size of list:\t%d\n", list_size(&ct->parent_children_list));
    // Release lock
    lock_release(&ct->thread_lock);

    /* Make a copy of FILE_NAME.
       Otherwise there's a race between the caller and load(). */
    fn_copy = palloc_get_page (0);

    if (fn_copy == NULL)
        return TID_ERROR;
    strlcpy (fn_copy, file_name, PGSIZE);


    // Fill the thread params struct
    struct child_arguments  * arguments = (struct child_arguments *) malloc (sizeof *arguments);
    arguments->fn_copy = fn_copy;
    arguments->parent_thread = ct;
    arguments->parent_child_link = parent_child_ptr;

    /* Create a new thread to execute FILE_NAME. */
    tid = thread_create (file_name, PRI_DEFAULT, start_process, (void*) arguments);

    // Update the child id
    if (tid == TID_ERROR)
    {
        free(parent_child_ptr);
        free(arguments);
        palloc_free_page (fn_copy);
    }
    else
    {

        process_log("Current thread [%p,'%s',%d] will be blocked until child process ['%s',%d] starts!\n",
                (void *) ct, thread_name(), ct->tid,
                file_name, tid);

        //Before creating, we should put the parent to sleep and wake him up when
        // the child has "loaded" the new program
       parent_child_ptr->child_id = tid;
       intr_disable();
       thread_block();
    }

    return parent_child_ptr->child_id;
}

static void print_stack(void ** esp, bool complete)
{
    printf("*esp is %p\nstack contents:\n", *esp);
    hex_dump((int)*esp , *esp, PHYS_BASE-*esp+16, true);
    if (complete)
    {
        /* The same information, only more verbose: */
        /* It prints every byte as if it was a char and every 32-bit aligned
           data as if it was a pointer. */
        void * ptr_save = PHYS_BASE;
        int i;
        i=-15;
        while(ptr_save - i >= *esp) {
            char *whats_there = (char *)(ptr_save - i);
            // show the address ...
            printf("%x\t", (uint32_t)whats_there);
            // ... printable byte content ...
            if(*whats_there >= 32 && *whats_there < 127)
                printf("%c\t", *whats_there);
            else
                printf("?\t");
            // ... and 32-bit aligned content
            if(i % 4 == 0) {
                uint32_t *wt_uint32 = (uint32_t *)(ptr_save - i);
                printf("%x\t", *wt_uint32);
                printf("\n-------");
                if(i != 0)
                    printf("------------------------------------------------");
                else
                    printf(" the border between KERNEL SPACE and USER SPACE ");
                printf("-------");
            }
            printf("\n");
            i++;
        }
    }
}
/* Pushes data to the stack */
static void * push_to_stack(void * init_address, uint32_t data, size_t nr_bytes)
{
    if (nr_bytes == WORD_SIZE)
    {
        uint32_t * ptr = (uint32_t * ) init_address;
        *--ptr = data;
        init_address -= WORD_SIZE;
    }
    else
    {
        // If single bytes are to be copied, just use memcpy
        init_address -= nr_bytes;
        memcpy(init_address, &data, nr_bytes);
    }
    return init_address;
}

/* A thread function that loads a user process and starts it
   running. */
    static void
start_process (void * data)
{
    char *token, *save_ptr;
    // init the arg count
    int argc = 0;
    size_t cmdlen = 0;
    char * argv[100];
    struct child_arguments * p = (struct child_arguments *) data;
    struct thread * parent = p->parent_thread;
    char *cmdline = p->fn_copy;

    struct intr_frame if_;
    bool success;

    process_log("****Starting process! Will load '%s' and set up its stack!\n", cmdline);

    /* Initialize interrupt frame and load executable. */
    memset (&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;

    // #########################################################################
    // ######################### Stack filling #################################
    // #########################################################################
    char * tmp = (char *) malloc (sizeof *tmp * 200);
    unsigned j = 0;
    for (token = strtok_r (cmdline, " ", &save_ptr); token != NULL;
            token = strtok_r (NULL, " ", &save_ptr))
    {
       for (unsigned i = 0; i < strlen(token); i++)
       {
          if (token[i] != ' ')
              tmp[j++] = token[i];
       }

       tmp[j++] = '\0';
       cmdlen += (strlen(token) + 1); // Account for the \0 byte (+1)
        /* memcpy(tmp, token, strlen(token)); */
        /* memset(tmp + strlen(token), 0, 1); */
        /* tmp += strlen(token); */
        argv[argc++] = token;
    }

    // reset tmp
    process_log("printing tmp: \n");
    for (uint8_t i=0; i<cmdlen; ++i)
    {
       if (tmp[i] == 0)
          process_log("\\0");
       else
          process_log("%c", tmp[i]);
    }
    process_log("\n");

    // Set the tokenized thread name
    const char * name = thread_current()->name;
    memset(name, 0, strlen(name));
    memcpy(name, argv[0], strlen(argv[0]));

    process_log("Loading new process '%s' ...\n", cmdline);
    success = load (cmdline, &if_.eip, &if_.esp);

    // Set up the stack
    // we want to dereference **esp to get the actual stack pointer
    void * current_ptr = BYTE_BELOW_PHYS_BASE(if_.esp);

    // Now, copy all cmdline bytes
    current_ptr -= (cmdlen-1);
//    memcpy(current_ptr, cmdline, cmdlen);
    memcpy(current_ptr, tmp, cmdlen);

    // Check for the whole length of the cmdline, and based on that, add word alignment
    size_t word_align = (cmdlen % WORD_SIZE == 0 ? 0 : WORD_SIZE - (cmdlen % WORD_SIZE) );
    current_ptr = push_to_stack(current_ptr, 0x00, word_align);

    // Next, add every argument
    current_ptr = push_to_stack(current_ptr, 0x00, WORD_SIZE);

    const void * cmdline_start = current_ptr + WORD_SIZE + word_align;

    // Get the pointers to each argv
    size_t offset = 0;
    for (size_t i = 0; i < argc; ++i)
    {
        // Calculate offset with respect to cmdline_start
        for (size_t j = 0; j < argc - i - 1; ++j)
            offset += strlen(argv[j]) + 1;


        process_log("String is='%s'\n", (char *) (cmdline_start + offset));


        current_ptr = push_to_stack(current_ptr,
                (uint32_t) (cmdline_start + offset),
                WORD_SIZE);
        // Reset offset
        offset = 0;
    }

    current_ptr = push_to_stack(current_ptr,
            (uint32_t ) current_ptr,
            WORD_SIZE); // Memory address of argv* !!

    current_ptr = push_to_stack(current_ptr, argc, WORD_SIZE);
    // Return address --> not needed ...
    current_ptr = push_to_stack(current_ptr, 0x00, WORD_SIZE);


    // #########################################################################
    // #########################################################################

    // Update the stack ptr
    if_.esp = current_ptr;

    /* If load failed, quit. */
    palloc_free_page (cmdline);
    if (!success)
    {
       p->parent_child_link->child_id = -1;
       //free(p);
       free(tmp);
       thread_unblock(parent);
       thread_exit();
    }

    // Wake up the parent

    process_log("(unblocking parent=%p, meaning that it will resume execution...). %p should be up and running!\n", (void*) parent, (void*) thread_current());

    thread_unblock(parent);

    // Free child_arguments struct
    free(p);
    free(tmp);


    process_log("&if_ = %p\n", (void *) &if_);


    /* Start the user process by simulating a return from an
       interrupt, implemented by intr_exit (in
       threads/intr-stubs.S).  Because intr_exit takes all of its
       arguments on the stack in the form of a `struct intr_frame',
       we just point the stack pointer (%esp) to our stack frame
       and jump to it. */
    asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
    NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
    int
process_wait (tid_t child_tid UNUSED)
{
    // Block the current thread and wait until the child has exited / been
    // terminated.
    //
    // Need to check first if child has already exited. If not, then dont
    // bother blocking
    struct thread * ct = thread_current();

    // Parse the parent-child structure of the current thread
    struct list * children = &ct->parent_children_list;
    struct list_elem * e;
    int exit_status = -1;


    process_log("[process_wait] Will check if I [%p,'%s',%d] need to wait for my child-ID %d. My children list '%s'\n",
            (void *)ct, thread_name(), ct->tid, child_tid,
            list_empty(children) ? "is empty" : "contains something");


    for (e = list_begin(children); e != list_end(children); e = list_next(e))
    {
        // Parse the current entry
        pc_t * current = list_entry(e, pc_t, list_element);
        // Check for my ID: then return that exit code
        if (current->child_id == child_tid && !current->has_exited)
        {
            exit_status = current->child_exit_status;

            process_log("Found my child '%d'! Updating its exit status: %d\n", child_tid, exit_status);

            current->has_exited = true;

            // Now check: if exit_status is the initial dummy status, then it is still running
            if (exit_status == CHILD_INIT_EXIT_STATUS)
            {

                process_log("Will block myself=%p (tid=%d)\n", (void *) ct, ct->tid);

                intr_disable();
                thread_block();
                // Once unblocked, break and return the newly set exit code
                // This new exit code will have been set by the child upon SYS_EXIT call
                exit_status = current->child_exit_status;

                process_log("I (%s) was unblocked! My child's exit status was:\t%d\n", thread_name(), exit_status);

                break;
            }
            else
            {
                break;
            }
        }
    }
    return exit_status;
}

/* Free the current process's resources. */
    void
process_exit (void)
{
    struct thread *cur = thread_current ();
    uint32_t *pd;

    /* Destroy the current process's page directory and switch back
       to the kernel-only page directory. */
    pd = cur->pagedir;
    if (pd != NULL)
    {
        /* Correct ordering here is crucial.  We must set
           cur->pagedir to NULL before switching page directories,
           so that a timer interrupt can't switch back to the
           process page directory.  We must activate the base page
           directory before destroying the process's page
           directory, or our active page directory will be one
           that's been freed (and cleared). */
        cur->pagedir = NULL;
        pagedir_activate (NULL);
        pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
    void
process_activate (void)
{
    struct thread *t = thread_current ();

    /* Activate thread's page tables. */
    pagedir_activate (t->pagedir);

    /* Set thread's kernel stack for use in processing
       interrupts. */
    tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
{
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
{
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
        uint32_t read_bytes, uint32_t zero_bytes,
        bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
    bool
load (const char *file_name, void (**eip) (void), void **esp)
{
    struct thread *t = thread_current ();
    struct Elf32_Ehdr ehdr;
    struct file *file = NULL;
    off_t file_ofs;
    bool success = false;
    int i;

    /* Allocate and activate page directory. */
    t->pagedir = pagedir_create ();
    if (t->pagedir == NULL)
        goto done;
    process_activate ();

    /* Set up stack. */
    if (!setup_stack (esp)){
        goto done;
    }

    /* Uncomment the following line to print some debug
       information. This will be useful when you debug the program
       stack.*/
    // #define STACK_DEBUG

#ifdef STACK_DEBUG
    print_stack(esp, true);
#endif

    /* Open executable file. */
    file = filesys_open (file_name);
    if (file == NULL)
    {
        printf ("load: %s: open failed\n", file_name);
        goto done;
    }

    /* Read and verify executable header. */
    if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
            || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
            || ehdr.e_type != 2
            || ehdr.e_machine != 3
            || ehdr.e_version != 1
            || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
            || ehdr.e_phnum > 1024)
    {
        printf ("load: %s: error loading executable\n", file_name);
        goto done;
    }

    /* Read program headers. */
    file_ofs = ehdr.e_phoff;
    for (i = 0; i < ehdr.e_phnum; i++)
    {
        struct Elf32_Phdr phdr;

        if (file_ofs < 0 || file_ofs > file_length (file))
            goto done;
        file_seek (file, file_ofs);

        if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
            goto done;
        file_ofs += sizeof phdr;
        switch (phdr.p_type)
        {
            case PT_NULL:
            case PT_NOTE:
            case PT_PHDR:
            case PT_STACK:
            default:
                /* Ignore this segment. */
                break;
            case PT_DYNAMIC:
            case PT_INTERP:
            case PT_SHLIB:
                goto done;
            case PT_LOAD:
                if (validate_segment (&phdr, file))
                {
                    bool writable = (phdr.p_flags & PF_W) != 0;
                    uint32_t file_page = phdr.p_offset & ~PGMASK;
                    uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
                    uint32_t page_offset = phdr.p_vaddr & PGMASK;
                    uint32_t read_bytes, zero_bytes;
                    if (phdr.p_filesz > 0)
                    {
                        /* Normal segment.
                           Read initial part from disk and zero the rest. */
                        read_bytes = page_offset + phdr.p_filesz;
                        zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                    }
                    else
                    {
                        /* Entirely zero.
                           Don't read anything from disk. */
                        read_bytes = 0;
                        zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                    }
                    if (!load_segment (file, file_page, (void *) mem_page,
                                read_bytes, zero_bytes, writable))
                        goto done;
                }
                else
                    goto done;
                break;
        }
    }

    /* Start address. */
    *eip = (void (*) (void)) ehdr.e_entry;

    success = true;

done:
    /* We arrive here whether the load is successful or not. */
    file_close (file);
    return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
    static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
    /* p_offset and p_vaddr must have the same page offset. */
    if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
        return false;

    /* p_offset must point within FILE. */
    if (phdr->p_offset > (Elf32_Off) file_length (file))
        return false;

    /* p_memsz must be at least as big as p_filesz. */
    if (phdr->p_memsz < phdr->p_filesz)
        return false;

    /* The segment must not be empty. */
    if (phdr->p_memsz == 0)
        return false;

    /* The virtual memory region must both start and end within the
       user address space range. */
    if (!is_user_vaddr ((void *) phdr->p_vaddr))
        return false;
    if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
        return false;

    /* The region cannot "wrap around" across the kernel virtual
       address space. */
    if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
        return false;

    /* Disallow mapping page 0.
       Not only is it a bad idea to map page 0, but if we allowed
       it then user code that passed a null pointer to system calls
       could quite likely panic the kernel by way of null pointer
       assertions in memcpy(), etc. */
    if (phdr->p_vaddr < PGSIZE)
        return false;

    /* It's okay. */
    return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

   - READ_BYTES bytes at UPAGE must be read from FILE
   starting at offset OFS.

   - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
    static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
        uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
    ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT (pg_ofs (upage) == 0);
    ASSERT (ofs % PGSIZE == 0);

    file_seek (file, ofs);
    while (read_bytes > 0 || zero_bytes > 0)
    {
        /* Calculate how to fill this page.
           We will read PAGE_READ_BYTES bytes from FILE
           and zero the final PAGE_ZERO_BYTES bytes. */
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        /* Get a page of memory. */
        uint8_t *kpage = palloc_get_page (PAL_USER);
        if (kpage == NULL)
            return false;

        /* Load this page. */
        if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
            palloc_free_page (kpage);
            return false;
        }
        memset (kpage + page_read_bytes, 0, page_zero_bytes);

        /* Add the page to the process's address space. */
        if (!install_page (upage, kpage, writable))
        {
            palloc_free_page (kpage);
            return false;
        }

        /* Advance. */
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;
    }
    return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
    static bool
setup_stack (void **esp)
{
    uint8_t *kpage;
    bool success = false;

    kpage = palloc_get_page (PAL_USER | PAL_ZERO);
    if (kpage != NULL)
    {
        success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
        if (success)
            *esp = PHYS_BASE;
        else
            palloc_free_page (kpage);
    }
    return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
    static bool
install_page (void *upage, void *kpage, bool writable)
{
    struct thread *t = thread_current ();

    /* Verify that there's not already a page at that virtual
       address, then map our page there. */
    return (pagedir_get_page (t->pagedir, upage) == NULL
            && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

void process_log(const char * fmt, ...)
{
    va_list args;
    va_start(args, fmt);
#if PROCESS_PRINT
    vprintf(fmt, args);
#endif
    va_end(args);
}
