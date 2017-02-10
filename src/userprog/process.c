#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
#include "threads/thread.h"
#include "threads/vaddr.h"

/* malloc 사용을 위해 */
#include "threads/malloc.h"
/* lock 관련 함수들 사용 */
#include "threads/synch.h"

/* 프로그램 인자 구분할 구분자 */
const char *delimiters = " ";
/* 실행중인 파일에 대해 쓰기 거부할 lock */
struct lock deny_write_lock;

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Command Line Parsing */
static void argument_stack (char **parse, const int count, void **esp);

/* Hierarchical Process Structure */
struct thread *get_child_process (int pid);
void remove_child_process (struct thread *cp);

/* File Description */
int process_add_file (struct file *f);
struct file *process_get_file (int fd);
void process_close_file (int fd);

/* Virtual Memory */
bool handle_mm_fault (struct vm_entry *vme);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */

tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;
  /* fn_copy 를 저장하고 있을 변수 */
  char *fn_copy_copy;
  /* thread_create 에 전달할 thread_name */
  const char *thread_name;
  /* strtok_r 에 전달할 save 포인터 */
  char *save_ptr;

  /* 쓰기 거부 락을 초기화 */
  lock_init (&deny_write_lock);

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  /* parsing 되지 않은 전체 프로그램 인자를 저장할 임시 변수 */
  fn_copy_copy = palloc_get_page (0);

  if (fn_copy == NULL)
    return TID_ERROR;

  if (fn_copy_copy == NULL)
    return TID_ERROR;

  /* 전체 프로그램 인자를 복사 */
  strlcpy (fn_copy, file_name, PGSIZE);
  strlcpy (fn_copy_copy, fn_copy, PGSIZE);
  
  /* fn_copy_copy 에서 thread name 추출 */
  thread_name = strtok_r(fn_copy_copy, delimiters, &save_ptr);

  if (thread_name == NULL)
    return TID_ERROR;

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (thread_name, PRI_DEFAULT, start_process, fn_copy);

  /* 임시 변수에 할당된 메모리를 해제 */
  palloc_free_page (fn_copy_copy);
  if (tid == TID_ERROR) 
      palloc_free_page (fn_copy); 
    
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  /* parsing 된 인자들을 가질 이차원 배열 */
  char **parse;
  /* strtok_r 의 save 포인터 */
  char *save_ptr;
  /* load () 에 전달할 file name */
  char *load_file_name;
  char *temp;

  /* 인자의 개수 */
  int count = 0;
  int i;

  /* delemiters 를 구분자로 전달받은 file name 을 parsing */
  for (temp = strtok_r (file_name, delimiters, &save_ptr);
      temp != NULL;
      temp = strtok_r (NULL, delimiters, &save_ptr), count++)
    {
      /* 처음만 malloc */
      if (count != 0)
        parse = (char **) realloc (parse, sizeof (char *) * (count + 1));
      else
        parse = (char **) malloc (sizeof (char *) * 1);

      parse[count] = (char *) malloc (sizeof (char *) * strlen(temp));
      strlcpy (parse[count], temp, sizeof (char *) * (strlen (temp) + 1));
    }
  load_file_name = parse[0];

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  success = load (load_file_name, &if_.eip, &if_.esp);
  /* If load failed, quit. */
  palloc_free_page (file_name);
  if (!success)
    {
      struct thread *t = thread_current ();
      /* load 에 실패하였으므로 thread 의 is_load 필드를 false 로 변경 */
      t->is_load = false;
      /* load_sema 를 up 시켜 더 이상 대기하지 않도록 함 */
      sema_up (&t->load_sema);
      thread_exit ();
    }
    
  struct thread *t = thread_current ();
  /* load 에 성공했으므로 thread 의 is_load 필드를 true 로 변경 */
  t->is_load = true;
  /* load_sema 를 up 시켜 더 이상 대기하지 않도록 함 */
  sema_up (&t->load_sema);

  /* 유저 스택에 파싱한 인자들을 쌓음 */
  argument_stack(parse, count, &if_.esp);
  /* 인자들을 저장했던 배열의 메모리를 해제 */
  for (i = 0; i < count; i++)
    free (parse[i]);
  free (parse);

  /* 메모리 내용을 확인하는 디버깅 코드 */
  // hex_dump (if_.esp, if_.esp, PHYS_BASE - if_.esp, true);
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
process_wait (tid_t child_tid) 
{
  struct thread *cp = get_child_process (child_tid);
  if (cp == NULL)
    return -1;
  /* exit_sema 를 down 시켜 부모 프로세스 대기 */
  sema_down (&cp->exit_sema);
  /* 프로세스의 종료 코드를 저장 */
  int exit_status = cp->exit_status;
  /* 자식 프로세스를 제거 */
  remove_child_process (cp);
  return exit_status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* 프로세스의 모든 파일을 닫음 */
  int i;
  for (i = 2; i < cur->fd; i++)
    process_close_file (i);
  /* 현재 프로세스의 실행중인 파일을 닫음 */
  file_close (cur->run_file);

  /* 프로세스의 파일 디스크립터 테이블 메모리를 해제 */
  palloc_free_page ((void *) cur->fd_table);

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

  /* 쓰기 거부 락 획득 */
  lock_acquire (&deny_write_lock);
  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      lock_release (&deny_write_lock);
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* 프로세스의 실행 파일을 현재 파일로 지정 */
  t->run_file = file;
  /* 현재 파일에 쓰기 거부*/
  file_deny_write (file);
  /* 쓰기 거부 락 해제 */
  lock_release (&deny_write_lock);

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

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  /* 해당 파일은 프로세스가 종료될 때 삭제됨 */
  // file_close (file);
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

/* 유저 스택에 프로그램 이름과 인자들을 저장하는 함수 
   parse: 프로그램 이름과 인자가 저장되어 있는 메모리 공간,
   count: 인자의 개수,
   esp: 스택 포인터를 가리키는 주소 */
static void
argument_stack (char **parse, int count, void **esp)
{
  int i, j;
  uint32_t argv[count];

  /* 프로그램 이름 및 인자 (문자열) 삽입 */
  for (i = count - 1; i > -1; i--)
    {
      for (j = strlen (parse[i]); j > -1; j--)
        {
          /* 스택 주소를 감소시키면서 인자를 스택에 삽입 */
          *esp = *esp - 1;
          ** (char **) esp = parse[i][j];
        }
      argv[i] = (uint32_t) (*esp);
    }

  /* Word align */
  *esp = (uint32_t) (*esp) & 0xfffffffc;
  *esp -= 4;
  memset (*esp, NULL, sizeof (int));

  for (i = count - 1; i > -1; i--)
    {
      /* 프로그램 이름 및 인자 주소들 삽입 */
      *esp -= 4;
      *(uint32_t *) (*esp) = argv[i];
    }
  /* **argv 삽입 */
  *esp -= 4;
  *(uint32_t *) (*esp) = (uint32_t) (*esp) + 4;
  /* argc 삽입 */
  *esp -= 4;
  *(int *) (*esp) = (int) count;

  *esp -= 4;
  memset (*esp, NULL, sizeof (int));
}

/* 전달받은 pid 로 자식 리스트를 검색하여 해당 프로세스 디스크립터 반환  */
struct thread *
get_child_process (int pid)
{
  if (pid < 0)
    return NULL;

  struct thread *cur = thread_current ();
  struct list_elem *e;

  /* 자식 리스트를 순회하며 pid 에 해당하는 자식 thread 를 검색 */
  for (e = list_begin (&cur->child_list);
      e != list_end (&cur->child_list);
      e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, child_elem);
      
      if (pid == t->tid)
        return t;
    }
  return NULL;
}

/* 전달받은 자식 프로세스를 제거 */
void
remove_child_process (struct thread *cp)
{
  if (cp != NULL)
    {
      list_remove (&cp->child_elem);
      palloc_free_page ((void *) cp);
    }
}

/* 전달받은 파일을 프로세스의 파일 디스크립터 테이블에 삽입  */
int
process_add_file (struct file *f)
{
  if (f == NULL)
    return -1;

  struct thread *t = thread_current ();
  t->fd_table[t->fd] = f;
  return t->fd++;
}

/* 전달받은 fd 에 해당하는 파일을 반환 */
struct file *
process_get_file (int fd)
{
  if (fd > 0)
    {
      struct file *f = thread_current ()->fd_table[fd];
      if (f == NULL)
        return NULL;

      return f;
    }
  return NULL;
}

/* 전달받은 fd 에 해당하는 파일을 닫음 */
void
process_close_file (int fd)
{
  if (fd > 1)
    {
      struct file *f = process_get_file (fd);
      file_close (f);
      /* 파일 디스크립터 테이블은 충분하므로 fd 를 -1 하지 않아도 됨 */
      thread_current ()->fd_table[fd] = NULL;
    }
}

/* Page fualt 발생 시 물리 페이지를 할당 */
bool
handle_mm_fault (struct vm_entry *vme)
{

}
