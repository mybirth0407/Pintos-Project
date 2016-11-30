#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#include "threads/vaddr.h"
#include "userprog/process.h"

#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "devices/input.h"
#include "filesys/file.h"
#include "threads/synch.h"

#define USER_VADDR_BOTTOM ((void *) 0x8048000)

struct lock file_lock;

static void syscall_handler (struct intr_frame *);
void check_address (void *addr);
void get_argument (void *esp, int *arg, int count);

void halt(void);
void exit(int status);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);

tid_t exec (const char *cmd_line);
int wait (tid_t tid);

void close (int fd);
off_t read (int fd, void *buffer, unsigned size);
off_t write (int fd, void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
int open (const char *file);
int filesize (int fd);

void
syscall_init (void) 
{
  lock_init (&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  // printf ("system call!\n");
  uint32_t *sp = f->esp;
  int arg[3];

  check_address ((void *) sp);

  int syscall_n = *sp;
  sp++;
  // printf ("system cll number = %d\n", syscall_n);
  switch (syscall_n)
    {
      // 0
      case SYS_HALT:                   /* Halt the operating system. */
        halt ();
        break;
      // 1
      case SYS_EXIT:                   /* Terminate this process. */
        get_argument (sp, arg, 1);
          exit ((int) arg[0]);
        break;
      // 2
      case SYS_EXEC:                   /* Start another process. */
        get_argument (sp, arg, 1);
        f->eax = exec ((const char *) arg[0]);
        break;
      // 3
      case SYS_WAIT:                   /* Wait for a child process to die. */
        get_argument (sp, arg, 1);
        f->eax = wait ((int) arg[0]);
        break;
      // 4
      case SYS_CREATE:                 /* Create a file. */
        get_argument (sp, arg, 2);
        f->eax = create ((const char *) arg[0], (unsigned) arg[1]);
        break;
      // 5
      case SYS_REMOVE:                 /* Delete a file. */
        get_argument (sp, arg, 1);
        f->eax = remove ((const char *) arg[0]);
        break;
      // 6
      case SYS_OPEN:                   /* Open a file. */
        get_argument (sp, arg, 1);
        f->eax = open ((const char *) arg[0]);
        break;
      // 7
      case SYS_FILESIZE:               /* Obtain a file's size. */
        get_argument (sp, arg, 1);
        f->eax = filesize ((int) arg[0]);
      // 8
      case SYS_READ:                   /* Read from a file. */
        get_argument (sp, arg, 3);
        f->eax = read ((int) arg[0], (void *) arg[1], (unsigned) arg[2]);
        break;
      // 9
      case SYS_WRITE:                  /* Write to a file. */
        get_argument (sp, arg, 3);
        f->eax = write ((int) arg[0], (void *) arg[1], (unsigned) arg[2]);
        break;
      // 10
      case SYS_SEEK:                   /* Change position in a file. */
        get_argument (sp, arg, 2);
        seek ((int) arg[0], (unsigned) arg[1]);
        break;
      // 11
      case SYS_TELL:                   /* Report current position in a file. */
        get_argument (sp, arg, 1);
        f->eax = tell ((int) arg[0]);
        break;
      // 12
      case SYS_CLOSE:                  /* Close a file. */
        get_argument (sp, arg, 1);
        close ((int) arg[0]);
        break;

      default:
        NOT_REACHED ()
    }
  // thread_exit ();
}

void
check_address (void *addr)
{
  if (!is_user_vaddr (addr) || addr <= USER_VADDR_BOTTOM)
    exit (-1);
}

void
get_argument (void *esp, int *arg, int count)
{
  int i;
  for (i = 0; i < count; i++)
    {
      /* 유저 스택에 저장된 인자값들을 커널로 저장 */
      check_address ((void *) esp);
      arg[i] = *(int *) esp;
      esp += 4;
    }
}

void
halt (void)
{
  shutdown_power_off ();
}

void
exit (int status)
{
  struct thread *cur = thread_current ();
  cur->exit_status = status;
  printf ("%s: exit(%d)\n", cur->name, status);
  thread_exit ();
}

bool
create (const char *file, unsigned initial_size)
{
  check_address ((void *) file);
  lock_acquire (&file_lock);
  bool success = filesys_create (file, initial_size);
  lock_release (&file_lock);
  return success;
}

bool
remove (const char *file)
{
  check_address ((void *) file);
  lock_acquire (&file_lock);
  bool success = filesys_remove (file);
  lock_release (&file_lock);
  return success;
}

tid_t
exec (const char *cmd_line)
{
  check_address ((void *) cmd_line);
  tid_t tid = process_execute (cmd_line);
  struct thread *cp = get_child_process (tid);
  if (cp == NULL)
    return -1;
  sema_down (&cp->load_sema);
  if (!cp->is_load)
    return -1;
  else
    return tid;
}

int
wait (tid_t tid)
{
  /* 자식 프로세스가 종료될 때까지 대기 */
  return process_wait (tid);
}

off_t
read (int fd, void *buffer, unsigned size)
{
  check_address (buffer);
  if (fd < 0)
    return -1;

  if (size < 0)
    return -1;

  uint8_t *buf = (uint8_t *) buffer;

  if (fd == 0)
    {
      unsigned i;
      for (i = 0; i < size; i++)
        {
          uint8_t input = input_getc ();
          buf[i] = input;
        }
      return (off_t) size;
    }
    
  lock_acquire (&file_lock);
  struct file *f = process_get_file (fd);
  if (f == NULL)
    {
      lock_release (&file_lock);
      return -1;
    }
    

  off_t bytes = file_read (f, buffer, size);
  lock_release (&file_lock);
  return bytes;
}

off_t
write (int fd, void *buffer, unsigned size)
{
  check_address (buffer);
  if (fd < 0)
    return -1;

  if (size < 0)
    return -1;

  if (fd == 1)
    {
      putbuf ((const char *) buffer, size);
      return (off_t) size;
    }

  lock_acquire (&file_lock);
  struct file *f = process_get_file (fd);
  if (f == NULL)
      return -1;

  off_t bytes = file_write (f, buffer, size);
  lock_release (&file_lock);
  return bytes;
}

void
seek (int fd, unsigned position)
{
  lock_acquire (&file_lock);
  struct file *f = process_get_file (fd);
  file_seek (f, position);
  lock_release (&file_lock);
}

unsigned
tell (int fd)
{
  lock_acquire (&file_lock);
  struct file *f = process_get_file (fd);
  off_t position = file_tell (f);
  lock_release (&file_lock);
  return (unsigned) position;

}

void
close (int fd)
{
  lock_acquire (&file_lock);
  process_close_file (fd);
  lock_release (&file_lock);
}

int
open (const char *file)
{
  check_address ((void *) file);
  lock_acquire (&file_lock);
  struct file *f = filesys_open (file);
  lock_release (&file_lock);
  if (f == NULL)
    {
      return -1;
    }
  int fd = process_add_file (f);
  // lock_release (&file_lock);
  return fd;
}

int
filesize (int fd)
{
  if (fd > 0)
    {
      struct file *f = process_get_file (fd);
      if (f == NULL)
        return -1;
      lock_acquire (&file_lock);
      off_t length = file_length (f);
      lock_release (&file_lock);
      return (int) length;
    }
  else
    return -1;
}
