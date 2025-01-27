#include "userprog/syscall.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "userprog/pagedir.h"


static void syscall_handler (struct intr_frame *);
void halt(void);
void exit(int status);
int exec(char *cmd_line);
int wait(tid_t pid);
int read(int fd, void* buffer, unsigned size);
int write(int fd, void* buffer, unsigned size);
void check_valid_addr(uint32_t* esp, int cnt);
int max_of_four_int(int a, int b, int c, int d);
int fibonacci(int n);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void check_valid_addr(uint32_t* esp, int cnt){
  for(int i = 0; i <= cnt; i++){
    //커널 공간인지, null 포인터인지
    if((esp + 4 * i) == NULL || is_kernel_vaddr(esp + 4 * i)){
      exit(-1);
    }

    //a pointer to unmapped virtual memory
    if(pagedir_get_page(thread_current()->pagedir, esp + 4 * i) == NULL){
      exit(-1);
    }
  }
}

void halt(void){
  shutdown_power_off();
}

void exit(int status){
  struct thread* current_thread = thread_current();

  char* next_ptr;
  char tmp[128];

  strlcpy(tmp, current_thread->name, strlen(current_thread-> name) + 1);

  char* ret_ptr = strtok_r(tmp, " ", &next_ptr);

  printf("%s: exit(%d)\n", ret_ptr, status);
  current_thread -> exit_status = status;

  thread_exit();
}

int exec(char *cmd_line){
  return process_execute(cmd_line);
}

int wait(tid_t pid){
  return process_wait(pid);
}

int read(int fd, void* buffer, unsigned size){
  int i;
  uint8_t temp;
  
  for(i=0;(i<size) && (temp=input_getc());i++){
      *(uint8_t*)(buffer+i)=temp;
    }

  return i;
}

int write(int fd, void* buffer, unsigned size){
  putbuf(buffer, size);
  return size;
}

int max_of_four_int(int a, int b, int c, int d){
  int max1, max2;
  if(a >= b) max1 = a;
  else if(a < b) max1 = b;

  if(c >= d) max2 = c;
  else if(c < d) max2 = d;

  if(max1 >= max2) return max1;
  else if(max1 < max2) return max2;
}

int fibonacci(int n){
  if(n == 1 || n == 2) return 1;
  else return fibonacci(n - 1) + fibonacci(n - 2);
}

static void
syscall_handler (struct intr_frame *f) 
{
  //syscall number마다 필요한 argc 저장하는 배열
  int arg_cnt[22];
  arg_cnt[SYS_HALT] = 0;

  arg_cnt[SYS_EXIT] = 1;

  arg_cnt[SYS_EXEC] = 1;

  arg_cnt[SYS_WAIT] = 1;

  arg_cnt[SYS_READ] = 3;

  arg_cnt[SYS_WRITE] = 3;

  arg_cnt[MAX_OF_FOUR_INT] = 4;

  arg_cnt[FIBONACCI] = 1;
  
  uint32_t* esp = (uint32_t*)f->esp;
  check_valid_addr(esp, arg_cnt[*esp]);


  if (*esp == SYS_HALT) {
    halt();
  }
  else if (*esp == SYS_EXIT) {
    int status = (int)*(esp + 1);
    exit(status);
  }
  else if (*esp == SYS_EXEC) {
    char *cmd_line = (char*)*(esp + 1);
    f->eax = exec(cmd_line);
  }
  else if (*esp == SYS_WAIT) {
    tid_t pid = (tid_t)*(esp + 1);
    f->eax = wait(pid);
  } 
  else if (*esp == SYS_READ) {
    int fd = (int)*(esp + 1);
    void* buffer = (void*)*(esp + 2);
    unsigned size = (unsigned)*(esp + 3);
    f->eax = read(fd, buffer, size);
  }
  else if (*esp == SYS_WRITE) {
    int fd = (int)*(esp + 1);
    void* buffer = (void*)*(esp + 2);
    unsigned size = (unsigned)*(esp + 3);
    f->eax = write(fd, buffer, size);
  }
  else if(*esp == MAX_OF_FOUR_INT){
    int a = (int)*(esp + 1);
    int b = (int)*(esp + 2);
    int c = (int)*(esp + 3);
    int d = (int)*(esp + 4);
    f->eax = max_of_four_int(a, b, c, d);

  }
  else if(*esp == FIBONACCI){
    int n = (int)*(esp + 1);
    f->eax = fibonacci(n);
  }
  else {
    exit(-1);
  }
}
