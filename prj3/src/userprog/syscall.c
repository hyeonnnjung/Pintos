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
#include "userprog/process.h"
#include "devices/input.h"
#include "threads/synch.h"
#include "filesys/file.h"
#include "filesys/filesys.h"


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

bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
void close(int fd);
int filesize(int fd);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void check_valid_filename(const char *file);
void check_valid_file(struct file *file_ptr);
void check_valid_fd(int fd);


struct lock file_access_lock;


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_access_lock);
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

//filename이 NULL인 경우 체크
void check_valid_filename(const char *file){
  if(file == NULL) exit(-1);
}

//file ptr이 NULL인 경우 체크
void check_valid_file(struct file *file_ptr){
  if(file_ptr == NULL) exit(-1);
}

void check_valid_fd(int fd){
  if(fd < 3 || fd >= 130) exit(-1);
}

//prj1
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
  tid_t child_tid = process_execute(cmd_line);

  if(child_tid != -1){
    struct list_elem* elem;
    struct list* child_list = &(thread_current()->child_threads);
    struct thread* child;

    for(elem = list_begin(child_list); elem != list_end(child_list); elem = list_next(elem)){
      child = list_entry(elem, struct thread, child_elem);

      if(child->tid == child_tid){
        //자식이 메모리에 load되는 동안 부모 동작 제한
        //이 코드를 실행시키는 주인이 부모이므로 sema_down을 사용해서
        //여기서 부모 프로세스가 대기하도록 구현
        sema_down(&(child->wait_load));
      }
    }
    if(child->exec_flag == false) return -1; //자식 프로세스 load에 실패한 경우
  }
  return child_tid;
}

int wait(tid_t pid){
  return process_wait(pid);
}

int read(int fd, void* buffer, unsigned size){
  if(fd < 0 || fd == 1 || fd >= 130) exit(-1);

  //buffer 주소 체크
  check_valid_addr(buffer, 1);

  lock_acquire(&file_access_lock);

  //stdin인 경우, 키보드 입력을 읽음
  if(fd == 0){
    int i;
    uint8_t temp;
  
    for(i = 0; (i < size) && (temp = input_getc()); i++){
      *(uint8_t*)(buffer + i) = temp;
    }

    lock_release(&file_access_lock);
    return i;
  }
  //그 이외의 입력
  else{
    struct thread* current_thread = thread_current();
    struct file* target_file = current_thread->fd_table[fd];
    
    if(target_file == NULL || fd == 2){
      lock_release(&file_access_lock);
      exit(-1);
    }

    int byte = file_read(target_file, buffer, size);
    lock_release(&file_access_lock);
    return byte;
  }
}

int write(int fd, void* buffer, unsigned size){
  if(fd < 0 || fd == 0 || fd >= 130) exit(-1);

  //buffer 주소 체크
  check_valid_addr(buffer, 1);

  lock_acquire(&file_access_lock);

  //stdout인 경우, 콘솔 출력
  if(fd == 1){
    putbuf(buffer, size);
    lock_release(&file_access_lock);
    return size;
  }
  //그 이외의 출력
  else{
    struct thread* current_thread = thread_current();
    struct file* target_file = current_thread->fd_table[fd];
    
    if(target_file == NULL || fd == 2){
      lock_release(&file_access_lock);
      exit(-1);
    }

    int byte = file_write(target_file, buffer, size);
    lock_release(&file_access_lock);
    return byte;
  }
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
  //if(n == 1 || n == 2) return 1;
  //else return fibonacci(n - 1) + fibonacci(n - 2);
  int a = 1;
  int b = 1;
  int res = 0;
  for(int i = 2; i < n; i++){
    res = a + b;
    a = b;
    b = res;
  }
  return res;
}


//prj2
bool create(const char *file, unsigned initial_size){
  check_valid_filename(file);
  return filesys_create(file, initial_size);
}

bool remove(const char *file){
  check_valid_filename(file);
  if(!is_user_vaddr(file)) exit(-1);
  return filesys_remove(file);
}

int open(const char *file){
  check_valid_filename(file);
  if(!is_user_vaddr(file)) exit(-1);

  //file 열 때, 다른 곳에서 file 수정하는 것 방지
  lock_acquire(&file_access_lock);

  struct file* open_file = filesys_open(file);
  //file 열기에 실패한 경우
  if(open_file == NULL){
    lock_release(&file_access_lock);
    return -1;
  }

  //file 열기에 성공했으면 fd_table에 넣어주어야 함
  struct thread* current_thread = thread_current();
  int i;
  for(i = 3; i < 130; i++){
    if(current_thread->fd_table[i] == NULL){
      current_thread->fd_table[i] = open_file;
      break;
    }
  }
  //fd_table이 모두 찬 경우
  if(i == 130) {
    file_close(open_file);
    lock_release(&file_access_lock);
    return -1;
  }

  lock_release(&file_access_lock);
  return i;
}

void close(int fd){
  check_valid_fd(fd);

  struct thread* current_thread = thread_current();
  struct file* target_file = current_thread->fd_table[fd];
  check_valid_file(target_file);

  file_close(target_file);
  current_thread->fd_table[fd] = NULL;
}

int filesize(int fd){
  check_valid_fd(fd);

  struct thread* current_thread = thread_current();
  struct file* target_file = current_thread->fd_table[fd];
  check_valid_file(target_file);

  return file_length(target_file);
}

void seek(int fd, unsigned position){
  check_valid_fd(fd);

  struct thread* current_thread = thread_current();
  struct file* target_file = current_thread->fd_table[fd];
  check_valid_file(target_file);

  return file_seek(target_file, position);
}

unsigned tell(int fd){
  check_valid_fd(fd);

  struct thread* current_thread = thread_current();
  struct file* target_file = current_thread->fd_table[fd];
  check_valid_file(target_file);

  return file_tell(target_file);
}

static void
syscall_handler (struct intr_frame *f) 
{
  //syscall number마다 필요한 argc 저장하는 배열
  int arg_cnt[22];

  //prj1
  arg_cnt[SYS_HALT] = 0;
  arg_cnt[SYS_EXIT] = 1;
  arg_cnt[SYS_EXEC] = 1;
  arg_cnt[SYS_WAIT] = 1;
  arg_cnt[SYS_READ] = 3;
  arg_cnt[SYS_WRITE] = 3;
  arg_cnt[MAX_OF_FOUR_INT] = 4;
  arg_cnt[FIBONACCI] = 1;

  
  //prj2
  arg_cnt[SYS_CREATE] = 2;
  arg_cnt[SYS_REMOVE] = 1;
  arg_cnt[SYS_OPEN] = 1;
  arg_cnt[SYS_CLOSE] = 1;
  arg_cnt[SYS_FILESIZE] = 1;
  arg_cnt[SYS_SEEK] = 2;
  arg_cnt[SYS_TELL] = 1;

  
  uint32_t* esp = (uint32_t*)f->esp;
  check_valid_addr(esp, arg_cnt[*esp]);


  //prj1
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
  //prj2
  else if(*esp == SYS_CREATE){
    char *file = (char*)*(esp + 1);
    unsigned initial_size = (unsigned)*(esp + 2);
    f->eax = create(file, initial_size);
  }
  else if(*esp == SYS_REMOVE){
    char *file = (char*)*(esp + 1);
    f->eax = remove(file);
  }
  else if(*esp == SYS_OPEN){
    char *file = (char*)*(esp + 1);
    f->eax = open(file);
  }
  else if(*esp == SYS_CLOSE){
    int fd = (int)*(esp + 1);
    close(fd);
  }
  else if(*esp == SYS_FILESIZE){
    int fd = (int)*(esp + 1);
    f->eax = filesize(fd);
  }
  else if(*esp == SYS_SEEK){
    int fd = (int)*(esp + 1);
    unsigned position = (unsigned)*(esp + 2);
    seek(fd, position);
  }
  else if(*esp == SYS_TELL){
    int fd = (int)*(esp + 1);
    f->eax = tell(fd);
  }
  else {
    exit(-1);
  }
}
