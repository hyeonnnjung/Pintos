#include "lib/kernel/hash.h"
#include "threads/vaddr.h"
#include <stdlib.h>
#include "filesys/file.h"
#include <string.h>
#include "threads/thread.h"
#include "threads/palloc.h"

#define VM_BINARY 0 //프로세스 load할 때 생긴 page임을 entry가 나타냄
#define VM_SWAP 1 //swap의 대상
#define VM_MAPPED 2 //memory mapping시 만들어진 page

#ifndef VM_PAGE_H
#define VM_PAGE_H

struct vm_entry{
    uint8_t type; //pte type
    void *vaddr; //VPN
    
    bool writable; //true : write 가능
    bool is_loaded; //true : physical memory에 loaded

    struct file *file; //mapping된 file : 해당 페이지가 속한 file
    size_t offset; //읽어야 할 file offset
    size_t read_bytes; //page에 쓰여져 있는 data 크기
    size_t zero_bytes; //0으로 채울 남은 page bytes

    //page가 mmap list에 속해 있는 경우
    struct list_elem mmap_elem; //mmap list element

    struct hash_elem elem; //hash table element, hash table == supplement page table

    size_t swap_slot; //swap slot : 해당 page가 Swap type인 경우 어떤 slot에 위치해있는지 (== 인덱스)

    //pinned 상태인 페이지는 victim 후보에서 제외
    //pinned가 false이면 Accessed 비트를 검사해서 victim 선정 가능성을 평가
    bool pinned;
};

struct mmap_file{
    int mapid;
    struct list_elem elem;
    struct vm_entry* vme;
};

struct page{
    void* kaddr; //페이지의 물리주소
    struct vm_entry *vme; //물리 페이지가 매핑된 가상 주소의 vm_entry 포인터
    struct thread *thread; //해당 물리 페이지를 사용 중인 스레드의 포인터
    struct list_elem lru; //list 연결을 위한 필드
};

//프로세스 생성 시, supplement 페이지 테이블(해시 테이블) 초기화
void vm_init(struct hash *vm);
static unsigned vm_hash_func(const struct hash_elem *e, void *aux);
static bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux);

//vm_entry를 해시 테이블에 추가
bool insert_vme(struct hash *vm, struct vm_entry *vme);
bool delete_vme(struct hash *vm, struct vm_entry *vme);

//page fault 발생하면 해시 테이블에서 vm_entry 탐색
struct vm_entry *find_vme(void *vaddr);

//프로세스 종료 시, 해시 테이블의 버킷리스트와 vm_entry 제거
void vm_destroy(struct hash *vm);
static void destructor(struct hash_elem* e, void* aux);

//디스크에서 메모리로 load
bool load_file(void* kaddr, struct vm_entry* vme);

struct list lru_list;		// page 구조체의 리스트
struct lock lru_list_lock;
void* lru_clock;

void lru_list_init(void);

#endif