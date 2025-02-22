#include "page.h"
#include "frame.h"
#include "swap.h"
#include <stdlib.h>
#include "userprog/syscall.h"
#include "userprog/pagedir.h"

//해시테이블 초기화
void vm_init(struct hash *vm){
    hash_init(vm, vm_hash_func, vm_less_func, NULL);
}

//vaddr을 키값으로 해시값 반환
static unsigned vm_hash_func(const struct hash_elem *e, void *aux){
    struct vm_entry* entry = hash_entry(e, struct vm_entry, elem);
    return hash_int((int)entry->vaddr);
}

//두 hash_elem의 vaddr기준 정렬
static bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux){
    struct vm_entry* entry_a = hash_entry(a, struct vm_entry, elem);
    struct vm_entry* entry_b = hash_entry(b, struct vm_entry, elem);
    return entry_a->vaddr < entry_b->vaddr;
}

//vm_entry insert
bool insert_vme(struct hash *vm, struct vm_entry *vme){
    if(hash_insert(vm, &(vme->elem)) == NULL) return true;
    return false;
}

//vm_entry delete
bool delete_vme(struct hash *vm, struct vm_entry *vme){
    if(hash_delete(vm, &(vme->elem)) != NULL) return true;
    return false;
}

//해시테이블에서 vme 찾아서 반환
struct vm_entry *find_vme(void *vaddr){
    //pg_round_down()으로 vaddr의 페이지의 vaddr 얻음 -> 이 값을 기준으로 해시 테이블에서 찾음
    struct vm_entry vme;
    vme.vaddr = pg_round_down(vaddr); //vaddr이 속한 페이지의 시작 주소

    //hash_find() 함수로 hash_elem 구조체 얻음
    struct hash* table = &thread_current()->supplemental_table;
    struct hash_elem* e = NULL;
    e = hash_find(table, &vme.elem);

    if(e != NULL) return hash_entry(e, struct vm_entry, elem);
    else return NULL;
}

static void destructor(struct hash_elem* e, void* aux){
    struct vm_entry* entry = hash_entry(e, struct vm_entry, elem);
    
    //만약 load되어 있는 상태라면 page 삭제 필요
    if(entry->is_loaded == true){
        //page 삭제
        free_page(pagedir_get_page(thread_current()->pagedir, entry->vaddr));
        //page table에서 not present 상태로 표시
        pagedir_clear_page(thread_current()->pagedir, entry->vaddr);
    }
    free(entry);
}

//해시테이블에서 모든 vme 삭제
//프로세스 종료 시 사용
void vm_destroy(struct hash *vm){
    hash_destroy(vm, destructor);
}

//디스크에서 메모리로 페이지 단위로 load
bool load_file(void* kaddr, struct vm_entry* vme){
    struct file* file = vme->file;
    size_t vme_offset = vme->offset;
    size_t vme_read_bytes = vme->read_bytes;
    size_t vme_zero_bytes = vme->zero_bytes;

    size_t read_bytes = 0;
    if(vme_read_bytes > 0){
        lock_acquire(&file_access_lock);

        file_seek(file, vme_offset);
        read_bytes = file_read(file, kaddr, vme_read_bytes);

        lock_release(&file_access_lock);

        //남은 부분 0으로 패딩
        memset(kaddr + vme_read_bytes, 0, vme_zero_bytes);
    }

    return read_bytes == vme_read_bytes;
}

//lru_list, lru_list_lock, lru_clock 초기화
void lru_list_init(void){
    list_init(&lru_list);
    lock_init(&lru_list_lock);
    lru_clock = NULL;
}
