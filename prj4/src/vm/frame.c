#include "frame.h"
#include "page.h"
#include "swap.h"
#include <stdlib.h>
#include "lib/kernel/list.h"
#include "userprog/syscall.h"


//LRU 알고리즘에 따라 페이지 할당 + LRU 리스트에 page 구조체 삽입
struct page* alloc_page(enum palloc_flags flags){
    void* kaddr = palloc_get_page(flags);
    if(kaddr == NULL){
        kaddr = try_to_free_pages(flags);
    }
    
    struct page* page = (struct page*)malloc(sizeof(struct page));
    page->kaddr = kaddr;
    page->thread = thread_current();
    page->vme = NULL;

    add_page_to_lru_list(page);
    return page;
}

//물리 주소 kaddr에 해당하는 page 구조체를 lru 리스트에서 검색
//매치되는 것 찾으면 __free_page() 호출
void free_page(void* kaddr){
    struct list_elem* elem;
    struct page* p = NULL;

    for(elem = list_begin(&lru_list) ; elem != list_end(&lru_list) ; elem = list_next(elem)){
        p = list_entry(elem, struct page, lru);
        if(p->kaddr == kaddr){
            //lru_clock이 삭제할 elem을 갖고 있음
            if(lru_clock != NULL && lru_clock == elem){
                if(list_size(&lru_list) == 1) lru_clock = NULL;
                else{
                    if(list_end(&lru_list) == lru_clock){
                        lru_clock = list_front(&lru_list);
                    }
                    else{
                        lru_clock = list_next(lru_clock);
                    }
                }
            }
            __free_page(p);
            break;
        }
    }
}

//LRU 리스트에서 page 제거하고 메모리 공간 해제
void __free_page(struct page* page){
    del_page_from_lru_list(page);
    palloc_free_page(page->kaddr);
    free(page);
}

//clock 알고리즘에서 lru 리스트의 다음 노드 위치를 반환
//victim이 될 페이지를 선택하는 것
struct list_elem* get_next_lru_clock(void){
    lock_acquire(&lru_list_lock);
    if(lru_clock == NULL){
        //lru list가 비어있는 경우
        if(list_empty(&lru_list)){
            lock_release(&lru_list_lock);
            return lru_clock;
        }
        //lru list가 비어있지 않은 경우
        else{
            lru_clock = list_front(&lru_list); //list의 맨 앞으로 일단 설정
        }
    }

    //lru_clock이 NULL이 아니지만 list가 비어있는 경우 -> NULL로 설정하고 반환
    if(list_empty(&lru_list)){
        lru_clock = NULL;
        lock_release(&lru_list_lock);
        return lru_clock;
    }

    //list의 맨 앞부터 돌면서 victim 찾기
    while(true){
        struct page* p = list_entry((struct list_elem*) lru_clock, struct page, lru);
        
        //victim 후보에서 제외되는 page인 경우 -> 검사 X
        //pinned가 false인 것만 검사
        if(!p->vme->pinned){
            //accessed bit가 1이면 -> 0으로 바꾸고 second chance
            if(pagedir_is_accessed(p->thread->pagedir, p->vme->vaddr)){
                pagedir_set_accessed(p->thread->pagedir, p->vme->vaddr, false);
            }
            //accessed bit가 0이면 -> victim
            else break;
        }

        //circular list로 순회하기
        if(lru_clock == list_back(&lru_list)){
            lru_clock = list_front(&lru_list);
        }
        else lru_clock = list_next(lru_clock);
    }
    
    lock_release(&lru_list_lock);
    return lru_clock;
}

//clock 알고리즘을 사용해서 여유 메모리를 확보하고
//여유 페이지의 커널 가상 주소 반환
void* try_to_free_pages(enum palloc_flags flags){
    //victim page 선정
    struct list_elem* elem = get_next_lru_clock();
    struct page* victim_page = list_entry(elem, struct page, lru);

    void* kaddr = victim_page->kaddr;
    void* uaddr = victim_page->vme->vaddr;

    //만약 VM_BINARY이면 -> dirsty bit 체크 -> 1이면 swap out
    if(victim_page->vme->type == VM_BINARY){
        if(pagedir_is_dirty(victim_page->thread->pagedir, uaddr)){
            victim_page->vme->type = VM_SWAP;
            victim_page->vme->swap_slot = swap_out(kaddr);
        }
    }
    //만약 VM_SWAP이면 -> 항상 swap out
    else if(victim_page->vme->type == VM_SWAP){
        victim_page->vme->swap_slot = swap_out(kaddr);
    }

    //is_loaded 수정 + pagedir에서 삭제 + 페이지 삭제
    victim_page->vme->is_loaded = false;
    pagedir_clear_page(victim_page->thread->pagedir, uaddr);
    free_page(kaddr);

    //새로운 주소 할당
    return palloc_get_page(flags);
}

//LRU list의 끝에 유저 페이지 삽입
void add_page_to_lru_list(struct page* page){
    lock_acquire(&lru_list_lock);
    list_push_back(&lru_list, &(page->lru));
    lock_release(&lru_list_lock);
}

//LRU list에 유저 페이지 제거
void del_page_from_lru_list(struct page* page){
    struct list_elem* elem;
    struct page* delete_page = NULL;

    lock_acquire(&lru_list_lock);
    list_remove(&page->lru);
    lock_release(&lru_list_lock);
}