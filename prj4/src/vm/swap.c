#include "swap.h"
#include "frame.h"
#include "page.h"
#include "devices/block.h"

//1이면 사용 중, 0이면 비어있음을 의미
//disk에 있는 swap partiion을 추적하는 메모리 상의 bitmap
struct bitmap* swap_bitmap;
struct block* swap_partition; //disk 상의 swap partition(swap block)을 의미

size_t SECTORS_PER_PAGE = PGSIZE / BLOCK_SECTOR_SIZE; //한 page에 몇개의 sector가 들어가는지 == 8개

//disk 상의 스왑 영역 초기화
void swap_init(void){
    //블록 장치 중에서 BLOCK_SWAP 역할을 가진 장치를 검색하고 반환
    swap_partition = block_get_role(BLOCK_SWAP);

    //disk에 위치한 swap partition에 총 몇개의 page가 들어갈 수 있는지
    //그 개수만큼 bitmap 생성
    swap_bitmap = bitmap_create(block_size(swap_partition)/SECTORS_PER_PAGE);

    lock_init(&swap_lock);
}

//kaddr 주소가 가리키는 페이지를 disk 상의 swap partition 빈 slot에 기록
//해당 slot 번호 반환
size_t swap_out(void* kaddr){
    lock_acquire(&swap_lock);
    int slot_index = bitmap_scan_and_flip(swap_bitmap, 0, 1, false);

    int sector_index = slot_index * SECTORS_PER_PAGE;
    for(size_t i = 0; i < SECTORS_PER_PAGE; i++){
        block_write(swap_partition, sector_index + i, kaddr);
        kaddr += BLOCK_SECTOR_SIZE;
    }

    lock_release(&swap_lock);

    return slot_index;
}

//used_index의 slot에 저장된 데이터를 kaddr로 복사
void swap_in(size_t used_index, void* kaddr){
    lock_acquire(&swap_lock);
    int sector_index = used_index * SECTORS_PER_PAGE;

    for(size_t i = 0; i < SECTORS_PER_PAGE; i++){
        block_read(swap_partition, sector_index + i, kaddr);
        kaddr += BLOCK_SECTOR_SIZE;
    }

    bitmap_set(swap_bitmap, used_index, false);
    lock_release(&swap_lock);
}