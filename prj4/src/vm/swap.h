#include "lib/kernel/bitmap.h"
#include <stddef.h>

void swap_init(void);
size_t swap_out(void* kaddr);
void swap_int(size_t used_index, void* kaddr);

struct lock swap_lock;