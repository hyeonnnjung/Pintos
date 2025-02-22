#include <stdio.h>
#include <stdlib.h>
#include "../lib/user/syscall.h"

int main(int argc, char* argv[]){
    if(argc != 5){
        printf("usage : additional int1 int2 int3 int4");
        return EXIT_FAILURE;
    }
    
    int a = atoi(argv[1]);
    int b = atoi(argv[2]);
    int c = atoi(argv[3]);
    int d = atoi(argv[4]);

    printf("%d ", fibonacci(a));
    printf("%d\n", max_of_four_int(a, b, c, d));

    return 0;
}