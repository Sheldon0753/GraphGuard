#include <stdio.h>
#include <stdlib.h>

void allocate_memory(int size) {
    // VULNERABLE: No overflow check before multiplication
    int total_size = size * sizeof(int);
    int* array = (int*)malloc(total_size);
    printf("Allocated %d bytes\n", total_size);
    free(array);
}

int main() {
    int user_size;
    scanf("%d", &user_size);
    allocate_memory(user_size);
    return 0;
}
