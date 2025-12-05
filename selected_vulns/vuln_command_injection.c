#include <stdio.h>
#include <stdlib.h>

void process_file(char* filename) {
    char command[256];
    // VULNERABLE: User input in system command
    sprintf(command, "cat %s", filename);
    system(command);
}

int main() {
    char file[100];
    scanf("%99s", file);
    process_file(file);
    return 0;
}
