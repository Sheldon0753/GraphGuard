#include <stdio.h>
#include <string.h>

void vulnerable_function(char* user_input) {
    char buffer[64];
    // VULNERABLE: No bounds checking
    strcpy(buffer, user_input);
    printf("Data: %s\n", buffer);
}

int main() {
    char input[256];
    gets(input);  // Also vulnerable!
    vulnerable_function(input);
    return 0;
}
