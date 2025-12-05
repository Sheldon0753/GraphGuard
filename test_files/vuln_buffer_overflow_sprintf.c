#include <stdio.h>

void format_message(char* username) {
    char message[32];
    // VULNERABLE: sprintf without size limit
    sprintf(message, "Welcome, %s!", username);
    printf("%s\n", message);
}

int main() {
    char name[100];
    scanf("%99s", name);
    format_message(name);
    return 0;
}
