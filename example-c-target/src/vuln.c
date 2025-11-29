#include <stdio.h>
#include <string.h>

void vulnerable_copy(const char *input) {
    char buffer[16];
    size_t len = strlen(input);
    memcpy(buffer, input, len); // deliberate overflow
    buffer[15] = '\0';
    printf("You entered: %s\n", buffer);
}

int main(int argc, char **argv) {
    const char *payload = argc > 1 ? argv[1] : "this input is definitely longer than sixteen bytes";
    vulnerable_copy(payload);
    return 0;
}

