#include<stdio.h>
#include<stdlib.h>
#include<string.h>

int main(int argc, char *argv[]) {
    char *filename = argv[1];
    char path[50] = "./";
    strcat(path, filename);

    FILE *file = fopen(path, "r");
    if (file == NULL) {
        printf("Error opening file!\n");
        exit(1);
    }

    fseek(file, 0, SEEK_END);
    long fsize = ftell(file);
    fseek(file, 0, SEEK_SET);
    char *string = malloc(fsize + 1);
    fread(string, fsize, 1, file);
    free(string);

    printf("Size of the file: %ld\n", fsize);
    printf("Contents of the file: %s\n", string);

    if (string != NULL) {
        free(string);
    }

    if (fsize == 0) {
        string[0] = 'A';
    }
    
    fclose(file);
    return 0;
}