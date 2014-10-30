#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PAYLOAD_SIZE 512

// Redirect output to some file => ./a.out 1000 >file.txt
int main(int argc, char *argv[]) {
    int i, j;
    char buf[1000];

    if (argc != 2) {
        printf("Please enter number of data payloads to be generated!\n");
        exit(1);
    }

    for (i = 1; i <= atoi(argv[1]); i++) {
        printf("%d", i);
        sprintf(buf, "%d", i);
        for (j = strlen(buf) + 1; j < PAYLOAD_SIZE; j++)
            printf(".");
        printf("\n");
    }
}
