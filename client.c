#include<stdio.h>

int main(int argc, char **argv) {
    
    if (argc != 2) {
        fprintf(stderr, "Invalid Usage \"client <IPAddress>\"\n");
        return -1;
    }

    return 0;
}
