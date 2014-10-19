#include "unp.h"
#include <stdio.h>

#define SERVER_IN "server.in"
#define READ_BUFF 1024

int main() {
    FILE *inp_file = fopen(SERVER_IN, "r");
    int PORT_NO, WINDOW_SIZE;

    if (inp_file == NULL) {
        err_quit("Unknown server argument file : '%s'\n", SERVER_IN);
    }

    char line[READ_BUFF];

    if(fgets(line, sizeof line, inp_file) != NULL) /* read a Port number*/
    {
        if(atoi(line) == 0)
        {
            printf("Port number not set correctly\n");
            exit(0);
        }
        printf("Port number read: %d\n", atoi(line));
        PORT_NUM = atoi(line);
    }
    
    if(fgets(line, sizeof line, inp_file) != NULL) /* read a Port number*/
    {
        if(atoi(line) == 0)
        {
            printf("Window size not set correctly\n");
            exit(0);
        }
        printf("Window Size read: %d\n", atoi(line));
        WINDOW_SIZE = atoi(line);
    }





    Fclose(inp_file);
}
