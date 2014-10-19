#include "unp.h"

#define SERVER_IN "server.in"

int main() {
    FILE *inp_file = fopen(SERVER_IN, "r");

    if (inp_file == NULL) {
        err_quit("Unknown server argument file : '%s'", SERVER_IN);
    }

    Fclose(inp_file);
}
