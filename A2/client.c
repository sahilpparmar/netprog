#include "unp.h"

#define CLIENT_IN "client.in"

int main() {
    FILE *inp_file = fopen(CLIENT_IN, "r");

    if (inp_file == NULL) {
        err_quit("Unknown client argument file : '%s'", CLIENT_IN);
    }

    Fclose(inp_file);
}
