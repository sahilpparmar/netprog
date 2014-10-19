#include "unp.h"
#include "common.h"

#define CLIENT_IN   "client.in"
#define PARAM_SIZE  100

enum client_params_t {
    SERVER_IP,      // Server IP
    SERVER_PORT,    // Server PortNo
    FILE_NAME,      // FileName to be transfered
    RECEIVE_WIN,    // Size of receiving sliding window
    RANDOM_SEED,    // Random Gen Seed Value
    PACKET_LOSS,    // Probability of packet loss
    READ_DELAY,     // mean millisec at which client reads data from receving window
    MAX_PARAMS      // total number of params
};

static struct hostent* getHostInfoByAddr(char *hostip) {
    struct hostent *hostInfo = NULL;
    struct in_addr ipInfo;

    if (inet_pton(AF_INET, hostip, &ipInfo) > 0) {
        hostInfo = gethostbyaddr(&ipInfo, sizeof(ipInfo), AF_INET);
    }
    return hostInfo;
}

int main() {
    FILE *inp_file = fopen(CLIENT_IN, "r");
    char inp_params[MAX_PARAMS][PARAM_SIZE];
    struct hostent *hostInfo;

    // Read input parameters
    if (inp_file != NULL) {
        int i;

        for (i = 0; i < MAX_PARAMS; i++) {
            //if (fgets(inp_params[i], PARAM_SIZE, inp_file) == NULL || strlen(inp_params[i]) == 0) {
            if (getParam(inp_file, inp_params[i], PARAM_SIZE) == NULL) {
                err_quit("Invalid client argument file : '%s'", CLIENT_IN);
            }
        }
        Fclose(inp_file);
    } else {
        err_quit("Unknown client argument file : '%s'", CLIENT_IN);
    }

    if ((hostInfo = getHostInfoByAddr(inp_params[SERVER_IP])) == NULL) {
        err_quit("Invalid Server IPAddress - %s", inp_params[SERVER_IP]);
    }

    printf("The server host is -> %s (%s)\n", hostInfo->h_name, inp_params[SERVER_IP]);
}
