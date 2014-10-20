#include "unp.h"
#include "unpifiplus.h"
#include "common.h"

#define CLIENT_IN   "client.in"
#define PARAM_SIZE  100

#define IFI_ADDR(ifi) (((struct sockaddr_in*)ifi->ifi_addr)->sin_addr.s_addr)
#define IFI_MASK(ifi) (((struct sockaddr_in*)ifi->ifi_ntmaddr)->sin_addr.s_addr)

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

static int verifyIfLocal(struct ifi_info *new_client_ifi,
                         struct ifi_info *client_ifi,
                         struct in_addr *server_ip)
{
    in_addr_t new_mask = IFI_MASK(new_client_ifi);

    if ((IFI_ADDR(new_client_ifi) & new_mask) == (server_ip->s_addr & new_mask)) {
        if (client_ifi == NULL || (IFI_MASK(client_ifi) < new_mask))
            return 1;
    }
    return 0;
}

static struct in_addr getClientIP(struct in_addr *server_ip) {
    struct ifi_info *ifi, *ifihead, *local_ifi, *arbitrary_ifi;
    struct in_addr client_ip;
    char buf[INET_ADDRSTRLEN];

    ifihead = Get_ifi_info_plus(AF_INET, 1);

    printf("\nFollowing are different Interfaces:\n");
    print_ifi_info_plus(ifihead);

    local_ifi = arbitrary_ifi = NULL;
    for (ifi = ifihead ; ifi != NULL; ifi = ifi->ifi_next) {
        if (verifyIfLocal(ifi, local_ifi, server_ip)) {
            local_ifi = ifi;
        }
        if (!(ifi->ifi_flags & IFF_LOOPBACK)) {
            arbitrary_ifi = ifi;
        }
    }
    if (local_ifi) {
        client_ip.s_addr = IFI_ADDR(local_ifi);
        printf("\nClient found on Local Interface: ");
    } else if (arbitrary_ifi) {
        client_ip.s_addr = IFI_ADDR(arbitrary_ifi);
        printf("\nClient Not found on Local Interface: ");
    }

    free_ifi_info_plus(ifihead);

    printf("IP => %s\n", inet_ntop(AF_INET, &client_ip, buf, INET_ADDRSTRLEN));
    return client_ip;
}

int main() {
    FILE *inp_file = fopen(CLIENT_IN, "r");
    char inp_params[MAX_PARAMS][PARAM_SIZE];
    struct hostent *hostInfo;
    struct in_addr client_ip;

    // Read input parameters
    if (inp_file != NULL) {
        int i;

        for (i = 0; i < MAX_PARAMS; i++) {
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

    client_ip = getClientIP((struct in_addr*) hostInfo->h_addr);

    return 0;
}

