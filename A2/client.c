#include "unp.h"
#include "unpifiplus.h"
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

static int verifyIfLocal(struct in_addr *client_ip, struct in_addr *mask, struct in_addr *server_ip) {
    if ((client_ip->s_addr & mask->s_addr) == (server_ip->s_addr & mask->s_addr))
        return 1;
    return 0;
}


int main() {
    FILE *inp_file = fopen(CLIENT_IN, "r");
    char inp_params[MAX_PARAMS][PARAM_SIZE];
    struct hostent *hostInfo;

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

    // Verfiy if server ip is in local network
    {
        struct ifi_info *ifi, *ifihead;
        struct sockaddr *sa;
	u_char          *ptr;
        int             i;

        printf("Different IP Addresses:\n");
        for (ifihead = ifi = Get_ifi_info_plus(AF_INET, 1);
                ifi != NULL; ifi = ifi->ifi_next) 
        {
            printf("  %s: ", ifi->ifi_name);
            if (ifi->ifi_index != 0)
                printf("(%d) ", ifi->ifi_index);
            printf("< ");
            /* *INDENT-OFF* */
            if (ifi->ifi_flags & IFF_UP)            printf("UP ");
            if (ifi->ifi_flags & IFF_BROADCAST)     printf("BCAST ");
            if (ifi->ifi_flags & IFF_MULTICAST)     printf("MCAST ");
            if (ifi->ifi_flags & IFF_LOOPBACK)      printf("LOOP ");
            if (ifi->ifi_flags & IFF_POINTOPOINT)   printf("P2P ");
            printf(">\n");
            /* *INDENT-ON* */

            if ( (i = ifi->ifi_hlen) > 0) {
                ptr = ifi->ifi_haddr;
                do {
                    printf("%s%x", (i == ifi->ifi_hlen) ? "  " : ":", *ptr++);
                } while (--i > 0);
                printf("\n");
            }
            if (ifi->ifi_mtu != 0)
                printf("    MTU: %d\n", ifi->ifi_mtu);

            if ( (sa = ifi->ifi_addr) != NULL)
                printf("    IP addr: %s\n",
                        Sock_ntop_host(sa, sizeof(*sa)));

            /*=================== cse 533 Assignment 2 modifications ======================*/

            if ((sa = ifi->ifi_ntmaddr) != NULL)
                printf("    network mask: %s\n",
                        Sock_ntop_host(sa, sizeof(*sa)));

            /*=============================================================================*/

            if ((sa = ifi->ifi_brdaddr) != NULL)
                printf("    broadcast addr: %s\n",
                        Sock_ntop_host(sa, sizeof(*sa)));
            if ((sa = ifi->ifi_dstaddr) != NULL)
                printf("    destination addr: %s\n",
                        Sock_ntop_host(sa, sizeof(*sa)));

            if (verifyIfLocal(&((struct sockaddr_in*)ifi->ifi_addr)->sin_addr,
                          &((struct sockaddr_in*)ifi->ifi_ntmaddr)->sin_addr,
                          (struct in_addr*)hostInfo->h_addr)
            ) {
                printf(" ----> isLOCAL");

            }
        }

        free_ifi_info_plus(ifihead);
    }
}

