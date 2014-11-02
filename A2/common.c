/***
 * common.c - contains common code between client and server
 *
 ***/
#include "unp.h"
#include "unpifiplus.h"
#include "common.h"

static char* getParam(FILE *fp, char *ptr, int n) {
    char line[MAXLINE];

    if (fgets(line, n, fp) == NULL || strlen(line) == 0) {
        return NULL;
    }
    
    if (sscanf(line, "%s", ptr) > 0)
        return ptr;
    return NULL;
}

char* getStringParamValue(FILE *inp_file, char *paramVal) {
    if (getParam(inp_file, paramVal, PARAM_SIZE) == NULL) {
        err_quit("Invalid parameter\n");
    }
    return paramVal;
}

int getIntParamValue(FILE *inp_file) {
    char paramStr[PARAM_SIZE];
    int paramIVal;

    if (getParam(inp_file, paramStr, PARAM_SIZE) == NULL ||
        ((paramIVal = atoi(paramStr)) == 0)
    ) {
        err_quit("Invalid parameter\n");
    }
    return paramIVal;
}

float getFloatParamValue(FILE *inp_file) {
    char paramStr[PARAM_SIZE];

    if (getParam(inp_file, paramStr, PARAM_SIZE) == NULL) {
        err_quit("Invalid parameter\n");
    }
    return atof(paramStr);
}

int print_ifi_info_plus(struct ifi_info *ifihead) {
    struct ifi_info *ifi;
    struct sockaddr *sa;
    u_char          *ptr;
    int             i, num;

    printf("\nFollowing are different Interfaces: \n");
    for (num = 0, ifi = ifihead; ifi != NULL; ifi = ifi->ifi_next) {
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

        if ((i = ifi->ifi_hlen) > 0) {
            ptr = ifi->ifi_haddr;
            do {
                printf("%s%x", (i == ifi->ifi_hlen) ? "  " : ":", *ptr++);
            } while (--i > 0);
            printf("\n");
        }
        if (ifi->ifi_mtu != 0)
            printf("    MTU: %d\n", ifi->ifi_mtu);

        if ((sa = ifi->ifi_addr) != NULL)
            printf("    IP addr: %s\n",
                    Sock_ntop_host(sa, sizeof(*sa)));

        if ((sa = ifi->ifi_ntmaddr) != NULL)
            printf("    network mask: %s\n",
                    Sock_ntop_host(sa, sizeof(*sa)));

        if ((sa = ifi->ifi_brdaddr) != NULL)
            printf("    broadcast addr: %s\n",
                    Sock_ntop_host(sa, sizeof(*sa)));
        if ((sa = ifi->ifi_dstaddr) != NULL)
            printf("    destination addr: %s\n",
                    Sock_ntop_host(sa, sizeof(*sa)));

        num++;
    }
    printf("\n");

    return num;
}

#define IFI_ADDR(ifi) (((struct sockaddr_in*)ifi->ifi_addr)->sin_addr.s_addr)
#define IFI_MASK(ifi) (((struct sockaddr_in*)ifi->ifi_ntmaddr)->sin_addr.s_addr)

static int verifyIfLocal(struct ifi_info *new_host_ifi,
                         struct ifi_info *host_ifi,
                         struct in_addr *remote_ip)
{
    in_addr_t new_mask = IFI_MASK(new_host_ifi);

    if ((IFI_ADDR(new_host_ifi) & new_mask) == (remote_ip->s_addr & new_mask)) {
        // Get longest prefix match
        if (host_ifi == NULL || (IFI_MASK(host_ifi) < new_mask))
            return 1;
    }
    return 0;
}

int verifyIfLocalAndGetHostIP(struct ifi_info *ifihead,
                              struct in_addr *remote_ip,
                              struct in_addr *host_ip)
{
    struct ifi_info *ifi, *local_ifi, *arbitrary_ifi;
    int isLocal;

    local_ifi = arbitrary_ifi = NULL;
    for (ifi = ifihead ; ifi != NULL; ifi = ifi->ifi_next) {
        if (verifyIfLocal(ifi, local_ifi, remote_ip)) {
            local_ifi = ifi;
        }
        if (!(ifi->ifi_flags & IFF_LOOPBACK)) {
            arbitrary_ifi = ifi;
        }
    }

    if (local_ifi) {
        if (host_ip) host_ip->s_addr = IFI_ADDR(local_ifi);
        isLocal = 1;
    } else if (arbitrary_ifi) {
        if (host_ip) host_ip->s_addr = IFI_ADDR(arbitrary_ifi);
        isLocal = 0;
    } else {
        isLocal = -1;
    }

    return isLocal;
}

int setTimer(struct itimerval *timer, long int milliSec) {
    
    timer->it_interval.tv_sec = 0;
    timer->it_interval.tv_usec = 0;
    
    timer->it_value.tv_sec = milliSec / 1000;
    timer->it_value.tv_usec = (milliSec % 1000) *1000;
    
    if( setitimer(ITIMER_REAL, timer, 0) != 0) {
        printf("Error in setting timer \n");
        exit(0);
    }
}
int fillPckt(TcpPckt *packet, uint32_t seqNum, uint32_t ackNum,
            uint32_t winSize, char* dataPtr, int len) {
    packet->seqNum = seqNum;
    packet->ackNum = ackNum;
    packet->winSize = winSize;
    if (dataPtr == NULL){
        packet->data[0] = '\0';
        return HEADER_LEN;
    }
    if (memcpy((void *)packet->data, (const void *) dataPtr, (size_t) len) == NULL) {
        printf("Error detected in memcpy while reading packet\n");
        return -1;
    }
    packet->data[MAX_PAYLOAD] = '\0';
    return HEADER_LEN + len;
}

int readPckt(TcpPckt *packet, int packet_size, uint32_t *seqNum,
            uint32_t *ackNum, uint32_t *winSize, char* dataPtr) {
    if (seqNum  != NULL) *seqNum = packet->seqNum;
    if (ackNum  != NULL) *ackNum = packet->ackNum;
    if (winSize != NULL) *winSize = packet->winSize;
    if (dataPtr != NULL) {
        if (memcpy((void *)dataPtr, (const void *)packet->data, packet_size-HEADER_LEN) == NULL) {
            printf("Error detected in memcpy while reading packet \n");
            return -1;
        }
        dataPtr[packet_size - HEADER_LEN] = '\0';
    }
    return 0;
}

