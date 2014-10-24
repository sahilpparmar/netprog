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

        num++;
    }

    return num;
}

