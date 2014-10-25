#include "unp.h"
#include "unpifiplus.h"
#include "common.h"
#include "setjmp.h"

#define IFI_ADDR(ifi) (((struct sockaddr_in*)ifi->ifi_addr)->sin_addr.s_addr)
#define IFI_MASK(ifi) (((struct sockaddr_in*)ifi->ifi_ntmaddr)->sin_addr.s_addr)
#define _1TAB    "\t"
#define _2TABS   "\t\t"
#define _3TABS   "\t\t\t"
#define _4TABS   "\t\t\t\t"

static char  in_server_ip[PARAM_SIZE];     // Server IP
static int   in_server_port;               // Server PortNo
static char  in_file_name[PARAM_SIZE];     // FileName to be transfered
static int   in_receive_win;               // Size of receiving sliding window
static int   in_random_seed;               // Random Gen Seed Value
static float in_packet_loss;               // Probability of packet loss
static int   in_read_delay;                // mean millisec at which client reads data from receving window

static int isPacketLost() {
    double rval = drand48();
    //printf("%f %f", rval, in_packet_loss);
    if (rval > in_packet_loss) {
        return 0;
    }
    return 1;
}

static int writeWithPacketDrops(int fd, SA* sa, int salen, void *ptr, size_t nbytes, int flags, char *msg) {
    printf("%s : ", msg);
    if (isPacketLost()) {
        err_msg(_3TABS "Lost");
        return -1;
    }
    printf(_4TABS "Sent\n");
    Writen(fd, ptr, nbytes);//, flags, sa, salen);
    return 1;
}

static int readWithPacketDrops(int fd, void *ptr, size_t nbytes, int flags, char *msg) {
    int n;
     while (1) {
        printf("%s : ", msg);
        n = Read(fd, ptr, nbytes);//, flags, NULL, NULL);
        if (isPacketLost()) {
            err_msg(_3TABS "Lost");
        } else {
            break;
        }
    }
    printf(_4TABS "Received\n", msg);
    return n;
}

static void parseClientParams() {
    FILE *inp_file = fopen(CLIENT_IN, "r");

    // Read input parameters
    if (inp_file != NULL) {
        getStringParamValue(inp_file, in_server_ip);
        in_server_port = getIntParamValue(inp_file);
        getStringParamValue(inp_file, in_file_name);
        in_receive_win = getIntParamValue(inp_file);
        in_random_seed = getIntParamValue(inp_file);
        in_packet_loss = getFloatParamValue(inp_file);
        in_read_delay  = getIntParamValue(inp_file);

        Fclose(inp_file);
    } else {
        err_quit("Unknown client argument file : '%s'", CLIENT_IN);
    }
}

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

static int getClientIP(struct in_addr *server_ip, struct in_addr *client_ip) {
    struct ifi_info *ifi, *ifihead, *local_ifi, *arbitrary_ifi;
    int isLocal;

    ifihead = Get_ifi_info_plus(AF_INET, 1);

    printf("\nFollowing are different Interfaces:\n");
    print_ifi_info_plus(ifihead);
    printf("\n");

    local_ifi = arbitrary_ifi = NULL;
    for (ifi = ifihead ; ifi != NULL; ifi = ifi->ifi_next) {
        if (verifyIfLocal(ifi, local_ifi, server_ip)) {
            local_ifi = ifi;
        }
        if (!(ifi->ifi_flags & IFF_LOOPBACK)) {
            arbitrary_ifi = ifi;
        }
    }

    isLocal = 0;
    if (local_ifi) {
        client_ip->s_addr = IFI_ADDR(local_ifi);
        if (!(local_ifi->ifi_flags & IFF_LOOPBACK))
            isLocal = 1;
    } else if (arbitrary_ifi) {
        client_ip->s_addr = IFI_ADDR(arbitrary_ifi);
    } else {
        isLocal = -1;
    }

    free_ifi_info_plus(ifihead);

    return isLocal;
}

static int bindAndConnect(struct sockaddr_in *servAddr, struct in_addr client_ip) {
    struct sockaddr_in cliAddr;
    int sockfd = Socket(AF_INET, SOCK_DGRAM, 0);
    char buf[INET_ADDRSTRLEN];
    int len;

    bzero(&cliAddr, sizeof(cliAddr));
    cliAddr.sin_family = AF_INET;
    cliAddr.sin_addr = client_ip;
    cliAddr.sin_port = 0;
    
    Bind(sockfd, (SA *)&cliAddr, sizeof(cliAddr));

    len = sizeof(cliAddr);
    Getsockname(sockfd, (SA *)&cliAddr, &len);

    printf("Client IP => %s, Port => %d\n",
            inet_ntop(AF_INET, &cliAddr.sin_addr, buf, INET_ADDRSTRLEN),
            ntohs(cliAddr.sin_port));

    len = sizeof(*servAddr);
    Connect(sockfd, (SA *) servAddr, len);

    Getpeername(sockfd, (SA *)servAddr, &len);

    printf("Server IP => %s, Port => %d\n\n",
            inet_ntop(AF_INET, &servAddr->sin_addr, buf, INET_ADDRSTRLEN),
            ntohs(servAddr->sin_port));

    return sockfd;
}

static sigjmp_buf jmpFor2HS;

static void sig_alarm(int signo) {
    siglongjmp(jmpFor2HS, 1);
}

static int handshake(int sockfd, struct sockaddr_in servAddr, char *fileName, int flags) {
    char sendBuf[MAXLINE], recvBuf[MAXLINE];
    int newPortNo, n, retransmitCount;
    
    retransmitCount = 0;
    strcpy(sendBuf, fileName);
    
send1HSAgain:
    // Send 1st HS
    writeWithPacketDrops(sockfd, (SA*) &servAddr, sizeof(servAddr), sendBuf, strlen(sendBuf),
                        flags, "Sending 1st HS");
    ++retransmitCount;

    // TODO: change alarm to setitimer
    alarm(3);
    
    if (sigsetjmp(jmpFor2HS, 1) != 0) {
        if (retransmitCount > MAX_RETRANSMIT) {
            err_quit("Client Terminated due to Timeout!!");
        }
        printf(_1TAB "Timeout\n");
        goto send1HSAgain;
    } 

    // Receive 2nd HS
    n = readWithPacketDrops(sockfd, recvBuf, MAXLINE, flags, "Receving 2nd HS");

    alarm(0);
    recvBuf[n] = '\0';
    newPortNo = atoi(recvBuf);

    // Reconnect to new port number
    printf(_2TABS "Reconnecting socket to new Port No => %d\n", newPortNo);
    servAddr.sin_port = htons(newPortNo);
    Connect(sockfd, (SA *) &servAddr, sizeof(servAddr));

    strcpy(sendBuf, "Done");

send3HSAgain:
    // Send 3rd HS
    writeWithPacketDrops(sockfd, (SA*) &servAddr, sizeof(servAddr), sendBuf, strlen(sendBuf),
                        flags, "Sending 3rd HS");

    // TODO: Read 1st File Packet and verify sequence number
    n = readWithPacketDrops(sockfd, recvBuf, MAXLINE, flags, "Receving New Packet");
    if (n != 1)
        goto send3HSAgain;
//  else begin file transfer

}

int main() {
    struct hostent *hostInfo;
    struct in_addr client_ip;
    struct sockaddr_in servAddr;
    int sockfd, isLocal;

    // Read input parameters
    parseClientParams();

    if ((hostInfo = getHostInfoByAddr(in_server_ip)) == NULL) {
        err_quit("Invalid Server IPAddress - %s", in_server_ip);
    }

    printf("The server host is -> %s (%s)\n", hostInfo->h_name, in_server_ip);

    // Get Client IP Address
    if ((isLocal = getClientIP((struct in_addr*) hostInfo->h_addr, &client_ip)) == -1) {
        err_quit("No interface found!\n");
    } else if (isLocal == 1) {
        printf("Server found on Local Interface:\n");
    } else {
        printf("Server Not found on Local Interface:\n");
    }

    bzero(&servAddr, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr = *(struct in_addr*) hostInfo->h_addr;
    servAddr.sin_port = htons(in_server_port);

    sockfd = bindAndConnect(&servAddr, client_ip);

    srand48(in_random_seed);
    Signal(SIGALRM, sig_alarm);

    // 3 way Handshake
    handshake(sockfd, servAddr, in_file_name, isLocal ? MSG_DONTROUTE : 0);

    return 0;
}

