#include "client.h"
#include "time.h"

static char  in_server_ip[PARAM_SIZE];     // Server IP
static int   in_server_port;               // Server PortNo
static char  in_file_name[PARAM_SIZE];     // FileName to be transfered
static int   in_receive_win;               // Size of receiving sliding window
static int   in_random_seed;               // Random Gen Seed Value
float        in_packet_loss;               // Probability of packet loss
int          in_read_delay;                // mean millisec at which client reads data from receving window

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
        err_quit("Unknown client argument file: '%s'", CLIENT_IN);
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

static int verifyIfLocalAndGetClientIP(struct in_addr *server_ip, struct in_addr *client_ip) {
    struct ifi_info *ifihead;
    int isLocal;

    ifihead = Get_ifi_info_plus(AF_INET, 1);
    print_ifi_info_plus(ifihead);
    
    isLocal = verifyIfLocalAndGetHostIP(ifihead, server_ip, client_ip);
    
    free_ifi_info_plus(ifihead);

    return isLocal;
}

static int bindAndConnect(struct sockaddr_in *servAddr, struct in_addr client_ip, int isLocal) {
    struct sockaddr_in cliAddr;
    char buf[INET_ADDRSTRLEN];
    int sockfd, n;

    sockfd = Socket(AF_INET, SOCK_DGRAM, 0);

    // Set socket option -> SO_DONTROUTE if server is local
    if (isLocal) {
        int optVal = 1;
        Setsockopt(sockfd, SOL_SOCKET, SO_DONTROUTE, &optVal, sizeof(optVal));
    }

    bzero(&cliAddr, sizeof(cliAddr));
    cliAddr.sin_family = AF_INET;
    cliAddr.sin_addr = client_ip;
    cliAddr.sin_port = 0;
    
    Bind(sockfd, (SA *)&cliAddr, sizeof(cliAddr));

    n = sizeof(cliAddr);
    Getsockname(sockfd, (SA *)&cliAddr, &n);

    printf("Client IP => %s, Port => %d\n",
            inet_ntop(AF_INET, &cliAddr.sin_addr, buf, INET_ADDRSTRLEN),
            ntohs(cliAddr.sin_port));

    n = sizeof(*servAddr);
    Connect(sockfd, (SA *) servAddr, n);

    Getpeername(sockfd, (SA *)servAddr, &n);

    printf("Server IP => %s, Port => %d\n\n",
            inet_ntop(AF_INET, &servAddr->sin_addr, buf, INET_ADDRSTRLEN),
            ntohs(servAddr->sin_port));

    return sockfd;
}

static sigjmp_buf jmpFor2HS;
static void sig_alarm(int signo) {
    siglongjmp(jmpFor2HS, 1);
}

static int handshake(int sockfd, struct sockaddr_in servAddr, RecWinQueue *RecWinQ) {
    TcpPckt packet;
    uint32_t seqNum, ackNum, winSize;
    char recvBuf[MAX_PAYLOAD+1];
    int newPortNo, retransmitCount, len;
    struct itimerval timer;

    
    Signal(SIGALRM, sig_alarm);
    retransmitCount = 0;
    
send1HSAgain:
    // Send 1st HS
    seqNum = SYN_SEQ_NO; ackNum = SYN_ACK_SEQ_NO; winSize = in_receive_win;
    fillPckt(&packet, seqNum, ackNum, winSize, in_file_name, strlen(in_file_name));

    writeWithPacketDrops(sockfd, &packet, HEADER_LEN+strlen(in_file_name),
                        "Sending 1st HS (SYN)\t");
    ++retransmitCount;

    setTimer(&timer, CLIENT_TIMER);
    
    if (sigsetjmp(jmpFor2HS, 1) != 0) {
        printf("\nReceiving 2nd HS (SYN-ACK): " _4TABS KRED "\tTimeout\n" RESET);
        if (retransmitCount >= MAX_RETRANSMIT) {
            err_quit("Client Terminated due to 12 Timeouts");
        }
        goto send1HSAgain;
    } 

    // Receive 2nd HS
    len = readWithPacketDrops(sockfd, &packet,
            DATAGRAM_SIZE, "Receiving 2nd HS (SYN-ACK)");
    readPckt(&packet, len, &seqNum, &ackNum, &winSize, recvBuf);

    setTimer(&timer, 0);
    newPortNo = atoi(recvBuf);

    // Reconnect to new port number
    printf("\nReconnecting socket to new Port No => %d\n", newPortNo);
    servAddr.sin_port = htons(newPortNo);
    Connect(sockfd, (SA *) &servAddr, sizeof(servAddr));

send3HSAgain:
    // Send 3rd HS
    seqNum = ACK_SEQ_NO; ackNum = DATA_SEQ_NO; winSize = in_receive_win;
    fillPckt(&packet, seqNum, ackNum, winSize, NULL, 0);

    writeWithPacketDrops(sockfd, &packet, HEADER_LEN, "Sending 3rd HS (ACK)\t");

    len = readWithPacketDrops(sockfd, &packet,
            DATAGRAM_SIZE, "Receiving 1st file packet");
    readPckt(&packet, len, &seqNum, &ackNum, &winSize, recvBuf);

    // Verify if packet is for 2HS or 1st file packet
    if (seqNum == SYN_ACK_SEQ_NO) {
        printf(KYEL "2HS from Server\n" RESET);
        goto send3HSAgain;
    }

    // Initialize Receiving Window
    if (initializeRecWinQ(RecWinQ, &packet, len, in_receive_win) == FIN_SEQ_NO) {
        // Received FIN - terminate connection
        terminateConnection(sockfd, RecWinQ, &packet, len);
        exit(0);
    }
    sendAck(RecWinQ, sockfd);
}

int main() {
    struct hostent *hostInfo;
    struct in_addr client_ip;
    struct sockaddr_in servAddr;
    RecWinQueue RecWinQ;
    int sockfd, isLocal;

    // Read input parameters
    parseClientParams();

    if ((hostInfo = getHostInfoByAddr(in_server_ip)) == NULL) {
        err_quit("Invalid Server IPAddress - %s", in_server_ip);
    }

    printf("The server host is -> %s (%s)\n", hostInfo->h_name, in_server_ip);

    // Get Client IP Address
    if ((isLocal = verifyIfLocalAndGetClientIP((struct in_addr*) hostInfo->h_addr, &client_ip)) == -1) {
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

    sockfd = bindAndConnect(&servAddr, client_ip, isLocal);

    srand48(in_random_seed);

    // 3 way Handshake
    handshake(sockfd, servAddr, &RecWinQ);

    // Begin file transfer
    fileTransfer(&sockfd, &RecWinQ);

    return 0;
}

