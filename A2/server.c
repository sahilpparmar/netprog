#include "server.h"

static int in_port_no, in_window_size;
static ClientRequest *Head = NULL;

static void sig_child(int signo) { 
    // Remove child entry from the linkedlist 
    ClientRequest *cur = Head;
    ClientRequest *prev = NULL;
    pid_t pid = wait(NULL);
    
    while (cur != NULL) {
        if (cur->childpid == pid) {
            // remove this entry
            if (Head == cur)
                Head = cur->next;
            else 
                prev = cur->next;

            printf(KRED "\nChild deleted => Pid: %d" RESET "\n", pid);
            free(cur);
            return;
        }
        prev = cur;
        cur = cur->next;
    }
    printf("ERROR!! Unable to find a record for child with pid:%d \n",pid);
    return;
}

static int initializeParams() {
    char data[MAXLINE];
    FILE *inp_file = fopen(SERVER_IN, "r");

    if (inp_file == NULL) {
        err_quit("Unknown server argument file: '%s'\n", SERVER_IN);
    }
    in_port_no = getIntParamValue(inp_file);
    in_window_size = getIntParamValue(inp_file);
    Fclose(inp_file);
}

static int* bindAllInterfaces(struct ifi_info *ifihead, int totalIP) {
    struct ifi_info *ifi;
    struct sockaddr_in servaddr;
    int *sockfd;
    int i;

    sockfd = (int *) Malloc(totalIP * sizeof(int));

    for (i = 0, ifi = ifihead; ifi != NULL; ifi = ifi->ifi_next) {
        sockfd[i] = Socket(AF_INET, SOCK_DGRAM, 0);
        bzero(&servaddr, sizeof(servaddr));
        servaddr = *(struct sockaddr_in *)ifi->ifi_addr;
        servaddr.sin_port = htons(in_port_no);
        Bind(sockfd[i++], (SA *)&servaddr, sizeof(servaddr));
    }

    return sockfd;
}

static int compare_address(struct sockaddr_in *prev_req, struct sockaddr_in *new_req) {
    if ((prev_req->sin_addr.s_addr != new_req->sin_addr.s_addr) ||  // Check the IP Address
        (prev_req->sin_port != new_req->sin_port) ||                // Check the Port Number
        (prev_req->sin_family != new_req->sin_family))              // Check the Address family
    {
        return 1; // New Request
    } else {
        return 0; // Duplicate Request
    }
}

static ClientRequest* searchAndUpdateClientList(struct sockaddr_in cliaddr) {
    ClientRequest *cur = Head;
 
    // Check if it is a duplicate request
    while(cur != NULL) {
        if (compare_address(&(cur->cliaddr), &cliaddr) == 0)
            return NULL;
        cur = cur->next;
    }
    
    // Create a node if the entry is not present
    ClientRequest *new_node = (ClientRequest*) Malloc(sizeof(ClientRequest));
    new_node->cliaddr = cliaddr;
    new_node->next = Head;
    Head = new_node; // update head node

    return new_node;
}

static sigjmp_buf jmpbuf;

static void sig_alarm(int signo) {
    siglongjmp(jmpbuf, 1);
}

static pid_t serveNewClient(struct sockaddr_in cliaddr, int *sock_fd, int req_sock,
                            int total_IP, char* fileName, int isLocal)
{
    pid_t pid;

    // Child process
    if ((pid = Fork()) == 0) {
        /* Child would close all the socket descriptor except one
         * Next it would create a new socket and send a second handshake
         * to the client with the new socket in the payload.
         * It would also start a new timer for the second handshake 
         */

        // Close all the sockets except the one where request arrived
        int i;
        for (i = 0; i < total_IP; i++ ) {
            if (i != req_sock)
                Close(sock_fd[i]);
        }

        struct sockaddr_in servAddr;
        SendWinQueue SendWinQ;
        TcpPckt packet;
        char sendBuf[MAX_PAYLOAD+1], recvBuf[MAX_PAYLOAD+1];
        char errMsg[MAX_PAYLOAD+1] = "";
        uint32_t seqNum, ackNum, winSize, timestamp, retransmitCnt;
        int len, connFd, newChildPortNo, send2HSFromConnFd;
        struct rtt_info rttInfo;
        struct itimerval timer;


        // To get server IP address
        len = sizeof(struct sockaddr_in);
        Getsockname(sock_fd[req_sock], (SA *) &servAddr, &len);

        printf("\nUsing Server IP:Port => %s\n", Sock_ntop((SA *) &servAddr, sizeof(struct sockaddr_in)));

        // Create a new connection socket
        connFd = Socket(AF_INET, SOCK_DGRAM, 0);

        // Set socket option -> SO_DONTROUTE if client is local
        if (isLocal) {
            int optVal = 1;
            Setsockopt(connFd, SOL_SOCKET, SO_DONTROUTE, &optVal, sizeof(optVal));
        }

        // Bind connection socket
        servAddr.sin_port = 0; // Choose a new port number
        Bind(connFd, (SA *)&servAddr, sizeof(servAddr));

        // Get new port number for connection socket
        Getsockname(connFd, (SA *) &servAddr, &len);
        newChildPortNo = ntohs(servAddr.sin_port);

        sprintf(sendBuf, "%d", newChildPortNo);
        send2HSFromConnFd = 0;
        Signal(SIGALRM, sig_alarm);

        rtt_init(&rttInfo);
        retransmitCnt = 0;

send2HSAgain:
        // Send second handshake
        len = fillPckt(&packet, SYN_ACK_SEQ_NO, ACK_SEQ_NO, 0, sendBuf, MAX_PAYLOAD);
        printf(KYEL);
        printf("\nSecond HS sent from Listening Socket => New Conn Port No: %s\n" , packet.data);
        Sendto(sock_fd[req_sock], &packet, len, 0, (SA *) &cliaddr, sizeof(cliaddr));

        if (send2HSFromConnFd) {
            printf("Second HS sent from Conn Socket => New Conn Port No: %s\n", packet.data);
            Sendto(connFd, &packet, len, 0, (SA *) &cliaddr, sizeof(cliaddr));
        }
        printf(RESET);
        timestamp = rtt_ts(&rttInfo);
        retransmitCnt++;
        
        setTimer(&timer, rtt_start(&rttInfo));

        if (sigsetjmp(jmpbuf, 1) != 0) {
            printf(KRED "Receving Third HS => TIMEOUT\n" RESET);
            if (rtt_timeout(&rttInfo, retransmitCnt)) {
                char *str = "\nServer Child Terminated due to 12 Timeouts";
                printf(KRED); err_msg(str); printf(RESET);
                strcpy(errMsg, str);
                goto error;
            }
            send2HSFromConnFd = 1;
            goto send2HSAgain;
        } 

        // Receive third Handshake
        len = Recvfrom(connFd, &packet, DATAGRAM_SIZE, 0,  NULL, NULL);

        setTimer(&timer, 0);

        rtt_stop(&rttInfo, timestamp);

        readPckt(&packet, len, &seqNum, &ackNum, &winSize, recvBuf);
        printf(KYEL "\nThird HS received =>  ACK num: %d\t Advertised Win: %d\n" RESET, ackNum, winSize);
        printf(KGRN "Connection Establised Successfully\n" RESET);

        // Connect to Client addr
        Connect(connFd, (SA *) &cliaddr, sizeof(cliaddr));
        Close(sock_fd[req_sock]);

        int fileFd;
        if ((fileFd = open(fileName, O_RDONLY)) == -1) {
            char *str = "\nServer Child Terminated due to Invalid FileName";
            printf(KRED); err_msg(str); printf(RESET);
            strcpy(errMsg, str);
            goto error;
        }

        initializeSendWinQ(&SendWinQ, in_window_size, winSize, ackNum);
        sendFile(&SendWinQ, connFd, fileFd, rttInfo);

error:
        terminateConnection(connFd, errMsg);

        exit(0);
    } // End - Child Process
    
    return pid;
} 

static int listenAllConnections(struct ifi_info *ifihead, int *sockfd, int totalIP) {
    sigset_t sigset;
    fd_set fixedFdset, varFdset;
    int maxfd = sockfd[totalIP-1] + 1;
    int i, n;
    
    TcpPckt packet; 
    uint32_t seqNum, ackNum, winSize;
    char recvBuf[MAX_PAYLOAD+1];

    FD_ZERO(&fixedFdset);
    for (i = 0 ; i < totalIP; i++)
        FD_SET(sockfd[i], &fixedFdset);

    Signal(SIGCHLD, sig_child); 
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGCHLD);

    while (1) {
        // Listen using select on all sockets
        varFdset = fixedFdset;
        if (select(maxfd, &varFdset, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) {
                // Retry select() if interupted by signal handler of SIGCHLD
                continue;
            } else {
                err_sys("Server termination due to error on select()");
            }
        }
        
        // Check which Socket got packets
        for (i = 0 ; i < totalIP; i++) {
            if (FD_ISSET(sockfd[i], &varFdset)) {
                struct sockaddr_in cliaddr;
                socklen_t len = sizeof(cliaddr);
        
                n = Recvfrom(sockfd[i], &packet, DATAGRAM_SIZE, 0, (SA *)&cliaddr, &len);
                readPckt(&packet, n, &seqNum, &ackNum, &winSize, recvBuf);

                if (searchAndUpdateClientList(cliaddr) != NULL) {
                    int isLocal = verifyIfLocalAndGetHostIP(ifihead, &cliaddr.sin_addr, NULL);

                    printf("\nNew request from client %son Local Interface => %s\n",
                            isLocal == 0 ? "Not " : "",
                            Sock_ntop((SA *) &cliaddr, sizeof(struct sockaddr_in)));
                    printf(KYEL "First HS received =>  fileName: %s\n" RESET, recvBuf);

                    // Block SIGCHLD until parent sets child pid in ClientRequest list
                    sigprocmask(SIG_BLOCK, &sigset, NULL);
                    Head->childpid = serveNewClient(cliaddr, sockfd, i, totalIP, recvBuf, isLocal);
                    sigprocmask(SIG_UNBLOCK, &sigset, NULL);
                }
            }
        }
    }
}

int main() {
    struct ifi_info *ifihead;
    int *sockfd, totalIP;

    initializeParams();
    
    // Get all interfaces
    ifihead = Get_ifi_info_plus(AF_INET, 1/*doalias*/);
    totalIP = print_ifi_info_plus(ifihead);

    sockfd = bindAllInterfaces(ifihead, totalIP);
    listenAllConnections(ifihead, sockfd, totalIP);

    free_ifi_info_plus(ifihead);
    exit(0);
}

