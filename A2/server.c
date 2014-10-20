#include "unp.h"
#include "unpifiplus.h"
#include "common.h"

#define SERVER_IN "server.in"
#define READ_BUFF 1024

typedef struct client_request {
    struct sockaddr_in cliaddr;
    pid_t childpid;
    struct client_request *next;
} client_request;

static int PORT_NO, WINDOW_SIZE;
static client_request *Head = NULL;

static void sig_child(int signo) { 
    // Remove child entry from the linkedlist 
    client_request *cur = Head;
    client_request *prev = NULL;
    pid_t pid = wait(NULL);
    
    while (cur != NULL) {
        if (cur->childpid == pid) {
            // remove this entry
            if (Head == cur)
                Head = cur->next;
            else 
                prev = cur->next;

            printf("Child deleted with Pid : %d\n", pid);
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
        err_quit("Unknown server argument file : '%s'\n", SERVER_IN);
    }
    if ((PORT_NO = atoi(getParam(inp_file, data, MAXLINE))) == 0) {
        err_quit("Port number not set correctly\n");
    }
    if ((WINDOW_SIZE = atoi(getParam(inp_file, data, MAXLINE))) == 0) {
        err_quit("Window Size not set correctly\n");
    }
    Fclose(inp_file);
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

static client_request* searchAndUpdateClientList(struct sockaddr_in cliaddr) {
    client_request *cur = Head;
 
    // Check if it is a duplicate request
    while(cur != NULL) {
        if (compare_address(&(cur->cliaddr), &cliaddr) == 0)
            return NULL;
        cur = cur->next;
    }
    
    // Create a node if the entry is not present
    client_request *new_node = (client_request*) malloc(sizeof(client_request));
    new_node->cliaddr = cliaddr;
    new_node->next = Head;
    Head = new_node; // update head node

    return new_node;
}

static void Sleep(int sec, int msec) {
    struct timeval timeout;
    timeout.tv_sec = sec;
    timeout.tv_usec = msec;
    Select(1, NULL, NULL, NULL, &timeout);
}

static void serveNewClient(client_request *cliReq, struct sockaddr_in cliaddr,
                            int *sock_fd, int req_sock, int total_IP, char* fileName)
{
    pid_t pid;
    printf("\nNew request from client: %s\n", Sock_ntop((SA *)&(cliReq->cliaddr), sizeof(struct sockaddr_in)));

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

        // create a new socked and connect with the client and bind to it
        
        struct sockaddr_in servAddr;
        int len, connFd, newChildPortNo;
        char message[MAXLINE];

        // To get server IP address
        len = sizeof(struct sockaddr_in);
        Getsockname(sock_fd[req_sock],(SA *) &servAddr, &len);

        printf("Server IP address is: %s\n", inet_ntoa(servAddr.sin_addr));
        printf("Local port is: %d\n", (int) ntohs(servAddr.sin_port));

        // Create a new connection socket
        connFd = Socket(AF_INET, SOCK_DGRAM, 0);

        // Bind connection socket
        servAddr.sin_port = 0; // Choose a new port number
        Bind(connFd, (SA *)&servAddr, sizeof(servAddr));

        // Get new port number for connection socket
        Getsockname(connFd,(SA *) &servAddr, &len);
        newChildPortNo = ntohs(servAddr.sin_port);
        printf("New Conn Port No : %d\n", newChildPortNo); 
        
        // Connect to Client request
        Connect(connFd, (SA *) &cliaddr, sizeof(cliaddr));

        // Send second handshake
        sprintf(message, "%d", newChildPortNo);
        Sendto(sock_fd[req_sock], message, strlen(message), 0, (SA *) &cliaddr, sizeof(cliaddr));
        printf("Second HS sent : %s\n", message);
        
        // Receive third Handshake
        len = Read(connFd, message, MAXLINE);
        message[len] = '\0';
        printf("Third HS received : %s\n", message);
        
        Close(sock_fd[req_sock]);

        // TODO: Begin file transfer
        // Also remove below Sleep once actual file transfer begins
        Sleep(0, 10);

        exit(0);
    } // End - Child Process

    // Parent Process
    else {
        cliReq->childpid = pid;
    }
} 

static int* getAllInterfaces(int *totalIP) {
    struct ifi_info *ifi, *ifihead;
    struct sockaddr *sa;
    int i, counter = 0;
    int *sockfd;
    struct sockaddr_in servaddr, cliaddr;
    u_char *ptr;
    
    // Iterate over get_ifi_info_plus and count the total number of IP addresses
    ifihead = Get_ifi_info_plus(AF_INET, 1/*doalias*/);
    *totalIP = print_ifi_info_plus(ifihead);
    printf("Total number of IP addresses: %d\n", *totalIP);

    sockfd = (int *) malloc(*totalIP * sizeof(int));

    for (ifi = ifihead; ifi != NULL; ifi = ifi->ifi_next) {
        sockfd[counter] = Socket(AF_INET, SOCK_DGRAM, 0);
        bzero(&servaddr, sizeof(servaddr));
        servaddr = *(struct sockaddr_in *)ifi->ifi_addr;
        servaddr.sin_port = htons(PORT_NO);
        Bind(sockfd[counter++], (SA *)&servaddr, sizeof(servaddr));
    }
    free_ifi_info_plus(ifihead);

    return sockfd;
}


static int listenAllConnections(int *sockfd,int totalIP) {
    int maxfd = sockfd[totalIP-1] + 1;
    char message[MAXLINE];
    int i, n = 0;

    // Listen using select on all sockets
    fd_set rset;
    FD_ZERO(&rset);

    while (1) {
        for (i = 0 ; i < totalIP; i++)
            FD_SET(sockfd[i], &rset);

    retry:
        if (n = select(maxfd, &rset, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) {
                goto retry;
            } else {
                err_sys("Server termination due to error on select()");
            }
        }
        
        // Check which Socket got packets
        for (i = 0 ; i < totalIP; i++) {
            if (FD_ISSET(sockfd[i], &rset)) {
                struct sockaddr_in cliaddr;
                socklen_t len = sizeof(cliaddr);
                n = Recvfrom(sockfd[i], message, MAXLINE, 0, (SA *)&cliaddr, &len);
                message[n] = '\0';
                if (searchAndUpdateClientList(cliaddr) != NULL) {
                    serveNewClient(Head, cliaddr, sockfd, i, totalIP, message);
                }
            }
        }
    }
}

int main() {
    int *sockfd, totalIP;

    Signal(SIGCHLD, sig_child); 
    initializeParams();
    sockfd = getAllInterfaces(&totalIP);
    listenAllConnections(sockfd, totalIP);
    exit(0);
}

