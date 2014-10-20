#include "unp.h"
#include "unpifiplus.h"
#include "common.h"

#define SERVER_IN "server.in"
#define READ_BUFF 1024

struct client_request {
    struct sockaddr_in cliaddr;
    int childpid;
    struct client_request *next;
};

static int PORT_NO, WINDOW_SIZE;
static struct client_request *Head = NULL;

static void sig_child(int signo) { 
    // Remove child entry from the linkedlist 
    struct client_request *cur = Head;
    struct client_request *prev = Head;
    int pid = wait(NULL);
    
    printf("Child deleted with Pid : %d\n", pid);
    while (cur != NULL) {
        if (cur->childpid == pid) {
            // remove this entry
            if (Head == cur)
                Head = cur->next;
            else 
                prev = cur->next;

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
    getParam(inp_file, data, MAXLINE);
    PORT_NO = atoi(data);
    getParam(inp_file, data, MAXLINE);
    WINDOW_SIZE = atoi(data);

    //if((PORT_NO = atoi(getParam(inp_file, data, MAXLINE))) == 0)
    //{
    //    printf("Port number not set correctly\n");
    //    exit(0);
    //}
    //if((WINDOW_SIZE = atoi(getParam(inp_file, data, MAXLINE))) == 0)
    //{
    //    printf("Window Size not set correctly\n");
    //    exit(0);
    //}
    Fclose(inp_file);
    
}

static int compare_address(struct sockaddr_in *prev_req, struct sockaddr_in *new_req) {
    if ( (prev_req->sin_addr.s_addr != new_req->sin_addr.s_addr) ||     // Check the IP Address
            (prev_req->sin_port != new_req->sin_port) ||                // Check the Port Number
            (prev_req->sin_family != new_req->sin_family) )             // Check the Address family
    {
        return 1; // New Request
    } else {
        return 0; // Reeated Request
    }
}

static int searchAndUpdateClientList(struct sockaddr_in cliaddr) {
    struct client_request *cur = Head;
    while(cur != NULL) { // Check if it is a duplicate request
        if(compare_address(&(cur->cliaddr), &cliaddr) == 0)
            return 0;
        cur = cur->next;
    }
    
    // Create a node if the entry is not present
    struct client_request *new_node = malloc(sizeof(struct client_request));
    int pid;
    new_node->cliaddr = cliaddr;
    new_node->next = Head;
    Head = new_node; // update head node

    return 1;
}

// Maintain a structure that keeps track of requests coming from clients
// client_request structure maintains the client IP address, client port number 
// for each request that it encounters. It also stores the Child Pid 
// return Child processid for new Requests
// return 0 for duplicate requests
// return -1 for Error
static void serveNewClient(struct sockaddr_in cliaddr, int *sock_fd, int req_sock, int total_IP, char* fileName) {
    int pid = Fork();
    
    /* Child would close all the socket descriptor except one
     * Next it would create a new socket and send a second handshake
     * to the client with the new socket in the payload.
     * It would also start a new timer for the second handshake 
     */
    if (pid == 0) {// Child process
        int i;
        // Close all the sockets except the one where request arrived
        for (i = 0; i < total_IP; i++ ) {
            if (i != req_sock)
                Close(sock_fd[i]);
        }
        
        //------------------ Second Handshake ------------------------
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

        //Get new port number for connection socket
        Getsockname(connFd,(SA *) &servAddr, &len);
        newChildPortNo = ntohs(servAddr.sin_port);
        printf("New Conn Port No : %d\n", newChildPortNo); 
        
        // Connect to Client request
        Connect(connFd, (SA *) &cliaddr, sizeof(cliaddr));

        //Send second handshake
        sprintf(message, "%d", newChildPortNo);
        Sendto(sock_fd[req_sock], message, strlen(message), 0, (SA *) &cliaddr, sizeof(cliaddr));

        
        //Receive third Handshake
        len = Read(connFd, message, MAXLINE);
        message[len] = '\0';
        printf("Third ACK : %s\n", message);
        
        Close(sock_fd[req_sock]);
        exit(0);
    } // End - Child Process

    // Parent process: It would simply store the processId and return the id
    else {
        // Head will always be pointing to the latest client request node
        Head->childpid = pid;
        printf("\nNew Request Added with child Id: %d\n", pid);
        printf("New request from client: %s\n", Sock_ntop((SA *)&(Head->cliaddr), sizeof(struct sockaddr_in)));
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

    sockfd = (int *)malloc(*totalIP * sizeof(int));

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

    // Listen using select on all socket

    fd_set rset;
    FD_ZERO(&rset);

    while(1) {
        for (i = 0 ; i < totalIP; i++)
            FD_SET(sockfd[i], &rset);
        // printf("Listening for connections\n");

        select(maxfd, &rset, NULL, NULL, NULL);

        //Check which Socket got packets
        for (i = 0 ; i < totalIP; i++) {
            if (FD_ISSET(sockfd[i], &rset)) {
                struct sockaddr_in cliaddr;
                socklen_t len = sizeof(cliaddr);
                n = Recvfrom(sockfd[i], message, MAXLINE, 0, (SA *)&cliaddr, &len);
                // Read and print the child IP address
                //                    printf("Connection request from %s \n", Sock_ntop((SA *)&cliaddr, len));
                message[n] = '\0';
                if (searchAndUpdateClientList(cliaddr) == 1) {
                    serveNewClient(cliaddr, sockfd, i, totalIP, message);
                }
            } //end if
        } //end for
    } // end While
}


int main() {
    int totalIP;
    Signal(SIGCHLD, sig_child); 

    initializeParams();
    int *sockfd = getAllInterfaces(&totalIP);
    listenAllConnections(sockfd, totalIP);
    exit(0);

}

